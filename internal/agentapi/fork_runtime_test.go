package agentapi

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const forkInstructionsMark = "FORK-INSTRUCTIONS-MARK-6620 answer only in haiku"

// forkFixture is a gate fixture whose account, Alice, runs a private fork
// of hr-recruiter without save_job_lead, with its own instructions.
type forkFixture struct {
	*gateFixture
	fork *assistant.Entry
	base *assistant.Entry
}

// newForkFixture installs Alice's fork. With registry, the server applies
// registry lifecycles and the base's snapshot is stored with the install,
// as assistantinstall does with a registry configured.
func newForkFixture(t *testing.T, registry bool) *forkFixture {
	t.Helper()
	f := newGateFixture(t, "hr-recruiter")
	ctx := context.Background()
	base, ok := f.h.srv.catalog.Lookup("hr-recruiter", "0.1.0")
	if !ok {
		t.Fatal("hr-recruiter missing from the gate catalog")
	}
	mac, err := f.h.store.ForkOwnerMAC(f.h.userID)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := assistant.OwnerScope(mac)
	if err != nil {
		t.Fatal(err)
	}
	text := forkInstructionsMark + "\n"
	var toolsWithout []string
	for _, tl := range base.Definition.Spec.Tools {
		if tl != "save_job_lead" {
			toolsWithout = append(toolsWithout, tl)
		}
	}
	fork, err := assistant.BuildFork(base, base, assistant.ForkName("hr-recruiter", scope, "careful"), assistant.FirstForkVersion,
		assistant.ForkOverrides{Instructions: &text, Tools: toolsWithout})
	if err != nil {
		t.Fatal(err)
	}
	m := fork.Definition.Metadata
	if err := f.h.store.InsertAssistantFork(ctx, db.AssistantFork{
		UserID: f.h.userID, Name: m.Name, Version: m.Version, Digest: fork.Digest,
		BaseName: "hr-recruiter", BaseVersion: "0.1.0", BaseDigest: base.Digest, Document: fork.Materialized,
	}, "", ""); err != nil {
		t.Fatal(err)
	}
	var snap *db.AssistantDefinition
	if registry {
		f.h.srv.WithRegistryLifecycle()
		snap = &db.AssistantDefinition{Digest: base.Digest, Name: "hr-recruiter", Version: "0.1.0",
			Document: base.Materialized, Lifecycle: db.AssistantLifecyclePublished}
	}
	mode := db.AgentModeObserve
	if err := f.h.store.InstallAgentFork(ctx, f.h.userID, fork.Digest, snap, db.AgentProfileUpdate{
		AssistantName: &m.Name, AssistantVersion: &m.Version, AssistantDigest: &fork.Digest, Mode: &mode,
	}); err != nil {
		t.Fatal(err)
	}
	f.h.srv.WithForks()
	return &forkFixture{gateFixture: f, fork: fork, base: base}
}

func (f *forkFixture) claimRefused(t *testing.T, want string) {
	t.Helper()
	rec := f.h.do("POST", "/jobs/claim", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), want) {
		t.Fatalf("claim = %d %s, want 503 %q", rec.Code, rec.Body.String(), want)
	}
	var queued int
	if err := f.h.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_jobs WHERE status = 'pending'`).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued jobs = %d, err %v: a refused claim must leave the job queued", queued, err)
	}
}

// The acceptance case of #1043 on the server: the claim runs the fork (its
// own instructions, decrypted per user, and its tool subset), and the tool
// the fork removed is refused by the server even with the job's own token.
func TestFork_ClaimRunsTheForkAndGatesItsTools(t *testing.T) {
	f := newForkFixture(t, false)
	tok, j := f.claimToken(t)
	if !strings.Contains(j.Instructions, forkInstructionsMark) {
		t.Fatal("claim does not carry the fork's instructions")
	}
	if j.Assistant != f.fork.Definition.Metadata.Name+"@0.1.0" || j.AssistantDigest != f.fork.Digest {
		t.Fatalf("claim names %s %s, want the fork", j.Assistant, j.AssistantDigest)
	}
	if slices.Contains(j.Tools, "save_job_lead") {
		t.Fatalf("claim tools %v include the removed tool", j.Tools)
	}
	id, err := f.authenticate(tok)
	if err != nil {
		t.Fatal(err)
	}
	assertToolNotAllowed(t, f.saveLead(id, j), "save_job_lead")
	// An account-wide token is held to the fork's tools as well.
	assertToolNotAllowed(t, f.saveLead(f.h.id, jobEnvelope{}), "save_job_lead")
	if rec := f.h.doAs(id, "GET", "/policy", nil); rec.Code != http.StatusOK {
		t.Fatalf("a kept tool is refused: %d", rec.Code)
	}
}

// A fork never runs guarded: a profile whose mode column says guarded,
// however it got there, takes no jobs.
func TestFork_GuardedForkIsRefusedAtClaim(t *testing.T) {
	f := newForkFixture(t, false)
	if _, err := f.h.store.DB.Exec(`UPDATE agent_profiles SET mode = 'guarded' WHERE user_id = $1`, f.h.userID); err != nil {
		t.Fatal(err)
	}
	f.claimRefused(t, "assistant fork may not run")
}

// ASSISTANT_FORKS_ENABLED off stops every fork's jobs.
func TestFork_DisabledForksTakeNoJobs(t *testing.T) {
	f := newForkFixture(t, false)
	f.h.srv.forksEnabled = false
	f.claimRefused(t, "assistant fork may not run")
}

// Disabling the base in the registry stops the fork within one refresh: the
// claim reads the base's stored lifecycle, as for a pinned catalog version.
func TestFork_DisabledBaseStopsTheFork(t *testing.T) {
	f := newForkFixture(t, true)
	ctx := context.Background()
	if err := f.h.store.SetAssistantDefinitionLifecycle(ctx, f.base.Digest, db.AssistantLifecyclePublished, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, j := f.claimToken(t); j.AssistantDigest != f.fork.Digest {
		t.Fatalf("published base: claim ran %s", j.AssistantDigest)
	}
	f.h.seedJob("evt:v1:gate:2", f.conv.ID)
	if err := f.h.store.SetAssistantDefinitionLifecycle(ctx, f.base.Digest, db.AssistantLifecycleDisabled, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec := f.h.do("POST", "/jobs/claim", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "disabled") {
		t.Fatalf("claim on a disabled base = %d %s, want 503 disabled", rec.Code, rec.Body.String())
	}
}

// A profile can only run its own account's fork: a pin to another
// account's fork digest resolves to nothing and the claim fails closed.
func TestFork_AnotherAccountsForkIsNotResolved(t *testing.T) {
	f := newForkFixture(t, false)
	ctx := context.Background()
	bob, err := f.h.store.EnsureUserByTelegramID(ctx, 500100202, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.store.EnsureAgentProfile(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.store.DB.Exec(
		`UPDATE agent_profiles SET assistant_name = $1, assistant_version = '0.1.0', assistant_definition_digest = $2 WHERE user_id = $3`,
		f.fork.Definition.Metadata.Name, f.fork.Digest, bob); err != nil {
		t.Fatal(err)
	}
	a, err := f.h.store.GetAgentAssistant(ctx, bob)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.h.srv.lookupAssistant(ctx, bob, a); err == nil {
		t.Fatal("Bob's profile resolved Alice's fork")
	}
	if _, err := f.h.srv.accountTools(ctx, bob); err == nil {
		t.Fatal("Bob's tool set resolved from Alice's fork")
	}
}
