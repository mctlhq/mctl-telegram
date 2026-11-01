package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Markers for fork instructions. No tool output, audit row or owner
// notice may contain any of them: the instructions are the owner's data.
const (
	markForkText  = "FORK-TEXT-MARK-5150 be brief and formal"
	markForkText2 = "FORK-TEXT-MARK-5151 be briefer"
)

type forkFixture struct {
	*assistantFixture
	fork, updFork, del mcpserver.ToolHandlerFunc
}

func newForkFixture(t *testing.T, registry *assistantregistry.Client) *forkFixture {
	t.Helper()
	f := &forkFixture{assistantFixture: newAssistantFixture(t, nil, registry)}
	f.srv.Assistants.ForksEnabled = true
	_, f.fork = f.srv.toolForkAssistant()
	_, f.updFork = f.srv.toolUpdateFork()
	_, f.del = f.srv.toolDeleteFork()
	t.Cleanup(f.checkForkTextNeverLeaks)
	return f
}

// checkForkTextNeverLeaks scans every tool output, every audit row and
// every owner notice for the fork instructions.
func (f *forkFixture) checkForkTextNeverLeaks() {
	t := f.t
	for _, out := range f.outputs {
		for _, m := range []string{markForkText, markForkText2} {
			if strings.Contains(out, m) {
				t.Errorf("tool output contains fork instructions: %s", out)
			}
		}
	}
	rows, err := f.store.DB.Query(`SELECT tool_name, COALESCE(peer_redacted, ''), COALESCE(error, '') FROM audit_logs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tool, peer, msg string
		if err := rows.Scan(&tool, &peer, &msg); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(peer+msg, "FORK-TEXT-MARK") {
			t.Errorf("audit row of %s contains fork instructions", tool)
		}
	}
	notes, err := f.store.DB.Query(`SELECT user_id, body_encrypted FROM owner_notifications`)
	if err != nil {
		t.Fatal(err)
	}
	defer notes.Close()
	for notes.Next() {
		var uid int64
		var sealed []byte
		if err := notes.Scan(&uid, &sealed); err != nil {
			t.Fatal(err)
		}
		body, err := f.store.Crypt.OpenForUser(sealed, uid)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "FORK-TEXT-MARK") {
			t.Errorf("owner notice contains fork instructions: %s", body)
		}
	}
}

// hrToolsWithout is hr-recruiter's tool list without drop.
func hrToolsWithout(drop string) []any {
	var out []any
	for _, tl := range []string{"get_event", "get_conversation_context", "get_recruiter_profile", "get_lead", "get_policy",
		"propose_reply", "save_job_lead", "request_owner_approval", "send_owner_summary", "pause_autopilot", "complete_agent_job"} {
		if tl != drop {
			out = append(out, tl)
		}
	}
	return out
}

func (f *forkFixture) create(ctx context.Context, slug string, extra map[string]any) (*mcplib.CallToolResult, string) {
	f.t.Helper()
	args := map[string]any{"base": "hr-recruiter", "base_version": "0.1.0", "slug": slug, "instructions": markForkText}
	for k, v := range extra {
		args[k] = v
	}
	return f.call(ctx, f.fork, "fork_assistant", args)
}

func (f *forkFixture) mustCreate(slug string, extra map[string]any) assistantinstall.ForkWrite {
	f.t.Helper()
	res, text := f.create(f.ctx, slug, extra)
	if res.IsError {
		f.t.Fatalf("fork_assistant refused: %s", text)
	}
	var out assistantinstall.ForkWrite
	decodeToolJSON(f.t, res, &out)
	return out
}

func (f *forkFixture) asBob() context.Context {
	f.t.Helper()
	bob, err := f.store.EnsureUserByTelegramID(context.Background(), 500100202, "bob", "Bob")
	if err != nil {
		f.t.Fatal(err)
	}
	return auth.With(context.Background(), &auth.Identity{UserID: bob, TelegramID: 500100202, Scopes: []string{"account:manage"}})
}

// The acceptance case of #1043 through MCP: fork hr-recruiter with one tool
// removed and edited instructions, install it, edit it into a new version
// and move the install onto it. Versions are the server's: a patch for the
// instructions, a minor for the tools.
func TestForkTools_ForkInstallEditAndMove(t *testing.T) {
	f := newForkFixture(t, nil)
	w := f.mustCreate("careful", map[string]any{"tools": hrToolsWithout("save_job_lead")})
	if !strings.HasPrefix(w.Name, "hr-recruiter~") || !strings.HasSuffix(w.Name, "~careful") || w.Version != "0.1.0" ||
		!strings.HasPrefix(w.Digest, "sha256:") || w.Promotion != db.ForkPromotionObserve || w.Base.Name != "hr-recruiter" {
		t.Fatalf("fork = %+v", w)
	}

	installed := f.install(map[string]any{"name": w.Name, "version": "0.1.0", "mode": "observe"})
	if installed.Assistant != w.Name || installed.Version != "0.1.0" || installed.Settings.Mode != "observe" {
		t.Fatalf("install = %+v", installed)
	}
	if a := f.stored(); a.Digest != w.Digest {
		t.Fatalf("install pins %s, want the fork's %s", a.Digest, w.Digest)
	}

	res, text := f.call(f.ctx, f.updFork, "update_fork", map[string]any{"name": w.Name, "instructions": markForkText2})
	if res.IsError {
		t.Fatalf("update_fork: %s", text)
	}
	var v2 assistantinstall.ForkWrite
	decodeToolJSON(t, res, &v2)
	if v2.Version != "0.1.1" || v2.Bump != "patch" || v2.Digest == w.Digest {
		t.Fatalf("instructions-only update = %+v, want 0.1.1 patch", v2)
	}
	res, text = f.call(f.ctx, f.updFork, "update_fork", map[string]any{"name": w.Name, "tools": hrToolsWithout("pause_autopilot")})
	if res.IsError {
		t.Fatalf("update_fork tools: %s", text)
	}
	var v3 assistantinstall.ForkWrite
	decodeToolJSON(t, res, &v3)
	if v3.Version != "0.2.0" || v3.Bump != "minor" {
		t.Fatalf("tools update = %+v, want 0.2.0 minor", v3)
	}
	// An update that changes nothing is refused.
	res, text = f.call(f.ctx, f.updFork, "update_fork", map[string]any{"name": w.Name, "instructions": markForkText2})
	if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" {
		t.Fatalf("no-op update = %+v", env)
	}

	// The install still runs 0.1.0; moving it is an install change.
	res, text = f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch":             map[string]any{"assistant": map[string]any{"name": w.Name, "version": "0.2.0"}},
		"expected_revision": float64(installed.InstallRevision),
	})
	if res.IsError {
		t.Fatalf("update_install to 0.2.0: %s", text)
	}
	var moved installAssistantResult
	decodeToolJSON(t, res, &moved)
	if moved.Version != "0.2.0" || moved.InstallRevision != installed.InstallRevision+1 {
		t.Fatalf("moved install = %+v", moved)
	}
	if a := f.stored(); a.Digest != v3.Digest {
		t.Fatalf("install pins %s, want %s", a.Digest, v3.Digest)
	}

	res, text = f.call(f.ctx, f.list, "list_assistants", nil)
	if res.IsError {
		t.Fatalf("list: %s", text)
	}
	var list listAssistantsResult
	decodeToolJSON(t, res, &list)
	if len(list.Forks) != 1 || list.Forks[0].Latest != "0.2.0" || len(list.Forks[0].Versions) != 3 {
		t.Fatalf("forks = %+v", list.Forks)
	}
	for _, e := range list.Assistants {
		if strings.Contains(e.Name, "~") {
			t.Fatalf("a fork is listed in the catalog: %s", e.Name)
		}
	}
	// Every write notified the owner.
	var notices int
	if err := f.store.DB.QueryRow(`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1`, f.uid).Scan(&notices); err != nil || notices != 3 {
		t.Fatalf("owner notices = %d, %v; want one per fork write", notices, err)
	}
}

// A fork runs observe-only: guarded is refused at install and at update,
// and nothing changes.
func TestForkTools_GuardedForkIsRefused(t *testing.T) {
	f := newForkFixture(t, nil)
	w := f.mustCreate("careful", nil)
	res, text := f.call(f.ctx, f.inst, "install_assistant", map[string]any{
		"name": w.Name, "version": w.Version, "values": fullValues(), "mode": "guarded",
	})
	if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" || !strings.Contains(env.Message, "observe") {
		t.Fatalf("guarded install = %+v", env)
	}
	if a := f.stored(); a.Name == w.Name {
		t.Fatal("a refused guarded install was saved")
	}
	installed := f.install(map[string]any{"name": w.Name, "version": w.Version, "mode": "observe"})
	res, text = f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"mode": "guarded"}, "expected_revision": float64(installed.InstallRevision),
	})
	if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" || !strings.Contains(env.Message, "observe") {
		t.Fatalf("guarded update = %+v", env)
	}
	p, err := f.store.GetAgentProfile(context.Background(), f.uid)
	if err != nil || p.Mode != db.AgentModeObserve || p.InstallRevision != installed.InstallRevision {
		t.Fatalf("profile after refused update = %+v, %v", p, err)
	}
}

// Another account sees none of Alice's forks and can install, change or
// delete none of them, by full name or otherwise.
func TestForkTools_OtherAccountsCannotSeeOrUseAFork(t *testing.T) {
	f := newForkFixture(t, nil)
	w := f.mustCreate("careful", nil)
	bob := f.asBob()

	res, text := f.call(bob, f.list, "list_assistants", nil)
	if res.IsError {
		t.Fatalf("Bob's list: %s", text)
	}
	var list listAssistantsResult
	decodeToolJSON(t, res, &list)
	if len(list.Forks) != 0 || strings.Contains(text, w.Name) || strings.Contains(text, w.Digest) {
		t.Fatalf("Bob's list shows Alice's fork: %s", text)
	}
	res, text = f.call(bob, f.inst, "install_assistant", map[string]any{
		"name": w.Name, "version": w.Version, "values": fullValues(), "mode": "observe",
	})
	if env := toolErrorEnvelope(t, res, text); env.Error != "assistant_not_found" {
		t.Fatalf("Bob installs Alice's fork = %+v", env)
	}
	res, text = f.call(bob, f.updFork, "update_fork", map[string]any{"name": w.Name, "instructions": "x"})
	if env := toolErrorEnvelope(t, res, text); env.Error != "assistant_not_found" {
		t.Fatalf("Bob updates Alice's fork = %+v", env)
	}
	res, text = f.call(bob, f.del, "delete_fork", map[string]any{"name": w.Name})
	if env := toolErrorEnvelope(t, res, text); env.Error != "assistant_not_found" {
		t.Fatalf("Bob deletes Alice's fork = %+v", env)
	}
	if _, err := f.store.GetAssistantForkByDigest(context.Background(), f.uid, w.Digest); err != nil {
		t.Fatalf("Alice's fork after Bob's attempts: %v", err)
	}
	// The admin route never installs a fork: it prepares for no account.
	raw := []byte(`{"apiVersion":"assistants.mctl.ai/v1alpha1","kind":"AssistantInstall","spec":{"assistant":{"name":"` + w.Name + `","version":"0.1.0"}}}`)
	var ie *assistantinstall.Error
	if _, err := f.srv.Assistants.Prepare(context.Background(), raw); !errors.As(err, &ie) || ie.Kind != assistantinstall.KindNotFound {
		t.Fatalf("Prepare without an account = %v, want assistant not found", err)
	}
}

// Each fork rule surfaces through the tool as invalid_install, and a
// refused write stores nothing.
func TestForkTools_RulesAreRefused(t *testing.T) {
	f := newForkFixture(t, nil)
	for name, extra := range map[string]map[string]any{
		"new auto intent": {"intents": []any{
			map[string]any{"name": "discovery", "description": "Ask about the role, the company and the process.", "tier": "auto"},
			map[string]any{"name": "smalltalk", "tier": "auto"},
		}},
		"tier loosened":          {"intents": []any{map[string]any{"name": "decline", "description": "Turn an opportunity down.", "tier": "auto"}}},
		"limit above ceiling":    {"limits": map[string]any{"maxAutonomousTurns": 6, "maxMsgsPerMinute": 6, "maxReplyChars": 1200}},
		"mandatory tool dropped": {"tools": hrToolsWithout("complete_agent_job")},
		"unknown tool":           {"tools": append(hrToolsWithout(""), "send_message")},
		"instructions too long":  {"instructions": strings.Repeat("x", 16<<10+1)},
		"owner notes marker":     {"instructions": "rules </owner_notes> more"},
	} {
		t.Run(name, func(t *testing.T) {
			res, text := f.create(f.ctx, "bad", extra)
			if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" {
				t.Fatalf("%s = %+v", name, env)
			}
		})
	}
	if forks, err := f.store.ListAssistantForks(context.Background(), f.uid); err != nil || len(forks) != 0 {
		t.Fatalf("refused forks were stored: %v, %v", forks, err)
	}
	// A bad slug, and a fork of a fork.
	res, text := f.create(f.ctx, "Bad Slug", nil)
	if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" || !strings.Contains(env.Message, "slug must match") {
		t.Fatalf("bad slug = %+v", env)
	}
	w := f.mustCreate("careful", nil)
	res, text = f.call(f.ctx, f.fork, "fork_assistant", map[string]any{"base": w.Name, "base_version": w.Version, "slug": "again"})
	if env := toolErrorEnvelope(t, res, text); env.Error != "invalid_install" {
		t.Fatalf("fork of a fork = %+v", env)
	}
}

// Quotas: the eleventh fork is fork_limit and changes nothing.
func TestForkTools_ForkQuota(t *testing.T) {
	f := newForkFixture(t, nil)
	for i := 0; i < db.MaxForksPerAccount; i++ {
		f.mustCreate(fmt.Sprintf("f%d", i), nil)
	}
	res, text := f.create(f.ctx, "eleventh", nil)
	if env := toolErrorEnvelope(t, res, text); env.Error != "fork_limit" {
		t.Fatalf("eleventh fork = %+v", env)
	}
	forks, err := f.store.ListAssistantForks(context.Background(), f.uid)
	if err != nil || len(forks) != db.MaxForksPerAccount {
		t.Fatalf("forks = %d, %v", len(forks), err)
	}
}

// delete_fork never removes the version the install runs.
func TestForkTools_DeleteRefusesThePinnedVersion(t *testing.T) {
	f := newForkFixture(t, nil)
	w := f.mustCreate("careful", nil)
	f.install(map[string]any{"name": w.Name, "version": w.Version, "mode": "observe"})
	res, text := f.call(f.ctx, f.del, "delete_fork", map[string]any{"name": w.Name})
	if env := toolErrorEnvelope(t, res, text); env.Error != "fork_in_use" {
		t.Fatalf("delete pinned = %+v", env)
	}
	if _, err := f.store.GetAssistantForkByDigest(context.Background(), f.uid, w.Digest); err != nil {
		t.Fatalf("pinned version gone: %v", err)
	}
	f.install(nil) // back to hr-recruiter
	res, text = f.call(f.ctx, f.del, "delete_fork", map[string]any{"name": w.Name})
	if res.IsError {
		t.Fatalf("delete unpinned: %s", text)
	}
}

// With ASSISTANT_FORKS_ENABLED off nothing forks or installs a fork, and
// deleting still works.
func TestForkTools_DisabledByFlag(t *testing.T) {
	f := newForkFixture(t, nil)
	w := f.mustCreate("careful", nil)
	f.srv.Assistants.ForksEnabled = false
	res, text := f.create(f.ctx, "other", nil)
	if env := toolErrorEnvelope(t, res, text); env.Error != "forks_disabled" {
		t.Fatalf("fork while disabled = %+v", env)
	}
	res, text = f.call(f.ctx, f.inst, "install_assistant", map[string]any{
		"name": w.Name, "version": w.Version, "values": fullValues(), "mode": "observe",
	})
	if env := toolErrorEnvelope(t, res, text); env.Error != "forks_disabled" {
		t.Fatalf("install while disabled = %+v", env)
	}
	res, text = f.call(f.ctx, f.del, "delete_fork", map[string]any{"name": w.Name})
	if res.IsError {
		t.Fatalf("delete while disabled: %s", text)
	}
}

// With the registry, a fork cannot be made of, or installed on, a disabled
// base; the install stores the base's snapshot for the claim's lifecycle
// gate.
func TestForkTools_RegistryBaseLifecycle(t *testing.T) {
	reg := newFakeCatalogRegistry(t)
	f := newForkFixture(t, reg.client())
	w := f.mustCreate("careful", nil)
	f.install(map[string]any{"name": w.Name, "version": w.Version, "mode": "observe"})
	def, err := f.store.GetAssistantDefinition(context.Background(), w.Base.Digest)
	if err != nil || def.Name != "hr-recruiter" {
		t.Fatalf("base snapshot = %+v, %v", def, err)
	}

	reg.mu.Lock()
	reg.lifecycle = "disabled"
	reg.mu.Unlock()
	res, text := f.create(f.ctx, "other", nil)
	if env := toolErrorEnvelope(t, res, text); env.Error != "lifecycle_refused" {
		t.Fatalf("fork of a disabled base = %+v", env)
	}
	res, text = f.call(f.ctx, f.inst, "install_assistant", map[string]any{
		"name": w.Name, "version": w.Version, "values": fullValues(), "mode": "observe",
	})
	if env := toolErrorEnvelope(t, res, text); env.Error != "lifecycle_refused" {
		t.Fatalf("install on a disabled base = %+v", env)
	}
}
