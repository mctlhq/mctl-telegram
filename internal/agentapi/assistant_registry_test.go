package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// otherText is the instructions of the registry-only assistant the fake
// serves; it is in no embedded catalog, so a claim that carries it can only
// have rendered from the stored snapshot.
const otherText = "Registry-only rules for the other assistant."

// registryDoc returns a materialized definition derived from the embedded
// hr-recruiter one, renamed to name@version with text as its instructions,
// and pretty-printed with the keys as encoding/json orders them, as a
// stand-in for the JSONB form the registry answers with.
func registryDoc(t *testing.T, name, version, text string) (json.RawMessage, string) {
	t.Helper()
	e, ok := embeddedCatalog(t).Lookup("hr-recruiter", "0.1.0")
	if !ok {
		t.Fatal("embedded hr-recruiter missing")
	}
	var doc map[string]any
	if err := json.Unmarshal(e.Materialized, &doc); err != nil {
		t.Fatal(err)
	}
	meta := doc["metadata"].(map[string]any)
	meta["name"], meta["version"] = name, version
	doc["spec"].(map[string]any)["instructions"] = map[string]any{"text": text}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := assistant.ParseMaterialized(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, parsed.Digest
}

// fakeRegistry serves GET .../assistant-catalog/{name}/versions/{version}/definition
// for the entries it holds. mode switches it to a failure.
type fakeRegistry struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	// mode: "" serves entries; "down" answers 500; "bare404" a 404
	// without the registry's code; "mismatch" reports a wrong contentHash.
	mode    string
	entries map[string]*fakeEntry
	calls   int
}

type fakeEntry struct {
	doc       json.RawMessage
	digest    string
	lifecycle string
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{t: t, entries: map[string]*fakeEntry{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) add(name, version, text, lifecycle string) string {
	doc, digest := registryDoc(f.t, name, version, text)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[name+"@"+version] = &fakeEntry{doc: doc, digest: digest, lifecycle: lifecycle}
	return digest
}

func (f *fakeRegistry) set(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

func (f *fakeRegistry) setLifecycle(ref, lifecycle string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[ref].lifecycle = lifecycle
}

func (f *fakeRegistry) remove(ref string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, ref)
}

func (f *fakeRegistry) client() *assistantregistry.Client {
	return assistantregistry.NewClient(f.srv.URL+"/", "surface-token", nil)
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if r.Header.Get("Authorization") != "Bearer surface-token" || r.Header.Get("X-MCTL-Surface-Actor") != "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/assistant-catalog/"), "/")
	switch f.mode {
	case "down":
		http.Error(w, "upstream down", http.StatusInternalServerError)
		return
	case "bare404":
		http.NotFound(w, r)
		return
	}
	if len(parts) != 4 || parts[1] != "versions" || parts[3] != "definition" {
		http.NotFound(w, r)
		return
	}
	e, ok := f.entries[parts[0]+"@"+parts[2]]
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"assistant_not_found","error":"assistant version not found"}`))
		return
	}
	hash := e.digest
	if f.mode == "mismatch" {
		hash = "sha256:" + strings.Repeat("0", 64)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name": parts[0], "version": parts[2], "lifecycle": e.lifecycle,
		"contentHash": hash, "definition": e.doc,
	})
}

// registryHarness is a claim harness whose account is Alice's (telegram id
// 500100101), so the admin install handler can address it, with the
// registry lifecycle gate on and a settable clock.
type registryHarness struct {
	*testHarness
	reg     *fakeRegistry
	install http.HandlerFunc
	mu      sync.Mutex
	now     time.Time
	peer    int64
}

// newJob queues one job in a conversation of its own: the claim serializes
// a conversation, so a job left claimed would hide the next one behind it.
func (rh *registryHarness) newJob() int64 {
	rh.t.Helper()
	rh.peer++
	conv := rh.seedConversation(rh.peer)
	return rh.seedJob("evt:v1:1:"+itoaTest(rh.peer)+":reg", conv.ID)
}

func newRegistryHarness(t *testing.T) *registryHarness {
	t.Helper()
	h := newHarness(t)
	uid, err := h.store.EnsureUserByTelegramID(context.Background(), 500100101, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	h.userID = uid
	h.id = &auth.Identity{UserID: uid, Subject: "tg:500100101", TelegramID: 500100101}
	rh := &registryHarness{testHarness: h, reg: newFakeRegistry(t), now: time.Now(), peer: 600}
	h.srv.WithCatalog(embeddedCatalog(t)).WithRegistryLifecycle()
	h.srv.now = rh.clock
	rh.install = NewAdminAgentInstallHandler(h.store, embeddedCatalog(t), rh.reg.client())
	return rh
}

func (rh *registryHarness) clock() time.Time {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return rh.now
}

func (rh *registryHarness) advance(d time.Duration) {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	rh.now = rh.now.Add(d)
}

func (rh *registryHarness) refresher() *assistantregistry.Refresher {
	return &assistantregistry.Refresher{Store: rh.store, Client: rh.reg.client(), Now: rh.clock}
}

func (rh *registryHarness) installOther(version string) *httptest.ResponseRecorder {
	rh.t.Helper()
	return doInstall(rh.t, rh.install, 500100101,
		hrInstallJSON(rh.t, map[string]any{"assistant": map[string]any{"name": "other-assistant", "version": version}}))
}

func (rh *registryHarness) alerts() int {
	rh.t.Helper()
	var n int
	if err := rh.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM owner_notifications WHERE user_id = $1 AND kind = $2`,
		rh.userID, db.NotificationAlert).Scan(&n); err != nil {
		rh.t.Fatal(err)
	}
	return n
}

func (rh *registryHarness) jobPending(jobID int64) {
	rh.t.Helper()
	rec := rh.do("GET", "/jobs/"+itoaTest(jobID), nil)
	var st jobStatusResponse
	decodeBody(rh.t, rec, &st)
	if st.Status != db.JobPending || st.Attempt != 0 {
		rh.t.Fatalf("job = %+v, want pending attempt 0", st)
	}
}

// An install with the registry on stores the fetched definition and the
// new revision together; after that the registry can go away and claims
// still carry the stored instructions.
func TestRegistryInstall_StoresSnapshotAndServesItWithoutRegistry(t *testing.T) {
	rh := newRegistryHarness(t)
	ctx := context.Background()
	digest := rh.reg.add("other-assistant", "0.2.0", otherText, db.AssistantLifecyclePublished)
	if err := rh.store.EnsureAgentProfile(ctx, rh.userID); err != nil {
		t.Fatal(err)
	}
	before, err := rh.store.GetAgentProfile(ctx, rh.userID)
	if err != nil {
		t.Fatal(err)
	}

	if rec := rh.installOther("0.2.0"); rec.Code != http.StatusOK {
		t.Fatalf("install = %d %s", rec.Code, rec.Body.String())
	}
	after, err := rh.store.GetAgentProfile(ctx, rh.userID)
	if err != nil {
		t.Fatal(err)
	}
	if after.InstallRevision != before.InstallRevision+1 {
		t.Fatalf("revision %d -> %d", before.InstallRevision, after.InstallRevision)
	}
	a, err := rh.store.GetAgentAssistant(ctx, rh.userID)
	if err != nil || a.Digest != digest {
		t.Fatalf("pinned digest = %+v, err=%v, want %s", a, err, digest)
	}
	snap, err := rh.store.GetAssistantDefinition(ctx, digest)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if snap.Name != "other-assistant" || snap.Version != "0.2.0" || snap.Lifecycle != db.AssistantLifecyclePublished {
		t.Fatalf("snapshot = %+v", snap)
	}

	// "Restart": the registry is gone and the server has nothing cached.
	rh.reg.set("down")
	rh.srv.snapshots = nil
	rh.newJob()
	calls := rh.reg.calls
	code, jobs := claimOne(t, rh.testHarness)
	if code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("claim = %d %+v", code, jobs)
	}
	if !strings.HasPrefix(jobs[0].Instructions, otherText) || jobs[0].AssistantDigest != digest ||
		jobs[0].Assistant != "other-assistant@0.2.0" {
		t.Fatalf("claim carried %q %s %s", jobs[0].Instructions, jobs[0].Assistant, jobs[0].AssistantDigest)
	}
	if rh.reg.calls != calls {
		t.Fatal("claim called the registry")
	}
}

func TestRegistryInstall_Refusals(t *testing.T) {
	cases := []struct {
		name string
		prep func(rh *registryHarness)
		ver  string
		code int
	}{
		{"digest mismatch", func(rh *registryHarness) { rh.reg.set("mismatch") }, "0.2.0", http.StatusBadGateway},
		{"not found", func(rh *registryHarness) {}, "9.9.9", http.StatusNotFound},
		{"registry down", func(rh *registryHarness) { rh.reg.set("down") }, "0.2.0", http.StatusServiceUnavailable},
		{"bare 404 is not an answer", func(rh *registryHarness) { rh.reg.set("bare404") }, "0.2.0", http.StatusServiceUnavailable},
		{"registry unreachable", func(rh *registryHarness) { rh.reg.srv.Close() }, "0.2.0", http.StatusServiceUnavailable},
		{"disabled", func(rh *registryHarness) { rh.reg.setLifecycle("other-assistant@0.2.0", db.AssistantLifecycleDisabled) }, "0.2.0", http.StatusConflict},
		{"deprecated for a new install", func(rh *registryHarness) {
			rh.reg.setLifecycle("other-assistant@0.2.0", db.AssistantLifecycleDeprecated)
		}, "0.2.0", http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rh := newRegistryHarness(t)
			ctx := context.Background()
			digest := rh.reg.add("other-assistant", "0.2.0", otherText, db.AssistantLifecyclePublished)
			if err := rh.store.EnsureAgentProfile(ctx, rh.userID); err != nil {
				t.Fatal(err)
			}
			before, _ := rh.store.GetAgentProfile(ctx, rh.userID)
			tc.prep(rh)
			if rec := rh.installOther(tc.ver); rec.Code != tc.code {
				t.Fatalf("install = %d %s, want %d", rec.Code, rec.Body.String(), tc.code)
			}
			after, _ := rh.store.GetAgentProfile(ctx, rh.userID)
			if after.InstallRevision != before.InstallRevision {
				t.Fatal("a refused install moved the revision")
			}
			if _, err := rh.store.GetAssistantDefinition(ctx, digest); err != db.ErrAssistantDefinitionNotFound {
				t.Fatalf("a refused install stored a snapshot: %v", err)
			}
		})
	}
}

// A deprecated version stays installable for the account that runs it.
func TestRegistryInstall_DeprecatedKeepsExistingPin(t *testing.T) {
	rh := newRegistryHarness(t)
	rh.reg.add("other-assistant", "0.2.0", otherText, db.AssistantLifecyclePublished)
	if rec := rh.installOther("0.2.0"); rec.Code != http.StatusOK {
		t.Fatalf("install = %d %s", rec.Code, rec.Body.String())
	}
	rh.reg.setLifecycle("other-assistant@0.2.0", db.AssistantLifecycleDeprecated)
	if rec := rh.installOther("0.2.0"); rec.Code != http.StatusOK {
		t.Fatalf("reinstall of a deprecated pin = %d %s", rec.Code, rec.Body.String())
	}
}

func TestRegistryLifecycle_GatesClaims(t *testing.T) {
	rh := newRegistryHarness(t)
	ctx := context.Background()
	digest := rh.reg.add("other-assistant", "0.2.0", otherText, db.AssistantLifecyclePublished)
	if rec := rh.installOther("0.2.0"); rec.Code != http.StatusOK {
		t.Fatalf("install = %d %s", rec.Code, rec.Body.String())
	}
	ref := "other-assistant@0.2.0"
	lifecycle := func() *db.AssistantDefinition {
		d, err := rh.store.GetAssistantDefinition(ctx, digest)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}

	// Deprecated keeps working for the pinned install.
	rh.reg.setLifecycle(ref, db.AssistantLifecycleDeprecated)
	rh.refresher().RefreshOnce(ctx)
	if got := lifecycle().Lifecycle; got != db.AssistantLifecycleDeprecated {
		t.Fatalf("lifecycle = %s", got)
	}
	rh.newJob()
	if code, jobs := claimOne(t, rh.testHarness); code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("deprecated claim = %d %+v", code, jobs)
	}

	// Disabled, observed by the refresh, stops new jobs; they stay queued.
	rh.reg.setLifecycle(ref, db.AssistantLifecycleDisabled)
	rh.refresher().RefreshOnce(ctx)
	disabledJob := rh.newJob()
	if code, _ := claimOne(t, rh.testHarness); code != http.StatusServiceUnavailable {
		t.Fatalf("disabled claim = %d", code)
	}
	rh.jobPending(disabledJob)

	// A failed read never changes a known lifecycle or its check time.
	known := lifecycle()
	rh.reg.set("down")
	rh.advance(time.Hour)
	rh.refresher().RefreshOnce(ctx)
	if got := lifecycle(); got.Lifecycle != db.AssistantLifecycleDisabled || !got.LifecycleCheckedAt.Equal(known.LifecycleCheckedAt) {
		t.Fatalf("after a failed refresh = %s at %v, want %s at %v", got.Lifecycle, got.LifecycleCheckedAt, known.Lifecycle, known.LifecycleCheckedAt)
	}

	// Published again; the registry goes away; under 24h the last known
	// lifecycle stands and jobs run.
	rh.reg.set("")
	rh.reg.setLifecycle(ref, db.AssistantLifecyclePublished)
	rh.refresher().RefreshOnce(ctx)
	if code, jobs := claimOne(t, rh.testHarness); code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("published claim = %d %+v", code, jobs)
	}
	rh.reg.set("down")
	rh.advance(23 * time.Hour)
	rh.refresher().RefreshOnce(ctx)
	rh.newJob()
	if code, jobs := claimOne(t, rh.testHarness); code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("claim 23h into an outage = %d %+v", code, jobs)
	}
	if n := rh.alerts(); n != 0 {
		t.Fatalf("alerts before 24h = %d", n)
	}

	// Past 24h the lifecycle is unknown: no jobs, and exactly one notice
	// however often the claim and the refresh run into it.
	rh.advance(2 * time.Hour)
	staleJob := rh.newJob()
	for range 3 {
		if code, _ := claimOne(t, rh.testHarness); code != http.StatusServiceUnavailable {
			t.Fatalf("claim past 24h = %d", code)
		}
		rh.refresher().RefreshOnce(ctx)
	}
	rh.jobPending(staleJob)
	if n := rh.alerts(); n != 1 {
		t.Fatalf("alerts = %d, want exactly 1", n)
	}

	// The registry answers again: jobs run, and a later outage notifies
	// once more.
	rh.reg.set("")
	rh.refresher().RefreshOnce(ctx)
	if code, jobs := claimOne(t, rh.testHarness); code != http.StatusOK || len(jobs) != 1 {
		t.Fatalf("claim after recovery = %d %+v", code, jobs)
	}
	rh.reg.set("down")
	rh.advance(25 * time.Hour)
	rh.refresher().RefreshOnce(ctx)
	if n := rh.alerts(); n != 2 {
		t.Fatalf("alerts after a second outage = %d, want 2", n)
	}

	// 404 assistant_not_found for the pinned version is an answer:
	// disabled.
	rh.reg.set("")
	rh.reg.remove(ref)
	rh.refresher().RefreshOnce(ctx)
	if got := lifecycle(); got.Lifecycle != db.AssistantLifecycleDisabled {
		t.Fatalf("lifecycle after 404 = %s", got.Lifecycle)
	}
	if code, _ := claimOne(t, rh.testHarness); code != http.StatusServiceUnavailable {
		t.Fatalf("claim after 404 = %d", code)
	}
}

// The embedded catalog bridges a profile with no snapshot only when it pins
// no digest or exactly the embedded digest; any other unstored digest fails
// the claim before claiming.
func TestRegistryBridge_EmbeddedCatalog(t *testing.T) {
	rh := newRegistryHarness(t)
	ctx := context.Background()
	hr, _ := embeddedCatalog(t).Lookup("hr-recruiter", "0.1.0")
	if err := rh.store.EnsureAgentProfile(ctx, rh.userID); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", hr.Digest} {
		d := digest
		if err := rh.store.UpdateAgentProfileFields(ctx, rh.userID, db.AgentProfileUpdate{AssistantDigest: &d}); err != nil {
			t.Fatal(err)
		}
		rh.newJob()
		code, jobs := claimOne(t, rh.testHarness)
		if code != http.StatusOK || len(jobs) != 1 || jobs[0].Instructions != deployedPrompt(t) || jobs[0].AssistantDigest != hr.Digest {
			t.Fatalf("digest %q: claim = %d %+v", digest, code, jobs)
		}
	}
	unknown := "sha256:" + strings.Repeat("1", 64)
	if err := rh.store.UpdateAgentProfileFields(ctx, rh.userID, db.AgentProfileUpdate{AssistantDigest: &unknown}); err != nil {
		t.Fatal(err)
	}
	jobID := rh.newJob()
	if code, _ := claimOne(t, rh.testHarness); code != http.StatusInternalServerError {
		t.Fatalf("unstored digest claim = %d, want 500", code)
	}
	rh.jobPending(jobID)
}

// An install made on main between #1023 and #1025 pinned hr-recruiter's
// digest in the scheme #1025 replaced. The migration clears exactly that
// value, so the account falls back to the embedded catalog; any other
// unbacked digest still fails the claim.
func TestRegistryBridge_MigratesLegacyDigest(t *testing.T) {
	rh := newRegistryHarness(t)
	ctx := context.Background()
	hr, _ := embeddedCatalog(t).Lookup("hr-recruiter", "0.1.0")
	if err := rh.store.EnsureAgentProfile(ctx, rh.userID); err != nil {
		t.Fatal(err)
	}
	legacy := "sha256:715ac8851f4c7a0600d74a1a8acfdaa1c58bec3dcb90608034006828a231ae29"
	if err := rh.store.UpdateAgentProfileFields(ctx, rh.userID, db.AgentProfileUpdate{AssistantDigest: &legacy}); err != nil {
		t.Fatal(err)
	}
	jobID := rh.newJob()
	if code, _ := claimOne(t, rh.testHarness); code != http.StatusInternalServerError {
		t.Fatalf("legacy digest before the migration: claim = %d, want 500", code)
	}
	rh.jobPending(jobID)

	for range 2 {
		if err := db.MigrateCached(ctx, rh.store.DB); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}
	if a, err := rh.store.GetAgentAssistant(ctx, rh.userID); err != nil || a.Digest != "" {
		t.Fatalf("digest after the migration = %+v, err=%v, want cleared", a, err)
	}
	code, jobs := claimOne(t, rh.testHarness)
	if code != http.StatusOK || len(jobs) != 1 || jobs[0].Instructions != deployedPrompt(t) || jobs[0].AssistantDigest != hr.Digest {
		t.Fatalf("claim after the migration = %d %+v", code, jobs)
	}

	other := "sha256:" + strings.Repeat("2", 64)
	if err := rh.store.UpdateAgentProfileFields(ctx, rh.userID, db.AgentProfileUpdate{AssistantDigest: &other}); err != nil {
		t.Fatal(err)
	}
	if err := db.MigrateCached(ctx, rh.store.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if a, _ := rh.store.GetAgentAssistant(ctx, rh.userID); a.Digest != other {
		t.Fatalf("the migration cleared an unrelated digest: %q", a.Digest)
	}
	jobID = rh.newJob()
	if code, _ := claimOne(t, rh.testHarness); code != http.StatusInternalServerError {
		t.Fatalf("unbacked digest after the migration: claim = %d, want 500", code)
	}
	rh.jobPending(jobID)
}
