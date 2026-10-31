package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Markers for every install value and note the tests store. No tool
// output may contain any of them.
const (
	markName     = "Alice Q. Marker"
	markRole     = "ROLE-MARK-7731"
	markHeadline = "HEADLINE-MARK-4410"
	markSalary   = "SALARY-FLOOR-MARK-9137"
	markNotes    = "NOTES-MARK-2205 keep it short"
	markNotes2   = "NOTES-MARK-3306 reply in English"
)

var allMarks = []string{markName, markRole, markHeadline, markSalary, markNotes, markNotes2}

type assistantFixture struct {
	t      *testing.T
	store  *db.Store
	srv    *Server
	uid    int64
	ctx    context.Context
	list   mcpserver.ToolHandlerFunc
	inst   mcpserver.ToolHandlerFunc
	update mcpserver.ToolHandlerFunc
	// outputs collects the text of every tool result, for the leak check.
	outputs []string
}

func embeddedAssistantCatalog(t *testing.T) *assistant.Catalog {
	t.Helper()
	c, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatalf("LoadCatalog: %v", err)
	}
	return c
}

func newAssistantFixture(t *testing.T, catalog *assistant.Catalog, registry *assistantregistry.Client) *assistantFixture {
	t.Helper()
	store := newToolsTestStore(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store.Crypt = crypt
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, 500100101, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if catalog == nil {
		catalog = embeddedAssistantCatalog(t)
	}
	srv := (&Server{Store: store}).WithAssistants(assistantinstall.New(store, catalog, registry))
	f := &assistantFixture{
		t: t, store: store, srv: srv, uid: uid,
		ctx: auth.With(ctx, &auth.Identity{UserID: uid, TelegramID: 500100101, Scopes: []string{"account:manage"}}),
	}
	_, f.list = srv.toolListAssistants()
	_, f.inst = srv.toolInstallAssistant()
	_, f.update = srv.toolUpdateInstall()
	t.Cleanup(f.checkNoLeak)
	return f
}

func (f *assistantFixture) call(ctx context.Context, h mcpserver.ToolHandlerFunc, name string, args map[string]any) (*mcplib.CallToolResult, string) {
	f.t.Helper()
	res, err := h(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}})
	if err != nil {
		f.t.Fatalf("%s: Go error %v", name, err)
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			text.WriteString(tc.Text)
		}
	}
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		text.Write(b)
	}
	f.outputs = append(f.outputs, text.String())
	return res, text.String()
}

func (f *assistantFixture) checkNoLeak() {
	for _, out := range f.outputs {
		for _, m := range allMarks {
			if strings.Contains(out, m) {
				f.t.Errorf("tool output contains install value or note %q: %s", m, out)
			}
		}
	}
}

// fullValues fills every hr-recruiter variable, the restricted one
// included.
func fullValues() map[string]any {
	return map[string]any{
		"name": markName, "role": markRole, "headline": markHeadline,
		"skills": []any{"Go"}, "salary_floor": markSalary,
	}
}

func (f *assistantFixture) install(args map[string]any) installAssistantResult {
	f.t.Helper()
	base := map[string]any{"name": "hr-recruiter", "version": "0.1.0", "values": fullValues()}
	for k, v := range args {
		base[k] = v
	}
	res, text := f.call(f.ctx, f.inst, "install_assistant", base)
	if res.IsError {
		f.t.Fatalf("install refused: %s", text)
	}
	var out installAssistantResult
	decodeToolJSON(f.t, res, &out)
	return out
}

func (f *assistantFixture) stored() *db.AgentAssistant {
	f.t.Helper()
	a, err := f.store.GetAgentAssistant(context.Background(), f.uid)
	if err != nil {
		f.t.Fatal(err)
	}
	return a
}

type toolErrEnvelope struct {
	Error           string `json:"error"`
	Message         string `json:"message"`
	Retryable       bool   `json:"retryable"`
	CurrentRevision *int64 `json:"current_revision"`
}

func toolErrorEnvelope(t *testing.T, res *mcplib.CallToolResult, text string) toolErrEnvelope {
	t.Helper()
	if !res.IsError {
		t.Fatalf("call succeeded, want an error: %s", text)
	}
	var env toolErrEnvelope
	if err := json.Unmarshal([]byte(text), &env); err != nil {
		t.Fatalf("error is not a JSON envelope: %s", text)
	}
	return env
}

func TestListAssistants_EmbeddedCatalogWithoutValuesOrNotes(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	res, text := f.call(f.ctx, f.list, "list_assistants", nil)
	if res.IsError {
		t.Fatalf("list refused: %s", text)
	}
	var before listAssistantsResult
	decodeToolJSON(t, res, &before)
	if before.Source != assistantinstall.SourceEmbedded || before.Mine.Installed || before.Mine.Assistant != "" {
		t.Fatalf("before install: %+v", before)
	}

	inst := f.install(map[string]any{"ownerNotes": markNotes})
	res, text = f.call(f.ctx, f.list, "list_assistants", nil)
	if res.IsError {
		t.Fatalf("list refused: %s", text)
	}
	var out listAssistantsResult
	decodeToolJSON(t, res, &out)
	if len(out.Assistants) != 1 {
		t.Fatalf("assistants = %+v", out.Assistants)
	}
	hr := out.Assistants[0]
	if hr.Name != "hr-recruiter" || hr.Version != "0.1.0" || hr.Lifecycle != "published" ||
		hr.Defaults.Mode != "observe" || hr.Defaults.DisclosurePolicy != "optional" ||
		hr.Defaults.Limits == nil || hr.Defaults.Limits.MaxReplyChars != 1200 || len(hr.Variables) != 7 || len(hr.Intents) != 4 {
		t.Fatalf("entry = %+v", hr)
	}
	if out.Mine != (assistantInstalled{Assistant: "hr-recruiter", Version: "0.1.0", InstallRevision: inst.InstallRevision, Installed: true}) {
		t.Fatalf("mine = %+v, install revision %d", out.Mine, inst.InstallRevision)
	}
	// Neither the definition's instructions nor its profile paths.
	for _, leak := range []string{"profilePath", "restricted.", "instructions", "get_recruiter_profile"} {
		if strings.Contains(text, leak) {
			t.Errorf("list output contains %q", leak)
		}
	}
}

// fakeCatalogRegistry serves the registry's public catalog and the
// definition read for the embedded hr-recruiter entry.
type fakeCatalogRegistry struct {
	mu    sync.Mutex
	down  bool
	entry *assistant.Entry
	srv   *httptest.Server
}

func newFakeCatalogRegistry(t *testing.T) *fakeCatalogRegistry {
	e, ok := embeddedAssistantCatalog(t).Lookup("hr-recruiter", "0.1.0")
	if !ok {
		t.Fatal("embedded hr-recruiter missing")
	}
	f := &fakeCatalogRegistry{entry: e}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCatalogRegistry) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeCatalogRegistry) client() *assistantregistry.Client {
	return assistantregistry.NewClient(f.srv.URL, "surface-token", nil)
}

func (f *fakeCatalogRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		http.Error(w, "upstream down", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/api/v1/assistant-catalog":
		_, _ = w.Write([]byte(`{"count":1,"items":[{"name":"registry-only","version":"2.0.0","title":"From the registry",
			"description":"d","tags":["x"],"examples":[],"lifecycle":"published","digest":"sha256:x",
			"variables":[{"name":"company","type":"string","required":false,"default":"Acme","description":"c"}],
			"intents":[{"name":"discovery","description":"d","tier":"auto"}],
			"defaults":{"mode":"guarded","limits":{"maxReplyChars":500},"disclosure":{"policy":"required"}}}]}`))
	case "/api/v1/assistant-catalog/hr-recruiter/versions/0.1.0/definition":
		if r.Header.Get("Authorization") != "Bearer surface-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "hr-recruiter", "version": "0.1.0", "lifecycle": "published",
			"contentHash": f.entry.Digest, "definition": json.RawMessage(f.entry.Materialized),
		})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"assistant_not_found"}`))
	}
}

func TestListAssistants_RegistryCatalog(t *testing.T) {
	reg := newFakeCatalogRegistry(t)
	f := newAssistantFixture(t, nil, reg.client())
	res, text := f.call(f.ctx, f.list, "list_assistants", nil)
	if res.IsError {
		t.Fatalf("list refused: %s", text)
	}
	var out listAssistantsResult
	decodeToolJSON(t, res, &out)
	if out.Source != assistantinstall.SourceRegistry || len(out.Assistants) != 1 {
		t.Fatalf("list = %+v", out)
	}
	e := out.Assistants[0]
	if e.Name != "registry-only" || e.Version != "2.0.0" || e.Defaults.Mode != "guarded" ||
		e.Defaults.DisclosurePolicy != "required" || e.Defaults.Limits == nil || e.Defaults.Limits.MaxReplyChars != 500 ||
		len(e.Variables) != 1 || e.Variables[0].Default != "Acme" {
		t.Fatalf("entry = %+v", e)
	}

	// An unreadable registry is a retryable error, never an empty catalog.
	reg.setDown(true)
	res, text = f.call(f.ctx, f.list, "list_assistants", nil)
	env := toolErrorEnvelope(t, res, text)
	if env.Error != "registry_unavailable" || !env.Retryable {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestInstallAssistant_StartsPausedAndNotListening(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	out := f.install(nil)
	if !out.Settings.Paused || out.Settings.Listening || out.Settings.Mode != "observe" {
		t.Fatalf("settings = %+v", out.Settings)
	}
	p, err := f.store.GetAgentProfile(context.Background(), f.uid)
	if err != nil {
		t.Fatal(err)
	}
	if !p.AutopilotPaused || p.ListenerEnabled || p.InstallRevision != out.InstallRevision {
		t.Fatalf("profile = %+v", p)
	}
	// The stored install leaves them out, so the spec's defaults decide.
	var doc struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(f.stored().Install, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Spec["paused"]; ok {
		t.Fatalf("stored install sets paused: %v", doc.Spec)
	}
	if _, ok := doc.Spec["listening"]; ok {
		t.Fatalf("stored install sets listening: %v", doc.Spec)
	}
	// An explicit choice is honoured.
	live := f.install(map[string]any{"paused": false, "listening": true, "mode": "guarded"})
	if live.Settings.Paused || !live.Settings.Listening || live.InstallRevision != out.InstallRevision+1 {
		t.Fatalf("explicit settings = %+v rev %d", live.Settings, live.InstallRevision)
	}
}

func TestInstallAssistant_ExactVersionOnly(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	for _, c := range []struct{ version, code string }{
		{"latest", "invalid_install"},
		{"0.1", "invalid_install"},
		{"9.9.9", "assistant_not_found"},
	} {
		res, text := f.call(f.ctx, f.inst, "install_assistant", map[string]any{
			"name": "hr-recruiter", "version": c.version, "values": fullValues(),
		})
		env := toolErrorEnvelope(t, res, text)
		if env.Error != c.code {
			t.Errorf("version %q: envelope %+v, want %s", c.version, env, c.code)
		}
		// The schema message names where it failed, not the value.
		if strings.Contains(env.Message, `"`+c.version+`"`) || strings.Contains(env.Message, "'"+c.version+"'") {
			t.Errorf("version %q: message quotes the value: %s", c.version, env.Message)
		}
	}
	if _, err := f.store.GetAgentProfile(context.Background(), f.uid); err != db.ErrAgentProfileNotFound {
		t.Fatalf("a refused install touched the profile: err=%v", err)
	}
}

func TestAssistantWrites_RequireAccountManage(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	ctx := context.Background()
	bob, err := f.store.EnsureUserByTelegramID(ctx, 500100202, "bob", "Bob")
	if err != nil {
		t.Fatal(err)
	}
	readOnly := auth.With(ctx, &auth.Identity{UserID: bob, TelegramID: 500100202, Scopes: []string{"telegram:dialogs:read", "telegram:messages:read"}})
	res, text := f.call(readOnly, f.inst, "install_assistant", map[string]any{
		"name": "hr-recruiter", "version": "0.1.0", "values": fullValues(),
	})
	if !res.IsError || !strings.Contains(text, "account:manage") {
		t.Fatalf("install without account:manage: %s", text)
	}
	res, text = f.call(readOnly, f.update, "update_install", map[string]any{"patch": map[string]any{"paused": false}, "expected_revision": 1})
	if !res.IsError || !strings.Contains(text, "account:manage") {
		t.Fatalf("update without account:manage: %s", text)
	}
	if _, err := f.store.GetAgentProfile(ctx, bob); err == nil {
		t.Fatal("a refused call created a profile")
	}
	// Listing needs no extra scope.
	if res, text := f.call(readOnly, f.list, "list_assistants", nil); res.IsError {
		t.Fatalf("list refused a read-only credential: %s", text)
	}
}

func TestUpdateInstall_PatchesDecryptedInstall(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	first := f.install(map[string]any{"ownerNotes": markNotes})
	before := f.stored()

	res, text := f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{
			"paused": false, "ownerNotes": markNotes2,
			"values": map[string]any{"headline": nil, "work_mode": "remote"},
		},
		"expected_revision": first.InstallRevision,
	})
	if res.IsError {
		t.Fatalf("update refused: %s", text)
	}
	var out installAssistantResult
	decodeToolJSON(t, res, &out)
	if out.InstallRevision != first.InstallRevision+1 || out.Settings.Paused || out.Settings.Listening {
		t.Fatalf("update = %+v", out)
	}
	after := f.stored()
	if after.InstallRevision != out.InstallRevision {
		t.Fatalf("stored revision %d, answered %d", after.InstallRevision, out.InstallRevision)
	}
	var doc struct {
		Spec struct {
			Paused     *bool          `json:"paused"`
			Values     map[string]any `json:"values"`
			OwnerNotes string         `json:"ownerNotes"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(after.Install, &doc); err != nil {
		t.Fatal(err)
	}
	v := doc.Spec.Values
	if doc.Spec.Paused == nil || *doc.Spec.Paused || doc.Spec.OwnerNotes != markNotes2 ||
		v["name"] != markName || v["salary_floor"] != markSalary || v["work_mode"] != "remote" {
		t.Fatalf("patched install = %s", after.Install)
	}
	if _, ok := v["headline"]; ok {
		t.Fatal("a null member was not removed")
	}
	if bytes.Equal(before.Install, after.Install) {
		t.Fatal("install unchanged")
	}
}

func TestUpdateInstall_StaleRevisionChangesNothing(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	first := f.install(nil)
	if _, text := f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"mode": "guarded"}, "expected_revision": first.InstallRevision,
	}); strings.Contains(text, `"error"`) {
		t.Fatalf("first update refused: %s", text)
	}
	before := f.stored()

	res, text := f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"paused": false}, "expected_revision": first.InstallRevision,
	})
	env := toolErrorEnvelope(t, res, text)
	if env.Error != "revision_conflict" || env.CurrentRevision == nil || *env.CurrentRevision != before.InstallRevision {
		t.Fatalf("envelope = %+v, want conflict at %d", env, before.InstallRevision)
	}
	after := f.stored()
	if after.InstallRevision != before.InstallRevision || !bytes.Equal(after.Install, before.Install) {
		t.Fatal("a conflicting update changed the install")
	}
	p, err := f.store.GetAgentProfile(context.Background(), f.uid)
	if err != nil || !p.AutopilotPaused {
		t.Fatalf("profile after conflict = %+v, err %v", p, err)
	}
}

// The compare-and-set is in the UPDATE itself, not only in the read
// before it: a revision that moves between the two still refuses.
func TestCommit_RevisionCheckedInTheUpdate(t *testing.T) {
	for _, withRegistry := range []bool{false, true} {
		var reg *assistantregistry.Client
		if withRegistry {
			reg = newFakeCatalogRegistry(t).client()
		}
		f := newAssistantFixture(t, nil, reg)
		first := f.install(nil)
		raw, err := json.Marshal(map[string]any{
			"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall",
			"spec": map[string]any{"assistant": map[string]any{"name": "hr-recruiter", "version": "0.1.0"}, "values": fullValues(), "mode": "off"},
		})
		if err != nil {
			t.Fatal(err)
		}
		before := f.stored()
		stale := first.InstallRevision - 1
		err = f.store.UpdateAgentProfileFields(context.Background(), f.uid, db.AgentProfileUpdate{
			Mode: new(string), BumpInstallRevision: true, ExpectedInstallRevision: &stale,
		})
		var rc *db.InstallRevisionConflict
		if !asConflict(err, &rc) || rc.Current != first.InstallRevision {
			t.Fatalf("registry=%v: store CAS err = %v", withRegistry, err)
		}
		if withRegistry {
			svc := f.srv.Assistants
			p, err := svc.Prepare(context.Background(), raw)
			if err != nil {
				t.Fatal(err)
			}
			err = f.store.InstallAgentAssistant(context.Background(), f.uid, db.AssistantDefinition{
				Digest: before.Digest, Name: p.Name(), Version: p.Version(), Document: []byte("{}"), Lifecycle: "published",
			}, db.AgentProfileUpdate{AssistantDigest: &before.Digest, BumpInstallRevision: true, ExpectedInstallRevision: &stale})
			if !asConflict(err, &rc) {
				t.Fatalf("snapshot transaction CAS err = %v", err)
			}
		}
		after := f.stored()
		if after.InstallRevision != before.InstallRevision || !bytes.Equal(after.Install, before.Install) {
			t.Fatalf("registry=%v: a stale compare-and-set changed the profile", withRegistry)
		}
	}
}

func asConflict(err error, target **db.InstallRevisionConflict) bool {
	c, ok := err.(*db.InstallRevisionConflict)
	if ok {
		*target = c
	}
	return ok
}

func TestUpdateInstall_InvalidPatchChangesNothing(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	first := f.install(map[string]any{"ownerNotes": markNotes})
	before := f.stored()
	for _, c := range []struct {
		name  string
		patch map[string]any
	}{
		{"required value removed", map[string]any{"values": map[string]any{"name": nil}}},
		{"value off its choices", map[string]any{"values": map[string]any{"work_mode": "castle"}}},
		{"limit above ceiling", map[string]any{"limits": map[string]any{"maxReplyChars": 99999}}},
		{"schema violation", map[string]any{"mode": "autopilot"}},
		// A pattern failure is the one the validator quotes the value in.
		{"pattern violation", map[string]any{"schedule": map[string]any{"mode": "outside_hours", "hours": []any{"PATTERN-MARK-55"}}}},
		{"unknown setting", map[string]any{"colour": "blue"}},
		{"assistant removed", map[string]any{"assistant": nil}},
	} {
		res, text := f.call(f.ctx, f.update, "update_install", map[string]any{"patch": c.patch, "expected_revision": first.InstallRevision})
		env := toolErrorEnvelope(t, res, text)
		if env.Error != "invalid_install" {
			t.Errorf("%s: envelope = %+v", c.name, env)
		}
		for _, v := range []string{"castle", "autopilot", "blue", "PATTERN-MARK-55", "file://"} {
			if strings.Contains(env.Message, v) {
				t.Errorf("%s: message quotes the submitted value: %s", c.name, env.Message)
			}
		}
	}
	after := f.stored()
	if after.InstallRevision != before.InstallRevision || !bytes.Equal(after.Install, before.Install) {
		t.Fatal("an invalid patch changed the install")
	}
}

func TestUpdateInstall_NoInstall(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	res, text := f.call(f.ctx, f.update, "update_install", map[string]any{"patch": map[string]any{"paused": false}, "expected_revision": 1})
	if env := toolErrorEnvelope(t, res, text); env.Error != "no_install" {
		t.Fatalf("envelope = %+v", env)
	}
	res, text = f.call(f.ctx, f.update, "update_install", map[string]any{"patch": map[string]any{"paused": false}})
	if !res.IsError || !strings.Contains(text, "expected_revision is required") {
		t.Fatalf("missing expected_revision: %s", text)
	}
}

// An update moves the install revision, so work created under the earlier
// one is fenced exactly as after an admin install (#1018): its approved
// actions are denied as install_changed.
func TestUpdateInstall_FencesEarlierRevisionWork(t *testing.T) {
	f := newAssistantFixture(t, nil, nil)
	first := f.install(nil)
	ctx := context.Background()
	conv, err := f.store.EnsureConversation(ctx, f.uid, 500100303, "dana", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	approved, err := f.store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: f.uid, ActionType: db.ActionTypeReply, Payload: "approved draft",
		PolicyDecision: db.PolicyRequireApproval, Status: db.ActionApproved,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, err := f.store.GetAgentAction(ctx, f.uid, approved); err != nil || a.InstallRevision != first.InstallRevision {
		t.Fatalf("action revision = %+v, err %v", a, err)
	}
	res, text := f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"ownerNotes": markNotes}, "expected_revision": first.InstallRevision,
	})
	if res.IsError {
		t.Fatalf("update refused: %s", text)
	}
	a, err := f.store.GetAgentAction(ctx, f.uid, approved)
	if err != nil || a.Status != db.ActionDenied || a.PolicyReasons != policy.ReasonInstallChanged {
		t.Fatalf("earlier-revision action = %+v, err %v, want denied as install_changed", a, err)
	}
}

// Self-service installs only what list_assistants offers: an
// admin-visibility definition is unknown to the owner, though an admin may
// install it, and an account already running it may keep reconfiguring it.
func TestInstallAssistant_SelfServiceOnlyPublic(t *testing.T) {
	def, err := os.ReadFile("../../assistants/hr-recruiter/assistant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	private := strings.NewReplacer(
		"name: hr-recruiter", "name: private-assistant",
		"visibility: public", "visibility: admin",
		"path: ../../deploy/agent-worker/system-prompt.txt", "path: prompt.txt",
	).Replace(string(def))
	catalog, err := assistant.LoadCatalog(fstest.MapFS{
		"assistants/private-assistant/assistant.yaml": {Data: []byte(private)},
		"assistants/private-assistant/prompt.txt":     {Data: []byte("Private rules.")},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newAssistantFixture(t, catalog, nil)
	res, text := f.call(f.ctx, f.list, "list_assistants", nil)
	var out listAssistantsResult
	decodeToolJSON(t, res, &out)
	if len(out.Assistants) != 0 {
		t.Fatalf("an admin-visibility assistant was listed: %s", text)
	}
	args := map[string]any{"name": "private-assistant", "version": "0.1.0", "values": fullValues()}
	res, text = f.call(f.ctx, f.inst, "install_assistant", args)
	if env := toolErrorEnvelope(t, res, text); env.Error != "assistant_not_found" {
		t.Fatalf("envelope = %+v", env)
	}

	// Installed by an admin, the owner may tune it.
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall",
		"spec": map[string]any{"assistant": map[string]any{"name": "private-assistant", "version": "0.1.0"}, "values": fullValues()},
	})
	if err != nil {
		t.Fatal(err)
	}
	res2, err := f.srv.Assistants.Apply(context.Background(), f.uid, raw, assistantinstall.CommitOptions{})
	if err != nil {
		t.Fatalf("admin install: %v", err)
	}
	res, text = f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"mode": "guarded"}, "expected_revision": res2.Profile.InstallRevision,
	})
	if res.IsError {
		t.Fatalf("owner could not tune the assistant they run: %s", text)
	}
}

func TestInstallAssistant_RegistryUnavailableIsRetryable(t *testing.T) {
	reg := newFakeCatalogRegistry(t)
	f := newAssistantFixture(t, nil, reg.client())
	out := f.install(map[string]any{"ownerNotes": markNotes})
	if out.Assistant != "hr-recruiter" {
		t.Fatalf("install = %+v", out)
	}
	reg.setDown(true)
	before := f.stored()
	res, text := f.call(f.ctx, f.update, "update_install", map[string]any{
		"patch": map[string]any{"paused": false}, "expected_revision": out.InstallRevision,
	})
	env := toolErrorEnvelope(t, res, text)
	if env.Error != "registry_unavailable" || !env.Retryable {
		t.Fatalf("envelope = %+v", env)
	}
	if after := f.stored(); after.InstallRevision != before.InstallRevision {
		t.Fatal("an update with the registry down changed the install")
	}
}

func TestAssistantTools_RefuseWithoutService(t *testing.T) {
	srv := &Server{Store: newToolsTestStore(t)}
	ctx := auth.With(context.Background(), &auth.Identity{UserID: 1, Scopes: []string{"account:manage"}})
	for name, h := range map[string]mcpserver.ToolHandlerFunc{
		"list_assistants":   second(srv.toolListAssistants()),
		"install_assistant": second(srv.toolInstallAssistant()),
		"update_install":    second(srv.toolUpdateInstall()),
	} {
		res, err := h(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: map[string]any{}}})
		if err != nil || !res.IsError {
			t.Errorf("%s without a service: res=%+v err=%v", name, res, err)
		}
	}
}

func second(_ mcplib.Tool, h mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc { return h }
