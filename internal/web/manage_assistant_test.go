package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"

	mctltelegram "github.com/mctlhq/mctl-telegram"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Markers for every install value and note the tests store. No page may
// contain any of them.
const (
	webMarkName   = "Alice Q. WebMarker"
	webMarkRole   = "ROLE-WEBMARK-5521"
	webMarkSalary = "SALARY-WEBMARK-8803"
	webMarkNotes  = "NOTES-WEBMARK-6617 keep it short"
)

var webMarks = []string{webMarkName, webMarkRole, webMarkSalary, webMarkNotes}

// instructionsMarker opens the hr-recruiter instructions; no page may
// contain it.
const instructionsMarker = "You are the owner's communication agent"

func assertNoAssistantLeak(t *testing.T, body string) {
	t.Helper()
	for _, m := range append(webMarks, instructionsMarker, "profilePath", "restricted.salary_floor", "get_recruiter_profile") {
		if strings.Contains(body, m) {
			t.Errorf("page contains %q", m)
		}
	}
}

type manageAssistantFixture struct {
	t     *testing.T
	store *db.Store
	svc   *assistantinstall.Service
	srv   *ManageServer
	uid   int64
}

func newManageAssistantFixture(t *testing.T, registry *assistantregistry.Client) *manageAssistantFixture {
	t.Helper()
	store := newManageTestStore(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store.Crypt = crypt
	uid, err := store.EnsureUserByTelegramID(context.Background(), 500100101, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := assistant.LoadCatalog(mctltelegram.Catalog)
	if err != nil {
		t.Fatal(err)
	}
	svc := assistantinstall.New(store, catalog, registry)
	srv := NewManageServer(store, nil, "https://tg.test", "", "mctl_self_connect").WithAssistants(svc)
	return &manageAssistantFixture{t: t, store: store, svc: svc, srv: srv, uid: uid}
}

func (f *manageAssistantFixture) identity(scopes ...string) *auth.Identity {
	return &auth.Identity{UserID: f.uid, TelegramID: 500100101, ClientID: "mctl_self_connect", Scopes: scopes}
}

func (f *manageAssistantFixture) get(id *auth.Identity) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/manage", nil)
	req = req.WithContext(auth.With(req.Context(), id))
	rec := httptest.NewRecorder()
	f.srv.HandleManage(rec, req)
	return rec
}

func (f *manageAssistantFixture) post(h http.HandlerFunc, path string, id *auth.Identity, form url.Values) *httptest.ResponseRecorder {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if id != nil {
		req = req.WithContext(auth.With(req.Context(), id))
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// installDirect installs hr-recruiter through the service, with every
// marker stored, the way the MCP tools would.
func (f *manageAssistantFixture) installDirect() *assistantinstall.Result {
	f.t.Helper()
	raw, _ := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1", "kind": "AssistantInstall",
		"spec": map[string]any{
			"assistant": map[string]any{"name": "hr-recruiter", "version": "0.1.0"},
			"values": map[string]any{
				"name": webMarkName, "role": webMarkRole, "salary_floor": webMarkSalary,
			},
			"ownerNotes": webMarkNotes,
		},
	})
	res, err := f.svc.Apply(context.Background(), f.uid, raw, assistantinstall.CommitOptions{SelfService: true})
	if err != nil {
		f.t.Fatalf("install: %v", err)
	}
	return res
}

func (f *manageAssistantFixture) profile() *db.AgentProfile {
	f.t.Helper()
	p, err := f.store.GetAgentProfile(context.Background(), f.uid)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *manageAssistantFixture) storedInstall() string {
	f.t.Helper()
	a, err := f.store.GetAgentAssistant(context.Background(), f.uid)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(a.Install)
}

func rev(n int64) string { return strconv.FormatInt(n, 10) }

func TestManageAssistant_ShowsInstallWithoutValuesOrNotes(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	rec := f.get(f.identity(accountManageScope))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`id="assistant-ref">hr-recruiter@0.1.0<`,
		`id="assistant-revision">` + rev(res.Profile.InstallRevision) + `<`,
		`id="assistant-mode">observe<`,
		`id="assistant-paused">yes<`,
		`id="assistant-listening">no<`,
		`name="expected_revision" value="` + rev(res.Profile.InstallRevision) + `"`,
		`action="/telegram/connect/manage/assistant/update"`,
		`action="/telegram/connect/manage/assistant/install"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	assertNoAssistantLeak(t, body)
}

func TestManageAssistant_InstallStartsPausedAndNotListening(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	cur, err := f.svc.Current(context.Background(), f.uid)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.post(f.srv.HandleAssistantInstall, "/telegram/connect/manage/assistant/install", f.identity(accountManageScope), url.Values{
		"expected_revision":  {rev(cur.InstallRevision)},
		"name":               {"hr-recruiter"},
		"version":            {"0.1.0"},
		"value.name":         {webMarkName},
		"value.role":         {webMarkRole},
		"value.skills":       {"Go, SQL\nKubernetes"},
		"value.salary_floor": {webMarkSalary},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	p := f.profile()
	if !p.AutopilotPaused || p.ListenerEnabled {
		t.Fatalf("install is live: paused=%v listening=%v", p.AutopilotPaused, p.ListenerEnabled)
	}
	if p.InstallRevision != cur.InstallRevision+1 {
		t.Fatalf("revision %d, want %d", p.InstallRevision, cur.InstallRevision+1)
	}
	stored := f.storedInstall()
	if !strings.Contains(stored, webMarkRole) || !strings.Contains(stored, `"skills":["Go","SQL","Kubernetes"]`) {
		t.Fatalf("form values not stored as typed values: %s", stored)
	}
	// The page after the redirect shows the install, never the values.
	page := f.get(f.identity(accountManageScope)).Body.String()
	if !strings.Contains(page, `id="assistant-ref">hr-recruiter@0.1.0<`) {
		t.Fatalf("installed assistant not shown")
	}
	assertNoAssistantLeak(t, page)
}

func TestManageAssistant_UpdateAppliesPatchAtRevision(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	r0 := res.Profile.InstallRevision
	rec := f.post(f.srv.HandleAssistantUpdate, "/telegram/connect/manage/assistant/update", f.identity(accountManageScope), url.Values{
		"expected_revision": {rev(r0)}, "setting": {"paused"}, "value": {"false"},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	p := f.profile()
	if p.AutopilotPaused || p.InstallRevision != r0+1 {
		t.Fatalf("paused=%v revision=%d, want unpaused at %d", p.AutopilotPaused, p.InstallRevision, r0+1)
	}
	// A merge patch: everything else in the install stays.
	stored := f.storedInstall()
	if !strings.Contains(stored, webMarkRole) || !strings.Contains(stored, webMarkNotes) || !strings.Contains(stored, `"paused":false`) {
		t.Fatalf("patch did not merge into the stored install: %s", stored)
	}

	rec = f.post(f.srv.HandleAssistantUpdate, "/telegram/connect/manage/assistant/update", f.identity(accountManageScope), url.Values{
		"expected_revision": {rev(r0 + 1)}, "setting": {"mode"}, "value": {"guarded"},
	})
	if rec.Code != http.StatusFound || f.profile().Mode != "guarded" {
		t.Fatalf("mode change: status %d, mode %q", rec.Code, f.profile().Mode)
	}
}

func TestManageAssistant_StaleRevisionConflictsAndChangesNothing(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	r0 := res.Profile.InstallRevision
	// Another surface moves the install on after this page was rendered.
	if _, err := f.svc.Patch(context.Background(), f.uid, json.RawMessage(`{"mode":"guarded"}`), r0); err != nil {
		t.Fatal(err)
	}
	before := f.profile()
	storedBefore := f.storedInstall()

	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		form url.Values
	}{
		{"update", f.srv.HandleAssistantUpdate, url.Values{"expected_revision": {rev(r0)}, "setting": {"paused"}, "value": {"false"}}},
		{"install", f.srv.HandleAssistantInstall, url.Values{
			"expected_revision": {rev(r0)}, "name": {"hr-recruiter"}, "version": {"0.1.0"},
			"value.name": {"Bob"}, "value.role": {"Engineer"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(tc.h, "/telegram/connect/manage/assistant/"+tc.name, f.identity(accountManageScope), tc.form)
			if rec.Code != http.StatusConflict {
				t.Fatalf("status %d, want 409: %s", rec.Code, rec.Body.String())
			}
			body := rec.Body.String()
			if !strings.Contains(body, "changed since this page was loaded") ||
				!strings.Contains(body, `id="assistant-revision">`+rev(before.InstallRevision)+`<`) ||
				!strings.Contains(body, `id="assistant-mode">guarded<`) {
				t.Fatalf("conflict page lacks the message or the current state: %s", body)
			}
			assertNoAssistantLeak(t, body)
			after := f.profile()
			if after.InstallRevision != before.InstallRevision || after.AutopilotPaused != before.AutopilotPaused || after.Mode != before.Mode {
				t.Fatalf("stale submission changed the profile: %+v -> %+v", before, after)
			}
			if f.storedInstall() != storedBefore {
				t.Fatal("stale submission changed the stored install")
			}
		})
	}
}

func TestManageAssistant_RequiresManageScope(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	r0 := res.Profile.InstallRevision
	// The browser sign-in without account:manage: it may reach the page,
	// as for disconnect, but not change the assistant.
	noScope := f.identity()
	page := f.get(noScope).Body.String()
	if !strings.Contains(page, `id="assistant-unavailable"`) || strings.Contains(page, `action="/telegram/connect/manage/assistant/`) {
		t.Fatalf("page offers assistant forms without account:manage")
	}
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		form url.Values
	}{
		{"update", f.srv.HandleAssistantUpdate, url.Values{"expected_revision": {rev(r0)}, "setting": {"paused"}, "value": {"false"}}},
		{"install", f.srv.HandleAssistantInstall, url.Values{
			"expected_revision": {rev(r0)}, "name": {"hr-recruiter"}, "version": {"0.1.0"},
			"value.name": {"Bob"}, "value.role": {"Engineer"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.post(tc.h, "/telegram/connect/manage/assistant/"+tc.name, noScope, tc.form)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d, want 403", rec.Code)
			}
			rec = f.post(tc.h, "/telegram/connect/manage/assistant/"+tc.name, nil, tc.form)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("no identity: status %d, want 401", rec.Code)
			}
			if p := f.profile(); p.InstallRevision != r0 || !p.AutopilotPaused {
				t.Fatalf("refused submission changed the profile: %+v", p)
			}
		})
	}
}

func TestManageAssistant_RefusesOtherChanges(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	r0 := res.Profile.InstallRevision
	for _, form := range []url.Values{
		{"expected_revision": {rev(r0)}, "setting": {"ownerNotes"}, "value": {"x"}},
		{"expected_revision": {rev(r0)}, "setting": {"mode"}, "value": {"autopilot"}},
		{"expected_revision": {rev(r0)}, "setting": {"paused"}, "value": {"maybe"}},
		{"setting": {"paused"}, "value": {"false"}},
	} {
		rec := f.post(f.srv.HandleAssistantUpdate, "/telegram/connect/manage/assistant/update", f.identity(accountManageScope), form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: status %d, want 400", form, rec.Code)
		}
	}
	if p := f.profile(); p.InstallRevision != r0 {
		t.Fatalf("refused change moved the revision to %d", p.InstallRevision)
	}
}

// fakeWebRegistry serves the registry's public catalog, or fails it.
type fakeWebRegistry struct {
	mu   sync.Mutex
	down bool
	srv  *httptest.Server
}

func newFakeWebRegistry(t *testing.T) *fakeWebRegistry {
	f := &fakeWebRegistry{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "upstream down", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/api/v1/assistant-catalog" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":1,"items":[{"name":"registry-only","version":"2.0.0","title":"From the registry",
			"description":"Answers for you.","tags":["x"],"examples":["Hello from a recruiter"],"lifecycle":"published",
			"variables":[{"name":"company","type":"string","required":false,"default":"Acme","description":"c"},
			             {"name":"floor","type":"string","required":false,"description":"never sent"},
			             {"name":"langs","type":"string_list","required":false,"choices":["en","ru"],"description":"l"},
			             {"name":"region","type":"string","required":false,"choices":["eu","us"],"description":"r"}],
			"intents":[{"name":"discovery","description":"d","tier":"auto"}],
			"defaults":{"mode":"guarded","limits":{"maxAutonomousTurns":3,"maxMsgsPerMinute":1,"maxReplyChars":500},"disclosure":{"policy":"required"}}}]}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeWebRegistry) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeWebRegistry) client() *assistantregistry.Client {
	return assistantregistry.NewClient(f.srv.URL, "surface-token", nil)
}

func TestManageAssistant_CatalogUnavailableIsNotEmpty(t *testing.T) {
	reg := newFakeWebRegistry(t)
	reg.setDown(true)
	f := newManageAssistantFixture(t, reg.client())
	rec := f.get(f.identity(accountManageScope))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `id="assistant-catalog-unavailable"`) ||
		strings.Contains(body, "No assistants are available to install") {
		t.Fatalf("status %d; unavailable catalog not stated: %s", rec.Code, body)
	}
	// The install section itself still renders: nothing is installed.
	if !strings.Contains(body, `id="assistant-none"`) {
		t.Fatal("install state missing")
	}
}

// Choices become a single select only for a string variable; a string_list
// keeps its list input, so more than one item can be given.
func TestManageAssistant_ChoicesSelectOnlyForStrings(t *testing.T) {
	reg := newFakeWebRegistry(t)
	f := newManageAssistantFixture(t, reg.client())
	body := f.get(f.identity(accountManageScope)).Body.String()
	if !strings.Contains(body, `<select name="value.region">`) {
		t.Error("string variable with choices is not a select")
	}
	if strings.Contains(body, `<select name="value.langs">`) || !strings.Contains(body, `<textarea name="value.langs"`) {
		t.Error("string_list variable with choices is not a list input")
	}
}

// A non-finite number is refused naming the variable, never sent on to
// become a generic encoding failure.
func TestAssistantValuesFromForm_RefusesNonFiniteNumbers(t *testing.T) {
	vars := []assistantinstall.CatalogVariable{{Name: "years", Type: "number"}}
	for _, raw := range []string{"NaN", "Inf", "-Inf", "+Inf", "abc"} {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"value.years": {raw}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		values, msg := assistantValuesFromForm(req, vars)
		if values != nil || !strings.Contains(msg, "years must be a number") {
			t.Errorf("%q: values %v, message %q", raw, values, msg)
		}
	}
}

// Each catalog version gets its own install form, and installing a later
// version from it moves the install to exactly that version.
func TestManageAssistant_InstallsEitherVersion(t *testing.T) {
	f := newManageAssistantFixture(t, nil)
	res := f.installDirect()
	body := f.get(f.identity(accountManageScope)).Body.String()
	for _, v := range []string{"0.1.1", "0.1.0"} {
		if !strings.Contains(body, `name="version" value="`+v+`"`) {
			t.Errorf("no install form for %s", v)
		}
	}
	rec := f.post(f.srv.HandleAssistantInstall, "/telegram/connect/manage/assistant/install", f.identity(accountManageScope), url.Values{
		"expected_revision": {rev(res.Profile.InstallRevision)},
		"name":              {"hr-recruiter"},
		"version":           {"0.1.1"},
		"value.name":        {webMarkName},
		"value.role":        {webMarkRole},
	})
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if page := f.get(f.identity(accountManageScope)).Body.String(); !strings.Contains(page, `id="assistant-ref">hr-recruiter@0.1.1<`) {
		t.Fatal("install did not move to 0.1.1")
	}
}
