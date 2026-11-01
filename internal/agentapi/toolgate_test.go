package agentapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const (
	gateSecret = "0123456789abcdef0123456789abcdef"
	gateIssuer = "https://tg.example.test"
	aliceTGID  = 500100101
)

// gateCatalog holds the embedded hr-recruiter definition and two
// narrower copies of it: restricted-assistant, without save_job_lead and
// pause_autopilot, and lead-only, without get_conversation_context.
func gateCatalog(t *testing.T) *assistant.Catalog {
	t.Helper()
	raw, err := os.ReadFile("../../assistants/hr-recruiter/assistant.yaml")
	if err != nil {
		t.Fatal(err)
	}
	full := strings.Replace(string(raw), "path: ../../deploy/agent-worker/system-prompt.txt", "path: prompt.txt", 1)
	variant := func(name string, cuts ...string) string {
		def := full
		for _, cut := range cuts {
			if !strings.Contains(def, cut) {
				t.Fatalf("definition has no %q", cut)
			}
			def = strings.Replace(def, cut, "", 1)
		}
		return strings.Replace(def, "name: hr-recruiter", "name: "+name, 1)
	}
	prompt, err := os.ReadFile("../../deploy/agent-worker/system-prompt.txt")
	if err != nil {
		t.Fatal(err)
	}
	fsys := fstest.MapFS{
		"assistants/hr-recruiter/assistant.yaml": {Data: []byte(full)},
		"assistants/hr-recruiter/prompt.txt":     {Data: prompt},
	}
	for name, def := range map[string]string{
		"restricted-assistant": variant("restricted-assistant", "    - save_job_lead\n", "    - pause_autopilot\n"),
		"lead-only":            variant("lead-only", "    - get_conversation_context\n"),
	} {
		fsys["assistants/"+name+"/assistant.yaml"] = &fstest.MapFile{Data: []byte(def)}
		fsys["assistants/"+name+"/prompt.txt"] = &fstest.MapFile{Data: prompt}
	}
	c, err := assistant.LoadCatalog(fsys)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type gateFixture struct {
	h        *testHarness
	m        *metrics.Registry
	provider *localjwt.Provider
	conv     *db.Conversation
}

// newGateFixture builds a server with a catalog and a job-token signer for
// Alice, whose profile runs assistantName.
func newGateFixture(t *testing.T, assistantName string) *gateFixture {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatal(err)
	}
	crypt, err := crypto.New(testCryptKey())
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUserByTelegramID(ctx, aliceTGID, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	iss, err := localjwt.NewIssuer([]byte(gateSecret), gateIssuer)
	if err != nil {
		t.Fatal(err)
	}
	m := metrics.New()
	srv := New(store, queue.New(store, "test-replica", m), time.Minute, m).
		WithLongPollTimeout(150 * time.Millisecond).
		WithCatalog(gateCatalog(t)).
		WithJobTokenSigner(iss)
	router := chi.NewRouter()
	srv.Register(router)
	h := &testHarness{
		t: t, srv: srv, store: store, router: router, userID: uid,
		id: &auth.Identity{UserID: uid, Subject: "tg:" + strconv.Itoa(aliceTGID), TelegramID: aliceTGID},
	}
	h.seedProfile("autonomous")
	if _, err := store.DB.ExecContext(ctx,
		`UPDATE agent_profiles SET assistant_name = $1, assistant_version = '0.1.0' WHERE user_id = $2`,
		assistantName, uid); err != nil {
		t.Fatal(err)
	}
	p, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret: []byte(gateSecret), ExpectedIssuer: gateIssuer,
		ExpectedAudience: jobTokenAudience, AudienceRequired: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &gateFixture{h: h, m: m, provider: p, conv: h.seedConversation(500100202)}
	h.seedJob("evt:v1:gate:1", f.conv.ID)
	return f
}

// claimToken claims the queued job with Alice's account token and returns
// its job token.
func (f *gateFixture) claimToken(t *testing.T) (string, jobEnvelope) {
	t.Helper()
	code, jobs := claimOne(t, f.h)
	if code != http.StatusOK || len(jobs) != 1 || jobs[0].JobToken == "" {
		t.Fatalf("claim = %d %+v", code, jobs)
	}
	return jobs[0].JobToken, jobs[0]
}

// authenticate verifies tok as the agent-job provider does in production.
func (f *gateFixture) authenticate(tok string) (*auth.Identity, error) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return f.provider.Authenticate(r)
}

func (f *gateFixture) saveLead(id *auth.Identity, j jobEnvelope) *httptest.ResponseRecorder {
	return f.h.doAs(id, "POST", "/leads", map[string]any{
		"conversation_id": f.conv.ID, "job_id": j.JobID, "attempt": j.Attempt, "company": "Acme",
	})
}

func (f *gateFixture) toolDenials(t *testing.T, tool string) int {
	t.Helper()
	var n int
	if err := f.h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE tool_name = $1 AND status = 'denied' AND error = 'tool gate: tool_not_allowed'`,
		tool).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func assertToolNotAllowed(t *testing.T, rec *httptest.ResponseRecorder, tool string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body %s, want 403", rec.Code, rec.Body.String())
	}
	var body map[string]string
	decodeBody(t, rec, &body)
	if body["error"] != "tool_not_allowed" || body["tool"] != tool {
		t.Fatalf("body = %v, want tool_not_allowed for %s", body, tool)
	}
}

// The acceptance case of #1041: a job whose definition omits save_job_lead
// POSTs the save route directly with its own valid job token, as a forged
// MCP config would, and is refused, audited and counted. Removing the gate
// (toolGate returning h unconditionally) turns this red.
func TestToolGate_JobTokenOutsideItsToolsIsRefused(t *testing.T) {
	f := newGateFixture(t, "restricted-assistant")
	tok, j := f.claimToken(t)
	if slices.Contains(j.Tools, "save_job_lead") {
		t.Fatalf("claim tools %v include save_job_lead", j.Tools)
	}
	id, err := f.authenticate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(id.JobTools, "save_job_lead") || !slices.Contains(id.JobTools, "propose_reply") {
		t.Fatalf("token tools = %v", id.JobTools)
	}
	counter := f.m.AgentPolicyDenialsTotal.WithLabelValues(string(policy.DenyToolNotAllowed), metrics.PolicySurfaceToolGate)
	before := testutil.ToFloat64(counter)

	assertToolNotAllowed(t, f.saveLead(id, j), "save_job_lead")
	assertToolNotAllowed(t, f.h.doAs(id, "POST", "/autopilot/pause", map[string]any{"paused": true}), "pause_autopilot")

	if n := f.toolDenials(t, "save_job_lead"); n != 1 {
		t.Fatalf("denied audit rows = %d, want 1", n)
	}
	if got := testutil.ToFloat64(counter); got != before+2 {
		t.Fatalf("tool_not_allowed denials = %v, want %v", got, before+2)
	}
	var leads int
	if err := f.h.store.DB.QueryRow(`SELECT COUNT(*) FROM job_leads`).Scan(&leads); err != nil || leads != 0 {
		t.Fatalf("job_leads = %d, err %v: the refused save was written", leads, err)
	}
	// A tool the definition keeps still works with the same token.
	if rec := f.h.doAs(id, "GET", "/policy", nil); rec.Code != http.StatusOK {
		t.Fatalf("get_policy status = %d, body %s", rec.Code, rec.Body.String())
	}
	// Routes serving no tool, and the mandatory tools, are not gated.
	if rec := f.h.doAs(id, "GET", "/jobs/"+strconv.FormatInt(j.JobID, 10), nil); rec.Code != http.StatusOK {
		t.Fatalf("job status = %d", rec.Code)
	}
	if rec := f.h.doAs(id, "GET", "/event/"+j.EventID, nil); rec.Code != http.StatusOK {
		t.Fatalf("get_event status = %d", rec.Code)
	}
}

// The full tool set reaches the same routes as before: the gate lets the
// save through.
func TestToolGate_FullToolSetUnaffected(t *testing.T) {
	f := newGateFixture(t, "hr-recruiter")
	tok, j := f.claimToken(t)
	id, err := f.authenticate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(id.JobTools, tools.Canonical) {
		t.Fatalf("token tools = %v, want every tool", id.JobTools)
	}
	if rec := f.saveLead(id, j); rec.Code != http.StatusOK {
		t.Fatalf("save status = %d, body %s", rec.Code, rec.Body.String())
	}
}

// A worker cannot widen its token's tool set: rewriting job_tools breaks the
// signature, and the provider rejects the token outright.
func TestToolGate_TamperedToolClaimIsRejected(t *testing.T) {
	f := newGateFixture(t, "restricted-assistant")
	tok, _ := f.claimToken(t)
	parts := strings.Split(tok, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["job_tools"] = tools.Canonical
	widened, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(widened) + "." + parts[2]
	if id, err := f.authenticate(forged); err == nil || id != nil {
		t.Fatalf("widened token accepted: id=%+v err=%v", id, err)
	}
}

// An account-wide token carries no tool set; on an account whose definition
// restricts tools it gets the definition's set, not every tool. So does a
// job token minted before job_tools existed.
func TestToolGate_AccountTokenOnRestrictedAccount(t *testing.T) {
	f := newGateFixture(t, "restricted-assistant")
	_, j := f.claimToken(t)
	assertToolNotAllowed(t, f.saveLead(f.h.id, jobEnvelope{}), "save_job_lead")
	assertToolNotAllowed(t, f.h.do("POST", "/autopilot/pause", map[string]any{"paused": true}), "pause_autopilot")
	if rec := f.h.do("GET", "/policy", nil); rec.Code != http.StatusOK {
		t.Fatalf("get_policy status = %d", rec.Code)
	}

	legacy := *f.h.id
	legacy.JobID, legacy.JobAttempt, legacy.ConversationID = j.JobID, j.Attempt, j.ConversationID
	assertToolNotAllowed(t, f.saveLead(&legacy, j), "save_job_lead")
}

// A tool set that cannot be resolved refuses the gated routes rather than
// allowing every tool.
func TestToolGate_UnresolvableToolSetFailsClosed(t *testing.T) {
	f := newGateFixture(t, "no-such-assistant")
	rec := f.saveLead(f.h.id, jobEnvelope{})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body %s, want 503", rec.Code, rec.Body.String())
	}
	// Routes serving no tool are unaffected.
	if rec := f.h.do("GET", "/jobs/1", nil); rec.Code == http.StatusServiceUnavailable {
		t.Fatalf("job status refused: %d", rec.Code)
	}
}

// get_lead reads through a route that returns the leads and no messages
// (#1043): a job whose tools keep get_lead but drop get_conversation_context
// reads its leads and is refused the conversation context. Mapping the
// context route to get_lead again turns this red.
func TestToolGate_GetLeadDoesNotGrantConversationContext(t *testing.T) {
	f := newGateFixture(t, "lead-only")
	tok, j := f.claimToken(t)
	id, err := f.authenticate(tok)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(id.JobTools, "get_conversation_context") || !slices.Contains(id.JobTools, "get_lead") {
		t.Fatalf("token tools = %v", id.JobTools)
	}
	if _, err := f.h.store.UpsertJobLead(context.Background(), db.JobLead{
		UserID: f.h.userID, ConversationID: f.conv.ID, Company: "Acme", Status: "discovery",
	}); err != nil {
		t.Fatal(err)
	}
	conv := strconv.FormatInt(j.ConversationID, 10)
	assertToolNotAllowed(t, f.h.doAs(id, "GET", "/conversations/"+conv+"/context", nil), "get_conversation_context")

	rec := f.h.doAs(id, "GET", "/conversations/"+conv+"/leads", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("leads status = %d, body %s", rec.Code, rec.Body.String())
	}
	var body map[string]json.RawMessage
	decodeBody(t, rec, &body)
	if _, ok := body["messages"]; ok || len(body) != 1 || !strings.Contains(string(body["leads"]), "Acme") {
		t.Fatalf("leads body = %s, want only the leads", rec.Body.String())
	}
	// The route is bound to the job's own conversation.
	if rec := f.h.doAs(id, "GET", "/conversations/"+strconv.FormatInt(j.ConversationID+1, 10)+"/leads", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other conversation's leads = %d, want 403", rec.Code)
	}
}

type routeRecorder struct{ routes []string }

func (r *routeRecorder) Get(p string, _ http.HandlerFunc)  { r.routes = append(r.routes, "GET "+p) }
func (r *routeRecorder) Post(p string, _ http.HandlerFunc) { r.routes = append(r.routes, "POST "+p) }

// Every route Register binds is either mapped to its tools or one of the
// routes that serve no tool, and every mapped route is registered, so a new
// route cannot skip the gate by being left out of tools.Endpoints.
func TestToolGate_EveryRouteIsMappedOrToolless(t *testing.T) {
	toolless := []string{"GET /events", "GET /jobs/{id}", "POST /jobs/claim", "POST /jobs/{id}/cost"}
	var rec routeRecorder
	New(nil, nil, time.Minute, nil).Register(&rec)
	for _, route := range rec.routes {
		_, mapped := tools.Endpoints[route]
		if mapped == slices.Contains(toolless, route) {
			t.Errorf("route %s: mapped=%v, toolless=%v; exactly one must hold", route, mapped, !mapped)
		}
	}
	for route := range tools.Endpoints {
		if !slices.Contains(rec.routes, route) {
			t.Errorf("tools.Endpoints names %s, which Register does not bind", route)
		}
	}
}
