package agenteval

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// confRun is a Conformance behind a test server and a scripted client.
type confRun struct {
	t       *testing.T
	target  *Target
	conf    *Conformance
	srv     *httptest.Server
	token   string
	fixture []string
}

func newConfRun(t *testing.T, ids ...string) *confRun {
	t.Helper()
	target := baseTarget(t)
	fixtures := make([]Fixture, 0, len(ids))
	for _, id := range ids {
		f, ok := target.Suite.Fixture(id)
		if !ok {
			t.Fatalf("no fixture %s", id)
		}
		fixtures = append(fixtures, f)
	}
	token := NewHarnessToken()
	c := NewConformance(target, fixtures, token, 50*time.Millisecond)
	srv := httptest.NewServer(c)
	t.Cleanup(srv.Close)
	return &confRun{t: t, target: target, conf: c, srv: srv, token: token, fixture: ids}
}

type claimed struct {
	JobID          int64  `json:"job_id"`
	EventID        string `json:"event_id"`
	ConversationID int64  `json:"conversation_id"`
	Attempt        int    `json:"attempt"`
	JobToken       string `json:"job_token"`
	Instructions   string `json:"instructions"`
}

func (r *confRun) do(token, method, path string, body any) (int, map[string]any) {
	r.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			r.t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, r.srv.URL+path, &buf)
	if err != nil {
		r.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (r *confRun) claim() (claimed, bool) {
	r.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/jobs/claim?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+r.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Jobs []claimed `json:"jobs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		r.t.Fatal(err)
	}
	if len(out.Jobs) == 0 {
		return claimed{}, false
	}
	return out.Jobs[0], true
}

func bindTo(j claimed, body map[string]any) map[string]any {
	body["job_id"], body["attempt"], body["conversation_id"] = j.JobID, j.Attempt, j.ConversationID
	return body
}

func jobPath(j claimed, suffix string) string {
	return "/jobs/" + strconv.FormatInt(j.JobID, 10) + suffix
}

// handle plays a correct worker for j: a lead when the fixture asks for one,
// then a reply or an ignore, then complete.
func (r *confRun) handle(j claimed, id string, text string) {
	r.t.Helper()
	f, _ := r.target.Suite.Fixture(id)
	if f.ExpectedAction == ActionIgnored {
		if code, _ := r.do(j.JobToken, http.MethodPost, jobPath(j, "/complete"), map[string]any{"attempt": j.Attempt, "status": "ignored"}); code != http.StatusNoContent {
			r.t.Fatalf("complete ignored: %d", code)
		}
		return
	}
	lead := map[string]any{}
	for k, v := range f.RequiredLead {
		lead[k] = v
	}
	if code, _ := r.do(j.JobToken, http.MethodPost, "/leads", bindTo(j, lead)); code != http.StatusOK {
		r.t.Fatalf("save lead: %d", code)
	}
	if code, _ := r.do(j.JobToken, http.MethodPost, "/actions/propose_reply", bindTo(j, map[string]any{"intent": "discovery", "text": text})); code != http.StatusOK {
		r.t.Fatalf("propose: %d", code)
	}
	if code, _ := r.do(j.JobToken, http.MethodPost, jobPath(j, "/complete"), map[string]any{"attempt": j.Attempt, "status": "completed"}); code != http.StatusNoContent {
		r.t.Fatalf("complete: %d", code)
	}
}

func (r *confRun) report(only ...string) Report {
	r.t.Helper()
	return Score(r.target.Suite, r.target.Adaptation, r.conf.Results(), only)
}

func TestConformance_ScriptedCorrectClientPasses(t *testing.T) {
	r := newConfRun(t, "outreach-01", "noise-01")
	for i, id := range r.fixture {
		j, ok := r.claim()
		if !ok {
			t.Fatalf("claim %d: no job", i)
		}
		if j.EventID != "eval-"+id || j.Attempt != 1 || j.ConversationID != 1 || j.JobToken == "" || j.Instructions == "" {
			t.Fatalf("envelope = %+v", j)
		}
		r.handle(j, id, cleanReply)
		if code, out := r.do(r.token, http.MethodGet, jobPath(j, ""), nil); code != http.StatusOK || out["status"] == "processing" {
			t.Fatalf("status read = %d %v", code, out)
		}
		if code, _ := r.do(r.token, http.MethodPost, jobPath(j, "/cost"), map[string]any{"attempt": 1, "cost_usd": 0.01}); code != http.StatusNoContent {
			t.Fatalf("cost = %d", code)
		}
	}
	if _, ok := r.claim(); ok {
		t.Fatal("claim after the queue drained returned a job")
	}
	if !r.conf.Finished() {
		t.Fatal("not finished")
	}
	timedOut, unsettled := r.conf.Settle(context.Background(), time.Second, 2*time.Second)
	if timedOut || len(unsettled) != 0 {
		t.Fatalf("settle = %v %v, want settled by the status read and the cost report", timedOut, unsettled)
	}
	rep := r.report(r.fixture...)
	if !rep.Passed || rep.Terminal != 2 || rep.BindingViolations != 0 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.Outcomes[0].CostUSD == nil || *rep.Outcomes[0].CostUSD != 0.01 {
		t.Fatalf("cost = %v", rep.Outcomes[0].CostUSD)
	}
}

func TestConformance_Credentials(t *testing.T) {
	r := newConfRun(t, "outreach-01")
	if code, _ := r.do("nope", http.MethodGet, "/policy", nil); code != http.StatusUnauthorized {
		t.Fatalf("unknown token = %d", code)
	}
	j, _ := r.claim()
	// A job token is refused on the claim route, as production refuses it.
	if code, _ := r.do(j.JobToken, http.MethodPost, "/jobs/claim", nil); code != http.StatusForbidden {
		t.Fatalf("job token on claim = %d, want 403", code)
	}
}

func TestConformance_LeakSendsAndNeverCompleteFailScore(t *testing.T) {
	t.Run("leak", func(t *testing.T) {
		r := newConfRun(t, "adversarial-01")
		j, _ := r.claim()
		r.handle(j, "adversarial-01", "My home is SECRET_HOME_ADDRESS")
		if rep := r.report("adversarial-01"); rep.Passed || rep.Leaks != 1 {
			t.Fatalf("report = %+v, want one leak", rep)
		}
	})
	t.Run("outside the tool set", func(t *testing.T) {
		r := newConfRun(t, "outreach-01")
		narrowed := *r.target
		narrowed.Tools = without(r.target.Tools, "pause_autopilot")
		f, _ := narrowed.Suite.Fixture("outreach-01")
		r.conf = NewConformance(&narrowed, []Fixture{f}, r.token, 50*time.Millisecond)
		r.srv.Config.Handler = r.conf
		j, _ := r.claim()
		// A definition without pause_autopilot: the fake refuses the route.
		code, out := r.do(j.JobToken, http.MethodPost, "/autopilot/pause", map[string]any{"paused": true})
		if code != http.StatusForbidden || out["error"] != "tool_not_allowed" {
			t.Fatalf("pause = %d %v", code, out)
		}
		if res := r.conf.Results()[0]; len(res.ToolRefused) != 1 {
			t.Fatalf("result = %+v", res)
		}
	})
	t.Run("never completes", func(t *testing.T) {
		r := newConfRun(t, "outreach-01")
		r.claim()
		if r.conf.Finished() {
			t.Fatal("finished with an open job")
		}
		if rep := r.report("outreach-01"); rep.Passed || rep.Terminal != 0 {
			t.Fatalf("report = %+v", rep)
		}
	})
}

// A and B are claimed in turn. A's late calls must reach A, not the most
// recently claimed fixture.
func TestConformance_RoutesByIdentityAfterTransition(t *testing.T) {
	r := newConfRun(t, "outreach-01", "outreach-02")
	a, _ := r.claim()
	r.handle(a, "outreach-01", cleanReply)
	b, _ := r.claim()

	if code, out := r.do(a.JobToken, http.MethodGet, jobPath(a, ""), nil); code != http.StatusOK || int64(out["job_id"].(float64)) != a.JobID || out["status"] != "completed" {
		t.Fatalf("late status read = %d %v", code, out)
	}
	if code, _ := r.do(a.JobToken, http.MethodPost, jobPath(a, "/cost"), map[string]any{"attempt": 1, "cost_usd": 0.5}); code != http.StatusNoContent {
		t.Fatalf("late cost = %d", code)
	}
	// The harness token resolves through the job id, not through B.
	if code, _ := r.do(r.token, http.MethodPost, jobPath(a, "/cost"), map[string]any{"attempt": 1, "cost_usd": 0.25}); code != http.StatusNoContent {
		t.Fatalf("late cost with the harness token = %d", code)
	}
	if code, _ := r.do(a.JobToken, http.MethodPost, "/actions/propose_reply", bindTo(a, map[string]any{"intent": "discovery", "text": cleanReply})); code != http.StatusConflict {
		t.Fatalf("late write = %d, want 409", code)
	}
	if code, _ := r.do(a.JobToken, http.MethodPost, jobPath(a, "/complete"), map[string]any{"attempt": 1, "status": "completed"}); code != http.StatusConflict {
		t.Fatalf("late complete = %d, want 409", code)
	}

	byID := map[string]FixtureResult{}
	for _, res := range r.conf.Results() {
		byID[res.ID] = res
	}
	if res := byID["outreach-01"]; res.CostUSD == nil || *res.CostUSD != 0.75 || res.BindingViolation || res.Action != "reply" {
		t.Fatalf("A = %+v", res)
	}
	if res := byID["outreach-02"]; res.CostUSD != nil || res.BindingViolation || res.Action != "" || res.Terminal {
		t.Fatalf("B changed by A's late calls: %+v", res)
	}

	// A's token on B's path is a cross-job use: 403, recorded against A.
	if code, _ := r.do(a.JobToken, http.MethodGet, jobPath(b, ""), nil); code != http.StatusForbidden {
		t.Fatalf("A's token on B's job = %d, want 403", code)
	}
	if code, _ := r.do(a.JobToken, http.MethodPost, "/leads", bindTo(b, map[string]any{"company": "x"})); code != http.StatusForbidden {
		t.Fatalf("A's token with B's job in the body = %d, want 403", code)
	}
	byID = map[string]FixtureResult{}
	for _, res := range r.conf.Results() {
		byID[res.ID] = res
	}
	if !byID["outreach-01"].BindingViolation || byID["outreach-02"].BindingViolation {
		t.Fatalf("violation recorded on the wrong fixture: A=%v B=%v", byID["outreach-01"].BindingViolation, byID["outreach-02"].BindingViolation)
	}

	// B's own calls still work with B's token.
	r.handle(b, "outreach-02", cleanReply)
}

func TestConformance_UnattributedRequestIsRefused(t *testing.T) {
	r := newConfRun(t, "outreach-01", "outreach-02")
	// Nothing claimed: a harness-token request names no fixture.
	if code, _ := r.do(r.token, http.MethodGet, "/policy", nil); code != http.StatusConflict {
		t.Fatalf("no open fixture = %d, want 409", code)
	}
	a, _ := r.claim()
	// One open fixture: the request is that fixture's.
	if code, _ := r.do(r.token, http.MethodGet, "/policy", nil); code != http.StatusOK {
		t.Fatalf("one open fixture = %d, want 200", code)
	}
	r.claim()
	// Two open and no job named: nothing is guessed.
	if code, _ := r.do(r.token, http.MethodGet, "/policy", nil); code != http.StatusConflict {
		t.Fatalf("two open fixtures = %d, want 409", code)
	}
	if code, _ := r.do(r.token, http.MethodGet, "/jobs/999999", nil); code != http.StatusConflict {
		t.Fatalf("unknown job = %d, want 409", code)
	}
	for _, res := range r.conf.Results() {
		if !res.BindingViolation {
			t.Fatalf("%s: the ambiguous request is not recorded as a binding violation", res.ID)
		}
	}
	if r.conf.Unattributed() != 3 {
		t.Fatalf("unattributed = %d, want 3", r.conf.Unattributed())
	}
	// The harness token with a job named reaches that job.
	if code, _ := r.do(r.token, http.MethodGet, jobPath(a, ""), nil); code != http.StatusOK {
		t.Fatalf("named job = %d", code)
	}
}

func TestConformance_SettleAndDrain(t *testing.T) {
	r := newConfRun(t, "noise-01")
	j, _ := r.claim()
	r.handle(j, "noise-01", cleanReply)

	// A worker that sends no status read and no cost report settles by quiet.
	start := time.Now()
	timedOut, unsettled := r.conf.Settle(context.Background(), 100*time.Millisecond, 5*time.Second)
	if timedOut || len(unsettled) != 0 || time.Since(start) < 100*time.Millisecond {
		t.Fatalf("quiet settle = %v %v after %v", timedOut, unsettled, time.Since(start))
	}

	// Late requests keep an unsettled fixture open until the max.
	r2 := newConfRun(t, "noise-01")
	j2, _ := r2.claim()
	r2.handle(j2, "noise-01", cleanReply)
	go func() {
		time.Sleep(60 * time.Millisecond)
		r2.do(r2.token, http.MethodGet, jobPath(j2, ""), nil)
		time.Sleep(60 * time.Millisecond)
		r2.do(r2.token, http.MethodPost, jobPath(j2, "/cost"), map[string]any{"attempt": 1, "cost_usd": 0.1})
	}()
	timedOut, unsettled = r2.conf.Settle(context.Background(), 5*time.Second, 5*time.Second)
	if timedOut || len(unsettled) != 0 {
		t.Fatalf("settle = %v %v, want both late requests awaited", timedOut, unsettled)
	}
	if res := r2.conf.Results()[0]; res.CostUSD == nil {
		t.Fatal("the late cost report is not recorded")
	}

	// The max bounds the wait and is reported, without touching the score.
	r3 := newConfRun(t, "noise-01")
	j3, _ := r3.claim()
	r3.handle(j3, "noise-01", cleanReply)
	timedOut, unsettled = r3.conf.Settle(context.Background(), 5*time.Second, 80*time.Millisecond)
	if !timedOut || len(unsettled) != 1 || unsettled[0] != "noise-01" {
		t.Fatalf("settle = %v %v, want a timeout naming noise-01", timedOut, unsettled)
	}
	if rep := r3.report("noise-01"); !rep.Passed {
		t.Fatalf("a settle timeout changed the verdict: %v", rep.Failures)
	}
}

func TestConformance_DrainReleasesALongPoll(t *testing.T) {
	r := newConfRun(t, "noise-01")
	r.conf.hold = time.Minute
	j, _ := r.claim()
	r.handle(j, "noise-01", cleanReply)
	done := make(chan bool)
	go func() {
		_, ok := r.claim()
		done <- ok
	}()
	time.Sleep(50 * time.Millisecond)
	r.conf.Drain()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("a drained claim returned a job")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the long-poll claim was not released")
	}
	// After the drain, claims answer at once.
	start := time.Now()
	r.claim()
	if time.Since(start) > time.Second {
		t.Fatal("a claim after the drain was held")
	}
}
