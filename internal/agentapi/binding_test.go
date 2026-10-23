package agentapi

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// bindingFixture seeds two conversations of one user (A and B), a job and a
// lead for each, and an identity bound to job A.
type bindingFixture struct {
	h            *testHarness
	convA, convB *db.Conversation
	jobA, jobB   int64
	evA, evB     string
	leadB        int64
	jobIdentity  *auth.Identity
}

func newBindingFixture(t *testing.T) *bindingFixture {
	t.Helper()
	h := newHarness(t)
	h.seedProfile("autonomous")
	f := &bindingFixture{h: h}
	f.convA = h.seedConversation(920001)
	f.convB = h.seedConversation(920002)
	f.evA, f.evB = "evt:v1:bind:a", "evt:v1:bind:b"
	f.jobA = h.seedJob(f.evA, f.convA.ID)
	f.jobB = h.seedJob(f.evB, f.convB.ID)
	lead, err := h.store.UpsertJobLead(context.Background(), db.JobLead{
		UserID: h.userID, ConversationID: f.convB.ID, Company: "Acme", Status: "new",
	})
	if err != nil {
		t.Fatalf("seed lead: %v", err)
	}
	f.leadB = lead
	f.jobIdentity = &auth.Identity{
		UserID: h.userID, Subject: "tg:1", TelegramID: 1,
		JobID: f.jobA, JobAttempt: 1, ConversationID: f.convA.ID,
	}
	return f
}

func (f *bindingFixture) deniedAudits(t *testing.T, tool string) int {
	t.Helper()
	var n int
	err := f.h.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_logs WHERE tool_name = $1 AND status = 'denied' AND error LIKE 'conversation binding:%'`,
		tool).Scan(&n)
	if err != nil {
		t.Fatalf("count audits: %v", err)
	}
	return n
}

// T3a: the mutation-verified case. Removing the enforceBinding call in
// handleConversationContext makes this fail.
func TestBinding_ConversationContextOtherConversationDenied(t *testing.T) {
	f := newBindingFixture(t)
	rec := f.h.doAs(f.jobIdentity, "GET", "/conversations/"+strconv.FormatInt(f.convB.ID, 10)+"/context", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.deniedAudits(t, "get_conversation_context"); n != 1 {
		t.Fatalf("denied audit rows = %d, want 1", n)
	}
	// The account token still reads it.
	if rec := f.h.do("GET", "/conversations/"+strconv.FormatInt(f.convB.ID, 10)+"/context", nil); rec.Code != http.StatusOK {
		t.Fatalf("account token status = %d", rec.Code)
	}
}

// A lead whose conversation was deleted (job_leads.conversation_id set NULL
// by ON DELETE SET NULL) must not be readable with a job credential: the
// zero conversation id comes from storage, not from the request.
func TestBinding_LeadWithoutConversationDenied(t *testing.T) {
	f := newBindingFixture(t)
	if _, err := f.h.store.DB.ExecContext(context.Background(),
		`UPDATE job_leads SET conversation_id = NULL WHERE id = $1`, f.leadB); err != nil {
		t.Fatalf("orphan lead: %v", err)
	}
	path := "/leads/" + strconv.FormatInt(f.leadB, 10)
	rec := f.h.doAs(f.jobIdentity, "GET", path, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if n := f.deniedAudits(t, "get_lead"); n != 1 {
		t.Fatalf("denied audit rows = %d, want 1", n)
	}
	// The account token still reads it.
	if rec := f.h.do("GET", path, nil); rec.Code != http.StatusOK {
		t.Fatalf("account token status = %d, body %s", rec.Code, rec.Body.String())
	}
}

// T3b
func TestBinding_CrossConversationRoutesDenied(t *testing.T) {
	f := newBindingFixture(t)
	b := f.convB.ID
	bs := strconv.FormatInt(b, 10)
	jobBs := strconv.FormatInt(f.jobB, 10)
	cases := []struct {
		name, method, path, tool string
		body                     any
	}{
		{"propose_reply", "POST", "/actions/propose_reply", "propose_reply", map[string]any{"conversation_id": b, "text": "hi"}},
		{"request_owner_approval", "POST", "/actions/request_owner_approval", "request_owner_approval", map[string]any{"conversation_id": b, "text": "hi"}},
		{"notify_summary", "POST", "/notify/summary", "notify_summary", map[string]any{"conversation_id": b, "text": "hi"}},
		{"save_lead", "POST", "/leads", "save_lead", map[string]any{"conversation_id": b, "company": "X"}},
		{"get_lead", "GET", "/leads/" + strconv.FormatInt(f.leadB, 10), "get_lead", nil},
		{"recruiter", "GET", "/recruiters/920002", "get_recruiter_profile", nil},
		{"get_job", "GET", "/jobs/" + jobBs, "get_agent_job", nil},
		{"complete_job", "POST", "/jobs/" + jobBs + "/complete", "complete_agent_job", map[string]any{"attempt": 1, "status": "ignored"}},
		{"cost", "POST", "/jobs/" + jobBs + "/cost", "report_agent_job_cost", map[string]any{"attempt": 1, "cost_usd": 0.1}},
		{"event", "GET", "/event/" + f.evB, "get_event", nil},
		{"context", "GET", "/conversations/" + bs + "/context", "get_conversation_context", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.h.doAs(f.jobIdentity, tc.method, tc.path, tc.body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			if tc.tool == "request_owner_approval" || tc.tool == "notify_summary" {
				return // audited under the handler's own tool name; status checked above
			}
			if n := f.deniedAudits(t, tc.tool); n != 1 {
				t.Fatalf("denied audit rows for %s = %d, want 1", tc.tool, n)
			}
		})
	}
}

func TestBinding_JobAndAttemptMismatchDenied(t *testing.T) {
	f := newBindingFixture(t)
	a := strconv.FormatInt(f.convA.ID, 10)
	_ = a
	// Own conversation but another job id.
	rec := f.h.doAs(f.jobIdentity, "POST", "/actions/propose_reply",
		map[string]any{"conversation_id": f.convA.ID, "job_id": f.jobB, "text": "hi"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("job mismatch status = %d", rec.Code)
	}
	// Own job, wrong attempt.
	rec = f.h.doAs(f.jobIdentity, "POST", "/jobs/"+strconv.FormatInt(f.jobA, 10)+"/complete",
		map[string]any{"attempt": 9, "status": "ignored"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("attempt mismatch status = %d", rec.Code)
	}
}

// T3c
func TestBinding_AccountScopedRoutes(t *testing.T) {
	f := newBindingFixture(t)
	for _, p := range []string{"/jobs/claim", "/events"} {
		method := "POST"
		if p == "/events" {
			method = "GET"
		}
		if rec := f.h.doAs(f.jobIdentity, method, p, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s status = %d, want 403", p, rec.Code)
		}
	}
	if n := f.deniedAudits(t, "get_events"); n != 2 {
		t.Errorf("denied audits for get_events = %d, want 2", n)
	}
	if rec := f.h.doAs(f.jobIdentity, "GET", "/policy", nil); rec.Code != http.StatusOK {
		t.Errorf("/policy status = %d", rec.Code)
	}
	if rec := f.h.doAs(f.jobIdentity, "POST", "/autopilot/pause", map[string]any{}); rec.Code != http.StatusOK {
		t.Errorf("/autopilot/pause status = %d, body %s", rec.Code, rec.Body.String())
	}
}

// T3d
func TestBinding_OwnConversationMatchesAccountToken(t *testing.T) {
	f := newBindingFixture(t)
	a := strconv.FormatInt(f.convA.ID, 10)
	for _, path := range []string{
		"/conversations/" + a + "/context",
		"/jobs/" + strconv.FormatInt(f.jobA, 10),
		"/event/" + f.evA,
		"/recruiters/920001",
	} {
		job := f.h.doAs(f.jobIdentity, "GET", path, nil)
		acct := f.h.do("GET", path, nil)
		if job.Code != http.StatusOK && path != "/recruiters/920001" {
			t.Errorf("%s: job token status %d, body %s", path, job.Code, job.Body.String())
		}
		if job.Code != acct.Code || job.Body.String() != acct.Body.String() {
			t.Errorf("%s: job %d %q != account %d %q", path, job.Code, job.Body.String(), acct.Code, acct.Body.String())
		}
	}
	// conversation_id omitted: the token's conversation is used.
	rec := f.h.doAs(f.jobIdentity, "POST", "/leads", map[string]any{"company": "Own"})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Errorf("save_lead without conversation_id: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBinding_JobWithoutConversationReachesNoConversation(t *testing.T) {
	f := newBindingFixture(t)
	id := *f.jobIdentity
	id.ConversationID = 0
	rec := f.h.doAs(&id, "GET", "/conversations/"+strconv.FormatInt(f.convA.ID, 10)+"/context", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestClaimJobs_MintsBoundJobToken(t *testing.T) {
	f := newBindingFixture(t)
	secret := []byte("0123456789abcdef0123456789abcdef")
	iss, err := localjwt.NewIssuer(secret, "https://tg.example.test")
	if err != nil {
		t.Fatal(err)
	}
	f.h.srv.WithJobTokenSigner(iss)
	rec := f.h.do("POST", "/jobs/claim", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Jobs) != 1 {
		t.Fatalf("jobs = %+v", resp.Jobs)
	}
	j := resp.Jobs[0]
	c, err := localjwt.Verify(j.JobToken, secret, "https://tg.example.test")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "agent-job" ||
		c.JobID != j.JobID || c.JobAttempt != j.Attempt || c.ConversationID != j.ConversationID || c.TelegramID != 1 {
		t.Fatalf("claims = %+v, job = %+v", c, j)
	}
	if exp := time.Unix(c.ExpiresAt, 0); exp.After(time.Now().Add(time.Minute + 2*time.Second)) {
		t.Fatalf("token outlives the claim deadline: %v", exp)
	}
}

func TestClaimJobs_NoSignerNoJobToken(t *testing.T) {
	f := newBindingFixture(t)
	rec := f.h.do("POST", "/jobs/claim", nil)
	var resp struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	decodeBody(t, rec, &resp)
	if len(resp.Jobs) != 1 || resp.Jobs[0].JobToken != "" {
		t.Fatalf("jobs = %+v", resp.Jobs)
	}
}

// A job-bound credential may read every event of its coalesced turn and no
// other event, not even one of the same account.
func TestBinding_GetEventAllowsEveryTurnMember(t *testing.T) {
	f := newBindingFixture(t)
	member := "evt:v1:bind:a2"
	memberJob := f.h.seedJob(member, f.convA.ID)
	if _, err := f.h.store.DB.ExecContext(context.Background(),
		`UPDATE agent_jobs SET status = 'coalesced', coalesced_into = $1 WHERE id = $2`, f.jobA, memberJob); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{f.evA, member} {
		if rec := f.h.doAs(f.jobIdentity, "GET", "/event/"+ev, nil); rec.Code != http.StatusOK {
			t.Fatalf("event %s: status = %d, body %s", ev, rec.Code, rec.Body.String())
		}
	}
	if rec := f.h.doAs(f.jobIdentity, "GET", "/event/"+f.evB, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("other event: status = %d", rec.Code)
	}
}
