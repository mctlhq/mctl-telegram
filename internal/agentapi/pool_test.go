package agentapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

var poolTestSecret = []byte("0123456789abcdef0123456789abcdef")

const poolTestIssuer = "https://tg.example.test"

func poolIdentity() *auth.Identity {
	return &auth.Identity{Subject: "pool:main", Pool: "main", Jti: "pool-jti", OriginalIssuedAt: time.Now().Add(-time.Hour).Unix()}
}

// poolHarness is the harness plus a job-token signer and the managed claim
// branch.
func poolHarness(t *testing.T) *testHarness {
	t.Helper()
	h := newHarness(t)
	iss, err := localjwt.NewIssuer(poolTestSecret, poolTestIssuer)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.WithJobTokenSigner(iss).WithManagedClaims(ManagedClaimConfig{MaxInflightPerAccount: 1})
	return h
}

// seedManaged creates a managed account (synthetic Telegram id tg) with n due
// jobs and returns its user id.
func (h *testHarness) seedManaged(tg int64, runtime string, n int) int64 {
	h.t.Helper()
	ctx := context.Background()
	uid, err := h.store.EnsureUserByTelegramID(ctx, tg, "", "")
	if err != nil {
		h.t.Fatalf("ensure user: %v", err)
	}
	if err := h.store.UpsertAgentProfile(ctx, db.AgentProfile{UserID: uid, Mode: db.AgentModeObserve}); err != nil {
		h.t.Fatalf("profile: %v", err)
	}
	if _, err := h.store.DB.ExecContext(ctx,
		`UPDATE agent_profiles SET runtime = $1, managed_consent_version = $2 WHERE user_id = $3`,
		runtime, db.ManagedConsentCurrent, uid); err != nil {
		h.t.Fatalf("set runtime: %v", err)
	}
	for i := 0; i < n; i++ {
		conv, err := h.store.EnsureConversation(ctx, uid, int64(1000+i), "peer", "Peer")
		if err != nil {
			h.t.Fatalf("conversation: %v", err)
		}
		ev := "evt:v1:" + itoaTest(tg) + ":" + itoaTest(int64(i))
		if _, _, err := h.store.InsertIncomingEvent(ctx, db.IncomingEvent{
			EventID: ev, UserID: uid, Kind: db.EventKindPrivateMessage,
			ChatTGID: int64(1000 + i), SenderTGID: int64(1000 + i), MessageID: 1, Body: "hello",
		}); err != nil {
			h.t.Fatalf("event: %v", err)
		}
		if _, _, err := h.store.EnqueueAgentJob(ctx, ev, uid, conv.ID); err != nil {
			h.t.Fatalf("enqueue: %v", err)
		}
	}
	return uid
}

func (h *testHarness) poolClaim(limit string) (int, []jobEnvelope) {
	h.t.Helper()
	rec := h.doAs(poolIdentity(), "POST", "/jobs/claim?limit="+limit, nil)
	var body struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	if rec.Code == http.StatusOK {
		decodeBody(h.t, rec, &body)
	}
	return rec.Code, body.Jobs
}

func TestHandleClaimJobs_Pool_MintsJobTokenFromJobUser(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9001, db.RuntimeManaged, 1)
	code, jobs := h.poolClaim("1")
	if code != 200 || len(jobs) != 1 {
		t.Fatalf("code=%d jobs=%+v", code, jobs)
	}
	c, err := localjwt.Verify(jobs[0].JobToken, poolTestSecret, poolTestIssuer)
	if err != nil {
		t.Fatalf("verify job token: %v", err)
	}
	pool := poolIdentity()
	if c.Subject != "tg:9001" || c.TelegramID != 9001 || c.TelegramUsername != "" {
		t.Errorf("subject/telegram from job user wrong: %+v", c)
	}
	if c.Jti != pool.Jti || c.OriginalIssuedAt != pool.OriginalIssuedAt {
		t.Errorf("jti/orig_iat must be the pool's: %+v", c)
	}
	if c.JobID != jobs[0].JobID || c.JobAttempt != 1 || len(c.Audience) != 1 || c.Audience[0] != "agent-job" {
		t.Errorf("job binding wrong: %+v", c)
	}
	got, err := h.store.GetAgentJob(context.Background(), uid, jobs[0].JobID)
	if err != nil || got.Runtime != db.RuntimeManaged {
		t.Errorf("job runtime = %q, err %v; want managed", got.Runtime, err)
	}
}

func TestHandleClaimJobs_Pool_RoundRobinAndRuntimeSeparation(t *testing.T) {
	h := poolHarness(t)
	h.srv.WithManagedClaims(ManagedClaimConfig{MaxInflightPerAccount: 5})
	for _, tg := range []int64{9101, 9102, 9103} {
		h.seedManaged(tg, db.RuntimeManaged, 2)
	}
	ownUID := h.seedManaged(9199, db.RuntimeOwn, 1)
	for _, limit := range []string{"3", "10"} {
		_, jobs := h.poolClaim(limit)
		seen := map[int64]bool{}
		for _, j := range jobs {
			c, _ := localjwt.Verify(j.JobToken, poolTestSecret, poolTestIssuer)
			if seen[c.TelegramID] {
				t.Fatalf("limit=%s: two jobs for one account", limit)
			}
			seen[c.TelegramID] = true
			if c.TelegramID == 9199 {
				t.Fatal("the pool claimed an own account's job")
			}
		}
		if len(jobs) != 3 {
			t.Fatalf("limit=%s: got %d jobs, want 3 (one per account)", limit, len(jobs))
		}
		// Let the next round reclaim: finish what was claimed.
		for _, j := range jobs {
			if err := h.srv.Queue.Complete(context.Background(), j.JobID, j.Attempt, db.JobCompleted, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The own account's job is claimable by its own worker only.
	own := &auth.Identity{UserID: ownUID, Subject: "tg:9199", TelegramID: 9199}
	rec := h.doAs(own, "POST", "/jobs/claim", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"job_id"`) {
		t.Fatalf("own worker should claim its own job: %d %s", rec.Code, rec.Body.String())
	}
}

func TestHandleClaimJobs_Pool_InflightCap(t *testing.T) {
	h := poolHarness(t)
	h.seedManaged(9201, db.RuntimeManaged, 2)
	if _, jobs := h.poolClaim("5"); len(jobs) != 1 {
		t.Fatalf("first claim: %d jobs, want 1", len(jobs))
	}
	if _, jobs := h.poolClaim("5"); len(jobs) != 0 {
		t.Fatalf("account at the in-flight cap must be skipped, got %d jobs", len(jobs))
	}
}

func TestHandleClaimJobs_Pool_NoJobSigner503(t *testing.T) {
	h := newHarness(t)
	h.srv.WithManagedClaims(ManagedClaimConfig{MaxInflightPerAccount: 1})
	uid := h.seedManaged(9301, db.RuntimeManaged, 1)
	code, _ := h.poolClaim("1")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", code)
	}
	var status string
	if err := h.store.DB.QueryRow(`SELECT status FROM agent_jobs WHERE user_id = $1`, uid).Scan(&status); err != nil || status != db.JobPending {
		t.Fatalf("job status = %q, err %v; want pending", status, err)
	}
}

func TestClaimAudit_UsesJobUser(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9401, db.RuntimeManaged, 1)
	if _, jobs := h.poolClaim("1"); len(jobs) != 1 {
		t.Fatal("no job claimed")
	}
	var n int
	if err := h.store.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND tool_name = 'get_events' AND error = 'pool:main'`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("audit rows under the job user = %d, err %v; want 1", n, err)
	}
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE user_id = 0`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("audit rows with user id 0 = %d, err %v", n, err)
	}
}

func TestHandleClaimJobs_Pool_MintFailureRequeuesWithoutChargingAttempt(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9501, db.RuntimeManaged, 1)
	var jobID int64
	var maxAttempts int
	if err := h.store.DB.QueryRow(`SELECT id, max_attempts FROM agent_jobs WHERE user_id = $1`, uid).Scan(&jobID, &maxAttempts); err != nil {
		t.Fatal(err)
	}
	healthy := h.srv.jobVisibility
	h.srv.jobVisibility = time.Nanosecond // every token is already expired: minting yields nothing
	for i := 0; i < maxAttempts+3; i++ {
		if _, jobs := h.poolClaim("1"); len(jobs) != 0 {
			t.Fatalf("a job without a token was returned: %+v", jobs)
		}
		var status string
		var attempts int
		var claimedBy *string
		var open int
		if err := h.store.DB.QueryRow(`SELECT status, attempts, claimed_by FROM agent_jobs WHERE id = $1`, jobID).Scan(&status, &attempts, &claimedBy); err != nil {
			t.Fatal(err)
		}
		if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_job_attempts WHERE job_id = $1 AND finished_at IS NULL`, jobID).Scan(&open); err != nil {
			t.Fatal(err)
		}
		if status != db.JobPending || attempts != 0 || claimedBy != nil || open != 0 {
			t.Fatalf("iteration %d: status=%s attempts=%d claimed_by=%v open attempt rows=%d", i, status, attempts, claimedBy, open)
		}
		// Make it due again without waiting out the release delay.
		if _, err := h.store.DB.Exec(`UPDATE agent_jobs SET next_run_at = $1 WHERE id = $2`, time.Now().Add(-time.Second).UTC(), jobID); err != nil {
			t.Fatal(err)
		}
	}
	h.srv.jobVisibility = healthy
	_, jobs := h.poolClaim("1")
	if len(jobs) != 1 || jobs[0].JobToken == "" || jobs[0].Attempt != 1 {
		t.Fatalf("reclaim with a healthy signer: %+v", jobs)
	}
}

func TestReleaseUnissuedClaim_CASMismatchWritesNothing(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9601, db.RuntimeManaged, 1)
	_, jobs := h.poolClaim("1")
	if len(jobs) != 1 {
		t.Fatal("no job claimed")
	}
	ctx := context.Background()
	if err := h.store.ReleaseUnissuedClaim(ctx, jobs[0].JobID, jobs[0].Attempt, "other-replica"); err == nil {
		t.Fatal("release by another claimant must be refused")
	}
	if err := h.store.ReleaseUnissuedClaim(ctx, jobs[0].JobID, jobs[0].Attempt+1, "test-replica"); err == nil {
		t.Fatal("release of another attempt must be refused")
	}
	got, err := h.store.GetAgentJob(ctx, uid, jobs[0].JobID)
	if err != nil || got.Status != db.JobProcessing || got.Attempts != 1 {
		t.Fatalf("job changed by a refused release: %+v err %v", got, err)
	}
}

// recordingRegistrar captures every route Register binds.
type recordingRegistrar struct{ routes []string }

func (r *recordingRegistrar) Get(p string, _ http.HandlerFunc) { r.routes = append(r.routes, "GET "+p) }
func (r *recordingRegistrar) Post(p string, _ http.HandlerFunc) {
	r.routes = append(r.routes, "POST "+p)
}

func TestPoolCredential_ClaimOnly(t *testing.T) {
	h := poolHarness(t)
	rec := &recordingRegistrar{}
	h.srv.Register(rec)
	if len(rec.routes) < 10 {
		t.Fatalf("route table suspiciously small: %v", rec.routes)
	}
	for _, route := range rec.routes {
		method, path, _ := strings.Cut(route, " ")
		path = strings.NewReplacer("{eventID}", "e1", "{id}", "1", "{peer}", "1").Replace(path)
		req := httptest.NewRequest(method, path, nil)
		req = req.WithContext(auth.With(req.Context(), poolIdentity()))
		w := httptest.NewRecorder()
		h.router.ServeHTTP(w, req)
		if route == "POST /jobs/claim" {
			if w.Code == http.StatusForbidden {
				t.Errorf("%s must stay open to the pool", route)
			}
			continue
		}
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "pool_credential_claim_only") {
			t.Errorf("%s: status %d body %s; want 403 pool_credential_claim_only", route, w.Code, w.Body.String())
		}
	}
}

func TestPoolCredential_RefusalAuditedUnderJobOwner(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9701, db.RuntimeManaged, 1)
	var jobID int64
	if err := h.store.DB.QueryRow(`SELECT id FROM agent_jobs WHERE user_id = $1`, uid).Scan(&jobID); err != nil {
		t.Fatal(err)
	}
	rec := h.doAs(poolIdentity(), "POST", "/jobs/"+itoaTest(jobID)+"/cost", map[string]any{"attempt": 1, "cost_usd": 1})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	var n int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND status = 'denied' AND error LIKE 'pool:main%'`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("denied audit rows = %d, err %v; want 1", n, err)
	}
}
