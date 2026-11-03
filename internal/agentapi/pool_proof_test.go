package agentapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// jobProvider is the real aud=agent-job provider over the harness store, as
// cmd/server's selectAgentJobProvider builds it.
func (h *testHarness) jobProvider() *localjwt.Provider {
	h.t.Helper()
	p, err := localjwt.NewProvider(h.store, localjwt.ProviderConfig{
		Secret: poolTestSecret, ExpectedIssuer: poolTestIssuer, ExpectedAudience: "agent-job",
		AudienceRequired: true, RevocationCache: localjwt.NewRevocationCache(h.store, time.Minute),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return p
}

func authBearer(p auth.Provider, tok string) (*auth.Identity, error) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return p.Authenticate(r)
}

// T6 (provider half): the job token minted for a pool claim authenticates,
// through the real job-token provider, as the job's own account.
// Mutation: copy Subject/TelegramID from the pool parent in mintJobTokenFor.
func TestHandleClaimJobs_Pool_JobTokenResolvesToJobOwner(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9011, db.RuntimeManaged, 1)
	_, jobs := h.poolClaim("1")
	if len(jobs) != 1 || jobs[0].JobToken == "" {
		t.Fatalf("pool claim: %+v", jobs)
	}
	id, err := authBearer(h.jobProvider(), jobs[0].JobToken)
	if err != nil {
		t.Fatalf("job provider refused the pool-derived job token: %v", err)
	}
	if id.UserID != uid || id.TelegramID != 9011 || id.IsPool() || id.JobID != jobs[0].JobID {
		t.Fatalf("identity %+v; want user %d, telegram 9011, job %d", id, uid, jobs[0].JobID)
	}
	// The resolved identity reaches the job it was minted for.
	if rec := h.doAs(id, "GET", "/jobs/"+itoaTest(jobs[0].JobID), nil); rec.Code != http.StatusOK {
		t.Fatalf("GET own job with the derived identity: %d %s", rec.Code, rec.Body.String())
	}
}

// T9: an account whose instructions cannot be rendered (here a fork while
// forks are disabled) is skipped by the pool without claiming anything: its
// job stays pending with attempts unchanged, and the other account is served.
// Mutation: claim before rendering, or ignore the render error.
func TestHandleClaimJobs_Pool_RendersBeforeClaim(t *testing.T) {
	h := poolHarness(t)
	h.srv.WithCatalog(gateCatalog(t))
	h.srv.WithManagedClaims(ManagedClaimConfig{MaxInflightPerAccount: 5})
	broken := h.seedManaged(9021, db.RuntimeManaged, 2)
	healthy := h.seedManaged(9022, db.RuntimeManaged, 1)
	ctx := context.Background()
	for uid, name := range map[int64]string{broken: "hr-recruiter~deadbeef~careful", healthy: "hr-recruiter"} {
		if _, err := h.store.DB.ExecContext(ctx, `UPDATE agent_profiles SET assistant_name = $1, assistant_version = '0.1.0' WHERE user_id = $2`, name, uid); err != nil {
			t.Fatal(err)
		}
	}
	_, jobs := h.poolClaim("5")
	if len(jobs) != 1 {
		t.Fatalf("claimed %d jobs, want only the healthy account's one", len(jobs))
	}
	got, err := h.store.GetAgentJob(ctx, healthy, jobs[0].JobID)
	if err != nil || got.UserID != healthy {
		t.Fatalf("served job %+v err %v; want the healthy account's", got, err)
	}
	var pending, attempts int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(attempts), 0) FROM agent_jobs WHERE user_id = $1 AND status = $2`,
		broken, db.JobPending).Scan(&pending, &attempts); err != nil || pending != 2 || attempts != 0 {
		t.Fatalf("broken account: pending=%d attempts=%d err %v; want 2 untouched jobs", pending, attempts, err)
	}
}

// T11 (account half): the account branch still audits the claim under its
// own user with an empty message, never with a pool marker.
// Mutation: audit the account branch with a pool:<name> message.
func TestClaimAudit_AccountBranchUnchanged(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9031, db.RuntimeOwn, 1)
	own := &auth.Identity{UserID: uid, Subject: "tg:9031", TelegramID: 9031}
	if rec := h.doAs(own, "POST", "/jobs/claim", nil); rec.Code != http.StatusOK {
		t.Fatalf("own claim: %d %s", rec.Code, rec.Body.String())
	}
	var n int
	if err := h.store.DB.QueryRow(
		`SELECT COUNT(*) FROM audit_logs WHERE user_id = $1 AND tool_name = 'get_events' AND COALESCE(error, '') = ''`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("account-branch audit rows = %d err %v; want 1 with an empty message", n, err)
	}
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE error LIKE 'pool:%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("pool-marked audit rows on an account claim = %d err %v", n, err)
	}
}

// T16: an account-token claim for an own account returns the same envelope
// and the same job-token claims as before this change: subject, Telegram id
// and username from the account token, no jti and no orig_iat, and the job is
// claimed (and stamped) as own.
// Mutations: (a) mint the account parent's job token through the pool
// branch; (b) pass db.RuntimeManaged from the account branch to the queue.
func TestHandleClaimJobs_OwnPathUnchanged(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9041, db.RuntimeOwn, 1)
	own := &auth.Identity{UserID: uid, Subject: "tg:9041", TelegramID: 9041, TelegramUsername: "alice"}
	rec := h.doAs(own, "POST", "/jobs/claim", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("own claim: %d %s", rec.Code, rec.Body.String())
	}
	var raw struct {
		Jobs []map[string]json.RawMessage `json:"jobs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil || len(raw.Jobs) != 1 {
		t.Fatalf("envelope: %s err %v", rec.Body.String(), err)
	}
	var keys []string
	for k := range raw.Jobs[0] {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	want := []string{"attempt", "conversation_id", "deadline", "event_id", "install_revision", "job_id", "job_token", "source_event_ids"}
	if !slices.Equal(keys, want) {
		t.Fatalf("envelope keys %v, want %v", keys, want)
	}
	var env jobEnvelope
	b, _ := json.Marshal(raw.Jobs[0])
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	c, err := localjwt.Verify(env.JobToken, poolTestSecret, poolTestIssuer)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Subject != "tg:9041" || c.TelegramID != 9041 || c.TelegramUsername != "alice" || c.Jti != "" || c.OriginalIssuedAt != 0 {
		t.Fatalf("own job token claims changed: %+v", c)
	}
	if c.JobID != env.JobID || c.JobAttempt != 1 || !slices.Equal(c.Audience, []string{"agent-job"}) {
		t.Fatalf("own job binding changed: %+v", c)
	}
	got, err := h.store.GetAgentJob(context.Background(), uid, env.JobID)
	if err != nil || got.Runtime != db.RuntimeOwn {
		t.Fatalf("job runtime %q err %v; want own", got.Runtime, err)
	}
}

// T12 (end to end, admin profile route): own claims a job, the admin route
// switches the account to managed and the install revision moves; the old
// attempt's reply is denied by the install fence and its completion is
// refused by the runtime fence; the sweep requeues the job and the pool
// reclaims it as managed.
// Mutations: drop the bump in RuntimeChange.Apply (the reply is no longer
// denied); drop completeRuntimeFence (the old attempt completes the job).
func TestRuntimeSwitch_FencesInflightJob(t *testing.T) {
	h := poolHarness(t)
	ctx := context.Background()
	uid := h.seedManaged(9051, db.RuntimeOwn, 1)
	consentAt := time.Now().Add(-time.Hour)
	if err := h.store.UpdateAgentProfileFields(ctx, uid, db.AgentProfileUpdate{ManagedConsentAt: &consentAt}); err != nil {
		t.Fatal(err)
	}
	own := &auth.Identity{UserID: uid, Subject: "tg:9051", TelegramID: 9051}
	rec := h.doAs(own, "POST", "/jobs/claim", nil)
	var claimed struct {
		Jobs []jobEnvelope `json:"jobs"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &claimed) != nil || len(claimed.Jobs) != 1 {
		t.Fatalf("own claim: %d %s", rec.Code, rec.Body.String())
	}
	j := claimed.Jobs[0]
	before, _ := h.store.GetAgentProfile(ctx, uid)

	admin := NewAdminAgentProfileHandlerWithManaged(h.store, assistantinstall.ManagedRuntime{Enabled: true, MaxAccounts: 5})
	if r := doProfileReq(admin, adminIdentity(), `{"telegram_id":9051,"runtime":"managed"}`); r.Code != http.StatusOK {
		t.Fatalf("admin switch to managed: %d %s", r.Code, r.Body.String())
	}
	after, _ := h.store.GetAgentProfile(ctx, uid)
	if after.Runtime != db.RuntimeManaged || after.InstallRevision <= before.InstallRevision {
		t.Fatalf("after switch: runtime %q revision %d (was %d); want managed and a bump", after.Runtime, after.InstallRevision, before.InstallRevision)
	}

	jobID := j.JobID
	rec = h.doAs(own, "POST", "/actions/propose_reply", proposeReplyRequest{
		ConversationID: j.ConversationID, JobID: jobID, Attempt: j.Attempt, Text: "hello from the old runtime",
	})
	var action actionResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &action) != nil || action.Decision != "deny" {
		t.Fatalf("old attempt's reply: %d %s; want a deny decision", rec.Code, rec.Body.String())
	}
	if rec := h.doAs(own, "POST", "/jobs/"+itoaTest(jobID)+"/complete", map[string]any{
		"attempt": j.Attempt, "status": db.JobCompleted, "result_action_id": action.ActionID,
	}); rec.Code != http.StatusConflict {
		t.Fatalf("old attempt's completion: %d %s; want 409", rec.Code, rec.Body.String())
	}
	if _, err := h.store.DB.ExecContext(ctx, `UPDATE agent_jobs SET claimed_at = $1 WHERE id = $2`, time.Now().UTC().Add(-time.Hour), jobID); err != nil {
		t.Fatal(err)
	}
	if n, _, err := h.store.RequeueStaleAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("requeue: %d err %v", n, err)
	}
	if rec := h.doAs(own, "POST", "/jobs/claim", nil); rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &claimed) != nil || len(claimed.Jobs) != 0 {
		t.Fatalf("own worker reclaimed a managed account's job: %s", rec.Body.String())
	}
	_, jobs := h.poolClaim("1")
	if len(jobs) != 1 || jobs[0].JobID != jobID || jobs[0].Attempt != j.Attempt+1 || jobs[0].JobToken == "" {
		t.Fatalf("pool reclaim: %+v", jobs)
	}
	if got, _ := h.store.GetAgentJob(ctx, uid, jobID); got.Runtime != db.RuntimeManaged || got.InstallRevision != after.InstallRevision {
		t.Fatalf("reclaimed job runtime %q revision %d; want managed at %d", got.Runtime, got.InstallRevision, after.InstallRevision)
	}
}

// Concurrent pool claims through the handler never put an account over its
// in-flight cap, however many race on the stale candidate list.
// Mutation: claim with Queue.Claim (no cap) instead of Queue.ClaimManaged.
func TestHandleClaimJobs_Pool_InflightCapConcurrent(t *testing.T) {
	h := poolHarness(t)
	uid := h.seedManaged(9061, db.RuntimeManaged, 6)
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	total := 0
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rec := h.doAs(poolIdentity(), "POST", "/jobs/claim?limit=5", nil)
			var body struct {
				Jobs []jobEnvelope `json:"jobs"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &body)
			mu.Lock()
			total += len(body.Jobs)
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	var processing int
	if err := h.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_jobs WHERE user_id = $1 AND status = $2`, uid, db.JobProcessing).Scan(&processing); err != nil {
		t.Fatal(err)
	}
	if total != 1 || processing != 1 {
		t.Fatalf("6 concurrent pool claims handed out %d jobs, %d processing; cap is 1", total, processing)
	}
}

// seedBrokenManaged creates n managed accounts whose assistant cannot render
// (a fork while forks are disabled), so the pool must skip every one of them.
func (h *testHarness) seedBrokenManaged(firstTG int64, n int) []int64 {
	h.t.Helper()
	var uids []int64
	for i := 0; i < n; i++ {
		uid := h.seedManaged(firstTG+int64(i), db.RuntimeManaged, 1)
		if _, err := h.store.DB.Exec(`UPDATE agent_profiles SET assistant_name = 'hr-recruiter~deadbeef~careful', assistant_version = '0.1.0' WHERE user_id = $1`, uid); err != nil {
			h.t.Fatal(err)
		}
		uids = append(uids, uid)
	}
	return uids
}

func (h *testHarness) seedHealthyManaged(tg int64) int64 {
	h.t.Helper()
	uid := h.seedManaged(tg, db.RuntimeManaged, 1)
	if _, err := h.store.DB.Exec(`UPDATE agent_profiles SET assistant_name = 'hr-recruiter', assistant_version = '0.1.0' WHERE user_id = $1`, uid); err != nil {
		h.t.Fatal(err)
	}
	return uid
}

// Accounts the pool must skip keep the front of the candidate order (their
// oldest job never leaves). limit+4 of them ahead of a healthy account must
// not starve it, with the default page and when the walk has to cross pages.
// Mutation: read one fixed window of limit*4 candidates instead of paging.
func TestHandleClaimJobs_Pool_SkippedAccountsDoNotStarveOthers(t *testing.T) {
	for _, page := range []int{defaultPoolCandidatePage, 2} {
		t.Run(fmt.Sprintf("page=%d", page), func(t *testing.T) { testSkippedAccountsDoNotStarve(t, page) })
	}
}

func testSkippedAccountsDoNotStarve(t *testing.T, page int) {
	{
		h := poolHarness(t)
		h.srv.WithCatalog(gateCatalog(t))
		h.srv.poolCandidatePage = page
		broken := h.seedBrokenManaged(9070, 5) // limit+4 for limit=1, all older
		healthy := h.seedHealthyManaged(9090)
		_, jobs := h.poolClaim("1")
		if len(jobs) != 1 {
			t.Fatalf("page %d: claimed %d jobs, want the healthy account's one", page, len(jobs))
		}
		if got, err := h.store.GetAgentJob(context.Background(), healthy, jobs[0].JobID); err != nil || got.UserID != healthy {
			t.Fatalf("page %d: served %+v err %v, want the healthy account", page, got, err)
		}
		for _, uid := range broken {
			var st string
			if err := h.store.DB.QueryRow(`SELECT status FROM agent_jobs WHERE user_id = $1`, uid).Scan(&st); err != nil || st != db.JobPending {
				t.Fatalf("page %d: skipped account %d job %q err %v, want pending", page, uid, st, err)
			}
		}
	}
}

// A request that skipped candidates and served nobody says so once, with the
// reasons, so a starved pool is visible in the logs.
// Mutation: drop the warning in handlePoolClaim's finish.
func TestHandleClaimJobs_Pool_LogsWhenAllCandidatesSkipped(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	h := poolHarness(t)
	h.srv.WithCatalog(gateCatalog(t))
	h.seedBrokenManaged(9095, 2)
	if _, jobs := h.poolClaim("1"); len(jobs) != 0 {
		t.Fatalf("claimed %d jobs from unservable accounts", len(jobs))
	}
	out := logs.String()
	if strings.Count(out, "candidate accounts were skipped and none was served") != 1 || !strings.Contains(out, "instructions_unavailable") {
		t.Fatalf("want exactly one skip warning naming the reason, got %q", out)
	}
}
