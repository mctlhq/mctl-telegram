package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/agentapi"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const managedTestSecret = "0123456789abcdef0123456789abcdef"

// managedSurface is the agent surface exactly as main builds it: the real
// agent and job providers chained, the real job-token signer, and
// wireManagedPool deciding everything managed-runtime.
type managedSurface struct {
	t     *testing.T
	cfg   *config.Config
	store *db.Store
	rc    *localjwt.RevocationCache
	mux   *chi.Mux
	admin int64
}

func newManagedSurface(t *testing.T, managedEnabled bool) *managedSurface {
	t.Helper()
	ctx := context.Background()
	name := strings.ReplaceAll(t.Name(), "/", "_") + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	conn, err := db.Open(ctx, "file:"+name+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	crypt, err := crypto.New(key)
	if err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, crypt)
	cfg := &config.Config{
		AuthMode:                     "local-jwt",
		OAUTHJWTSecret:               managedTestSecret,
		PublicBaseURL:                "https://tg.example.test",
		ManagedRuntimeEnabled:        managedEnabled,
		ManagedMaxInflightPerAccount: 1,
	}
	m := metrics.New()
	rc := localjwt.NewRevocationCache(store, time.Hour) // advanced explicitly with Refresh
	agentProvider := selectAgentProvider(cfg, store, rc)
	if jobProvider := selectAgentJobProvider(cfg, store, rc); jobProvider != nil {
		agentProvider = chainProvider{agentProvider, jobProvider}
	}
	agentSrv := agentapi.New(store, queue.New(store, "test-replica", m), time.Minute, m).WithLongPollTimeout(100 * time.Millisecond)
	signer, err := localjwt.NewIssuer([]byte(cfg.OAUTHJWTSecret), cfg.PublicBaseURL)
	if err != nil {
		t.Fatal(err)
	}
	agentSrv.WithJobTokenSigner(signer)
	adminUID, err := store.EnsureUser(ctx, "admin", "", "test")
	if err != nil {
		t.Fatal(err)
	}
	adminMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(auth.With(r.Context(), &auth.Identity{UserID: adminUID, Scopes: []string{"admin:users"}})))
		})
	}
	mux := chi.NewRouter()
	agentProvider = wireManagedPool(cfg, mux, adminMW, agentProvider, agentSrv, rc)
	agentMux := chi.NewRouter()
	agentSrv.Register(agentMux)
	mux.Mount("/api/agent/v1", auth.Middleware(agentProvider, true, m, auth.ResourceMetadata{BaseURL: cfg.PublicBaseURL})(agentMux))
	return &managedSurface{t: t, cfg: cfg, store: store, rc: rc, mux: mux, admin: adminUID}
}

func (s *managedSurface) do(method, path, bearer, body string) *httptest.ResponseRecorder {
	s.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// seedManaged creates a managed, consented account (Telegram id tg) with n
// due jobs in separate conversations and returns its user id.
func (s *managedSurface) seedManaged(tg int64, n int) int64 {
	s.t.Helper()
	ctx := context.Background()
	uid, err := s.store.EnsureUserByTelegramID(ctx, tg, "", "")
	if err != nil {
		s.t.Fatal(err)
	}
	if err := s.store.UpsertAgentProfile(ctx, db.AgentProfile{UserID: uid, Mode: db.AgentModeObserve}); err != nil {
		s.t.Fatal(err)
	}
	if _, err := s.store.DB.ExecContext(ctx, `UPDATE agent_profiles SET runtime = $1, managed_consent_version = $2 WHERE user_id = $3`,
		db.RuntimeManaged, db.ManagedConsentCurrent, uid); err != nil {
		s.t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		conv, err := s.store.EnsureConversation(ctx, uid, int64(2000+i), "peer", "Peer")
		if err != nil {
			s.t.Fatal(err)
		}
		ev := "evt:v1:" + strconv.FormatInt(tg, 10) + ":" + strconv.Itoa(i)
		if _, _, err := s.store.InsertIncomingEvent(ctx, db.IncomingEvent{
			EventID: ev, UserID: uid, Kind: db.EventKindPrivateMessage,
			ChatTGID: int64(2000 + i), SenderTGID: int64(2000 + i), MessageID: 1, Body: "hello",
		}); err != nil {
			s.t.Fatal(err)
		}
		if _, _, err := s.store.EnqueueAgentJob(ctx, ev, uid, conv.ID); err != nil {
			s.t.Fatal(err)
		}
	}
	return uid
}

func (s *managedSurface) mintPool() (token, jti string) {
	s.t.Helper()
	rec := s.do("POST", "/api/agent/pool-token", "", `{"pool_name":"main"}`)
	if rec.Code != http.StatusOK {
		s.t.Fatalf("mint pool token: %d %s", rec.Code, rec.Body)
	}
	var resp struct {
		PoolToken string `json:"pool_token"`
		Jti       string `json:"jti"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		s.t.Fatal(err)
	}
	return resp.PoolToken, resp.Jti
}

type claimedJob struct {
	JobID    int64  `json:"job_id"`
	Attempt  int    `json:"attempt"`
	JobToken string `json:"job_token"`
	ConvID   int64  `json:"conversation_id"`
}

func (s *managedSurface) claim(bearer string) (int, []claimedJob) {
	s.t.Helper()
	rec := s.do("POST", "/api/agent/v1/jobs/claim?limit=5", bearer, "")
	var body struct {
		Jobs []claimedJob `json:"jobs"`
	}
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			s.t.Fatal(err)
		}
	}
	return rec.Code, body.Jobs
}

// T2: revoking the pool's jti kills a job token already issued from it, not
// only the pool itself, through the real chained providers. The cache is
// advanced with Refresh, which is what the TTL expiry runs; until then the
// cached snapshot still admits the token (the documented bound).
// Mutation: skip the revocation check for aud=agent-job in
// localjwt.Provider.Authenticate.
func TestPoolRevocation_KillsIssuedJobToken(t *testing.T) {
	s := newManagedSurface(t, true)
	ctx := context.Background()
	s.seedManaged(9001, 2)
	pool, jti := s.mintPool()
	code, jobs := s.claim(pool)
	if code != http.StatusOK || len(jobs) != 1 || jobs[0].JobToken == "" {
		t.Fatalf("pool claim: %d %+v", code, jobs)
	}
	jobPath := "/api/agent/v1/jobs/" + strconv.FormatInt(jobs[0].JobID, 10)
	if rec := s.do("GET", jobPath, jobs[0].JobToken, ""); rec.Code != http.StatusOK {
		t.Fatalf("job token before revocation: %d %s", rec.Code, rec.Body)
	}
	if err := s.store.RevokeWorkerToken(ctx, jti, 0, "pool leak", s.admin); err != nil {
		t.Fatal(err)
	}
	if err := s.rc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	propose := `{"conversation_id":` + strconv.FormatInt(jobs[0].ConvID, 10) + `,"job_id":` + strconv.FormatInt(jobs[0].JobID, 10) + `,"text":"hi","intent":"reply"}`
	if rec := s.do("POST", "/api/agent/v1/actions/propose_reply", jobs[0].JobToken, propose); rec.Code != http.StatusUnauthorized {
		t.Fatalf("propose_reply with a job token of a revoked pool: %d, want 401", rec.Code)
	}
	if rec := s.do("GET", jobPath, jobs[0].JobToken, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET job with a job token of a revoked pool: %d, want 401", rec.Code)
	}
	if code, _ := s.claim(pool); code != http.StatusUnauthorized {
		t.Fatalf("claim with the revoked pool: %d, want 401", code)
	}
}

// T3 (end to end): a blanket revocation of one account refuses the job token
// already derived for it, leaves the pool credential working, and makes the
// pool skip that account (its other job stays pending) while serving others.
// Mutation: drop the IsBlanketRevoked skip in poolClaimOne.
func TestPoolBlanketRevocation_SkipsAccountKeepsPool(t *testing.T) {
	s := newManagedSurface(t, true)
	ctx := context.Background()
	revoked := s.seedManaged(9101, 2)
	pool, _ := s.mintPool()
	_, first := s.claim(pool)
	if len(first) != 1 {
		t.Fatalf("first claim: %+v", first)
	}
	if err := s.store.RevokeWorkerTokensForTelegramID(ctx, 9101, "account revoked", s.admin); err != nil {
		t.Fatal(err)
	}
	if err := s.rc.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if rec := s.do("GET", "/api/agent/v1/jobs/"+strconv.FormatInt(first[0].JobID, 10), first[0].JobToken, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("job token of a blanket-revoked account: %d, want 401", rec.Code)
	}
	// Free the in-flight slot so only the revocation can keep the account out.
	if _, err := s.store.DB.ExecContext(ctx, `UPDATE agent_jobs SET status = $1 WHERE id = $2`, db.JobCompleted, first[0].JobID); err != nil {
		t.Fatal(err)
	}
	other := s.seedManaged(9102, 1)
	code, jobs := s.claim(pool)
	if code != http.StatusOK {
		t.Fatalf("pool claim after a blanket revocation of one account: %d, want 200", code)
	}
	if len(jobs) != 1 {
		t.Fatalf("claimed %d jobs, want exactly the other account's one: %+v", len(jobs), jobs)
	}
	var owner int64
	if err := s.store.DB.QueryRow(`SELECT user_id FROM agent_jobs WHERE id = $1`, jobs[0].JobID).Scan(&owner); err != nil || owner != other {
		t.Fatalf("claimed job owner = %d err %v, want %d", owner, err, other)
	}
	var pending int
	if err := s.store.DB.QueryRow(`SELECT COUNT(*) FROM agent_jobs WHERE user_id = $1 AND status = $2`, revoked, db.JobPending).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("revoked account pending jobs = %d err %v, want 1", pending, err)
	}
}

// T14: with MANAGED_RUNTIME_ENABLED off, the wiring main uses mounts no mint
// route and chains no pool provider, so a pool token (signed with the same
// secret) is 401 on the claim route; with it on, the same token claims.
// Mutation: make wireManagedPool ignore cfg.ManagedRuntimeEnabled.
func TestServer_PoolFlagOff(t *testing.T) {
	signer, err := localjwt.NewIssuer([]byte(managedTestSecret), "https://tg.example.test")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pool, err := signer.Mint(localjwt.Claims{
		Subject: localjwt.PoolSubjectPrefix + "main", Audience: []string{localjwt.PoolAudience},
		Jti: "flag-test", IssuedAt: now.Unix(), OriginalIssuedAt: now.Unix(),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	off := newManagedSurface(t, false)
	off.seedManaged(9201, 1)
	if rec := off.do("POST", "/api/agent/pool-token", "", `{"pool_name":"main"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("flag off: mint route answered %d, want 404", rec.Code)
	}
	if code, _ := off.claim(pool); code != http.StatusUnauthorized {
		t.Fatalf("flag off: pool token on the claim route = %d, want 401", code)
	}
	var status string
	if err := off.store.DB.QueryRow(`SELECT status FROM agent_jobs`).Scan(&status); err != nil || status != db.JobPending {
		t.Fatalf("flag off: job status %q err %v, want pending", status, err)
	}

	on := newManagedSurface(t, true)
	on.seedManaged(9202, 1)
	if code, jobs := on.claim(pool); code != http.StatusOK || len(jobs) != 1 || jobs[0].JobToken == "" {
		t.Fatalf("flag on: pool claim = %d %+v", code, jobs)
	}
}

// Flag-off surfacing: with the pool disabled, the managed accounts whose jobs
// are paused are counted in a startup warning; with it enabled nothing is
// logged. Mutation: return early from warnManagedJobsPaused unconditionally.
func TestWarnManagedJobsPaused(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(prev)
	ctx := context.Background()

	s := newManagedSurface(t, false)
	s.seedManaged(9301, 2)
	s.seedManaged(9302, 1)
	logs.Reset()
	warnManagedJobsPaused(ctx, s.cfg, s.store)
	if out := logs.String(); !strings.Contains(out, "jobs of managed accounts are paused") || !strings.Contains(out, "managed_accounts_with_pending_jobs=2") {
		t.Fatalf("flag off: warning missing or wrong: %q", out)
	}

	s.cfg.ManagedRuntimeEnabled = true
	logs.Reset()
	warnManagedJobsPaused(ctx, s.cfg, s.store)
	if logs.Len() != 0 {
		t.Fatalf("flag on: unexpected warning %q", logs.String())
	}
	s.cfg.OAUTHJWTSecret = ""
	if managedPoolEnabled(s.cfg) {
		t.Fatal("pool must stay disabled without a signing secret")
	}
}
