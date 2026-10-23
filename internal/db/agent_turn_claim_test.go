package db

import (
	"context"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/turn"
)

var turnBase = time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)

var turnCfg = turn.Config{QuietMS: 3000, MaxWaitMS: 15000, MaxMsgs: 10, MaxBytes: 100}

type turnFixture struct {
	s   *Store
	uid int64
	now time.Time
}

func newTurnFixture(t *testing.T, cfg *turn.Config) *turnFixture {
	t.Helper()
	f := &turnFixture{now: turnBase}
	f.s = newTestStoreCrypted(t).WithEventOutbox(reasonBuilder).WithOperatorRouting(true).WithTurnCoalescing(cfg)
	f.s.timeNow = func() time.Time { return f.now }
	f.uid = seedAgentUser(t, f.s, "owner")
	return f
}

// ingest stores one event of chat (Alice=555, Bob=556) with a body of n bytes,
// created offset after turnBase.
func (f *turnFixture) ingest(t *testing.T, chat int64, msg int64, n int, offset time.Duration) string {
	t.Helper()
	ctx := context.Background()
	conv, err := f.s.EnsureConversation(ctx, f.uid, chat, "peer", "Peer")
	if err != nil {
		t.Fatal(err)
	}
	id := "evt:v1:1:" + itoa(chat) + ":" + itoa(msg)
	if _, ok, err := f.s.InsertEventEnqueueJobAndTouch(ctx, IncomingEvent{
		EventID: id, UserID: f.uid, Kind: EventKindPrivateMessage,
		ChatTGID: chat, SenderTGID: chat, MessageID: msg, Body: strings.Repeat("x", n),
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest: %v %v", ok, err)
	}
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1, next_run_at = $1 WHERE event_id = $2`, turnBase.Add(offset), id); err != nil {
		t.Fatal(err)
	}
	return id
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (f *turnFixture) claim(t *testing.T, limit int) []AgentJob {
	t.Helper()
	jobs, err := f.s.ClaimAgentJobs(context.Background(), "r", f.uid, limit)
	if err != nil {
		t.Fatal(err)
	}
	return jobs
}

func (f *turnFixture) status(t *testing.T, eventID string) (string, int64) {
	t.Helper()
	var st string
	var into *int64
	if err := f.s.DB.QueryRow(`SELECT status, coalesced_into FROM agent_jobs WHERE event_id = $1`, eventID).Scan(&st, &into); err != nil {
		t.Fatal(err)
	}
	if into == nil {
		return st, 0
	}
	return st, *into
}

func TestTurnClaim_BurstBecomesOneJob(t *testing.T) { // T1.1
	f := newTurnFixture(t, &turnCfg)
	var ids []string
	for i := int64(0); i < 4; i++ {
		ids = append(ids, f.ingest(t, 555, 10+i, 5, time.Duration(i)*time.Second))
	}
	f.now = turnBase.Add(4 * time.Second) // 1s after the last event: still collecting
	if got := f.claim(t, 5); len(got) != 0 {
		t.Fatalf("claimed %d while collecting", len(got))
	}
	f.now = turnBase.Add(7 * time.Second) // quiet window passed
	got := f.claim(t, 5)
	if len(got) != 1 {
		t.Fatalf("claimed %d, want 1", len(got))
	}
	if strings.Join(got[0].SourceEventIDs, ",") != strings.Join(ids, ",") {
		t.Fatalf("source events = %v, want %v", got[0].SourceEventIDs, ids)
	}
	if !strings.HasPrefix(got[0].TurnID, "turn:v1:") {
		t.Fatalf("turn id = %q", got[0].TurnID)
	}
	for _, id := range ids[1:] {
		if st, into := f.status(t, id); st != JobCoalesced || into != got[0].ID {
			t.Fatalf("member %s: %s into %d", id, st, into)
		}
	}
	loaded, err := f.s.GetAgentJob(context.Background(), f.uid, got[0].ID)
	if err != nil || len(loaded.SourceEventIDs) != 4 {
		t.Fatalf("GetAgentJob: %v %v", loaded, err)
	}
}

func TestTurnClaim_OversizedEventFormsOwnTurn(t *testing.T) { // T1.2
	f := newTurnFixture(t, &turnCfg)
	a := f.ingest(t, 555, 10, 5, 0)
	b := f.ingest(t, 555, 11, 100, time.Second) // >= MaxBytes
	c := f.ingest(t, 555, 12, 5, 2*time.Second)
	f.now = turnBase.Add(time.Minute)
	first := f.claim(t, 1)
	if len(first) != 1 || strings.Join(first[0].SourceEventIDs, ",") != a {
		t.Fatalf("first turn = %+v", first)
	}
	// Completion of each turn releases the conversation for the next.
	complete := func(j AgentJob) {
		if err := f.s.CompleteAgentJob(context.Background(), j.ID, j.Attempts, JobIgnored, ""); err != nil {
			t.Fatal(err)
		}
	}
	complete(first[0])
	second := f.claim(t, 1)
	if len(second) != 1 || strings.Join(second[0].SourceEventIDs, ",") != b {
		t.Fatalf("second turn = %+v", second)
	}
	complete(second[0])
	third := f.claim(t, 1)
	if len(third) != 1 || strings.Join(third[0].SourceEventIDs, ",") != c {
		t.Fatalf("third turn = %+v", third)
	}
}

func TestTurnClaim_ReplayAndRetryKeepTurnID(t *testing.T) { // T1.3
	run := func() (*turnFixture, AgentJob) {
		f := newTurnFixture(t, &turnCfg)
		f.ingest(t, 555, 10, 5, 0)
		f.ingest(t, 555, 11, 5, time.Second)
		f.now = turnBase.Add(time.Minute)
		got := f.claim(t, 1)
		if len(got) != 1 {
			t.Fatalf("claimed %d", len(got))
		}
		return f, got[0]
	}
	f, j1 := run()
	co, _ := turn.New(turnCfg)
	co.Offer(turn.Event{ID: j1.EventID, SessionKey: turn.SessionKey(f.uid, 555), At: turnBase})
	if want := co.Tick(turnBase.Add(time.Hour))[0].TurnID; want != j1.TurnID {
		t.Fatalf("turn id %s != coalescer %s", j1.TurnID, want)
	}
	if _, err := f.s.RetryAgentJob(context.Background(), j1.ID, j1.Attempts, "boom"); err != nil {
		t.Fatal(err)
	}
	f.now = time.Now().UTC().Add(time.Hour)
	again := f.claim(t, 1)
	if len(again) != 1 || again[0].TurnID != j1.TurnID ||
		strings.Join(again[0].SourceEventIDs, ",") != strings.Join(j1.SourceEventIDs, ",") {
		t.Fatalf("retry claim = %+v, want membership %v", again, j1.SourceEventIDs)
	}
	// Replay the same rows into a fresh store (the shared in-memory database
	// only goes away once the first store is closed).
	_ = f.s.DB.Close()
	_, j2 := run()
	if j1.TurnID != j2.TurnID {
		t.Fatalf("replay turn ids differ: %s vs %s", j1.TurnID, j2.TurnID)
	}
}

func TestTurnClaim_CollectingDoesNotBlockOtherConversation(t *testing.T) { // T1.4
	f := newTurnFixture(t, &turnCfg)
	f.ingest(t, 555, 10, 5, 9*time.Second) // still collecting at now
	ready := f.ingest(t, 556, 20, 5, 0)
	f.now = turnBase.Add(10 * time.Second)
	got := f.claim(t, 1)
	if len(got) != 1 || got[0].EventID != ready {
		t.Fatalf("claim = %+v, want %s", got, ready)
	}
}

func TestTurnClaim_OffIsOneJobPerEvent(t *testing.T) { // T1.5
	f := newTurnFixture(t, nil)
	f.ingest(t, 555, 10, 5, 0)
	f.ingest(t, 555, 11, 5, time.Second)
	got := f.claim(t, 5)
	if len(got) != 1 || got[0].TurnID != "" || len(got[0].SourceEventIDs) != 1 {
		t.Fatalf("claim = %+v", got)
	}
	var n int
	if err := f.s.DB.QueryRow(`SELECT COUNT(*) FROM agent_jobs WHERE status = 'coalesced' OR turn_id IS NOT NULL`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("coalesced rows = %d %v", n, err)
	}
}

func TestTurnClaim_MaxMsgsClosesTurn(t *testing.T) { // T1.6
	cfg := turnCfg
	cfg.MaxMsgs = 2
	f := newTurnFixture(t, &cfg)
	for i := int64(0); i < 3; i++ {
		f.ingest(t, 555, 10+i, 5, time.Duration(i)*100*time.Millisecond)
	}
	f.now = turnBase.Add(time.Minute)
	first := f.claim(t, 5)
	if len(first) != 1 || len(first[0].SourceEventIDs) != 2 {
		t.Fatalf("first = %+v", first)
	}
	if more := f.claim(t, 5); len(more) != 0 {
		t.Fatalf("second turn claimed before first completed: %+v", more)
	}
	if err := f.s.CompleteAgentJob(context.Background(), first[0].ID, first[0].Attempts, JobIgnored, ""); err != nil {
		t.Fatal(err)
	}
	if next := f.claim(t, 5); len(next) != 1 || len(next[0].SourceEventIDs) != 1 {
		t.Fatalf("next = %+v", next)
	}
}

func TestTurnClaim_FailedTurnRoutesEverySourceEvent(t *testing.T) { // T1.7
	f := newTurnFixture(t, &turnCfg)
	a := f.ingest(t, 555, 10, 5, 0)
	b := f.ingest(t, 555, 11, 5, time.Second)
	f.now = turnBase.Add(time.Minute)
	got := f.claim(t, 1)
	if len(got) != 1 {
		t.Fatal(got)
	}
	// b was already routed for another reason: it keeps its first row.
	if _, err := f.s.DB.Exec(`INSERT INTO event_outbox(event_id, user_id, stream, envelope, created_at)
		VALUES($1,$2,'s','{"routing_reason":"policy_deny"}',$3)`, b, f.uid, turnBase); err != nil {
		t.Fatal(err)
	}
	if err := f.s.CompleteAgentJob(context.Background(), got[0].ID, got[0].Attempts, JobFailed, "x"); err != nil {
		t.Fatal(err)
	}
	rows, err := f.s.PendingOutbox(context.Background(), 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("outbox = %v %v", rows, err)
	}
	for _, r := range rows {
		switch r.EventID {
		case a:
			if !strings.Contains(r.Envelope, RouteWorkerFailure) {
				t.Fatalf("a envelope %s", r.Envelope)
			}
		case b:
			if !strings.Contains(r.Envelope, "policy_deny") {
				t.Fatalf("b lost its first reason: %s", r.Envelope)
			}
		}
	}
}

func TestRouteUnclaimed(t *testing.T) { // T3.1, T3.3, T3.5
	f := newTurnFixture(t, nil)
	old := f.ingest(t, 555, 10, 5, 0)
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	fresh := f.ingest(t, 556, 20, 5, 0)
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1 WHERE event_id = $2`, time.Now().UTC(), fresh); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.s.operatorRouting = false
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 0 {
		t.Fatalf("routing off: %d %v", n, err)
	}
	f.s.operatorRouting = true
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
	if st, _ := f.status(t, old); st != JobRouted {
		t.Fatalf("status = %s", st)
	}
	rows, _ := f.s.PendingOutbox(ctx, 10)
	if len(rows) != 1 || rows[0].EventID != old || !strings.Contains(rows[0].Envelope, RouteWorkerUnclaimed) {
		t.Fatalf("outbox = %+v", rows)
	}
	// The routed job is not claimable any more; the fresh one is.
	got := f.claim(t, 5)
	if len(got) != 1 || got[0].EventID != fresh {
		t.Fatalf("claim = %+v", got)
	}
}

func TestRouteUnclaimed_SkipsClaimedAndKeepsFirstReason(t *testing.T) { // T3.2, T3.3
	f := newTurnFixture(t, nil)
	a := f.ingest(t, 555, 10, 5, 0)
	b := f.ingest(t, 556, 20, 5, 0)
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got := f.claim(t, 1)
	if len(got) != 1 {
		t.Fatal(got)
	}
	if _, err := f.s.RetryAgentJob(ctx, got[0].ID, got[0].Attempts, "boom"); err != nil {
		t.Fatal(err)
	}
	claimed := got[0].EventID
	other := a
	if claimed == a {
		other = b
	}
	if _, err := f.s.DB.Exec(`INSERT INTO event_outbox(event_id, user_id, stream, envelope, created_at)
		VALUES($1,$2,'s','{"routing_reason":"policy_deny"}',$3)`, other, f.uid, turnBase); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if st, _ := f.status(t, claimed); st != JobPending {
		t.Fatalf("retried job status = %s, want pending", st)
	}
	if st, _ := f.status(t, other); st != JobRouted {
		t.Fatalf("unclaimed job status = %s", st)
	}
	if n := outboxCount(t, f.s); n != 1 {
		t.Fatalf("outbox rows = %d, want 1 (first reason wins)", n)
	}
}

// A job that only waits behind an earlier job of its conversation is being
// served, not unclaimed: the sweep must leave it alone while the head is
// processing or backing off (claude P2 on #876). A head nobody claimed is
// routed, and its follower is routed by the next sweep, not the same one.
func TestRouteUnclaimed_SkipsJobsWaitingBehindHead(t *testing.T) { // T3.2
	f := newTurnFixture(t, nil)
	ctx := context.Background()
	head := f.ingest(t, 555, 10, 5, 0)
	follower := f.ingest(t, 555, 11, 5, time.Second)
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := f.claim(t, 5)
	if len(got) != 1 || got[0].EventID != head {
		t.Fatalf("claim = %+v", got)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 0 {
		t.Fatalf("sweep behind a processing head: %d %v", n, err)
	}
	if _, err := f.s.RetryAgentJob(ctx, got[0].ID, got[0].Attempts, "boom"); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 0 {
		t.Fatalf("sweep behind a backing-off head: %d %v", n, err)
	}
	for _, id := range []string{head, follower} {
		if st, _ := f.status(t, id); st != JobPending {
			t.Fatalf("%s status = %s, want pending", id, st)
		}
	}

	// Bob's conversation: nobody ever claimed the head.
	bHead := f.ingest(t, 556, 20, 5, 0)
	bNext := f.ingest(t, 556, 21, 5, time.Second)
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1 WHERE event_id IN ($2, $3)`,
		time.Now().UTC().Add(-time.Hour), bHead, bNext); err != nil {
		t.Fatal(err)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("first sweep: %d %v", n, err)
	}
	if st, _ := f.status(t, bHead); st != JobRouted {
		t.Fatalf("unclaimed head status = %s", st)
	}
	if st, _ := f.status(t, bNext); st != JobPending {
		t.Fatalf("follower routed in the same sweep: %s", st)
	}
	if n, err := f.s.RouteUnclaimedAgentJobs(ctx, time.Minute); err != nil || n != 1 {
		t.Fatalf("second sweep: %d %v", n, err)
	}
	if st, _ := f.status(t, bNext); st != JobRouted {
		t.Fatalf("follower status = %s", st)
	}
}

// T3.4: the sweep and a claim racing for one job move it exactly once. On
// SQLite the single connection serializes them; on Postgres
// (TEST_DATABASE_URL) the row lock does.
func TestRouteUnclaimed_RaceWithClaimMovesJobOnce(t *testing.T) { // T3.4
	for i := 0; i < 20; i++ {
		f := newTurnFixture(t, nil)
		ctx := context.Background()
		ev := f.ingest(t, 555, 10, 5, 0)
		if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1, next_run_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var claimed []AgentJob
		var routed int64
		var claimErr, routeErr error
		wg.Add(2)
		go func() { defer wg.Done(); claimed, claimErr = f.s.ClaimAgentJobs(ctx, "r", f.uid, 1) }()
		go func() { defer wg.Done(); routed, routeErr = f.s.RouteUnclaimedAgentJobs(ctx, time.Minute) }()
		wg.Wait()
		if claimErr != nil || routeErr != nil {
			t.Fatalf("claim %v, route %v", claimErr, routeErr)
		}
		if (len(claimed) == 1) == (routed == 1) {
			t.Fatalf("run %d: claimed %d and routed %d, want exactly one", i, len(claimed), routed)
		}
		st, _ := f.status(t, ev)
		if len(claimed) == 1 && (st != JobProcessing || outboxCount(t, f.s) != 0) {
			t.Fatalf("run %d: claimed job is %s with %d outbox rows", i, st, outboxCount(t, f.s))
		}
		if routed == 1 && st != JobRouted {
			t.Fatalf("run %d: routed job is %s", i, st)
		}
		_ = f.s.DB.Close()
	}
}

// Task 2: ingest records the plaintext size, and only the size.
func TestIngest_RecordsBodyBytes(t *testing.T) {
	f := newTurnFixture(t, nil)
	ev := f.ingest(t, 555, 10, 37, 0)
	var n int
	var sealed []byte
	if err := f.s.DB.QueryRow(`SELECT j.body_bytes, e.body_encrypted FROM agent_jobs j
		JOIN incoming_events e ON e.event_id = j.event_id WHERE j.event_id = $1`, ev).Scan(&n, &sealed); err != nil {
		t.Fatal(err)
	}
	if n != 37 {
		t.Fatalf("body_bytes = %d, want 37", n)
	}
	if strings.Contains(string(sealed), strings.Repeat("x", 37)) {
		t.Fatal("body stored in plaintext")
	}
}

// Task 1: on a database from before slice 2, the migration adds the turn
// columns (NULL on existing rows) and a second run changes nothing.
func TestMigrateAgent_TurnColumnsUpgradeAndRerun(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		s := newTestStore(t)
		checkTurnColumnsUpgrade(t, s, false)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		checkTurnColumnsUpgrade(t, newPostgresTestStore(t, dsn), true)
	})
}

func checkTurnColumnsUpgrade(t *testing.T, s *Store, pg bool) {
	t.Helper()
	ctx := context.Background()
	cols := []string{"turn_id", "coalesced_into", "body_bytes"}
	if _, err := s.DB.ExecContext(ctx, `DROP INDEX IF EXISTS idx_agent_jobs_coalesced_into`); err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if _, err := s.DB.ExecContext(ctx, `ALTER TABLE agent_jobs DROP COLUMN `+c); err != nil {
			t.Fatalf("drop %s: %v", c, err)
		}
	}
	for run := 1; run <= 2; run++ {
		if err := migrateAgent(ctx, s.DB, pg); err != nil {
			t.Fatalf("migrate run %d: %v", run, err)
		}
		for _, c := range cols {
			ok, err := columnExists(ctx, s.DB, pg, "agent_jobs", c)
			if err != nil || !ok {
				t.Fatalf("run %d: column %s present=%v err=%v", run, c, ok, err)
			}
		}
	}
}
