package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestForkEvals(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { checkForkEvals(t, newTestStoreCrypted(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		checkForkEvals(t, newPostgresTestStore(t, dsn))
	})
}

type evalEnv struct {
	t   *testing.T
	s   *Store
	ctx context.Context
	sfx string
	seq int64
	// names maps a fork digest to the fork's name.
	names map[string]string
}

func (e *evalEnv) user(name string) int64 {
	e.t.Helper()
	e.seq++
	uid, err := e.s.EnsureUserByTelegramID(e.ctx, 500200000+e.seq, name+e.sfx, name)
	if err != nil {
		e.t.Fatal(err)
	}
	return uid
}

// fork inserts a fork version for uid and returns its binding.
func (e *evalEnv) fork(uid int64) ForkEvalBinding {
	e.t.Helper()
	base := randomDigest(e.t)
	e.seq++
	name := fmt.Sprintf("hr-recruiter~abcdefgh23~f%d", e.seq)
	f := forkRow(e.t, uid, name, "0.1.0", base)
	if e.names == nil {
		e.names = map[string]string{}
	}
	e.names[f.Digest] = name
	if err := e.s.InsertAssistantFork(e.ctx, f, "", "saved"); err != nil {
		e.t.Fatal(err)
	}
	return ForkEvalBinding{UserID: uid, ForkDigest: f.Digest, BaseDigest: base, SuiteDigest: "sha256:suite", HarnessVersion: "h1"}
}

func (e *evalEnv) count(table string) int {
	e.t.Helper()
	var n int
	if err := e.s.DB.QueryRowContext(e.ctx, `SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *evalEnv) state(run int64) string {
	e.t.Helper()
	var st string
	if err := e.s.DB.QueryRowContext(e.ctx, `SELECT state FROM assistant_fork_eval_runs WHERE id = $1`, run).Scan(&st); err != nil {
		e.t.Fatal(err)
	}
	return st
}

// refused asserts err is want and no row was written to either table.
func (e *evalEnv) refused(err, want error, runs, tasks int) {
	e.t.Helper()
	if !errors.Is(err, want) {
		e.t.Fatalf("err = %v, want %v", err, want)
	}
	if e.count("assistant_fork_eval_runs") != runs || e.count("assistant_fork_eval_tasks") != tasks {
		e.t.Fatalf("a refused create wrote rows")
	}
}

func scoreWith(passed bool, calls *int) ForkEvalScorer {
	return func(rs []ForkEvalTaskResult) (bool, []byte, error) {
		*calls++
		ids := ""
		for _, r := range rs {
			ids += r.FixtureID + ","
		}
		return passed, []byte(ids), nil
	}
}

// finish drives a run to a verdict: claims and finishes every task.
func (e *evalEnv) verdict(b ForkEvalBinding, passed bool, now time.Time) int64 {
	e.t.Helper()
	run, err := e.s.CreateForkEvalRun(e.ctx, b, []string{"f1", "f2"}, now)
	if err != nil {
		e.t.Fatalf("create: %v", err)
	}
	var calls int
	for i := 0; i < 2; i++ {
		task, err := e.s.ClaimForkEvalTask(e.ctx, b.UserID, now, 10*time.Minute)
		if err != nil {
			e.t.Fatalf("claim: %v", err)
		}
		if _, err := e.s.FinishForkEvalTask(e.ctx, run, task.FixtureID, task.Attempt, false, []byte(`{}`), scoreWith(passed, &calls), now); err != nil {
			e.t.Fatalf("finish: %v", err)
		}
	}
	return run
}

func checkForkEvals(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		t.Fatal(err)
	}
	e := &evalEnv{t: t, s: s, ctx: ctx, sfx: hex.EncodeToString(tag[:])}
	// The global limit counts every account: start from an empty table.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM assistant_fork_eval_runs`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lease := 10 * time.Minute

	alice, bob := e.user("Alice"), e.user("Bob")
	ab := e.fork(alice)
	bb := e.fork(bob)

	// Input validation and unknown digest write nothing.
	for _, tc := range []struct {
		b   ForkEvalBinding
		ids []string
	}{
		{ab, nil}, {ab, []string{"a", "a"}}, {ab, []string{""}},
		{ForkEvalBinding{UserID: alice, ForkDigest: ab.ForkDigest}, []string{"a"}},
	} {
		if _, err := s.CreateForkEvalRun(ctx, tc.b, tc.ids, now); err == nil {
			t.Fatalf("accepted %+v %v", tc.b, tc.ids)
		}
	}
	other := ab
	other.ForkDigest = randomDigest(t)
	_, err := s.CreateForkEvalRun(ctx, other, []string{"a"}, now)
	e.refused(err, ErrAssistantForkNotFound, 0, 0)
	cross := bb
	cross.UserID = alice
	_, err = s.CreateForkEvalRun(ctx, cross, []string{"a"}, now)
	e.refused(err, ErrAssistantForkNotFound, 0, 0)

	// Open run, scoring, digest limits.
	run1, err := s.CreateForkEvalRun(ctx, ab, []string{"f1", "f2"}, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateForkEvalRun(ctx, ab, []string{"f1"}, now)
	e.refused(err, ErrForkEvalRunOpen, 1, 2)
	if _, err := s.LatestScoredForkEvalRun(ctx, alice, ab.ForkDigest); !errors.Is(err, ErrForkEvalRunNotFound) {
		t.Fatalf("latest of an unscored digest: %v", err)
	}

	// Account-scoped claim never returns another account's task.
	if _, err := s.ClaimForkEvalTask(ctx, bob, now, lease); !errors.Is(err, ErrForkEvalNoTask) {
		t.Fatalf("Bob claims Alice's task: %v", err)
	}
	task, err := s.ClaimForkEvalTask(ctx, 0, now, lease)
	if err != nil || task.RunID != run1 || task.FixtureID != "f1" || task.Attempt != 1 || task.Binding != ab {
		t.Fatalf("any-account claim = %+v, %v", task, err)
	}
	if e.state(run1) != ForkEvalRunning {
		t.Fatalf("run state = %s", e.state(run1))
	}
	var calls int
	// Stale: wrong attempt, unclaimed task.
	if _, err := s.FinishForkEvalTask(ctx, run1, "f1", 2, false, nil, scoreWith(true, &calls), now); !errors.Is(err, ErrForkEvalTaskStale) {
		t.Fatalf("wrong attempt: %v", err)
	}
	if _, err := s.FinishForkEvalTask(ctx, run1, "f2", 1, false, nil, scoreWith(true, &calls), now); !errors.Is(err, ErrForkEvalTaskStale) {
		t.Fatalf("unclaimed task: %v", err)
	}
	// A scorer error leaves task claimed and run running.
	t2, err := s.ClaimForkEvalTask(ctx, alice, now, lease)
	if err != nil || t2.FixtureID != "f2" {
		t.Fatalf("second claim = %+v, %v", t2, err)
	}
	if _, err := s.FinishForkEvalTask(ctx, run1, "f1", 1, false, []byte(`{"a":1}`), scoreWith(true, &calls), now); err != nil {
		t.Fatal(err)
	}
	boom := func([]ForkEvalTaskResult) (bool, []byte, error) { return false, nil, errors.New("boom") }
	if _, err := s.FinishForkEvalTask(ctx, run1, "f2", 1, false, []byte(`{}`), boom, now); err == nil {
		t.Fatal("scorer error swallowed")
	}
	if e.state(run1) != ForkEvalRunning {
		t.Fatalf("run state after scorer error = %s", e.state(run1))
	}
	// The scorer alone decides the verdict.
	st, err := s.FinishForkEvalTask(ctx, run1, "f2", 1, false, []byte(`{"passed":true}`), scoreWith(false, &calls), now)
	if err != nil || st != ForkEvalFailed || calls != 1 {
		t.Fatalf("finish = %s, %v, calls %d", st, err, calls)
	}
	if _, err := s.FinishForkEvalTask(ctx, run1, "f2", 1, false, nil, scoreWith(true, &calls), now); !errors.Is(err, ErrForkEvalTaskStale) {
		t.Fatalf("finish on a finished run: %v", err)
	}
	got, err := s.LatestScoredForkEvalRun(ctx, alice, ab.ForkDigest)
	if err != nil || got.State != ForkEvalFailed || string(got.Report) != "f1,f2," || got.FinishedAt == nil {
		t.Fatalf("latest = %+v, %v", got, err)
	}
	if _, err := s.LatestScoredForkEvalRun(ctx, bob, ab.ForkDigest); !errors.Is(err, ErrForkEvalRunNotFound) {
		t.Fatalf("Bob reads Alice's run: %v", err)
	}

	// One fail leaves room, a second fail exhausts the digest.
	e.verdict(ab, false, now)
	_, err = s.CreateForkEvalRun(ctx, ab, []string{"f1"}, now)
	e.refused(err, ErrForkEvalDigestLimit, 2, 4)

	// A pass closes a digest; the newest scored run wins.
	backdate := func() {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx, `UPDATE assistant_fork_eval_runs SET created_at = $1 WHERE user_id = $2`,
			now.Add(-25*time.Hour), alice); err != nil {
			t.Fatal(err)
		}
	}
	backdate()
	cb := e.fork(alice)
	e.verdict(cb, false, now)
	pass := e.verdict(cb, true, now.Add(time.Second))
	got, err = s.LatestScoredForkEvalRun(ctx, alice, cb.ForkDigest)
	if err != nil || got.ID != pass || got.State != ForkEvalPassed {
		t.Fatalf("latest after pass = %+v, %v", got, err)
	}
	// Account limit is 3 in 24 h: a third run fits, a 4th does not.
	e.verdict(e.fork(alice), false, now)
	fresh := e.fork(alice)
	_, err = s.CreateForkEvalRun(ctx, fresh, []string{"f1"}, now)
	if !errors.Is(err, ErrForkEvalAccountLimit) {
		t.Fatalf("4th run in 24h: %v", err)
	}
	// Once older than 24 h they stop counting; the passed digest still refuses.
	backdate()
	if _, err := s.CreateForkEvalRun(ctx, cb, []string{"f1"}, now); !errors.Is(err, ErrForkEvalDigestPassed) {
		t.Fatalf("run after a pass: %v", err)
	}

	// Unscored runs never count and are never returned.
	db3 := e.fork(alice)
	for _, st := range []string{ForkEvalIncomplete, ForkEvalExpired, ForkEvalCancelled} {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO assistant_fork_eval_runs(user_id, fork_digest, base_digest, suite_digest, harness_version, state, created_at)
			 VALUES ($1,$2,'b','s','h',$3,$4)`, alice, db3.ForkDigest, st, now.Add(-30*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.LatestScoredForkEvalRun(ctx, alice, db3.ForkDigest); !errors.Is(err, ErrForkEvalRunNotFound) {
		t.Fatalf("unscored runs returned: %v", err)
	}
	if _, err := s.CreateForkEvalRun(ctx, db3, []string{"f1"}, now); err != nil {
		t.Fatalf("unscored runs counted: %v", err)
	}

	// Timeouts: attempt 1 is re-offered as attempt 2, attempt 2 ends the run.
	task, err = s.ClaimForkEvalTask(ctx, alice, now, lease)
	if err != nil || task.Attempt != 1 {
		t.Fatalf("claim = %+v, %v", task, err)
	}
	later := now.Add(lease + time.Second)
	task, err = s.ClaimForkEvalTask(ctx, alice, later, lease)
	if err != nil || task.Attempt != 2 {
		t.Fatalf("retry claim = %+v, %v", task, err)
	}
	if _, err := s.ClaimForkEvalTask(ctx, alice, later.Add(lease+time.Second), lease); !errors.Is(err, ErrForkEvalNoTask) {
		t.Fatalf("claim after second timeout: %v", err)
	}
	if e.state(task.RunID) != ForkEvalIncomplete {
		t.Fatalf("run state = %s", e.state(task.RunID))
	}

	// Infrastructure failure makes the run incomplete.
	dd := e.fork(bob)
	r, err := s.CreateForkEvalRun(ctx, dd, []string{"f1", "f2"}, now)
	if err != nil {
		t.Fatal(err)
	}
	task, err = s.ClaimForkEvalTask(ctx, bob, now, lease)
	if err != nil {
		t.Fatal(err)
	}
	st, err = s.FinishForkEvalTask(ctx, r, task.FixtureID, task.Attempt, true, nil, nil, now)
	if err != nil || st != ForkEvalIncomplete || e.state(r) != ForkEvalIncomplete {
		t.Fatalf("infra failure = %s, %v", st, err)
	}
	if _, err := s.ClaimForkEvalTask(ctx, 0, now, lease); !errors.Is(err, ErrForkEvalNoTask) {
		t.Fatalf("task of an incomplete run offered: %v", err)
	}

	// Expiry and fork deletion cancel open runs; finished runs stay.
	ee := e.fork(bob)
	re, err := s.CreateForkEvalRun(ctx, ee, []string{"f1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireForkEvalRuns(ctx, now.Add(ForkEvalRunTTL-time.Minute)); err != nil || n != 0 {
		t.Fatalf("early expire = %d, %v", n, err)
	}
	if _, err := s.DeleteAssistantFork(ctx, bob, "nope", ""); !errors.Is(err, ErrAssistantForkNotFound) || e.state(re) != ForkEvalQueued {
		t.Fatalf("refused delete changed a run: %v %s", err, e.state(re))
	}
	if _, err := s.DeleteAssistantFork(ctx, bob, e.names[ee.ForkDigest], "0.1.0"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if e.state(re) != ForkEvalCancelled {
		t.Fatalf("run state after fork delete = %s", e.state(re))
	}
	var fin sql.NullTime
	if err := s.DB.QueryRowContext(ctx, `SELECT finished_at FROM assistant_fork_eval_runs WHERE id = $1`, re).Scan(&fin); err != nil || !fin.Valid {
		t.Fatalf("finished_at = %v, %v", fin, err)
	}
	if e.state(r) != ForkEvalIncomplete {
		t.Fatal("a finished run changed")
	}
	ex := e.fork(alice)
	rx, err := s.CreateForkEvalRun(ctx, ex, []string{"f1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireForkEvalRuns(ctx, now.Add(ForkEvalRunTTL)); err != nil || n < 1 || e.state(rx) != ForkEvalExpired {
		t.Fatalf("expire = %d, %v, state %s", n, err, e.state(rx))
	}
	if _, err := s.ClaimForkEvalTask(ctx, 0, now.Add(ForkEvalRunTTL), lease); !errors.Is(err, ErrForkEvalNoTask) {
		t.Fatalf("task of an expired run offered: %v", err)
	}
}

func TestForkEvals_Global(t *testing.T) {
	s := newTestStoreCrypted(t)
	e := &evalEnv{t: t, s: s, ctx: context.Background(), sfx: "g"}
	now := time.Now().UTC()
	b := e.fork(e.user("Alice"))
	carol := e.user("Carol")
	for i := 0; i < forkEvalGlobal24h; i++ {
		if _, err := s.DB.ExecContext(e.ctx,
			`INSERT INTO assistant_fork_eval_runs(user_id, fork_digest, base_digest, suite_digest, harness_version, state, created_at)
			 VALUES ($1,$2,'b','s','h','expired',$3)`, carol, fmt.Sprintf("d%d", i), now.Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.CreateForkEvalRun(e.ctx, b, []string{"f1"}, now)
	e.refused(err, ErrForkEvalGlobalLimit, forkEvalGlobal24h, 0)
}

func TestForkEvals_Concurrent(t *testing.T) {
	s := newTestStoreCrypted(t)
	e := &evalEnv{t: t, s: s, ctx: context.Background(), sfx: "c"}
	now := time.Now().UTC()
	uid := e.user("Dana")
	b := e.fork(uid)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = s.CreateForkEvalRun(e.ctx, b, []string{"f1"}, now)
		}()
	}
	wg.Wait()
	ok, open := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrForkEvalRunOpen):
			open++
		}
	}
	if ok != 1 || open != 1 {
		t.Fatalf("concurrent creates: %v", errs)
	}
	var cw sync.WaitGroup
	claims := make([]error, 2)
	for i := range claims {
		cw.Add(1)
		go func() {
			defer cw.Done()
			_, claims[i] = s.ClaimForkEvalTask(e.ctx, uid, now, time.Minute)
		}()
	}
	cw.Wait()
	ok, none := 0, 0
	for _, err := range claims {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrForkEvalNoTask):
			none++
		}
	}
	if ok != 1 || none != 1 {
		t.Fatalf("concurrent claims: %v", claims)
	}
}
