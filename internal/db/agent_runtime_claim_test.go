package db

import (
	"context"
	"testing"
	"time"
)

func setRuntime(t *testing.T, s *Store, uid int64, runtime string) {
	t.Helper()
	ctx := context.Background()
	if err := s.UpsertAgentProfile(ctx, AgentProfile{UserID: uid, Mode: AgentModeObserve}); err != nil {
		t.Fatalf("profile: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_profiles SET runtime = $1, managed_consent_version = $2 WHERE user_id = $3`,
		runtime, ManagedConsentCurrent, uid); err != nil {
		t.Fatalf("set runtime: %v", err)
	}
}

func TestClaimAgentJobs_RuntimePredicate(t *testing.T) {
	ctx := context.Background()

	t.Run("plain", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		own := seedAgentUser(t, s, "own")
		managed := seedAgentUser(t, s, "managed")
		bare := seedAgentUser(t, s, "bare") // no profile row: counts as own
		setRuntime(t, s, own, RuntimeOwn)
		setRuntime(t, s, managed, RuntimeManaged)
		seedJob(t, s, own, "evt:v1:1:1:1")
		seedJob(t, s, managed, "evt:v1:1:2:1")
		seedJob(t, s, bare, "evt:v1:1:3:1")

		for uid, want := range map[int64]string{own: RuntimeOwn, bare: RuntimeOwn, managed: RuntimeManaged} {
			wrong := RuntimeManaged
			if want == RuntimeManaged {
				wrong = RuntimeOwn
			}
			if jobs, err := s.ClaimAgentJobs(ctx, "r", uid, wrong, 5); err != nil || len(jobs) != 0 {
				t.Fatalf("user %d claimed under %s: %d jobs, err %v", uid, wrong, len(jobs), err)
			}
			jobs, err := s.ClaimAgentJobs(ctx, "r", uid, want, 5)
			if err != nil || len(jobs) != 1 || jobs[0].Runtime != want {
				t.Fatalf("user %d under %s: %+v err %v", uid, want, jobs, err)
			}
		}
		if _, err := s.ClaimAgentJobs(ctx, "r", own, "bogus", 1); err == nil {
			t.Fatal("an unknown runtime must be refused")
		}
	})

	t.Run("coalesced", func(t *testing.T) {
		f := newTurnFixture(t, &turnCfg)
		setRuntime(t, f.s, f.uid, RuntimeManaged)
		f.ingest(t, 555, 1, 5, 0)
		f.now = turnBase.Add(time.Minute)
		if jobs, err := f.s.ClaimAgentJobs(ctx, "r", f.uid, RuntimeOwn, 5); err != nil || len(jobs) != 0 {
			t.Fatalf("own claimed a managed account's turn: %d jobs, err %v", len(jobs), err)
		}
		jobs, err := f.s.ClaimAgentJobs(ctx, "r", f.uid, RuntimeManaged, 5)
		if err != nil || len(jobs) != 1 || jobs[0].Runtime != RuntimeManaged {
			t.Fatalf("managed claim: %+v err %v", jobs, err)
		}
	})

	t.Run("coalesced profile-less is own", func(t *testing.T) {
		f := newTurnFixture(t, &turnCfg) // no agent_profiles row
		f.ingest(t, 555, 1, 5, 0)
		f.now = turnBase.Add(time.Minute)
		if jobs, err := f.s.ClaimAgentJobs(ctx, "r", f.uid, RuntimeManaged, 5); err != nil || len(jobs) != 0 {
			t.Fatalf("managed claimed a profile-less turn: %d jobs, err %v", len(jobs), err)
		}
		jobs, err := f.s.ClaimAgentJobs(ctx, "r", f.uid, RuntimeOwn, 5)
		if err != nil || len(jobs) != 1 || jobs[0].Runtime != RuntimeOwn {
			t.Fatalf("own claim of a profile-less turn: %+v err %v", jobs, err)
		}
	})
}

func TestListManagedClaimCandidates(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	mk := func(name string, tg int64, runtime string) int64 {
		uid := seedAgentUser(t, s, name)
		if tg != 0 {
			if _, err := s.DB.ExecContext(ctx, `UPDATE users SET telegram_login_id = $1 WHERE id = $2`, tg, uid); err != nil {
				t.Fatal(err)
			}
		}
		setRuntime(t, s, uid, runtime)
		return uid
	}
	a := mk("a", 9801, RuntimeManaged)
	b := mk("b", 9802, RuntimeManaged)
	noTG := mk("notg", 0, RuntimeManaged)
	own := mk("own", 9803, RuntimeOwn)
	for i, uid := range []int64{a, b, noTG, own} {
		seedJob(t, s, uid, "evt:v1:9:"+itoa(int64(i))+":1")
	}
	cands, err := s.ListManagedClaimCandidates(ctx, time.Now(), 1, 0, 10)
	if err != nil || len(cands) != 2 || cands[0].UserID != a || cands[1].UserID != b {
		t.Fatalf("candidates = %+v err %v; want a then b", cands, err)
	}
	// Account a at the in-flight cap drops out.
	if jobs, err := s.ClaimAgentJobs(ctx, "r", a, RuntimeManaged, 1); err != nil || len(jobs) != 1 {
		t.Fatalf("claim a: %v", err)
	}
	seedJob(t, s, a, "evt:v1:9:9:2")
	cands, _ = s.ListManagedClaimCandidates(ctx, time.Now(), 1, 0, 10)
	if len(cands) != 1 || cands[0].UserID != b {
		t.Fatalf("candidates after cap = %+v", cands)
	}
	// Stale consent drops out.
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_profiles SET managed_consent_version = 'old' WHERE user_id = $1`, b); err != nil {
		t.Fatal(err)
	}
	if cands, _ = s.ListManagedClaimCandidates(ctx, time.Now(), 1, 0, 10); len(cands) != 0 {
		t.Fatalf("stale consent must not be a candidate: %+v", cands)
	}
}
