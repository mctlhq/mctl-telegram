package db

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Admission simulator: drives the real Store.ClaimAgentJobs /
// CompleteAgentJob under a global and a per-user concurrency cap that only
// the simulator applies. It proves the existing per-conversation NOT EXISTS
// clause keeps one turn per session while the caps hold, and that no session
// starves. Test code only; production claim behaviour is untouched.

type simSession struct {
	convID   int64
	userIdx  int
	firstRnd int // round of first claim, 0 = never
	done     int
}

type simResult struct {
	rounds    int
	sessions  []*simSession
	completed int
}

func runAdmissionSim(t *testing.T, users []string, sessionsPerUser []int, jobsPerSession, capGlobal, capUser int) simResult {
	t.Helper()
	ctx := context.Background()
	s := newTestStoreCrypted(t)

	uids := make([]int64, len(users))
	for i, u := range users {
		uids[i] = seedAgentUser(t, s, u)
	}
	var sessions []*simSession
	convByID := map[int64]*simSession{}
	peer := int64(910000)
	evSeq := 0
	// Interleave job creation across sessions so arrival order is mixed.
	for i, n := range sessionsPerUser {
		for k := 0; k < n; k++ {
			peer++
			c, err := s.EnsureConversation(ctx, uids[i], peer, fmt.Sprintf("sim_%d", peer), "Sim")
			if err != nil {
				t.Fatalf("ensure conversation: %v", err)
			}
			ss := &simSession{convID: c.ID, userIdx: i}
			sessions = append(sessions, ss)
			convByID[c.ID] = ss
		}
	}
	for j := 0; j < jobsPerSession; j++ {
		for _, ss := range sessions {
			evSeq++
			evID := fmt.Sprintf("evt:v1:sim:%d:%d", ss.convID, evSeq)
			if _, _, err := s.InsertIncomingEvent(ctx, IncomingEvent{
				EventID: evID, UserID: uids[ss.userIdx], Kind: EventKindPrivateMessage,
				ChatTGID: 1, SenderTGID: 1, MessageID: int64(evSeq),
			}); err != nil {
				t.Fatalf("insert event: %v", err)
			}
			if _, ok, err := s.EnqueueAgentJob(ctx, evID, uids[ss.userIdx], ss.convID); err != nil || !ok {
				t.Fatalf("enqueue: ok=%v err=%v", ok, err)
			}
		}
	}
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET next_run_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	total := len(sessions) * jobsPerSession

	checkInvariants := func(round int) int {
		var global int
		if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_jobs WHERE status='processing'`).Scan(&global); err != nil {
			t.Fatal(err)
		}
		if global > capGlobal {
			t.Fatalf("round %d: %d processing > global cap %d", round, global, capGlobal)
		}
		rows, err := s.DB.QueryContext(ctx, `SELECT conversation_id, COUNT(*) FROM agent_jobs WHERE status='processing' GROUP BY conversation_id`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var cid, n int64
			if err := rows.Scan(&cid, &n); err != nil {
				t.Fatal(err)
			}
			if n > 1 {
				t.Fatalf("round %d: conversation %d has %d processing jobs", round, cid, n)
			}
		}
		_ = rows.Close()
		rows, err = s.DB.QueryContext(ctx, `SELECT user_id, COUNT(*) FROM agent_jobs WHERE status='processing' GROUP BY user_id`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var uid, n int64
			if err := rows.Scan(&uid, &n); err != nil {
				t.Fatal(err)
			}
			if n > int64(capUser) {
				t.Fatalf("round %d: user %d has %d processing > cap %d", round, uid, n, capUser)
			}
		}
		_ = rows.Close()
		return global
	}

	var running []AgentJob
	res := simResult{sessions: sessions}
	cursor := 0
	// Hard stop well above the asserted bound so a starvation bug fails the
	// bound assertion below instead of hanging.
	for round := 1; round <= 200 && res.completed < total; round++ {
		// Finish everything that has been running since the previous round.
		for _, j := range running {
			if err := s.CompleteAgentJob(ctx, j.ID, j.Attempts, JobCompleted, ""); err != nil {
				t.Fatalf("complete %d: %v", j.ID, err)
			}
			convByID[j.ConversationID].done++
			res.completed++
		}
		running = nil
		globalFree := capGlobal
		perUser := map[int]int{}
		for k := 0; k < len(uids); k++ {
			i := (cursor + k) % len(uids)
			free := capUser - perUser[i]
			if free > globalFree {
				free = globalFree
			}
			if free <= 0 {
				continue
			}
			jobs, err := s.ClaimAgentJobs(ctx, "sim", uids[i], free)
			if err != nil {
				t.Fatalf("claim: %v", err)
			}
			for _, j := range jobs {
				running = append(running, j)
				perUser[i]++
				globalFree--
				if ss := convByID[j.ConversationID]; ss.firstRnd == 0 {
					ss.firstRnd = round
				}
			}
			checkInvariants(round)
		}
		cursor = (cursor + 1) % len(uids)
		res.rounds = round
	}
	return res
}

func TestAdmissionSim_TenSessionsFourUsers(t *testing.T) {
	const jobsPerSession, capGlobal, capUser = 3, 5, 2
	users := []string{"alice", "bob", "carol", "dana"}
	res := runAdmissionSim(t, users, []int{3, 3, 2, 2}, jobsPerSession, capGlobal, capUser)

	total := 10 * jobsPerSession
	if res.completed != total {
		t.Fatalf("completed %d of %d jobs in %d rounds", res.completed, total, res.rounds)
	}
	rMax := (total+capGlobal-1)/capGlobal + jobsPerSession + len(users)
	if res.rounds > rMax {
		t.Fatalf("took %d rounds, bound R_max=%d", res.rounds, rMax)
	}
	for _, ss := range res.sessions {
		if ss.firstRnd == 0 || ss.firstRnd > len(users)+1 {
			t.Fatalf("session %d first claimed in round %d, want within %d", ss.convID, ss.firstRnd, len(users)+1)
		}
		if ss.done != jobsPerSession {
			t.Fatalf("session %d completed %d jobs", ss.convID, ss.done)
		}
	}
}

func TestAdmissionSim_OneUserTenSessions(t *testing.T) {
	const jobsPerSession, capGlobal = 3, 5
	// The per-user cap equals the global cap, so only global and per-session
	// limits constrain this user.
	res := runAdmissionSim(t, []string{"alice"}, []int{10}, jobsPerSession, capGlobal, capGlobal)

	total := 10 * jobsPerSession
	if res.completed != total {
		t.Fatalf("completed %d of %d jobs in %d rounds", res.completed, total, res.rounds)
	}
	rMax := (total+capGlobal-1)/capGlobal + jobsPerSession + 1
	if res.rounds > rMax {
		t.Fatalf("took %d rounds, bound R_max=%d", res.rounds, rMax)
	}
	for _, ss := range res.sessions {
		if ss.firstRnd == 0 || ss.done != jobsPerSession {
			t.Fatalf("session %d: first=%d done=%d", ss.convID, ss.firstRnd, ss.done)
		}
	}
}
