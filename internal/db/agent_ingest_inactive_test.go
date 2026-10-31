package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// inactiveConversationCases covers #601: a message in a conversation the
// owner has taken over (or closed, or paused) is recorded but never reaches
// the model.
func inactiveConversationCases(t *testing.T, setup func(t *testing.T) (*Store, int64)) {
	for _, state := range []string{ConversationTakenOver, ConversationClosed, ConversationPaused} {
		t.Run(state, func(t *testing.T) {
			s, uid := setup(t)
			f := newSupersessionFixture(t, s, uid)
			ctx := context.Background()
			if err := s.SetConversationState(ctx, uid, f.convID, state); err != nil {
				t.Fatalf("set state: %v", err)
			}
			id := f.ingest(t, 20, "")
			if _, err := s.GetIncomingEvent(ctx, uid, id); err != nil {
				t.Fatalf("event not recorded: %v", err)
			}
			var status, reason string
			if err := s.DB.QueryRow(`SELECT status, COALESCE(last_error, '') FROM agent_jobs WHERE event_id = $1`, id).
				Scan(&status, &reason); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if status != JobIgnored || reason != ReasonConversationNotActive {
				t.Fatalf("job = %q / %q, want %q / %q", status, reason, JobIgnored, ReasonConversationNotActive)
			}
			jobs, err := s.ClaimAgentJobs(ctx, "r", uid, 5)
			if err != nil || len(jobs) != 0 {
				t.Fatalf("claimed %d jobs in a %s conversation, err=%v", len(jobs), state, err)
			}

			// /mctl continue: the next message is handled again.
			if err := s.SetConversationState(ctx, uid, f.convID, ConversationActive); err != nil {
				t.Fatalf("reactivate: %v", err)
			}
			f.ingest(t, 21, "")
			if job := f.claim(t); job.EventID != f.eventID(21, "") {
				t.Fatalf("claimed %s, want the message sent after continue", job.EventID)
			}
		})
	}
	t.Run("active", func(t *testing.T) {
		s, uid := setup(t)
		f := newSupersessionFixture(t, s, uid)
		id := f.ingest(t, 30, "")
		if job := f.claim(t); job.EventID != id {
			t.Fatalf("claimed %s, want %s", job.EventID, id)
		}
	})
}

func TestIngestInactiveConversation_SQLite(t *testing.T) {
	inactiveConversationCases(t, func(t *testing.T) (*Store, int64) {
		s := newTestStoreCrypted(t)
		return s, seedAgentUser(t, s, "owner")
	})
}

func TestIngestInactiveConversation_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	inactiveConversationCases(t, func(t *testing.T) (*Store, int64) {
		uid := seedAgentUser(t, s, fmt.Sprintf("inact_%d", time.Now().UnixNano()))
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM agent_job_attempts WHERE job_id IN (SELECT id FROM agent_jobs WHERE user_id = $1)`,
				`DELETE FROM agent_jobs WHERE user_id = $1`,
				`DELETE FROM incoming_events WHERE user_id = $1`,
				`DELETE FROM conversations WHERE user_id = $1`,
				`DELETE FROM users WHERE id = $1`,
			} {
				_, _ = s.DB.Exec(q, uid)
			}
		})
		return s, uid
	})
}
