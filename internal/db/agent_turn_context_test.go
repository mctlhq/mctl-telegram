package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Turn context for edits (#962). The #950 scenario: Alice sends 230 and 231,
// they are coalesced into one turn, and she edits 231 before the turn's reply
// is sent. The edit job must see 230 as well as the corrected 231.

const editSuffix = ":e100:aa"

// coalescedTurn ingests 230 and 231, claims 230 as the head with 231
// coalesced into it, and gives the head a draft that is not sent.
func coalescedTurn(t *testing.T, f *supersessionFixture) (head AgentJob, draft AgentAction) {
	t.Helper()
	f.ingest(t, 230, "")
	member := f.ingest(t, 231, "")
	head = f.claim(t)
	f.coalesce(t, head.ID, f.jobID(t, member))
	return head, f.action(t, head, PolicyRequireApproval, ActionPendingApproval)
}

// finish closes the head so the conversation's next job can be claimed.
func (f *supersessionFixture) finish(t *testing.T, jobID int64) {
	t.Helper()
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET status = $1 WHERE id = $2`, JobCompleted, jobID); err != nil {
		t.Fatalf("finish job: %v", err)
	}
}

func sourceList(ids []string) string { return strings.Join(ids, ",") }

func turnContextCases(t *testing.T, setup func(t *testing.T) (*Store, int64)) {
	cases := []struct {
		name string
		run  func(t *testing.T, f *supersessionFixture)
	}{
		{"edit job sees the rest of the unsent turn", assertEditSeesTurn},
		{"context message is shown at its latest version", assertContextLatestVersion},
		{"deleted context message is left out", assertContextDeletedSkipped},
		{"turn whose reply was sent adds no context", assertSentTurnNoContext},
		{"single-message turn adds no context", assertSingleMessageNoContext},
		{"context edited after claim withdraws the draft", assertContextEditAfterClaim},
		{"context deleted after claim supersedes the job", assertContextDeleteAfterClaim},
		{"re-claim recomputes the context", assertReclaimRecomputes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, uid := setup(t)
			tc.run(t, newSupersessionFixture(t, s, uid))
		})
	}
}

func TestTurnContext_SQLite(t *testing.T) {
	turnContextCases(t, func(t *testing.T) (*Store, int64) {
		s := newTestStoreCrypted(t)
		return s, seedAgentUser(t, s, "owner")
	})
}

func TestTurnContext_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	turnContextCases(t, func(t *testing.T) (*Store, int64) {
		uid := seedAgentUser(t, s, fmt.Sprintf("tc_%d", time.Now().UnixNano()))
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM agent_actions WHERE user_id = $1`,
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

// claimEdit claims the edit job and checks that GetAgentJob, which
// authorizes get_event for the job token, returns the same list.
func (f *supersessionFixture) claimEdit(t *testing.T, editEvent string) AgentJob {
	t.Helper()
	job := f.claim(t)
	if job.EventID != editEvent {
		t.Fatalf("claimed %s, want the edit job %s", job.EventID, editEvent)
	}
	loaded, err := f.s.GetAgentJob(context.Background(), f.uid, job.ID)
	if err != nil {
		t.Fatalf("GetAgentJob: %v", err)
	}
	if sourceList(loaded.SourceEventIDs) != sourceList(job.SourceEventIDs) {
		t.Fatalf("GetAgentJob sources = %v, claim gave %v", loaded.SourceEventIDs, job.SourceEventIDs)
	}
	return job
}

func assertEditSeesTurn(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	want := sourceList([]string{f.eventID(230, ""), edit})
	if got := sourceList(job.SourceEventIDs); got != want {
		t.Fatalf("edit job sources = %s, want %s", got, want)
	}
	if got := f.superseded(t, job.ID); got != "" {
		t.Fatalf("fresh edit job superseded: %q", got)
	}
}

func assertContextLatestVersion(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	edit230 := f.ingest(t, 230, ":e200:bb")
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	want := sourceList([]string{edit230, edit})
	if got := sourceList(job.SourceEventIDs); got != want {
		t.Fatalf("edit job sources = %s, want %s", got, want)
	}
}

func assertContextDeletedSkipped(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	f.recordDelete(t, 230)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	if got := sourceList(job.SourceEventIDs); got != edit {
		t.Fatalf("edit job sources = %s, want only %s", got, edit)
	}
}

func assertSentTurnNoContext(t *testing.T, f *supersessionFixture) {
	head, draft := coalescedTurn(t, f)
	if _, err := f.s.DB.Exec(`UPDATE agent_actions SET status = $1 WHERE id = $2`, ActionExecuted, draft.ID); err != nil {
		t.Fatal(err)
	}
	edit := f.ingest(t, 231, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	if got := sourceList(job.SourceEventIDs); got != edit {
		t.Fatalf("edit job sources = %s, want only %s", got, edit)
	}
}

func assertSingleMessageNoContext(t *testing.T, f *supersessionFixture) {
	f.ingest(t, 230, "")
	head := f.claim(t)
	edit := f.ingest(t, 230, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	if got := sourceList(job.SourceEventIDs); got != edit {
		t.Fatalf("edit job sources = %s, want only %s", got, edit)
	}
}

func assertContextEditAfterClaim(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	a := f.action(t, job, PolicyAllow, ActionApproved)
	f.ingest(t, 230, ":e200:bb")
	if got := f.superseded(t, job.ID); got != SourceEdited {
		t.Fatalf("edit job after context edit: %q, want %q", got, SourceEdited)
	}
	ok, err := f.reserve(a)
	var se *SourceSupersededError
	if ok || !errors.As(err, &se) || se.Kind != SourceEdited {
		t.Fatalf("reserve: ok=%v err=%v, want SourceSupersededError(edited)", ok, err)
	}
}

func assertContextDeleteAfterClaim(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	f.ingest(t, 230, ":e200:bb")
	f.recordDelete(t, 230)
	if got := f.superseded(t, job.ID); got != SourceDeleted {
		t.Fatalf("edit job after context delete: %q, want %q", got, SourceDeleted)
	}
}

func assertReclaimRecomputes(t *testing.T, f *supersessionFixture) {
	head, _ := coalescedTurn(t, f)
	edit := f.ingest(t, 231, editSuffix)
	f.finish(t, head.ID)
	job := f.claimEdit(t, edit)
	edit230 := f.ingest(t, 230, ":e200:bb")
	// The edit of 230 queued its own job; take it out of the way so the
	// retried edit job is the conversation's next claim.
	f.finish(t, f.jobID(t, edit230))
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET status = $1 WHERE id = $2`, JobPending, job.ID); err != nil {
		t.Fatal(err)
	}
	again := f.claimEdit(t, edit)
	want := sourceList([]string{edit230, edit})
	if got := sourceList(again.SourceEventIDs); got != want {
		t.Fatalf("re-claimed sources = %s, want %s", got, want)
	}
	if got := f.superseded(t, again.ID); got != "" {
		t.Fatalf("re-claimed job superseded: %q", got)
	}
}

// The coalescing claim path stores the context too.
func TestTurnContext_CoalescingClaim(t *testing.T) {
	f := newTurnFixture(t, &turnCfg)
	ctx := context.Background()
	first := f.ingest(t, 555, 230, 5, 0)
	f.ingest(t, 555, 231, 5, time.Second)
	f.now = turnBase.Add(10 * time.Second)
	got := f.claim(t, 1)
	if len(got) != 1 || len(got[0].SourceEventIDs) != 2 {
		t.Fatalf("head claim = %+v", got)
	}
	conv, err := f.s.EnsureConversation(ctx, f.uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatal(err)
	}
	edit := "evt:v1:1:555:231" + editSuffix
	if _, ok, err := f.s.InsertEventEnqueueJobAndTouch(ctx, IncomingEvent{
		EventID: edit, UserID: f.uid, Kind: EventKindMessageEdit,
		ChatTGID: 555, SenderTGID: 555, MessageID: 231, Body: "xxxxx",
	}, conv.ID); err != nil || !ok {
		t.Fatalf("ingest edit: %v %v", ok, err)
	}
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET created_at = $1, next_run_at = $1 WHERE event_id = $2`, turnBase.Add(20*time.Second), edit); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET status = $1 WHERE id = $2`, JobCompleted, got[0].ID); err != nil {
		t.Fatal(err)
	}
	f.now = turnBase.Add(40 * time.Second)
	next := f.claim(t, 1)
	if len(next) != 1 || next[0].EventID != edit {
		t.Fatalf("edit claim = %+v", next)
	}
	if want := first + "," + edit; sourceList(next[0].SourceEventIDs) != want {
		t.Fatalf("edit job sources = %v, want %s", next[0].SourceEventIDs, want)
	}
}
