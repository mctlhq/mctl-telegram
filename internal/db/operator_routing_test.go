package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// reasonBuilder stands in for internal/events and records the routing reason
// in the envelope so tests can read it back.
func reasonBuilder(ev IncomingEvent, _ time.Time, reason string) (OutboxRow, bool, error) {
	return OutboxRow{EventID: ev.EventID, Stream: "mctl:events:telegram",
		Envelope: `{"id":"telegram:` + ev.EventID + `","routing_reason":"` + reason + `"}`}, true, nil
}

type routingFixture struct {
	s      *Store
	uid    int64
	conv   int64
	job    AgentJob
	notify int
}

// newRoutingFixture ingests one event (creating its job) with routing on and
// claims the job.
func newRoutingFixture(t *testing.T, routing bool, maxAttempts int) *routingFixture {
	t.Helper()
	f := &routingFixture{}
	f.s = newTestStoreCrypted(t).WithEventOutbox(reasonBuilder).
		WithEventOutboxNotify(func() { f.notify++ }).WithOperatorRouting(routing)
	f.uid = seedAgentUser(t, f.s, "owner")
	if ok, err := ingestForOutbox(t, f.s, f.uid, "evt:v1:1:555:42", "secret body"); err != nil || !ok {
		t.Fatalf("ingest: ok=%v err=%v", ok, err)
	}
	if maxAttempts > 0 {
		if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET max_attempts = $1`, maxAttempts); err != nil {
			t.Fatal(err)
		}
	}
	jobs, err := f.s.ClaimAgentJobs(context.Background(), "r", f.uid, 1)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("claim: %v %v", jobs, err)
	}
	f.job = jobs[0]
	f.conv = f.job.ConversationID
	f.notify = 0
	return f
}

func (f *routingFixture) reasons(t *testing.T) []string {
	t.Helper()
	rows, err := f.s.PendingOutbox(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		if r.EventID != "evt:v1:1:555:42" {
			t.Fatalf("unexpected event %q", r.EventID)
		}
		if strings.Contains(r.Envelope, "secret") {
			t.Fatalf("envelope carries body: %s", r.Envelope)
		}
		i := strings.Index(r.Envelope, `"routing_reason":"`)
		out = append(out, strings.TrimSuffix(r.Envelope[i+len(`"routing_reason":"`):], `"}`))
	}
	return out
}

func (f *routingFixture) propose(t *testing.T, status string) {
	t.Helper()
	_, err := f.s.InsertAgentAction(context.Background(), AgentAction{
		JobID: f.job.ID, Attempt: f.job.Attempts, ConversationID: f.conv, UserID: f.uid,
		ActionType: ActionTypeReply, Payload: "reply", PolicyDecision: "x", Status: status,
		ApprovalCode: map[bool]string{true: "ABCD2345"}[status == ActionPendingApproval],
	})
	if err != nil {
		t.Fatalf("insert action: %v", err)
	}
}

func wantReasons(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("reasons = %v, want %v", got, want)
	}
}

func TestOperatorRouting_IngestSkipsJobBackedEvent(t *testing.T) {
	f := &routingFixture{}
	f.s = newTestStoreCrypted(t).WithEventOutbox(reasonBuilder).WithOperatorRouting(true)
	uid := seedAgentUser(t, f.s, "owner")
	if ok, err := ingestForOutbox(t, f.s, uid, "evt:v1:1:555:42", "x"); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if n := outboxCount(t, f.s); n != 0 {
		t.Fatalf("outbox rows = %d, want 0", n)
	}
}

func TestOperatorRouting_PolicyDeny(t *testing.T) { // T4a
	f := newRoutingFixture(t, true, 0)
	f.propose(t, ActionDenied)
	wantReasons(t, f.reasons(t), RoutePolicyDeny)
	if f.notify != 1 {
		t.Fatalf("notify = %d", f.notify)
	}
}

func TestOperatorRouting_RequireApproval(t *testing.T) { // T4b
	f := newRoutingFixture(t, true, 0)
	f.propose(t, ActionPendingApproval)
	wantReasons(t, f.reasons(t), RoutePolicyRequireApproval)
}

func TestOperatorRouting_WorkerFailure(t *testing.T) { // T4c
	t.Run("dead letter via RetryAgentJob", func(t *testing.T) {
		f := newRoutingFixture(t, true, 1)
		if st, err := f.s.RetryAgentJob(context.Background(), f.job.ID, f.job.Attempts, "boom"); err != nil || st != JobDeadLetter {
			t.Fatal(st, err)
		}
		wantReasons(t, f.reasons(t), RouteWorkerFailure)
	})
	t.Run("retry with attempts left routes nothing", func(t *testing.T) {
		f := newRoutingFixture(t, true, 3)
		if _, err := f.s.RetryAgentJob(context.Background(), f.job.ID, f.job.Attempts, "boom"); err != nil {
			t.Fatal(err)
		}
		wantReasons(t, f.reasons(t))
	})
	t.Run("completed failed", func(t *testing.T) {
		f := newRoutingFixture(t, true, 0)
		if err := f.s.CompleteAgentJob(context.Background(), f.job.ID, f.job.Attempts, JobFailed, "x"); err != nil {
			t.Fatal(err)
		}
		wantReasons(t, f.reasons(t), RouteWorkerFailure)
	})
	t.Run("completed failed with result", func(t *testing.T) {
		f := newRoutingFixture(t, true, 0)
		if err := f.s.CompleteAgentJobWithResult(context.Background(), f.uid, f.job.ID, f.job.Attempts, JobFailed, "x", 0, 0); err != nil {
			t.Fatal(err)
		}
		wantReasons(t, f.reasons(t), RouteWorkerFailure)
	})
	t.Run("stale dead letter", func(t *testing.T) {
		f := newRoutingFixture(t, true, 1)
		if _, err := f.s.DB.Exec(`UPDATE agent_jobs SET claimed_at = $1`, time.Now().UTC().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, dead, err := f.s.RequeueStaleAgentJobs(context.Background(), time.Minute); err != nil || dead != 1 {
			t.Fatal(dead, err)
		}
		wantReasons(t, f.reasons(t), RouteWorkerFailure)
	})
}

func TestOperatorRouting_HappyPathPublishesNothing(t *testing.T) { // T4d
	f := newRoutingFixture(t, true, 0)
	f.propose(t, ActionApproved)
	var actionID int64
	if err := f.s.DB.QueryRow(`SELECT id FROM agent_actions WHERE job_id = $1`, f.job.ID).Scan(&actionID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.CompleteAgentJobWithResult(context.Background(), f.uid, f.job.ID, f.job.Attempts, JobCompleted, "", actionID, 0); err != nil {
		t.Fatal(err)
	}
	wantReasons(t, f.reasons(t))
}

func TestOperatorRouting_IgnoredPublishesNothing(t *testing.T) {
	g := newRoutingFixture(t, true, 0)
	if err := g.s.CompleteAgentJob(context.Background(), g.job.ID, g.job.Attempts, JobIgnored, ""); err != nil {
		t.Fatal(err)
	}
	wantReasons(t, g.reasons(t))
}

func TestOperatorRouting_FirstReasonWins(t *testing.T) {
	f := newRoutingFixture(t, true, 0)
	f.propose(t, ActionPendingApproval)
	if err := f.s.CompleteAgentJob(context.Background(), f.job.ID, f.job.Attempts, JobFailed, "x"); err != nil {
		t.Fatal(err)
	}
	wantReasons(t, f.reasons(t), RoutePolicyRequireApproval)
}

func TestOperatorRouting_OffPublishesAtIngestOnly(t *testing.T) { // T4e (store side)
	f := newRoutingFixture(t, false, 0)
	wantReasons(t, f.reasons(t), "") // written at ingest, no reason
	f.propose(t, ActionDenied)
	if err := f.s.CompleteAgentJob(context.Background(), f.job.ID, f.job.Attempts, JobFailed, "x"); err != nil {
		t.Fatal(err)
	}
	wantReasons(t, f.reasons(t), "")
}

// TestOperatorRouting_InactiveConversationPublishesNothing pins the #601
// decision: with routing on, a message in a conversation the owner is
// handling is not forwarded to the operator. The job is closed at ingest as
// ignored, the same outcome as a worker run that ends ignored. With routing
// off, ingest still publishes it like any other event.
func TestOperatorRouting_InactiveConversationPublishesNothing(t *testing.T) {
	for _, routing := range []bool{true, false} {
		t.Run(fmt.Sprintf("routing=%v", routing), func(t *testing.T) {
			ctx := context.Background()
			s := newTestStoreCrypted(t).WithEventOutbox(reasonBuilder).WithOperatorRouting(routing)
			uid := seedAgentUser(t, s, "owner")
			conv, err := s.EnsureConversation(ctx, uid, 555, "peer", "Peer")
			if err != nil {
				t.Fatal(err)
			}
			if err := s.SetConversationState(ctx, uid, conv.ID, ConversationTakenOver); err != nil {
				t.Fatal(err)
			}
			if ok, err := ingestForOutbox(t, s, uid, "evt:v1:1:555:42", "x"); err != nil || !ok {
				t.Fatal(ok, err)
			}
			want := map[bool]int{true: 0, false: 1}[routing]
			if n := outboxCount(t, s); n != want {
				t.Fatalf("outbox rows = %d, want %d", n, want)
			}
			if jobs, err := s.ClaimAgentJobs(ctx, "r", uid, 1); err != nil || len(jobs) != 0 {
				t.Fatalf("claimed %d jobs, err=%v", len(jobs), err)
			}
		})
	}
}
