package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// executeAction drives a fresh pending action through approve -> executing
// and, when send is true, records it executed.
func executeAction(t *testing.T, s *Store, uid, convID int64, decision string, send bool) int64 {
	t.Helper()
	ctx := context.Background()
	status := ActionPendingApproval
	if decision == PolicyAllow {
		status = ActionApproved
	}
	id, err := s.InsertAgentAction(ctx, AgentAction{
		ConversationID: convID, UserID: uid, ActionType: ActionTypeReply,
		Payload: "Thanks!", PolicyDecision: decision, Status: status,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if status == ActionPendingApproval {
		if ok, err := s.UpdateAgentActionStatus(ctx, uid, id, ActionPendingApproval, ActionApproved); err != nil || !ok {
			t.Fatalf("approve: ok=%v err=%v", ok, err)
		}
	}
	if ok, err := s.BeginExecutingAgentAction(ctx, uid, id, id+1000); err != nil || !ok {
		t.Fatalf("begin executing: ok=%v err=%v", ok, err)
	}
	if send {
		if ok, err := s.RecordAgentActionSent(ctx, uid, id, convID, id+2000, "Thanks!"); err != nil || !ok {
			t.Fatalf("record sent: ok=%v err=%v", ok, err)
		}
	}
	return id
}

func engagedAt(t *testing.T, s *Store, uid, convID int64) time.Time {
	t.Helper()
	conv, err := s.GetConversation(context.Background(), uid, convID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	return conv.OwnerEngagedAt
}

// TestOwnerEngagement_OnlyExecutedApprovedReplyEngages covers #953's
// engagement events from the action side: an approved action that reached
// Telegram engages the conversation; an approved one whose send never
// completed does not, and neither does an auto-approved (policy allow) send.
func TestOwnerEngagement_OnlyExecutedApprovedReplyEngages(t *testing.T) {
	s := newTestStoreCrypted(t)
	assertOnlyExecutedApprovedReplyEngages(t, s, seedAgentUser(t, s, "owner"))
}

func assertOnlyExecutedApprovedReplyEngages(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	if !conv.OwnerEngagedAt.IsZero() || conv.OwnerEngaged(time.Now()) {
		t.Fatalf("new conversation engaged: %v", conv.OwnerEngagedAt)
	}

	executeAction(t, s, uid, conv.ID, PolicyRequireApproval, false)
	if got := engagedAt(t, s, uid, conv.ID); !got.IsZero() {
		t.Fatalf("approved but unsent action engaged the conversation at %v", got)
	}
	executeAction(t, s, uid, conv.ID, PolicyAllow, true)
	if got := engagedAt(t, s, uid, conv.ID); !got.IsZero() {
		t.Fatalf("auto-approved send engaged the conversation at %v", got)
	}
	before := time.Now().Add(-time.Second)
	executeAction(t, s, uid, conv.ID, PolicyRequireApproval, true)
	got := engagedAt(t, s, uid, conv.ID)
	if got.Before(before) {
		t.Fatalf("owner_engaged_at = %v after an executed approved reply, want >= %v", got, before)
	}
	conv, _ = s.GetConversation(ctx, uid, conv.ID)
	if !conv.OwnerEngaged(time.Now()) {
		t.Fatal("conversation not engaged after an executed approved reply")
	}
}

func TestMarkConversationOwnerEngaged(t *testing.T) {
	s := newTestStoreCrypted(t)
	assertMarkConversationOwnerEngaged(t, s, seedAgentUser(t, s, "owner"))
}

// TestOwnerEngagement_Postgres runs the same engagement checks against
// Postgres: owner_engaged_at is hand-written SQL in two schema lists, and a
// dialect break (a timestamp the driver scans differently, a comparison the
// planner types wrongly) must fail here, not on the first approved reply.
func TestOwnerEngagement_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	// Postgres keeps state between runs, so each run gets fresh owners.
	freshOwner := func(name string) int64 {
		uid := seedAgentUser(t, s, fmt.Sprintf("eng_%s_%d", name, time.Now().UnixNano()))
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM agent_actions WHERE user_id = $1`,
				`DELETE FROM conversations WHERE user_id = $1`,
				`DELETE FROM users WHERE id = $1`,
			} {
				_, _ = s.DB.Exec(q, uid)
			}
		})
		return uid
	}
	t.Run("actions", func(t *testing.T) { assertOnlyExecutedApprovedReplyEngages(t, s, freshOwner("actions")) })
	t.Run("mark", func(t *testing.T) { assertMarkConversationOwnerEngaged(t, s, freshOwner("mark")) })
	t.Run("summary", func(t *testing.T) { assertHasExecutedOwnerSummarySince(t, s, freshOwner("summary")) })
}

func assertMarkConversationOwnerEngaged(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	// Postgres stores microseconds; truncate so Equal compares like for like.
	t1 := time.Now().Add(-10 * 24 * time.Hour).UTC().Truncate(time.Microsecond)
	if err := s.MarkConversationOwnerEngaged(ctx, uid, 555, t1); err != nil {
		t.Fatalf("mark: %v", err)
	}
	if got := engagedAt(t, s, uid, conv.ID); !got.Equal(t1) {
		t.Fatalf("owner_engaged_at = %v, want %v", got, t1)
	}
	// An older replayed event never moves the stamp backwards.
	if err := s.MarkConversationOwnerEngaged(ctx, uid, 555, t1.Add(-time.Hour)); err != nil {
		t.Fatalf("mark older: %v", err)
	}
	if got := engagedAt(t, s, uid, conv.ID); !got.Equal(t1) {
		t.Fatalf("older event moved owner_engaged_at to %v", got)
	}
	// Each new event extends the window.
	t2 := t1.Add(5 * 24 * time.Hour)
	if err := s.MarkConversationOwnerEngaged(ctx, uid, 555, t2); err != nil {
		t.Fatalf("mark newer: %v", err)
	}
	if got := engagedAt(t, s, uid, conv.ID); !got.Equal(t2) {
		t.Fatalf("owner_engaged_at = %v, want %v", got, t2)
	}
	// A peer with no conversation gets no row.
	if err := s.MarkConversationOwnerEngaged(ctx, uid, 777, t2); err != nil {
		t.Fatalf("mark unknown peer: %v", err)
	}
	if _, err := s.GetConversationByPeer(ctx, uid, 777); err != ErrConversationNotFound {
		t.Fatalf("unknown peer lookup err = %v, want ErrConversationNotFound", err)
	}
	// Visible through ListConversations too.
	list, err := s.ListConversations(ctx, uid, 10)
	if err != nil || len(list) != 1 || !list[0].OwnerEngagedAt.Equal(t2) {
		t.Fatalf("ListConversations = %+v err=%v", list, err)
	}
}

func TestConversationOwnerEngaged_Window(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"never", time.Time{}, false},
		{"29 days ago", now.Add(-29 * 24 * time.Hour), true},
		{"exactly 30 days ago", now.Add(-OwnerEngagementWindow), true},
		{"30 days and a minute ago", now.Add(-OwnerEngagementWindow - time.Minute), false},
		{"31 days ago", now.Add(-31 * 24 * time.Hour), false},
	} {
		if got := (Conversation{OwnerEngagedAt: tc.at}).OwnerEngaged(now); got != tc.want {
			t.Errorf("%s: OwnerEngaged = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestHasExecutedOwnerSummarySince(t *testing.T) {
	s := newTestStoreCrypted(t)
	assertHasExecutedOwnerSummarySince(t, s, seedAgentUser(t, s, "owner"))
}

func assertHasExecutedOwnerSummarySince(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	since := time.Now().Add(-time.Hour)
	has := func(convID int64, intent string) bool {
		t.Helper()
		ok, err := s.HasExecutedOwnerSummarySince(ctx, uid, convID, intent, since)
		if err != nil {
			t.Fatalf("has: %v", err)
		}
		return ok
	}
	if has(conv.ID, "assistant_manipulation") {
		t.Fatal("empty table reported a summary")
	}
	for _, a := range []AgentAction{
		{ConversationID: conv.ID, Intent: "scam_warning", Status: ActionExecuted},
		{ConversationID: conv.ID, Intent: "assistant_manipulation", Status: ActionDenied},
		{Intent: "assistant_manipulation", Status: ActionExecuted},
	} {
		a.UserID, a.ActionType, a.Payload, a.PolicyDecision = uid, ActionTypeOwnerSummary, "x", PolicyAllow
		if _, err := s.InsertAgentAction(ctx, a); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if has(conv.ID, "assistant_manipulation") {
		t.Fatal("another intent, a denied row or a conversation-less row counted for the conversation")
	}
	if !has(0, "assistant_manipulation") {
		t.Fatal("conversation-less executed alert not found")
	}
	if _, err := s.InsertAgentAction(ctx, AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: ActionTypeOwnerSummary, Intent: "assistant_manipulation",
		Payload: "x", PolicyDecision: PolicyAllow, Status: ActionExecuted,
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if !has(conv.ID, "assistant_manipulation") {
		t.Fatal("executed alert for the conversation not found")
	}
	if ok, err := s.HasExecutedOwnerSummarySince(ctx, uid, conv.ID, "assistant_manipulation", time.Now().Add(time.Hour)); err != nil || ok {
		t.Fatalf("alert older than since counted: ok=%v err=%v", ok, err)
	}
}
