package control

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// fakeApprover records Approve/Reject calls and returns a canned error.
type fakeApprover struct {
	approveCalls, rejectCalls []string
	approveErr, rejectErr     error
}

func (f *fakeApprover) Approve(_ context.Context, _ int64, code string) error {
	f.approveCalls = append(f.approveCalls, code)
	return f.approveErr
}

func (f *fakeApprover) Reject(_ context.Context, _ int64, code string) error {
	f.rejectCalls = append(f.rejectCalls, code)
	return f.rejectErr
}

// fakeSelfSender records every Saved Messages reply instead of touching a
// real MTProto client. err, when set, makes every SendToSelf call fail
// instead — notifier_test.go's delivery-failure tests use this.
type fakeSelfSender struct {
	sent      []string
	randomIDs []int64
	err       error
}

func (f *fakeSelfSender) SendToSelf(_ context.Context, _ int64, text string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.sent = append(f.sent, text)
	return int64(len(f.sent)), nil
}

func (f *fakeSelfSender) SendToSelfWithRandomID(_ context.Context, _, randomID int64, text string) (int64, error) {
	if f.err != nil {
		return 0, f.err
	}
	f.sent = append(f.sent, text)
	f.randomIDs = append(f.randomIDs, randomID)
	return int64(len(f.sent)), nil
}

func testKey() []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func newTestRouter(t *testing.T) (*Router, *fakeApprover, *fakeSelfSender, *db.Store, int64) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(testKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeObserve, DisclosureText: "AI assistant.",
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	approver := &fakeApprover{}
	sender := &fakeSelfSender{}
	notifier := NewNotifier(store, sender)
	router := NewRouter(store, approver, notifier)
	return router, approver, sender, store, uid
}

func TestRouter_Status_RepliesWithProfileSummary(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl status"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

func TestRouter_UnknownCommand_RepliesWithHelp(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl frobnicate"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

func TestRouter_Approve_DelegatesToExecutorWithCode(t *testing.T) {
	router, approver, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve AB12CD"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.approveCalls) != 1 || approver.approveCalls[0] != "AB12CD" {
		t.Fatalf("approve calls = %v, want [AB12CD]", approver.approveCalls)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
}

// TestRouter_Approve_NormalizesCodeCase guards against a Codex finding on
// #307: approval codes are generated uppercase-only, and GetAgentActionByCode
// matches case-sensitively — a lowercased/autocorrected code typed by the
// owner must still resolve.
func TestRouter_Approve_NormalizesCodeCase(t *testing.T) {
	router, approver, _, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve ab12cd"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.approveCalls) != 1 || approver.approveCalls[0] != "AB12CD" {
		t.Fatalf("approve calls = %v, want [AB12CD]", approver.approveCalls)
	}
}

func TestRouter_Reject_NormalizesCodeCase(t *testing.T) {
	router, approver, _, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl reject  ab12cd  "); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.rejectCalls) != 1 || approver.rejectCalls[0] != "AB12CD" {
		t.Fatalf("reject calls = %v, want [AB12CD]", approver.rejectCalls)
	}
}

func TestRouter_Approve_SurfacesErrorFromExecutor(t *testing.T) {
	router, approver, sender, _, uid := newTestRouter(t)
	approver.approveErr = executor.ErrApprovalCodeNotFound
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve ZZZZZZ"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	if sender.sent[0] == "Approved and sent (ZZZZZZ)." {
		t.Fatalf("router reported success despite executor error: %q", sender.sent[0])
	}
}

// TestRouter_Approve_QueuedRetryIsNotReportedAsFailure guards against a
// Codex finding on #307: a transient send error leaves the action
// `executing` for automatic retry (Executor wraps this in
// ErrSendQueuedForRetry specifically so callers can tell it apart) — the
// owner must be told it's queued, not that approval failed, since the
// message will likely still go out shortly after.
func TestRouter_Approve_QueuedRetryIsNotReportedAsFailure(t *testing.T) {
	router, approver, sender, _, uid := newTestRouter(t)
	approver.approveErr = executor.ErrSendQueuedForRetry
	if err := router.HandleSavedText(context.Background(), uid, "/mctl approve AB12CD"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	reply := sender.sent[0]
	if strings.Contains(reply, "Could not approve") {
		t.Fatalf("reported a queued retry as a failed approval: %q", reply)
	}
	if !strings.Contains(reply, "Approved") || !strings.Contains(reply, "queued") {
		t.Fatalf("reply doesn't reflect the queued-for-retry state: %q", reply)
	}
}

func TestRouter_Reject_DelegatesToExecutorWithCode(t *testing.T) {
	router, approver, _, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl reject XY9988"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(approver.rejectCalls) != 1 || approver.rejectCalls[0] != "XY9988" {
		t.Fatalf("reject calls = %v, want [XY9988]", approver.rejectCalls)
	}
}

func TestRouter_Pause_SetsAutopilotPaused(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl pause"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	profile, err := store.GetAgentProfile(context.Background(), uid)
	if err != nil {
		t.Fatalf("get profile: %v", err)
	}
	if !profile.AutopilotPaused {
		t.Fatal("autopilot_paused = false, want true")
	}
}

func TestRouter_Takeover_SetsStateAndDeniesPending(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	actionID, err := store.InsertAgentAction(ctx, db.AgentAction{
		ConversationID: conv.ID, UserID: uid, ActionType: db.ActionTypeReply,
		Payload: "draft", PolicyDecision: db.PolicyRequireApproval, Status: db.ActionPendingApproval,
		ApprovalCode: "PEND01",
	})
	if err != nil {
		t.Fatalf("seed pending action: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl takeover "+strconv.FormatInt(conv.ID, 10)); err != nil {
		t.Fatalf("handle: %v", err)
	}

	gotConv, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if gotConv.State != db.ConversationTakenOver {
		t.Fatalf("state = %q, want taken_over", gotConv.State)
	}
	action, err := store.GetAgentAction(ctx, uid, actionID)
	if err != nil {
		t.Fatalf("get action: %v", err)
	}
	if action.Status != db.ActionDenied {
		t.Fatalf("pending action status = %q, want denied", action.Status)
	}
}

// TestRouter_Leads_ShowsConversationIDNotLeadID guards against the P2 found
// in review: the leads list must print the conversation id (what /mctl show
// actually takes), not job_leads.id — a different sequence entirely. An
// owner copying the printed number into /mctl show must land on the right
// conversation.
func TestRouter_Leads_ShowsConversationIDNotLeadID(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if _, err := store.UpsertJobLead(ctx, db.JobLead{
		UserID: uid, ConversationID: conv.ID, Company: "Acme", Role: "Engineer",
	}); err != nil {
		t.Fatalf("seed lead: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl leads"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	wantMarker := "Conv #" + strconv.FormatInt(conv.ID, 10)
	if !strings.Contains(sender.sent[0], wantMarker) {
		t.Fatalf("leads reply = %q, want it to contain %q (the conversation id, not the lead's own id)", sender.sent[0], wantMarker)
	}
}

// TestRouter_Leads_IncludesPeerName guards the new /mctl leads line format —
// the owner should see who the conversation is with, not just the
// company/role.
func TestRouter_Leads_IncludesPeerName(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer Name")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if _, err := store.UpsertJobLead(ctx, db.JobLead{
		UserID: uid, ConversationID: conv.ID, Company: "Acme", Role: "Engineer",
	}); err != nil {
		t.Fatalf("seed lead: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl leads"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	if !strings.Contains(sender.sent[0], "Peer Name") {
		t.Fatalf("leads reply = %q, want it to contain the peer display name", sender.sent[0])
	}
}

// TestRouter_Leads_FallsBackToDashOnMissingConversation guards the failure
// path: a lead pointing at a conversation id that can't be looked up (e.g.
// deleted) must not error the whole command — it should render a dash for
// the name instead.
func TestRouter_Leads_FallsBackToDashOnMissingConversation(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	// UpsertJobLead itself requires an existing conversation, so a dangling
	// conversation_id (the ON DELETE SET NULL / lookup-fails case this
	// fallback exists for) is seeded directly, bypassing that validation.
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO job_leads(user_id, conversation_id, company, role, status, detail) VALUES($1,$2,$3,$4,$5,$6)`,
		uid, 999999, "Acme", "Engineer", "new", "{}",
	); err != nil {
		t.Fatalf("seed dangling lead: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl leads"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	if !strings.Contains(sender.sent[0], "Conv #999999 — — — Acme") {
		t.Fatalf("leads reply = %q, want dash fallback for missing conversation name", sender.sent[0])
	}
}

func TestRouter_Conversations_ListsAndHandlesEmpty(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	ctx := context.Background()

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations"); err != nil {
		t.Fatalf("handle empty: %v", err)
	}
	if len(sender.sent) != 1 || sender.sent[0] != "No conversations yet." {
		t.Fatalf("empty reply = %v, want [No conversations yet.]", sender.sent)
	}
}

// TestRouter_Conversations_IncludesTakenOverWithNoLead guards the exact gap
// this command exists to fill: a conversation that was taken over before the
// agent ever produced a job lead has no job_leads row, so /mctl leads cannot
// surface its id — /mctl conversations must.
func TestRouter_Conversations_IncludesTakenOverWithNoLead(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer Name")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	reply := sender.sent[0]
	wantMarker := "Conv #" + strconv.FormatInt(conv.ID, 10) + " — Peer Name (taken_over)"
	if !strings.Contains(reply, wantMarker) {
		t.Fatalf("conversations reply = %q, want it to contain %q", reply, wantMarker)
	}
}

func TestRouter_Conversations_TruncationNoticeAndFilter(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	for i := 1; i <= 21; i++ {
		name := "Peer"
		handle := "other"
		if i == 1 {
			name = "Anna HR"
			handle = "anna_hr"
		}
		if _, err := store.EnsureConversation(ctx, uid, int64(1000+i), handle, name); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations"); err != nil {
		t.Fatalf("handle default: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("default replies = %d, want 1", len(sender.sent))
	}
	if !strings.Contains(sender.sent[0], "Showing the 20 most recently updated") {
		t.Fatalf("default reply = %q, want a truncation notice", sender.sent[0])
	}
	if strings.Count(sender.sent[0], "Conv #") != 20 {
		t.Fatalf("default listed %d conversations, want 20", strings.Count(sender.sent[0], "Conv #"))
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, uid, "/mctl conversations 5"); err != nil {
		t.Fatalf("handle count: %v", err)
	}
	if strings.Count(sender.sent[0], "Conv #") != 5 {
		t.Fatalf("count=5 listed %d conversations, want 5", strings.Count(sender.sent[0], "Conv #"))
	}
	if !strings.Contains(sender.sent[0], "Showing the 5 most recently updated") {
		t.Fatalf("count=5 reply = %q, want a truncation notice", sender.sent[0])
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, uid, "/mctl conversations @Anna_HR"); err != nil {
		t.Fatalf("handle filter: %v", err)
	}
	if !strings.Contains(sender.sent[0], "Anna HR") {
		t.Fatalf("filter reply = %q, want Anna HR", sender.sent[0])
	}
	if strings.Count(sender.sent[0], "Conv #") != 1 {
		t.Fatalf("filter listed %d conversations, want 1", strings.Count(sender.sent[0], "Conv #"))
	}
	if strings.Contains(sender.sent[0], "Showing the") || strings.Contains(sender.sent[0], "Search covered only") {
		t.Fatalf("filter reply = %q, want no truncation notice when the scan is under the cap", sender.sent[0])
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, uid, "/mctl conversations nobody"); err != nil {
		t.Fatalf("handle miss: %v", err)
	}
	if sender.sent[0] != "No conversations matched your search." {
		t.Fatalf("miss reply = %q", sender.sent[0])
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, uid, "/mctl conversations _unclosed["); err != nil {
		t.Fatalf("handle markdown-ish miss: %v", err)
	}
	if sender.sent[0] != "No conversations matched your search." {
		t.Fatalf("markdown-ish miss reply = %q, want a generic no-match (do not echo the filter)", sender.sent[0])
	}
	if strings.Contains(sender.sent[0], "_unclosed[") {
		t.Fatalf("markdown-ish miss reply = %q, must not reflect the raw filter", sender.sent[0])
	}
}

// TestRouter_Conversations_FilterScanCapFewMatches is Claude's P2 on #539:
// hitting conversationFilterScan with fewer matches than limit must not
// claim "Showing the 20 most recently updated" when only a couple of Conv
// lines were printed. The scan-cap notice is the honest signal.
func TestRouter_Conversations_FilterScanCapFewMatches(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	for i := 1; i <= conversationFilterScan; i++ {
		name := "Peer"
		handle := "other"
		if i <= 2 {
			name = "Anna HR"
			handle = "anna_hr"
		}
		if _, err := store.EnsureConversation(ctx, uid, int64(2000+i), handle, name); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations @Anna_HR"); err != nil {
		t.Fatalf("handle filter: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	reply := sender.sent[0]
	if got := strings.Count(reply, "Conv #"); got != 2 {
		t.Fatalf("listed %d conversations, want 2", got)
	}
	if strings.Contains(reply, "Showing the") {
		t.Fatalf("reply = %q, count-truncation notice must not fire when matches < limit", reply)
	}
	wantScan := fmt.Sprintf("Search covered only the %d most recently updated conversations; older matches may not appear.", conversationFilterScan)
	if !strings.Contains(reply, wantScan) {
		t.Fatalf("reply = %q, want scan-cap notice %q", reply, wantScan)
	}

	sender.sent = nil
	if err := router.HandleSavedText(ctx, uid, "/mctl conversations nobody"); err != nil {
		t.Fatalf("handle miss: %v", err)
	}
	if !strings.HasPrefix(sender.sent[0], "No conversations matched your search.") {
		t.Fatalf("miss reply = %q, want the generic no-match prefix", sender.sent[0])
	}
	if strings.Contains(sender.sent[0], "nobody") {
		t.Fatalf("miss reply = %q, must not reflect the raw filter", sender.sent[0])
	}
	if !strings.Contains(sender.sent[0], wantScan) {
		t.Fatalf("miss reply = %q, want scan-cap notice when the empty result may be incomplete", sender.sent[0])
	}
}

func TestParseConversationsArg(t *testing.T) {
	cases := []struct {
		arg        string
		wantLimit  int
		wantFilter string
	}{
		{"", defaultConversationList, ""},
		{"50", 50, ""},
		{"150", maxConversationList, ""},
		{"@anna_hr", defaultConversationList, "@anna_hr"},
		{"_unclosed[", defaultConversationList, "_unclosed["},
	}
	for _, c := range cases {
		limit, filter := parseConversationsArg(c.arg)
		if limit != c.wantLimit || filter != c.wantFilter {
			t.Errorf("parseConversationsArg(%q) = (%d, %q), want (%d, %q)",
				c.arg, limit, filter, c.wantLimit, c.wantFilter)
		}
	}
}

// TestRouter_Conversations_CountCappedAt100 is Agy's P3 on #539: a requested
// count above maxConversationList must be clamped, and the listing plus
// truncation notice must reflect that cap.
func TestRouter_Conversations_CountCappedAt100(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	for i := 1; i <= 150; i++ {
		if _, err := store.EnsureConversation(ctx, uid, int64(3000+i), "other", "Peer"); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations 150"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	reply := sender.sent[0]
	if got := strings.Count(reply, "Conv #"); got != maxConversationList {
		t.Fatalf("listed %d conversations, want %d", got, maxConversationList)
	}
	if !strings.Contains(reply, "Showing the 100 most recently updated") {
		t.Fatalf("reply = %q, want the 100-row truncation notice", reply)
	}
}

// TestRouter_Conversations_FilterTruncationOmitsCountHint is Agy's other P3
// on #539: parseConversationsArg accepts count XOR filter, so a truncated
// filtered listing must not tell the owner to "Pass a count".
func TestRouter_Conversations_FilterTruncationOmitsCountHint(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	for i := 1; i <= 25; i++ {
		if _, err := store.EnsureConversation(ctx, uid, int64(4000+i), "other", "Peer"); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl conversations peer"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 {
		t.Fatalf("replies = %d, want 1", len(sender.sent))
	}
	reply := sender.sent[0]
	if got := strings.Count(reply, "Conv #"); got != defaultConversationList {
		t.Fatalf("listed %d conversations, want %d", got, defaultConversationList)
	}
	if !strings.Contains(reply, "Showing the 20 most recently updated matches.") {
		t.Fatalf("reply = %q, want the filtered truncation notice", reply)
	}
	if strings.Contains(reply, "Pass a count") {
		t.Fatalf("reply = %q, must not suggest passing a count while a filter is active", reply)
	}
}

// TestRouter_Show_ResolvesPeerReference guards the new resolution path: an
// owner who never got a job lead for a conversation (e.g. a takeover) can
// still address it by user:<id> or @username instead of the numeric id.
func TestRouter_Show_ResolvesPeerReference(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl show user:555"); err != nil {
		t.Fatalf("handle user: %v", err)
	}
	wantMarker := "Conversation #" + strconv.FormatInt(conv.ID, 10)
	if len(sender.sent) != 1 || !strings.Contains(sender.sent[0], wantMarker) {
		t.Fatalf("show user:555 reply = %v, want it to contain %q", sender.sent, wantMarker)
	}

	if err := router.HandleSavedText(ctx, uid, "/mctl show @anna_hr"); err != nil {
		t.Fatalf("handle @username: %v", err)
	}
	if len(sender.sent) != 2 || !strings.Contains(sender.sent[1], wantMarker) {
		t.Fatalf("show @anna_hr reply = %v, want it to contain %q", sender.sent, wantMarker)
	}
}

// TestRouter_Show_PlainIntegerStillWorks guards byte-identical behavior for
// the pre-existing numeric-id path once resolveConversationID sits in front
// of it.
func TestRouter_Show_PlainIntegerStillWorks(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := router.HandleSavedText(ctx, uid, "/mctl show "+strconv.FormatInt(conv.ID, 10)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	wantMarker := "Conversation #" + strconv.FormatInt(conv.ID, 10)
	if len(sender.sent) != 1 || !strings.Contains(sender.sent[0], wantMarker) {
		t.Fatalf("show reply = %v, want it to contain %q", sender.sent, wantMarker)
	}
}

// TestRouter_Show_MalformedArgUsesUsageMessage guards the "bad input" branch:
// garbage that isn't a numeric id and isn't a recognized user:/@ reference
// must get the usage text, not a not-found reply.
func TestRouter_Show_MalformedArgUsesUsageMessage(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl show garbage"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 || !strings.HasPrefix(sender.sent[0], "Usage:") {
		t.Fatalf("show garbage reply = %v, want a Usage message", sender.sent)
	}
}

// TestRouter_Show_UnmatchedPeerReferenceUsesNotFoundMessage guards the
// "well-formed reference, no match" branch distinct from the usage branch.
func TestRouter_Show_UnmatchedPeerReferenceUsesNotFoundMessage(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl show @nobody"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 || !strings.Contains(sender.sent[0], "not found") {
		t.Fatalf("show @nobody reply = %v, want a not-found message", sender.sent)
	}
	sender.sent = nil
	if err := router.HandleSavedText(context.Background(), uid, "/mctl show user:404"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 || !strings.Contains(sender.sent[0], "not found") {
		t.Fatalf("show user:404 reply = %v, want a not-found message", sender.sent)
	}
}

// TestRouter_PeerReferencePrefixesAreCaseInsensitive pins the prefix matching
// to the same case-insensitivity ParseCommand already applies to the
// subcommand, and for the same stated reason: the owner types this by hand on
// a phone keyboard that may autocapitalize, turning "user:555" into "User:555"
// and "@anna_hr" into an arg the switch would otherwise drop to the usage
// line. The seeded conversation is the control -- an exact-case reference has
// to resolve first, or the assertions below would pass on a router that
// resolves nothing.
func TestRouter_PeerReferencePrefixesAreCaseInsensitive(t *testing.T) {
	router, _, sender, store, uid := newTestRouter(t)
	ctx := context.Background()
	if _, err := store.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna"); err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	for _, arg := range []string{"user:555", "User:555", "USER:555", "@anna_hr", "@Anna_HR"} {
		sender.sent = nil
		if err := router.HandleSavedText(ctx, uid, "/mctl show "+arg); err != nil {
			t.Fatalf("handle %q: %v", arg, err)
		}
		if len(sender.sent) != 1 {
			t.Fatalf("show %q sent %d replies, want 1", arg, len(sender.sent))
		}
		if strings.HasPrefix(sender.sent[0], "Usage:") || strings.Contains(sender.sent[0], "not found") {
			t.Errorf("show %q reply = %q, want the conversation; the prefix match is case-sensitive", arg, sender.sent[0])
		}
	}
}

// TestRouter_Show_MalformedPeerIDUsesUsageMessage separates "malformed" from
// "no match". A "user:" prefix with a non-numeric tail never reaches the
// store, so answering "Conversation user:abc not found." tells the owner the
// same thing a well-formed reference to an unknown peer would -- and hides
// that they mistyped the reference itself. errNotAReference routes them to
// the usage line, which is what its own doc comment says it is for.
func TestRouter_Show_MalformedPeerIDUsesUsageMessage(t *testing.T) {
	router, _, sender, _, uid := newTestRouter(t)
	if err := router.HandleSavedText(context.Background(), uid, "/mctl show user:abc"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(sender.sent) != 1 || !strings.HasPrefix(sender.sent[0], "Usage:") {
		t.Fatalf("show user:abc reply = %v, want a Usage message (it is malformed, not a miss)", sender.sent)
	}
}

// TestRouter_Continue_ResolvesPeerReference and
// TestRouter_Takeover_ResolvesPeerReference guard the same resolution path
// for the other two commands sharing resolveConversationID.
func TestRouter_Continue_ResolvesPeerReference(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}
	if err := router.HandleSavedText(ctx, uid, "/mctl continue @anna_hr"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if got.State != db.ConversationActive {
		t.Fatalf("state = %q, want active", got.State)
	}
}

func TestRouter_Takeover_ResolvesPeerReference(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "anna_hr", "Anna")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := router.HandleSavedText(ctx, uid, "/mctl takeover user:555"); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if got.State != db.ConversationTakenOver {
		t.Fatalf("state = %q, want taken_over", got.State)
	}
}

func TestRouter_Continue_ResetsStateAndTurns(t *testing.T) {
	router, _, _, store, uid := newTestRouter(t)
	ctx := context.Background()
	conv, err := store.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("seed conversation: %v", err)
	}
	if err := store.SetConversationState(ctx, uid, conv.ID, db.ConversationTakenOver); err != nil {
		t.Fatalf("take over: %v", err)
	}
	if err := router.HandleSavedText(ctx, uid, "/mctl continue "+strconv.FormatInt(conv.ID, 10)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	got, err := store.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	if got.State != db.ConversationActive {
		t.Fatalf("state = %q, want active", got.State)
	}
}
