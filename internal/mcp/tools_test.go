package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tgerr"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func newToolsTestStore(t *testing.T) *db.Store {
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
	return &db.Store{DB: conn}
}

func TestEvaluateSendGate_ServerFlagOff(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	real, reason := evaluateSendGate(context.Background(), nil, id, false, 0)
	if real {
		t.Fatal("ALLOW_SEND=false must block real send")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

func TestEvaluateSendGate_MissingScope(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	real, reason := evaluateSendGate(context.Background(), nil, id, true, 0)
	if real {
		t.Fatal("missing send scope must block real send")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

func TestEvaluateSendGate_PerAccountFlagOff(t *testing.T) {
	ctx := context.Background()
	s := newToolsTestStore(t)
	uid, err := s.EnsureUser(ctx, "alice", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), false,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	real, reason := evaluateSendGate(ctx, s, id, true, 0)
	if real {
		t.Fatal("per-account send_enabled=false must block real send")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

func TestEvaluateSendGate_AllChecksPass(t *testing.T) {
	ctx := context.Background()
	s := newToolsTestStore(t)
	uid, err := s.EnsureUser(ctx, "bob", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	real, reason := evaluateSendGate(ctx, s, id, true, 0)
	if !real {
		t.Fatalf("all gates passed but real=false (reason=%q)", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason on success, got %q", reason)
	}
}

// TestEvaluateSendGate_ReviewerForcedDryRun proves the reviewer/demo identity is
// forced to a dry-run preview even when every other gate is wide open
// (ALLOW_SEND=true, send scope present, per-account send_enabled=true). This is
// the App Directory safety guarantee: the connect flow re-enables send_enabled
// and ChatGPT can auto-execute the send tool, so only the reviewer-identity
// check keeps the demo account's sends preview-only.
func TestEvaluateSendGate_ReviewerForcedDryRun(t *testing.T) {
	const reviewerTGID int64 = 8745115872
	ctx := context.Background()
	s := newToolsTestStore(t)
	uid, err := s.EnsureUser(ctx, "reviewer", "", "test")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	id := &auth.Identity{UserID: uid, TelegramID: reviewerTGID, Scopes: []string{"telegram:messages:send"}}
	real, reason := evaluateSendGate(ctx, s, id, true, reviewerTGID)
	if real {
		t.Fatal("reviewer identity must be forced to dry-run despite send_enabled=true")
	}
	if !strings.Contains(reason, "preview-only") {
		t.Fatalf("expected the reviewer-specific dry-run reason, got %q", reason)
	}

	// The reviewer check runs ahead of the ALLOW_SEND guard, so even with the
	// server flag off the reviewer sees the reviewer-specific reason, not a
	// generic one.
	real, reason = evaluateSendGate(ctx, s, id, false, reviewerTGID)
	if real || !strings.Contains(reason, "preview-only") {
		t.Fatalf("reviewer reason must take precedence over ALLOW_SEND=false (real=%v reason=%q)", real, reason)
	}

	// A non-reviewer identity on the same server (reviewer mode armed) is
	// unaffected: its sends still pass when its own gates are open.
	other := &auth.Identity{UserID: uid, TelegramID: 210408407, Scopes: []string{"telegram:messages:send"}}
	real, _ = evaluateSendGate(ctx, s, other, true, reviewerTGID)
	if !real {
		t.Fatal("non-reviewer identity must not be gagged by reviewer mode")
	}
}

// activeAccountCount returns the number of non-revoked telegram_accounts rows
// for a user — used to assert a blocked destructive call left the session
// intact (count stays 1) vs. an allowed disconnect that revokes it (count 0).
func activeAccountCount(t *testing.T, store *db.Store, uid int64) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM telegram_accounts WHERE user_id = $1 AND revoked_at IS NULL`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count active accounts: %v", err)
	}
	return n
}

// totalAccountCount returns the total telegram_accounts rows (revoked or not)
// for a user — used to assert a blocked delete left the row in place vs. an
// allowed delete that hard-removes it.
func totalAccountCount(t *testing.T, store *db.Store, uid int64) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	return n
}

// latestAudit returns the newest audit_logs row for a user.
func latestAudit(t *testing.T, store *db.Store, uid int64) (tool, status, errMsg string) {
	t.Helper()
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT tool_name, status, COALESCE(error, '') FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, uid,
	).Scan(&tool, &status, &errMsg); err != nil {
		t.Fatalf("read latest audit: %v", err)
	}
	return tool, status, errMsg
}

const guardReviewerTGID int64 = 8745115872

// TestToolDisconnect_DemoReviewerBlocked proves the demo/reviewer identity is
// refused when it tries to disconnect its own account, the session row is left
// untouched, and the blocked attempt is audited.
func TestToolDisconnect_DemoReviewerBlocked(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, guardReviewerTGID, false)
	// Pool is deliberately nil: the guard must short-circuit before any pool/DB
	// mutation, so a nil pool also proves nothing destructive ran.
	srv := &Server{Store: store, DemoReviewerTGID: guardReviewerTGID}
	id := &auth.Identity{UserID: uid, TelegramID: guardReviewerTGID, Scopes: []string{"telegram:messages:read"}}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolDisconnectAccount()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "disconnect_telegram_account"}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("demo reviewer disconnect must be refused")
	}
	if got := contentText(res); !strings.Contains(got, "cannot be disconnected or deleted during review") {
		t.Fatalf("expected the reviewer refusal message, got %q", got)
	}
	if n := activeAccountCount(t, store, uid); n != 1 {
		t.Fatalf("blocked disconnect must NOT revoke the session row (active=%d, want 1)", n)
	}
	tool, status, msg := latestAudit(t, store, uid)
	if tool != "disconnect_telegram_account" || status != "error" || !strings.Contains(msg, "cannot be disconnected") {
		t.Fatalf("blocked attempt not audited: tool=%q status=%q msg=%q", tool, status, msg)
	}
}

// TestToolDelete_DemoReviewerBlocked proves the demo/reviewer identity is
// refused when it tries to hard-delete its own account, the row survives, and
// the blocked attempt is audited. This is the exact path that bricked the demo
// session in a prior review.
func TestToolDelete_DemoReviewerBlocked(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, guardReviewerTGID, false)
	srv := &Server{Store: store, DemoReviewerTGID: guardReviewerTGID}
	id := &auth.Identity{UserID: uid, TelegramID: guardReviewerTGID, Scopes: []string{"telegram:messages:read"}}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolDeleteAccount()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "delete_telegram_account"}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !res.IsError {
		t.Fatal("demo reviewer delete must be refused")
	}
	if got := contentText(res); !strings.Contains(got, "cannot be disconnected or deleted during review") {
		t.Fatalf("expected the reviewer refusal message, got %q", got)
	}
	if n := totalAccountCount(t, store, uid); n != 1 {
		t.Fatalf("blocked delete must NOT remove the row (total=%d, want 1)", n)
	}
	tool, status, msg := latestAudit(t, store, uid)
	if tool != "delete_telegram_account" || status != "error" || !strings.Contains(msg, "cannot be") {
		t.Fatalf("blocked attempt not audited: tool=%q status=%q msg=%q", tool, status, msg)
	}
}

// TestToolDisconnect_NormalUserAllowed proves a normal (non-reviewer) identity
// can still disconnect even while reviewer mode is armed — its active session
// row is revoked.
func TestToolDisconnect_NormalUserAllowed(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	const normalTGID int64 = 210408407
	uid := seedAccountWithSession(t, store, normalTGID, false)
	srv := &Server{Store: store, Pool: telegram.NewClientPool(0, "", 0, store), DemoReviewerTGID: guardReviewerTGID}
	id := &auth.Identity{UserID: uid, TelegramID: normalTGID, Scopes: []string{"telegram:messages:read"}}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolDisconnectAccount()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "disconnect_telegram_account"}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("normal-user disconnect must succeed, got error: %s", contentText(res))
	}
	if n := activeAccountCount(t, store, uid); n != 0 {
		t.Fatalf("normal disconnect must revoke the active session (active=%d, want 0)", n)
	}
}

// TestToolDelete_NormalUserAllowed proves a normal (non-reviewer) identity can
// still hard-delete its account even while reviewer mode is armed.
func TestToolDelete_NormalUserAllowed(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	const normalTGID int64 = 210408407
	uid := seedAccountWithSession(t, store, normalTGID, false)
	srv := &Server{Store: store, Pool: telegram.NewClientPool(0, "", 0, store), DemoReviewerTGID: guardReviewerTGID}
	id := &auth.Identity{UserID: uid, TelegramID: normalTGID, Scopes: []string{"telegram:messages:read"}}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolDeleteAccount()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "delete_telegram_account"}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("normal-user delete must succeed, got error: %s", contentText(res))
	}
	if n := totalAccountCount(t, store, uid); n != 0 {
		t.Fatalf("normal delete must hard-remove the row (total=%d, want 0)", n)
	}
}

func TestDirectSendLimiter_AllowsWhenBudgetAvailable(t *testing.T) {
	limiter := audit.NewRateLimiter(0)
	id := &auth.Identity{UserID: 1}
	blocked, reason := evaluateDirectSendLimiter(limiter, id, "@peer")
	if blocked {
		t.Fatalf("expected allowed, got reason=%q", reason)
	}
}

func TestDirectSendLimiter_BlocksWhenExhausted(t *testing.T) {
	limiter := audit.NewRateLimiter(0)
	id := &auth.Identity{UserID: 1}
	for i := 0; i < audit.PeerSendCap; i++ {
		limiter.AllowPeer(id, "@peer", audit.PeerSendCap, audit.PeerWindow)
	}
	blocked, reason := evaluateDirectSendLimiter(limiter, id, "@peer")
	if !blocked {
		t.Fatal("expected blocked after exhausting budget")
	}
	if !strings.Contains(reason, "rate limit") {
		t.Errorf("unexpected reason %q", reason)
	}
}

// TestBorrowErrResultSessionSentinelsUnchanged is a regression guard: the
// known session sentinel errors must still produce a non-nil error result
// whose content mentions "session".
func TestBorrowErrResultSessionSentinelsUnchanged(t *testing.T) {
	result := borrowErrResult("t", db.ErrSessionRevoked)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := contentText(result)
	if !strings.Contains(strings.ToLower(text), "session") {
		t.Errorf("expected 'session' in content, got %q", text)
	}
}

// TestBorrowErrResultFloodWait verifies that a FLOOD_WAIT error wrapped in a
// plain fmt.Errorf is recognised and produces a JSON envelope with a
// retry_after_seconds field.
func TestBorrowErrResultFloodWait(t *testing.T) {
	wrapped := fmt.Errorf("list_dialogs: %w", tgerr.New(420, "FLOOD_WAIT_30"))
	result := borrowErrResult("list_dialogs", wrapped)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := contentText(result)
	if !strings.Contains(text, "retry_after_seconds") {
		t.Errorf("expected 'retry_after_seconds' in content, got %q", text)
	}
}

func TestRetryPolicy_FloodWait(t *testing.T) {
	err := tgerr.New(420, "FLOOD_WAIT_30")
	ok, n := retryPolicy(err)
	if !ok {
		t.Fatal("expected retry=true for FLOOD_WAIT_30")
	}
	if n != 30 {
		t.Errorf("sleep = %d, want 30", n)
	}
}

func TestRetryPolicy_PeerFlood(t *testing.T) {
	err := tgerr.New(420, "PEER_FLOOD")
	ok, n := retryPolicy(err)
	if !ok {
		t.Fatal("expected retry=true for PEER_FLOOD")
	}
	if n != 60 {
		t.Errorf("sleep = %d, want 60", n)
	}
}

func TestRetryPolicy_PermanentError(t *testing.T) {
	err := tgerr.New(400, "PEER_ID_INVALID")
	ok, _ := retryPolicy(err)
	if ok {
		t.Fatal("expected retry=false for PEER_ID_INVALID")
	}
}

func TestRetryPolicy_Nil(t *testing.T) {
	ok, _ := retryPolicy(nil)
	if ok {
		t.Fatal("expected retry=false for nil error")
	}
}

// seedAccountWithSession creates a user resolvable by telegram id with one
// active telegram_accounts row, returning the internal user id.
func seedAccountWithSession(t *testing.T, store *db.Store, tgID int64, sendEnabled bool) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "seed", "Seed User")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), sendEnabled,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return uid
}

func TestToolSetAccountSend_RequiresAdminScope(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetAccountSend()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_account_send",
		Arguments: map[string]any{"telegram_id": float64(123), "enabled": true},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected scope rejection for identity without admin:users")
	}
}

func TestToolSetAccountSend_HappyPath(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 555, false)
	srv := &Server{Store: store}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetAccountSend()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_account_send",
		Arguments: map[string]any{"telegram_id": float64(555), "enabled": true},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got tool error: %s", contentText(result))
	}
	var out map[string]any
	if jsonErr := json.Unmarshal([]byte(contentText(result)), &out); jsonErr != nil {
		t.Fatalf("result is not JSON: %v", jsonErr)
	}
	if out["send_enabled"] != true || out["ok"] != true {
		t.Errorf("unexpected response: %v", out)
	}
	on, serr := store.IsSendEnabled(ctx, uid)
	if serr != nil || !on {
		t.Errorf("send_enabled not persisted: on=%v err=%v", on, serr)
	}
}

func TestToolSetAccountSend_UserNotFound(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetAccountSend()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_account_send",
		Arguments: map[string]any{"telegram_id": float64(999999), "enabled": true},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error for unknown telegram_id")
	}
}

// A user with no active session row must get a clear error, not a silent ok=true.
func TestToolSetAccountSend_NoActiveSession(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, 777, "nosess", "No Session"); err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	srv := &Server{Store: store}
	id := &auth.Identity{UserID: 1, Scopes: []string{"admin:users"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetAccountSend()
	req := mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_account_send",
		Arguments: map[string]any{"telegram_id": float64(777), "enabled": true},
	}}
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error when user has no active session")
	}
	if !strings.Contains(contentText(result), "no active Telegram session") {
		t.Errorf("unexpected error text: %s", contentText(result))
	}
}

// --- handler-level tests for the 5 new message-op tools ---

func TestToolEditMessage_MissingArgs(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolEditMessage()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "edit_message",
		Arguments: map[string]any{"peer": "user:1"},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing message_id/text")
	}
}

func TestToolEditMessage_SendGateBlocked(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolEditMessage()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "edit_message",
		Arguments: map[string]any{
			"peer":       "user:1",
			"message_id": float64(42),
			"text":       "hello",
		},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when AllowSend=false")
	}
}

func TestToolDeleteMessages_MissingArgs(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolDeleteMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "delete_messages",
		Arguments: map[string]any{},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing peer/message_ids")
	}
}

func TestToolDeleteMessages_SendGateBlocked(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolDeleteMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "delete_messages",
		Arguments: map[string]any{
			"peer":        "user:1",
			"message_ids": []any{float64(1)},
		},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when AllowSend=false")
	}
}

func TestToolForwardMessages_MissingArgs(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolForwardMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "forward_messages",
		Arguments: map[string]any{"from_peer": "user:1"},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing to_peer/message_ids")
	}
}

func TestToolForwardMessages_SendGateBlocked(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolForwardMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "forward_messages",
		Arguments: map[string]any{
			"from_peer":   "user:1",
			"to_peer":     "user:2",
			"message_ids": []any{float64(1)},
		},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when AllowSend=false")
	}
}

func TestToolSearchMessages_MissingScope(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSearchMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "search_messages",
		Arguments: map[string]any{"query": "hello"},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected scope error for identity without telegram:messages:read")
	}
}

func TestToolSearchMessages_MissingQuery(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t)}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSearchMessages()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "search_messages",
		Arguments: map[string]any{},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing query")
	}
}

func TestToolSetReaction_MissingArgs(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: true}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetReaction()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_reaction",
		Arguments: map[string]any{"emoji": "👍"},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for missing peer/message_id")
	}
}

func TestToolSetReaction_SendGateBlocked(t *testing.T) {
	ctx := context.Background()
	srv := &Server{Store: newToolsTestStore(t), AllowSend: false}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolSetReaction()
	result, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name: "set_reaction",
		Arguments: map[string]any{
			"peer":       "user:1",
			"message_id": float64(42),
			"emoji":      "👍",
		},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when AllowSend=false")
	}
}

func TestIntSliceArg(t *testing.T) {
	cases := []struct {
		name    string
		args    map[string]any
		key     string
		want    []int
		wantOK  bool
	}{
		{
			name:   "key absent",
			args:   map[string]any{},
			key:    "ids",
			wantOK: false,
		},
		{
			name:   "float64 elements (JSON numbers)",
			args:   map[string]any{"ids": []any{float64(1), float64(2), float64(3)}},
			key:    "ids",
			want:   []int{1, 2, 3},
			wantOK: true,
		},
		{
			name:   "int elements",
			args:   map[string]any{"ids": []any{10, 20}},
			key:    "ids",
			want:   []int{10, 20},
			wantOK: true,
		},
		{
			name:   "not a slice",
			args:   map[string]any{"ids": "not a slice"},
			key:    "ids",
			wantOK: false,
		},
		{
			name:   "empty slice",
			args:   map[string]any{"ids": []any{}},
			key:    "ids",
			want:   []int{},
			wantOK: true,
		},
		{
			name:   "mixed numeric and non-numeric elements",
			args:   map[string]any{"ids": []any{float64(123), "not-a-number"}},
			key:    "ids",
			wantOK: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := intSliceArg(c.args, c.key)
			if ok != c.wantOK {
				t.Errorf("intSliceArg ok = %v, want %v", ok, c.wantOK)
			}
			if ok && len(got) != len(c.want) {
				t.Errorf("intSliceArg len = %d, want %d", len(got), len(c.want))
			}
			for i := range c.want {
				if i < len(got) && got[i] != c.want[i] {
					t.Errorf("intSliceArg[%d] = %d, want %d", i, got[i], c.want[i])
				}
			}
		})
	}
}
