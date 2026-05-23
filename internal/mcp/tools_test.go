package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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

func TestEvaluateSendGate_DraftMode(t *testing.T) {
	real, reason := evaluateSendGate(context.Background(), nil, nil, "draft", true)
	if real || reason == "" {
		t.Fatalf("draft must never go live: real=%v reason=%q", real, reason)
	}
}

func TestEvaluateSendGate_ServerFlagOff(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	real, reason := evaluateSendGate(context.Background(), nil, id, "send", false)
	if real {
		t.Fatal("ALLOW_SEND=false must block real send")
	}
	if reason == "" {
		t.Fatal("expected reason")
	}
}

func TestEvaluateSendGate_MissingScope(t *testing.T) {
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:read"}}
	real, reason := evaluateSendGate(context.Background(), nil, id, "send", true)
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
	real, reason := evaluateSendGate(ctx, s, id, "send", true)
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
	real, reason := evaluateSendGate(ctx, s, id, "send", true)
	if !real {
		t.Fatalf("all gates passed but real=false (reason=%q)", reason)
	}
	if reason != "" {
		t.Fatalf("expected empty reason on success, got %q", reason)
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

// makePrepareSendRequest constructs a CallToolRequest with the given peer and
// text arguments, matching the structure expected by toolPrepareSendMessage.
func makePrepareSendRequest(peer, text string) mcplib.CallToolRequest {
	args := map[string]any{}
	if peer != "" {
		args["peer"] = peer
	}
	if text != "" {
		args["text"] = text
	}
	return mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name:      "prepare_send_message",
			Arguments: args,
		},
	}
}

// TestToolPrepareSendMessage_Success verifies the happy-path: a valid identity,
// non-nil confirms store, nil limiter, peer and text provided.
func TestToolPrepareSendMessage_Success(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	srv := &Server{
		Store:    store,
		Confirms: NewConfirmStore(),
		Limiter:  nil,
	}
	id := &auth.Identity{UserID: 1, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolPrepareSendMessage()
	req := makePrepareSendRequest("@testuser", "hello")
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.IsError {
		t.Fatalf("expected success, got tool error: %s", contentText(result))
	}
	text := contentText(result)
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("result is not valid JSON: %v — content: %q", err, text)
	}
	confID, _ := out["confirmation_id"].(string)
	if !strings.HasPrefix(confID, "cs_") {
		t.Errorf("confirmation_id must start with cs_, got %q", confID)
	}
	if len(confID) != 35 {
		t.Errorf("confirmation_id must be 35 chars, got %d (%q)", len(confID), confID)
	}
	peerRedacted, _ := out["peer_redacted"].(string)
	if peerRedacted != telegram.RedactPeer("@testuser") {
		t.Errorf("peer_redacted = %q, want %q", peerRedacted, telegram.RedactPeer("@testuser"))
	}
	expiresAtStr, _ := out["expires_at"].(string)
	if expiresAtStr == "" {
		t.Fatal("expires_at must not be empty")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expiresAtStr)
	if err != nil {
		// Try RFC3339 without nanoseconds.
		expiresAt, err = time.Parse(time.RFC3339, expiresAtStr)
		if err != nil {
			t.Fatalf("expires_at is not parseable: %v — value: %q", err, expiresAtStr)
		}
	}
	if !expiresAt.After(time.Now()) {
		t.Errorf("expires_at must be in the future, got %v", expiresAt)
	}
	payloadHash, _ := out["payload_hash"].(string)
	wantHash := HashSendPayload("@testuser", "hello")
	if payloadHash != wantHash {
		t.Errorf("payload_hash = %q, want %q", payloadHash, wantHash)
	}
	// Verify the token can be consumed by Confirms.Consume.
	if _, cerr := srv.Confirms.Consume(confID, id.UserID, wantHash); cerr != nil {
		t.Errorf("Confirms.Consume failed: %v", cerr)
	}
}

// TestToolPrepareSendMessage_RateLimited verifies that an exhausted per-peer
// bucket produces a tool error and does not issue a confirmation token.
func TestToolPrepareSendMessage_RateLimited(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	limiter := audit.NewRateLimiter(0)
	id := &auth.Identity{UserID: 1}
	// Exhaust the per-peer bucket.
	peerRedacted := telegram.RedactPeer("@victim")
	for i := 0; i < audit.PeerSendCap; i++ {
		limiter.AllowPeer(id, peerRedacted, audit.PeerSendCap, audit.PeerWindow)
	}
	srv := &Server{
		Store:    store,
		Confirms: NewConfirmStore(),
		Limiter:  limiter,
	}
	ctx = auth.With(ctx, id)

	_, handler := srv.toolPrepareSendMessage()
	req := makePrepareSendRequest("@victim", "spam")
	result, err := handler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected tool error when rate limited, got success")
	}
	// Confirm store must be empty — no token was issued.
	srv.Confirms.mu.Lock()
	storeLen := len(srv.Confirms.m)
	srv.Confirms.mu.Unlock()
	if storeLen != 0 {
		t.Errorf("confirm store must be empty after rate-limit rejection, got %d entries", storeLen)
	}
}

// TestToolPrepareSendMessage_MissingArgs verifies that omitting peer and/or text
// returns a tool error without panicking.
func TestToolPrepareSendMessage_MissingArgs(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	srv := &Server{
		Store:    store,
		Confirms: NewConfirmStore(),
	}
	id := &auth.Identity{UserID: 1}
	ctx = auth.With(ctx, id)
	_, handler := srv.toolPrepareSendMessage()

	cases := []struct {
		name string
		peer string
		text string
	}{
		{"empty peer", "", "hello"},
		{"empty text", "@user", ""},
		{"both empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makePrepareSendRequest(tc.peer, tc.text)
			result, err := handler(ctx, req)
			if err != nil {
				t.Fatalf("unexpected Go error: %v", err)
			}
			if !result.IsError {
				t.Errorf("expected tool error for peer=%q text=%q", tc.peer, tc.text)
			}
		})
	}
}

// TestSendMessage_ExpiredConfirmationDryReason verifies that an expired
// confirmation_id produces a dry_reason that mentions prepare_send_message.
func TestSendMessage_ExpiredConfirmationDryReason(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	uid, err := store.EnsureUser(ctx, "testuser", "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, send_enabled) VALUES($1, $2, $3)`,
		uid, []byte("blob"), true,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	confirms := NewConfirmStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	confirms.now = func() time.Time { return fixed }

	srv := &Server{
		Store:     store,
		Confirms:  confirms,
		AllowSend: true,
	}

	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:send"}}
	ctx = auth.With(ctx, id)

	// Issue a token at fixed time.
	hash := HashSendPayload("@peer", "hello")
	c, err := confirms.Issue(uid, "send", hash)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Advance clock past TTL so the token is expired.
	confirms.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }

	_, sendHandler := srv.toolSendMessage()
	req := mcplib.CallToolRequest{
		Params: mcplib.CallToolParams{
			Name: "send_message",
			Arguments: map[string]any{
				"peer":            "@peer",
				"text":            "hello",
				"mode":            "send",
				"confirmation_id": c.ID,
			},
		},
	}
	result, err := sendHandler(ctx, req)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	text := contentText(result)
	var out map[string]any
	if jsonErr := json.Unmarshal([]byte(text), &out); jsonErr != nil {
		t.Fatalf("result is not JSON: %v — content: %q", jsonErr, text)
	}
	dryReason, _ := out["dry_reason"].(string)
	if !strings.Contains(dryReason, "prepare_send_message") {
		t.Errorf("dry_reason must mention prepare_send_message, got %q", dryReason)
	}
}
