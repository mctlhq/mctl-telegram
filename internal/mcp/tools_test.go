package mcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
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

func TestEvaluateSendGate_DraftDefault(t *testing.T) {
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
