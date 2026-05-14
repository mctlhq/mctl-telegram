package mcp

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newToolsTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared")
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
