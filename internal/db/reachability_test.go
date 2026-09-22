package db

import (
	"context"
	"database/sql"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// TestRecordBotReachability_ConclusiveWrites is the happy path: a conclusive
// outcome (e.g. a classified 403 "bot was blocked") is persisted with its
// state, reason code, source and an observation time.
func TestRecordBotReachability_ConclusiveWrites(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	outcome := notify.ClassifyDelivery(403, "Forbidden: bot was blocked by the user")
	if !outcome.Conclusive {
		t.Fatal("test setup: expected a conclusive outcome")
	}
	if err := s.RecordBotReachability(ctx, uid, outcome, "digest_delivery"); err != nil {
		t.Fatalf("RecordBotReachability: %v", err)
	}

	got, err := s.getBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("getBotReachability: %v", err)
	}
	if got == nil {
		t.Fatal("no reachability row was written")
	}
	if got.State != notify.StateBlocked {
		t.Errorf("state = %q, want %q", got.State, notify.StateBlocked)
	}
	if got.ReasonCode != "bot_blocked" {
		t.Errorf("reason_code = %q, want bot_blocked", got.ReasonCode)
	}
	if got.Source != "digest_delivery" {
		t.Errorf("source = %q, want digest_delivery", got.Source)
	}
	if got.ObservedAt == nil {
		t.Error("observed_at is nil, want stamped")
	}
}

// TestRecordBotReachability_NonConclusiveDoesNotDowngrade is T7: a 429 and a
// 500 delivered against an existing "reachable" row must leave state and
// observed_at unchanged. A transient failure is not evidence the user
// blocked the bot.
func TestRecordBotReachability_NonConclusiveDoesNotDowngrade(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	reachable := notify.ClassifyDelivery(200, "")
	if err := s.RecordBotReachability(ctx, uid, reachable, "digest_delivery"); err != nil {
		t.Fatalf("seed reachable: %v", err)
	}
	before, err := s.getBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("getBotReachability (before): %v", err)
	}
	if before == nil || before.State != notify.StateReachable {
		t.Fatalf("test setup: want a seeded reachable row, got %+v", before)
	}

	for _, outcome := range []notify.DeliveryOutcome{
		notify.ClassifyDelivery(429, "Too Many Requests"),
		notify.ClassifyDelivery(500, "Internal Server Error"),
	} {
		if outcome.Conclusive {
			t.Fatalf("test setup: expected a non-conclusive outcome, got %+v", outcome)
		}
		if err := s.RecordBotReachability(ctx, uid, outcome, "digest_delivery"); err != nil {
			t.Fatalf("RecordBotReachability(non-conclusive): %v", err)
		}
	}

	after, err := s.getBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("getBotReachability (after): %v", err)
	}
	if after.State != before.State {
		t.Errorf("state changed from %q to %q after a non-conclusive outcome", before.State, after.State)
	}
	if !after.ObservedAt.Equal(*before.ObservedAt) {
		t.Errorf("observed_at changed from %v to %v after a non-conclusive outcome", before.ObservedAt, after.ObservedAt)
	}
}

// TestBotReachability_IndependentOfSessionAndToken is T8: a user with a
// valid refresh token and an active MTProto session still reports "unknown"
// (no row at all) until a real delivery result is recorded.
func TestBotReachability_IndependentOfSessionAndToken(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, last_used_at, expires_at)
		 VALUES($1,$2,$3,$4,$5)`,
		uid, 111, []byte("blob"), sql.NullTime{}, sql.NullTime{},
	); err != nil {
		t.Fatalf("seed active session: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens(family_id, token_hash, user_id, client_id, telegram_id, scope, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6, datetime('now','+1 day'))`,
		"fam", []byte("hash"), uid, "client", 111, "telegram:read",
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	got, err := s.getBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("getBotReachability: %v", err)
	}
	if got != nil {
		t.Fatalf("reachability row exists (%+v) before any delivery was recorded; want no row (reads as unknown)", got)
	}
}
