package db

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

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

	got, err := s.GetBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("GetBotReachability: %v", err)
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
	before, err := s.GetBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("GetBotReachability (before): %v", err)
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

	after, err := s.GetBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("GetBotReachability (after): %v", err)
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

	got, err := s.GetBotReachability(ctx, uid)
	if err != nil {
		t.Fatalf("GetBotReachability: %v", err)
	}
	if got != nil {
		t.Fatalf("reachability row exists (%+v) before any delivery was recorded; want no row (reads as unknown)", got)
	}
}

// TestRecordInboundBotReachability_StaleNeverOverwritesNewer pins the guard a
// late-dispatched inbound update relies on, in both dialects (an upsert's
// WHERE and timestamp comparison are exactly what differs between them): an
// inbound observation applies when it is newer than the stored one and is
// ignored, reporting applied=false, when the stored one is newer.
func TestRecordInboundBotReachability_StaleNeverOverwritesNewer(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { assertInboundReachabilityGuard(t, newTestStore(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		t.Cleanup(func() {
			_, _ = s.DB.Exec(`DELETE FROM client_bot_reachability`)
			_, _ = s.DB.Exec(`DELETE FROM bot_updates`)
		})
		assertInboundReachabilityGuard(t, s)
	})
}

func assertInboundReachabilityGuard(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	uid, err := s.EnsureUserByTelegramID(ctx, 9191, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	reachable := notify.DeliveryOutcome{State: notify.StateReachable, ReasonCode: "bot_start", Conclusive: true}
	record := func(at time.Time) bool {
		t.Helper()
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		applied, err := s.RecordInboundBotReachabilityTx(ctx, tx, uid, reachable, "bot_start", at)
		if err != nil {
			_ = tx.Rollback()
			t.Fatalf("record: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return applied
	}

	// No row yet: applies.
	if !record(time.Now().Add(-time.Hour)) {
		t.Fatal("first inbound observation was not applied")
	}
	// A newer conclusive outbound observation.
	if err := s.RecordBotReachability(ctx, uid, notify.DeliveryOutcome{State: notify.StateBlocked, ReasonCode: "bot_blocked", Conclusive: true}, "digest_delivery"); err != nil {
		t.Fatal(err)
	}
	// An inbound observation older than it is ignored.
	if record(time.Now().Add(-30 * time.Minute)) {
		t.Error("stale inbound observation reported applied")
	}
	got, _ := s.GetBotReachability(ctx, uid)
	if got == nil || got.State != notify.StateBlocked {
		t.Fatalf("stale inbound overwrote a newer observation: %+v", got)
	}
	// A newer inbound observation applies.
	if !record(time.Now().Add(time.Minute)) {
		t.Error("newer inbound observation was not applied")
	}
	if got, _ := s.GetBotReachability(ctx, uid); got == nil || got.State != notify.StateReachable {
		t.Errorf("newer inbound observation not stored: %+v", got)
	}

	// The observation time a handler uses is the update's own received_at.
	if _, err := s.AcceptUpdate(ctx, 77, KindStartCommand, chat(9191)); err != nil {
		t.Fatal(err)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	at, err := s.UpdateReceivedAtTx(ctx, tx, 77)
	if err != nil {
		t.Fatalf("received_at: %v", err)
	}
	if d := time.Since(at); d < 0 || d > time.Minute {
		t.Errorf("received_at = %v, want about now", at)
	}
	if _, err := s.UpdateReceivedAtTx(ctx, tx, 78); err == nil {
		t.Error("received_at of an unknown update returned no error")
	}
}
