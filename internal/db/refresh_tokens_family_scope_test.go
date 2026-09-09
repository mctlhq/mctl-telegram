package db

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// TestFamilyEverHeldScope_Postgres covers the dialect the SQLite tests cannot
// reach, and exists because of a bug they could not catch: FamilyEverHeldScope
// originally scanned `SELECT EXISTS(...)` into an int. SQLite (modernc) yields
// an int64 there, so every test passed; Postgres yields a boolean, and
// database/sql has no bool -> int conversion, so the query would have failed in
// production with "converting driver.Value type bool ("true") to a int" the
// first time a scopeless refresh reached it.
//
// Following db_test.go's convention it runs only when TEST_DATABASE_URL is set
// -- which CI does set, with a guard step that fails if any Postgres-backed
// test skips. So this is a CI gate, not an opt-in local check.
//
// Both directions are asserted: a bool scan that silently returned the zero
// value would pass a false-only test while leaving the guard it powers dead.
func TestFamilyEverHeldScope_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := NewStore(conn, crypt)

	const tgID int64 = 500100202
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "dana_tg", "Dana")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	const scopeless, granted = "pg-family-scopeless", "pg-family-granted"
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = conn.ExecContext(ctx,
			`DELETE FROM oauth_refresh_tokens WHERE family_id IN ($1, $2)`, scopeless, granted)
		// The users row too. Both conventions exist in this package
		// (store_access_tier_test.go deletes its user, local_bridge_devices_test.go
		// does not); follow the one that leaves the shared CI database as it
		// found it. The FK is ON DELETE CASCADE, so ordering here is belt and
		// braces rather than load-bearing.
		_, _ = conn.ExecContext(ctx, `DELETE FROM users WHERE telegram_login_id = $1`, tgID)
	})

	mk := func(family, token, scope string) {
		t.Helper()
		if err := store.SaveRefreshToken(ctx, token, RefreshToken{
			FamilyID: family, UserID: uid, ClientID: "claude.ai",
			TelegramID: tgID, Scope: scope,
			ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("save %s: %v", token, err)
		}
	}
	mk(scopeless, "pg-tok-scopeless", "")
	mk(granted, "pg-tok-granted-predecessor", "admin:users:read")
	mk(granted, "pg-tok-granted-successor", "")

	if got, err := store.FamilyEverHeldScope(ctx, scopeless); err != nil || got {
		t.Errorf("scopeless family: got %v err %v, want false", got, err)
	}
	if got, err := store.FamilyEverHeldScope(ctx, granted); err != nil || !got {
		t.Errorf("family with a granted predecessor: got %v err %v, want true", got, err)
	}
}
