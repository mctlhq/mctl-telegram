package db

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// TestMigrate_IdempotentAndNonDestructive is T1: seed users at every tier, an
// active session and a live refresh token; run Migrate a second time; assert
// every pre-existing value is unchanged and the audit chain still verifies.
func TestMigrate_IdempotentAndNonDestructive(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto.New: %v", err)
	}
	s.Crypt = crypt

	clientUID, err := s.EnsureUserByTelegramID(ctx, 111, "alice", "Alice Example")
	if err != nil {
		t.Fatalf("ensure client user: %v", err)
	}
	if err := s.SetAccessTier(ctx, 111, TierClient); err != nil {
		t.Fatalf("set client tier: %v", err)
	}
	noneUID, err := s.EnsureUserByTelegramID(ctx, 222, "bob", "Bob")
	if err != nil {
		t.Fatalf("ensure none-tier user: %v", err)
	}
	if err := s.SetAccessTier(ctx, 222, TierNone); err != nil {
		t.Fatalf("set none tier: %v", err)
	}

	// An active session for the client user.
	if err := s.SaveSession(ctx, clientUID, []byte("session-blob"), 111, "Alice Example", "alice"); err != nil {
		t.Fatalf("save session: %v", err)
	}

	// A live refresh token, inserted directly (mirrors what SaveRefreshToken
	// writes) so the test does not depend on the localjwt token format.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens(family_id, token_hash, user_id, client_id, telegram_id, telegram_username, scope, client_name, expires_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		"fam-1", []byte("hash-1"), clientUID, "claude-client", int64(111), "alice", "telegram:read", "Claude",
		time.Now().UTC().Add(24*time.Hour),
	); err != nil {
		t.Fatalf("seed refresh token: %v", err)
	}

	// Log a tool call so VerifyAuditChain has something to walk.
	s.LogToolCall(ctx, clientUID, "get_my_identity", "", "ok", "", "")

	// Snapshot every pre-existing value the migration must not rewrite.
	// sessionEncrypted is read as a string (not []byte) so the snapshot
	// struct stays comparable with ==.
	type snapshot struct {
		accessTierClient, accessTierNone      string
		telegramUsername, telegramDisplayName string
		sessionEncrypted                      string
		refreshTokenScope, refreshTokenClient string
	}
	readSnapshot := func() snapshot {
		var snap snapshot
		if err := s.DB.QueryRowContext(ctx, `SELECT access_tier FROM users WHERE telegram_login_id=$1`, 111).Scan(&snap.accessTierClient); err != nil {
			t.Fatalf("read client access_tier: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx, `SELECT access_tier FROM users WHERE telegram_login_id=$1`, 222).Scan(&snap.accessTierNone); err != nil {
			t.Fatalf("read none access_tier: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx,
			`SELECT telegram_username, telegram_display_name FROM users WHERE telegram_login_id=$1`, 111,
		).Scan(&snap.telegramUsername, &snap.telegramDisplayName); err != nil {
			t.Fatalf("read telegram identity columns: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx,
			`SELECT session_encrypted FROM telegram_accounts WHERE user_id=$1 AND revoked_at IS NULL`, clientUID,
		).Scan(&snap.sessionEncrypted); err != nil {
			t.Fatalf("read session_encrypted: %v", err)
		}
		if err := s.DB.QueryRowContext(ctx,
			`SELECT scope, client_name FROM oauth_refresh_tokens WHERE user_id=$1`, clientUID,
		).Scan(&snap.refreshTokenScope, &snap.refreshTokenClient); err != nil {
			t.Fatalf("read refresh token: %v", err)
		}
		return snap
	}
	before := readSnapshot()
	_ = noneUID

	if err := Migrate(ctx, s.DB); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	// And a third time, since Migrate runs on every boot.
	if err := Migrate(ctx, s.DB); err != nil {
		t.Fatalf("third migrate: %v", err)
	}

	after := readSnapshot()
	if before != after {
		t.Fatalf("migration rewrote pre-existing values:\nbefore=%+v\nafter=%+v", before, after)
	}

	verification, err := s.VerifyAuditChain(ctx, clientUID)
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !verification.OK {
		t.Fatalf("audit chain verification failed after re-migration: %+v", verification)
	}
}

// TestMigrate_BackfillsLegacyIdentityRow is T4: a users row that predates
// identity capture (identity_source/identity_captured_at both NULL) gets
// identity_source='backfill_legacy', identity_captured_at stays NULL
// (provenance unknown, not not_supplied), telegram_display_name is NOT split
// into first/last name, and onboarding_completed_at is derived from the
// earliest finalised telegram_accounts row.
func TestMigrate_BackfillsLegacyIdentityRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	// EnsureUserByTelegramID is the legacy path: it never touches
	// identity_source/identity_captured_at, so this row looks exactly like
	// one created before issue-438 shipped.
	uid, err := s.EnsureUserByTelegramID(ctx, 333, "", "Carol Legacy")
	if err != nil {
		t.Fatalf("ensure legacy user: %v", err)
	}

	earliest := time.Now().UTC().Add(-72 * time.Hour)
	later := time.Now().UTC().Add(-24 * time.Hour)
	// Two non-revoked, finalised rows for the same user (an account can
	// legitimately re-authenticate more than once): the backfill must pick
	// the earliest of the two, not the most recent.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, connected_at)
		 VALUES($1,$2,$3,$4)`,
		uid, 333, []byte("old-blob"), earliest,
	); err != nil {
		t.Fatalf("seed earliest finalised account: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, connected_at)
		 VALUES($1,$2,$3,$4)`,
		uid, 333, []byte("new-blob"), later,
	); err != nil {
		t.Fatalf("seed later finalised account: %v", err)
	}
	// A revoked, non-finalised (telegram_user_id NULL) row that predates
	// both and must be ignored by the backfill's WHERE clause.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted, connected_at, revoked_at)
		 VALUES($1,$2,$3,$4)`,
		uid, []byte("dead-blob"), earliest.Add(-48*time.Hour), earliest.Add(-47*time.Hour),
	); err != nil {
		t.Fatalf("seed excluded account: %v", err)
	}

	if err := Migrate(ctx, s.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var (
		identitySource   sql.NullString
		identityCaptured sql.NullTime
		onboardedAt      sql.NullTime
		firstName        sql.NullString
		lastName         sql.NullString
		displayName      string
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT identity_source, identity_captured_at, onboarding_completed_at, telegram_first_name, telegram_last_name, telegram_display_name
		   FROM users WHERE id = $1`, uid,
	).Scan(&identitySource, &identityCaptured, &onboardedAt, &firstName, &lastName, &displayName); err != nil {
		t.Fatalf("read backfilled row: %v", err)
	}
	if identitySource.String != "backfill_legacy" {
		t.Errorf("identity_source = %q, want backfill_legacy", identitySource.String)
	}
	if identityCaptured.Valid {
		t.Errorf("identity_captured_at is set (%v), want NULL so provenance reads unknown, not not_supplied", identityCaptured.Time)
	}
	if firstName.Valid || lastName.Valid {
		t.Errorf("backfill split telegram_display_name into first/last name: first=%v last=%v, want both NULL", firstName, lastName)
	}
	if displayName != "Carol Legacy" {
		t.Errorf("telegram_display_name = %q, want unchanged 'Carol Legacy'", displayName)
	}
	if !onboardedAt.Valid {
		t.Fatal("onboarding_completed_at was not backfilled")
	}
	if !onboardedAt.Time.Equal(earliest) {
		t.Errorf("onboarding_completed_at = %v, want the earliest finalised connected_at %v", onboardedAt.Time, earliest)
	}

	got := ResolveIdentityProvenance(identityCaptured.Valid, firstName.String)
	if got != ProvenanceUnknown {
		t.Errorf("resolved provenance = %q, want unknown", got)
	}
}
