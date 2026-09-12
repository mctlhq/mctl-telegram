package db

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestMigrate_BackfillsOnboardingCompletedAtOnALegacyRow is T1: a user row
// that predates issue-620 (the five identity columns NULL, exactly what a
// pre-change deployment leaves after the additive ALTERs run) converges to
// the correct onboarding_completed_at on the next Migrate pass, while
// access_tier, telegram_login_id, the session row and the refresh-token row
// are all left untouched.
func TestMigrate_BackfillsOnboardingCompletedAtOnALegacyRow(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	var uid int64
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO users(github_login, provider, telegram_login_id, telegram_username, telegram_display_name, access_tier)
		 VALUES ('tg:600100201', 'tg-mcp', 600100201, 'carol_tg', 'Carol', 'client')
		 RETURNING id`,
	).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	connectedAt := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Second)
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, display_name, username, session_encrypted, connected_at)
		 VALUES ($1, $2, 'Carol', 'carol_tg', X'0badc0de', $3)`,
		uid, 600100201, connectedAt,
	); err != nil {
		t.Fatalf("insert telegram_accounts: %v", err)
	}

	if _, err := conn.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens(family_id, token_hash, user_id, client_id, telegram_id, expires_at)
		 VALUES ('fam-carol', X'aa', $1, 'client-carol', 600100201, $2)`,
		uid, time.Now().UTC().Add(30*24*time.Hour),
	); err != nil {
		t.Fatalf("insert oauth_refresh_tokens: %v", err)
	}

	// Explicitly reset the five identity columns to NULL -- the defensive
	// step drop_legacy_columns_test.go's pattern uses, so this test proves
	// the "before" state actually holds rather than trusting that a fresh
	// insert happened to omit them.
	if _, err := conn.ExecContext(ctx,
		`UPDATE users SET telegram_first_name = NULL, telegram_last_name = NULL,
		                   telegram_language_code = NULL, identity_captured_at = NULL,
		                   onboarding_completed_at = NULL
		  WHERE id = $1`, uid,
	); err != nil {
		t.Fatalf("reset identity columns to NULL: %v", err)
	}
	var onboardedBefore sql.NullTime
	if err := conn.QueryRowContext(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&onboardedBefore); err != nil {
		t.Fatalf("read onboarding_completed_at before re-migrate: %v", err)
	}
	if onboardedBefore.Valid {
		t.Fatal("onboarding_completed_at was not actually reset to NULL; the test proves nothing")
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("re-migrate a legacy row: %v", err)
	}

	var (
		accessTier  string
		tgLoginID   int64
		onboardedAt time.Time
	)
	if err := conn.QueryRowContext(ctx,
		`SELECT access_tier, telegram_login_id, onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&accessTier, &tgLoginID, &onboardedAt); err != nil {
		t.Fatalf("read back user: %v", err)
	}
	if accessTier != "client" {
		t.Errorf("access_tier = %q, want %q", accessTier, "client")
	}
	if tgLoginID != 600100201 {
		t.Errorf("telegram_login_id = %d, want 600100201", tgLoginID)
	}
	if !onboardedAt.Equal(connectedAt) {
		t.Errorf("onboarding_completed_at = %v, want %v (the account's connected_at)", onboardedAt, connectedAt)
	}

	var sessionBlob []byte
	if err := conn.QueryRowContext(ctx,
		`SELECT session_encrypted FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&sessionBlob); err != nil {
		t.Fatalf("read back telegram_accounts: %v", err)
	}
	if len(sessionBlob) != 4 || sessionBlob[0] != 0x0b {
		t.Errorf("session_encrypted changed across re-migrate: %x", sessionBlob)
	}

	var refreshCount int
	if err := conn.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oauth_refresh_tokens WHERE user_id = $1`, uid,
	).Scan(&refreshCount); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	if refreshCount != 1 {
		t.Errorf("oauth_refresh_tokens row count = %d, want 1", refreshCount)
	}

	// Idempotence: a second Migrate must not move onboarding_completed_at
	// off the value the first backfill wrote.
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("second re-migrate: %v", err)
	}
	var onboardedAgain time.Time
	if err := conn.QueryRowContext(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&onboardedAgain); err != nil {
		t.Fatalf("read onboarding_completed_at after second migrate: %v", err)
	}
	if !onboardedAgain.Equal(onboardedAt) {
		t.Errorf("onboarding_completed_at changed on the second migrate: %v -> %v", onboardedAt, onboardedAgain)
	}
}

// TestMigrate_OnboardingBackfillLeavesUnfinalisedUsersNull covers the other
// half of T1/T2's contract: a user with no finalised telegram_accounts row
// (telegram_user_id NULL, e.g. a partial/mid-login row) keeps
// onboarding_completed_at NULL rather than being backfilled from it.
func TestMigrate_OnboardingBackfillLeavesUnfinalisedUsersNull(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	var uid int64
	if err := conn.QueryRowContext(ctx,
		`INSERT INTO users(github_login, provider) VALUES ('dana', 'test') RETURNING id`,
	).Scan(&uid); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	// A mid-login row: session bytes exist but telegram_user_id was never
	// finalised.
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, session_encrypted) VALUES ($1, X'aa')`, uid,
	); err != nil {
		t.Fatalf("insert unfinalised telegram_accounts: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var onboarded sql.NullTime
	if err := conn.QueryRowContext(ctx,
		`SELECT onboarding_completed_at FROM users WHERE id = $1`, uid,
	).Scan(&onboarded); err != nil {
		t.Fatalf("read onboarding_completed_at: %v", err)
	}
	if onboarded.Valid {
		t.Errorf("onboarding_completed_at = %v, want NULL for a user with no finalised session", onboarded.Time)
	}
}

// TestAttrProvenance is T3: the three provenance states attrProvenance can
// return, both dialect-independent (it takes a plain sql.NullTime).
func TestAttrProvenance(t *testing.T) {
	var neverCaptured sql.NullTime
	captured := sql.NullTime{Time: time.Now().UTC(), Valid: true}

	cases := []struct {
		name       string
		capturedAt sql.NullTime
		value      string
		want       string
	}{
		{"never captured, empty value", neverCaptured, "", ProvenanceNotCaptured},
		{"never captured, non-empty value", neverCaptured, "Alice", ProvenanceNotCaptured},
		{"captured, empty value", captured, "", ProvenanceNotSupplied},
		{"captured, non-empty value", captured, "Alice", ProvenanceVerified},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := attrProvenance(tc.capturedAt, tc.value); got != tc.want {
				t.Errorf("attrProvenance(%+v, %q) = %q, want %q", tc.capturedAt, tc.value, got, tc.want)
			}
		})
	}
}

// TestCaptureTelegramIdentity is T4: a full snapshot sets every attribute and
// the timestamp; a later partial snapshot never erases a previously captured
// value; a snapshot with every optional field empty still stamps
// identity_captured_at, which is what makes not_supplied reachable.
func TestCaptureTelegramIdentity(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)

	uid, err := st.EnsureUserByTelegramID(ctx, 600100301, "carol_tg", "")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}

	// Before any capture, the row reads not_captured for everything.
	before, err := st.GetIdentity(ctx, uid)
	if err != nil {
		t.Fatalf("GetIdentity before capture: %v", err)
	}
	if before == nil {
		t.Fatal("GetIdentity before capture: row is nil")
	}
	if before.Provenance.FirstName != ProvenanceNotCaptured {
		t.Errorf("before capture: FirstName provenance = %q, want %q", before.Provenance.FirstName, ProvenanceNotCaptured)
	}

	// A full snapshot sets every attribute and the timestamp.
	if err := st.CaptureTelegramIdentity(ctx, uid, TelegramIdentityAttrs{
		Username:     "carol_tg",
		FirstName:    "Carol",
		LastName:     "Danvers",
		DisplayName:  "Carol Danvers",
		LanguageCode: "en",
	}); err != nil {
		t.Fatalf("CaptureTelegramIdentity (full): %v", err)
	}
	row, err := st.GetIdentity(ctx, uid)
	if err != nil {
		t.Fatalf("GetIdentity after full capture: %v", err)
	}
	if row == nil {
		t.Fatal("GetIdentity after full capture: row is nil")
	}
	if row.FirstName != "Carol" || row.LastName != "Danvers" || row.LanguageCode != "en" || row.DisplayName != "Carol Danvers" {
		t.Fatalf("attributes not captured: %+v", row)
	}
	if row.Provenance.FirstName != ProvenanceVerified || row.Provenance.LastName != ProvenanceVerified ||
		row.Provenance.LanguageCode != ProvenanceVerified || row.Provenance.DisplayName != ProvenanceVerified {
		t.Errorf("provenance after full capture = %+v, want all verified", row.Provenance)
	}

	// A later snapshot with empty first/last name must not erase the
	// previously captured values (the COALESCE(NULLIF($n,''), column) shape).
	if err := st.CaptureTelegramIdentity(ctx, uid, TelegramIdentityAttrs{Username: "carol_tg"}); err != nil {
		t.Fatalf("CaptureTelegramIdentity (partial): %v", err)
	}
	row2, err := st.GetIdentity(ctx, uid)
	if err != nil {
		t.Fatalf("GetIdentity after partial capture: %v", err)
	}
	if row2 == nil {
		t.Fatal("GetIdentity after partial capture: row is nil")
	}
	if row2.FirstName != "Carol" || row2.LastName != "Danvers" || row2.LanguageCode != "en" {
		t.Errorf("a partial capture erased a previously captured value: %+v", row2)
	}

	// A snapshot with every optional field empty still stamps
	// identity_captured_at, so a never-supplied attribute reads
	// not_supplied rather than staying not_captured forever.
	uid2, err := st.EnsureUserByTelegramID(ctx, 600100302, "", "")
	if err != nil {
		t.Fatalf("ensure second user: %v", err)
	}
	if err := st.CaptureTelegramIdentity(ctx, uid2, TelegramIdentityAttrs{}); err != nil {
		t.Fatalf("CaptureTelegramIdentity (empty): %v", err)
	}
	row3, err := st.GetIdentity(ctx, uid2)
	if err != nil {
		t.Fatalf("GetIdentity after empty capture: %v", err)
	}
	if row3 == nil {
		t.Fatal("GetIdentity after empty capture: row is nil")
	}
	if row3.Provenance.FirstName != ProvenanceNotSupplied || row3.Provenance.LastName != ProvenanceNotSupplied ||
		row3.Provenance.LanguageCode != ProvenanceNotSupplied {
		t.Errorf("empty capture did not stamp identity_captured_at correctly: %+v", row3.Provenance)
	}
}

// TestListIdentities_ProvenanceAndLastSeen is T6: a captured user reads
// verified/not_supplied as appropriate; a never-captured legacy user reads
// not_captured for every optional attribute while access_tier/has_session/
// connected_via still populate; last_seen_at picks the later of the session
// and refresh-token timestamps and reads derived; a user with neither reads
// not_captured for last_seen_at too.
func TestListIdentities_ProvenanceAndLastSeen(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Now().UTC()

	// Alice: captured, with a last_used_at newer than her refresh token.
	aliceUID, err := st.EnsureUserByTelegramID(ctx, 600100401, "alice_tg", "Alice")
	if err != nil {
		t.Fatalf("ensure alice: %v", err)
	}
	if err := st.CaptureTelegramIdentity(ctx, aliceUID, TelegramIdentityAttrs{
		Username:    "alice_tg",
		FirstName:   "Alice",
		DisplayName: "Alice",
		// LastName and LanguageCode deliberately omitted -> not_supplied.
	}); err != nil {
		t.Fatalf("capture alice: %v", err)
	}
	// aliceLastUsed is deliberately OLDER than the refresh token's created_at
	// below, so LastSeenAt has to actually pick the later of the two rather
	// than always the session row.
	aliceLastUsed := now.Add(-2 * time.Hour)
	seedAccount(t, st, aliceUID, &aliceLastUsed, nil, nil)
	aliceTokenCreatedAt := now.Add(-1 * time.Hour)
	// Direct SQL, not SaveRefreshToken: that helper does not accept a
	// caller-supplied created_at (the column defaults to insert time), and
	// this test needs an exact, older-than-now value to compare against.
	if _, err := st.DB.ExecContext(ctx,
		`INSERT INTO oauth_refresh_tokens(family_id, token_hash, user_id, client_id, telegram_id, client_name, created_at, expires_at)
		 VALUES ('fam-alice', X'01', $1, 'client-alice', 600100401, 'Claude', $2, $3)`,
		aliceUID, aliceTokenCreatedAt, now.Add(30*24*time.Hour),
	); err != nil {
		t.Fatalf("insert alice refresh token: %v", err)
	}

	// Bob: never captured (legacy row) and no session/refresh token at all.
	if _, err := st.EnsureUserByTelegramID(ctx, 600100402, "bob_tg", "Bob"); err != nil {
		t.Fatalf("ensure bob: %v", err)
	}
	if err := st.SetAccessTier(ctx, 600100402, TierClient); err != nil {
		t.Fatalf("set bob access tier: %v", err)
	}

	rows, err := st.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	byID := make(map[int64]IdentityRow, len(rows))
	for _, r := range rows {
		byID[r.TelegramID] = r
	}

	alice, ok := byID[600100401]
	if !ok {
		t.Fatal("alice not found in identities")
	}
	if alice.Provenance.FirstName != ProvenanceVerified {
		t.Errorf("alice FirstName provenance = %q, want %q", alice.Provenance.FirstName, ProvenanceVerified)
	}
	if alice.Provenance.LastName != ProvenanceNotSupplied {
		t.Errorf("alice LastName provenance = %q, want %q", alice.Provenance.LastName, ProvenanceNotSupplied)
	}
	if alice.LastSeenAt == nil {
		t.Fatal("alice LastSeenAt is nil, want the later of the session and refresh-token timestamps")
	}
	if !alice.LastSeenAt.Equal(aliceTokenCreatedAt) {
		t.Errorf("alice LastSeenAt = %v, want %v (the refresh token, newer than the session's last_used_at)", alice.LastSeenAt, aliceTokenCreatedAt)
	}
	if alice.Provenance.LastSeenAt != ProvenanceDerived {
		t.Errorf("alice LastSeenAt provenance = %q, want %q", alice.Provenance.LastSeenAt, ProvenanceDerived)
	}
	if alice.Provenance.OnboardingCompletedAt != ProvenanceNotCaptured {
		t.Errorf("alice OnboardingCompletedAt provenance = %q, want %q (no finalised telegram_accounts row)", alice.Provenance.OnboardingCompletedAt, ProvenanceNotCaptured)
	}

	bob, ok := byID[600100402]
	if !ok {
		t.Fatal("bob not found in identities")
	}
	if bob.AccessTier != TierClient {
		t.Errorf("bob AccessTier = %q, want %q", bob.AccessTier, TierClient)
	}
	if bob.HasSession {
		t.Error("bob HasSession = true, want false (no telegram_accounts row)")
	}
	for name, got := range map[string]string{
		"Username":     bob.Provenance.Username,
		"FirstName":    bob.Provenance.FirstName,
		"LastName":     bob.Provenance.LastName,
		"DisplayName":  bob.Provenance.DisplayName,
		"LanguageCode": bob.Provenance.LanguageCode,
	} {
		if got != ProvenanceNotCaptured {
			t.Errorf("bob %s provenance = %q, want %q (never captured)", name, got, ProvenanceNotCaptured)
		}
	}
	if bob.LastSeenAt != nil {
		t.Errorf("bob LastSeenAt = %v, want nil (no session, no refresh token)", bob.LastSeenAt)
	}
	if bob.Provenance.LastSeenAt != ProvenanceNotCaptured {
		t.Errorf("bob LastSeenAt provenance = %q, want %q", bob.Provenance.LastSeenAt, ProvenanceNotCaptured)
	}
}

// TestMigrate_IndexesTheIdentityLastSeenCorrelation guards the two indexes
// identityLastSeenExpr depends on.
//
// Review of PR #627 found the sub-query correlating on
// oauth_refresh_tokens(user_id) and telegram_accounts(user_id) with neither
// usable: the token table was indexed only on token_hash and family_id, and
// idx_telegram_accounts_user_active is partial on `revoked_at IS NULL`, a
// predicate this sub-query deliberately does not carry -- a revoked account's
// last use is still when the user was last seen. GetIdentity, a point read on
// the get_my_identity hot path, therefore scanned the whole token table on
// every call, and ListIdentities was O(users x tokens).
//
// Asserting on the index names rather than on a query plan keeps this true for
// both dialects from a SQLite-only test: the same two CREATE INDEX statements
// are issued from the Postgres schema block, and a plan assertion would only
// ever have covered the dialect the test runs on.
func TestMigrate_IndexesTheIdentityLastSeenCorrelation(t *testing.T) {
	ctx := context.Background()
	conn := openMigrated(t, "file:"+t.Name()+"?mode=memory&cache=shared")

	for _, want := range []struct {
		index string
		table string
	}{
		{"idx_oauth_refresh_tokens_user_created", "oauth_refresh_tokens"},
		{"idx_telegram_accounts_user_last_used", "telegram_accounts"},
	} {
		var count int
		if err := conn.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ? AND tbl_name = ?`,
			want.index, want.table,
		).Scan(&count); err != nil {
			t.Fatalf("check %s: %v", want.index, err)
		}
		if count != 1 {
			t.Errorf("%s on %s: found %d, want 1 -- identityLastSeenExpr "+
				"correlates on that column and falls back to a scan without it",
				want.index, want.table, count)
		}
	}

	// The leading column alone is not enough: the sub-query takes MAX() of the
	// second, so an index that stops at user_id still sends the MAX to the
	// heap. Assert the stored DDL names both columns.
	for _, want := range []struct {
		index   string
		columns string
	}{
		{"idx_oauth_refresh_tokens_user_created", "(user_id, created_at)"},
		{"idx_telegram_accounts_user_last_used", "(user_id, last_used_at)"},
	} {
		var ddl sql.NullString
		if err := conn.QueryRowContext(ctx,
			`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, want.index,
		).Scan(&ddl); err != nil {
			t.Fatalf("read %s ddl: %v", want.index, err)
		}
		if !ddl.Valid || !strings.Contains(ddl.String, want.columns) {
			t.Errorf("%s covers %q, want it to cover %s", want.index, ddl.String, want.columns)
		}
	}
}
