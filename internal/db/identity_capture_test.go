package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// TestEnsureUserByTelegramCapture_ClaimsPresent covers the "OIDC claims
// present" shape (mirrors T2 at the oauth layer, exercised directly against
// the store): username, first and last name each land in their own column,
// identity_source and a non-NULL identity_captured_at are stamped.
func TestEnsureUserByTelegramCapture_ClaimsPresent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 111,
		Username:   "alice",
		FirstName:  "Alice",
		LastName:   "Example",
		Source:     "telegram_oidc",
		CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("EnsureUserByTelegramCapture: %v", err)
	}

	var (
		username    string
		firstName   string
		lastName    string
		displayName string
		source      string
		capturedAt  sql.NullTime
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, telegram_first_name, telegram_last_name, telegram_display_name, identity_source, identity_captured_at
		   FROM users WHERE id = $1`, uid,
	).Scan(&username, &firstName, &lastName, &displayName, &source, &capturedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username != "alice" || firstName != "Alice" || lastName != "Example" {
		t.Fatalf("got (username=%q, first=%q, last=%q), want (alice, Alice, Example)", username, firstName, lastName)
	}
	if displayName != "Alice Example" {
		t.Errorf("telegram_display_name = %q, want derived 'Alice Example'", displayName)
	}
	if source != "telegram_oidc" {
		t.Errorf("identity_source = %q, want telegram_oidc", source)
	}
	if !capturedAt.Valid {
		t.Error("identity_captured_at is NULL, want stamped")
	}
}

// TestEnsureUserByTelegramCapture_ClaimsAbsent covers T3: the OIDC exchange
// returns only a Telegram id (no username/first/last name). The username
// must stay empty -- NO display-name fallback, unlike EnsureUserByTelegramID
// -- and provenance must resolve to not_supplied (capture ran), not unknown.
func TestEnsureUserByTelegramCapture_ClaimsAbsent(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 222,
		Source:     "telegram_oidc",
		CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("EnsureUserByTelegramCapture: %v", err)
	}

	var (
		username   sql.NullString
		firstName  sql.NullString
		capturedAt sql.NullTime
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, telegram_first_name, identity_captured_at FROM users WHERE id = $1`, uid,
	).Scan(&username, &firstName, &capturedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username.Valid && username.String != "" {
		t.Errorf("telegram_username = %q, want empty (no display-name fallback, and there was no display name anyway)", username.String)
	}
	if !capturedAt.Valid {
		t.Fatal("identity_captured_at is NULL, want stamped even though no claims were supplied")
	}
	got := ResolveIdentityProvenance(capturedAt.Valid, username.String)
	if got != ProvenanceNotSupplied {
		t.Errorf("provenance = %q, want not_supplied", got)
	}
}

// TestEnsureUserByTelegramCapture_NoDisplayNameFallback is the direct
// regression for the defect this whole feature exists to fix:
// EnsureUserByTelegramID's effectiveUsername folds a display name into
// telegram_username when username is empty; EnsureUserByTelegramCapture must
// never do that.
func TestEnsureUserByTelegramCapture_NoDisplayNameFallback(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 444,
		FirstName:  "Dana",
		LastName:   "NoHandle",
		Source:     "telegram_oidc",
		CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("EnsureUserByTelegramCapture: %v", err)
	}
	var username sql.NullString
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username FROM users WHERE id = $1`, uid,
	).Scan(&username); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username.Valid && username.String != "" {
		t.Errorf("telegram_username = %q, want empty even though a display name was captured", username.String)
	}
}

// TestEnsureUserByTelegramCapture_ClaimlessCaptureOnPreexistingRow is the
// direct regression for the provenance-staleness defect: a row created
// earlier by EnsureUserByTelegramID with no username already holds a
// display-name fallback in telegram_username (effectiveUsername). A later
// claim-less EnsureUserByTelegramCapture call (e.g. an OIDC exchange that
// returns only the Telegram id) supplies nothing new and must NOT stamp
// identity_source/identity_captured_at — otherwise provenance would report
// that pre-existing display name as "supplied" by this capture's source.
func TestEnsureUserByTelegramCapture_ClaimlessCaptureOnPreexistingRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramID(ctx, 777, "", "Display Only")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}

	if _, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 777,
		Source:     "telegram_oidc",
		CapturedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("EnsureUserByTelegramCapture: %v", err)
	}

	var (
		username   string
		source     sql.NullString
		capturedAt sql.NullTime
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, identity_source, identity_captured_at FROM users WHERE id = $1`, uid,
	).Scan(&username, &source, &capturedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username != "Display Only" {
		t.Errorf("telegram_username = %q, want untouched pre-existing 'Display Only'", username)
	}
	if source.Valid {
		t.Errorf("identity_source = %q, want NULL — a claim-less capture must not attribute the pre-existing display name to it", source.String)
	}
	if capturedAt.Valid {
		t.Error("identity_captured_at is set, want NULL — a claim-less capture supplied nothing new")
	}
}

// TestEnsureUserByTelegramCapture_Reauth covers the refresh path: a second
// call with new claims advances last_seen_at and updates identity_source /
// identity_captured_at.
func TestEnsureUserByTelegramCapture_Reauth(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	first := time.Now().UTC().Add(-time.Hour)
	uid, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 111,
		Username:   "alice",
		FirstName:  "Alice",
		LastName:   "Example",
		Source:     "telegram_oidc",
		CapturedAt: first,
	})
	if err != nil {
		t.Fatalf("first capture: %v", err)
	}

	second := time.Now().UTC()
	uid2, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: 111,
		Username:   "alice2",
		FirstName:  "Alice",
		LastName:   "Example",
		Source:     "local_bridge_activation",
		CapturedAt: second,
	})
	if err != nil {
		t.Fatalf("second capture: %v", err)
	}
	if uid != uid2 {
		t.Fatalf("re-authentication created a second user row: %d != %d", uid, uid2)
	}

	var (
		username   string
		source     string
		capturedAt time.Time
		lastSeenAt time.Time
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, identity_source, identity_captured_at, last_seen_at FROM users WHERE id = $1`, uid,
	).Scan(&username, &source, &capturedAt, &lastSeenAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username != "alice2" {
		t.Errorf("telegram_username = %q, want refreshed alice2", username)
	}
	if source != "local_bridge_activation" {
		t.Errorf("identity_source = %q, want refreshed local_bridge_activation", source)
	}
	if !capturedAt.After(first) {
		t.Errorf("identity_captured_at did not advance: %v (first was %v)", capturedAt, first)
	}
	if !lastSeenAt.After(first) {
		t.Errorf("last_seen_at did not advance: %v (first was %v)", lastSeenAt, first)
	}
}

// TestEnsureUserByTelegramCapture_ConcurrentNoUniqueIndexError exercises the
// same race EnsureUserByTelegramID documents: two concurrent callers for the
// same brand-new Telegram id must not surface a unique-index violation as a
// 500 -- the loser observes the winner's row on the SELECT.
func TestEnsureUserByTelegramCapture_ConcurrentNoUniqueIndexError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	const n = 8
	var wg sync.WaitGroup
	ids := make([]int64, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
				TelegramID: 555,
				Username:   "concurrent",
				FirstName:  "Concurrent",
				Source:     "telegram_oidc",
				CapturedAt: time.Now().UTC(),
			})
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d returned an error instead of resolving to the winner's row: %v", i, err)
		}
	}
	for i := 1; i < n; i++ {
		if ids[i] != ids[0] {
			t.Fatalf("call %d resolved to user id %d, call 0 resolved to %d — expected every concurrent caller to converge on one row", i, ids[i], ids[0])
		}
	}
}

// TestEnsureUserByTelegramID_UntouchedBehaviour is a guard: the legacy
// function must keep its effectiveUsername fallback and must not stamp any
// of the new identity columns, since it is left byte-identical for its three
// existing callers.
func TestEnsureUserByTelegramID_UntouchedBehaviour(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	uid, err := s.EnsureUserByTelegramID(ctx, 666, "", "Display Only")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	var (
		username   string
		source     sql.NullString
		capturedAt sql.NullTime
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_username, identity_source, identity_captured_at FROM users WHERE id = $1`, uid,
	).Scan(&username, &source, &capturedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username != "Display Only" {
		t.Errorf("telegram_username = %q, want the display-name fallback 'Display Only'", username)
	}
	if source.Valid {
		t.Errorf("identity_source = %q, want NULL — EnsureUserByTelegramID must not touch it", source.String)
	}
	if capturedAt.Valid {
		t.Error("identity_captured_at is set, want NULL — EnsureUserByTelegramID must not touch it")
	}
}

// TestEnsureUserByTelegramCapture_BackfillsLegacyTelegramLoginID pins the
// fallback path that finds a legacy row by its synthetic github_login.
//
// The row this seeds is the one shape the fallback exists for: github_login
// = "tg:<id>" with telegram_login_id still NULL. Before the COALESCE in the
// refresh UPDATE, the fallback found the row, refreshed its identity
// attributes and returned its id -- but never wrote telegram_login_id, so the
// column stayed NULL forever. Every projection and lookup keyed on it
// (ListIdentities, UserIDByTelegramID, SetAccessTier, AccessTierByTelegramID)
// silently skipped the user, and re-authenticating never repaired it because
// each capture took the same fallback again.
//
// Run against both dialects, per issue #620's acceptance: the refresh UPDATE
// carries a bool parameter inside a CASE and now a COALESCE onto a column
// covered by a partial unique index, and neither is worth assuming behaves
// identically. The Postgres leg is skipped unless TEST_DATABASE_URL is set,
// matching TestOpenPool.
func TestEnsureUserByTelegramCapture_BackfillsLegacyTelegramLoginID(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertLegacyTelegramLoginIDBackfill(t, newTestStore(t), 90210)
	})
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		t.Run("postgres", func(t *testing.T) {
			assertLegacyTelegramLoginIDBackfill(t, newPostgresTestStore(t, dsn), 90211)
		})
	}
}

// newPostgresTestStore opens and migrates the Postgres database named by
// TEST_DATABASE_URL. It skips rather than fails when the server is not
// reachable, so a developer without a local Postgres sees the same green run
// as CI without it.
func newPostgresTestStore(t *testing.T, dsn string) *Store {
	t.Helper()
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 5, 2)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	c, err := crypto.New(makeKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	return &Store{DB: conn, Crypt: c}
}

// assertLegacyTelegramLoginIDBackfill is the dialect-independent body. tgID is
// distinct per dialect because the Postgres database is reused across runs.
func assertLegacyTelegramLoginIDBackfill(t *testing.T, s *Store, tgID int64) {
	t.Helper()
	ctx := context.Background()
	syntheticLogin := fmt.Sprintf("tg:%d", tgID)
	// Postgres keeps state between runs; SQLite is fresh each time.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE github_login = $1 OR telegram_login_id = $2`, syntheticLogin, tgID); err != nil {
		t.Fatalf("clear prior row: %v", err)
	}

	// A row that predates telegram_login_id being written: synthetic login
	// present, telegram_login_id NULL. Inserted directly because no current
	// code path can still produce it.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO users(github_login, provider, telegram_display_name) VALUES($1,$2,$3)`,
		syntheticLogin, "tg-mcp", "Legacy Row",
	); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	var legacyID int64
	if err := s.DB.QueryRowContext(ctx, `SELECT id FROM users WHERE github_login = $1`, syntheticLogin).Scan(&legacyID); err != nil {
		t.Fatalf("read seeded id: %v", err)
	}

	var before sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_login_id FROM users WHERE id = $1`, legacyID,
	).Scan(&before); err != nil {
		t.Fatalf("read seeded telegram_login_id: %v", err)
	}
	if before.Valid {
		t.Fatalf("seed is not a legacy row: telegram_login_id = %d, want NULL", before.Int64)
	}

	id, err := s.EnsureUserByTelegramCapture(ctx, TelegramIdentityCapture{
		TelegramID: tgID,
		Username:   "legacyuser",
		FirstName:  "Legacy",
		Source:     "telegram_oidc",
		CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	if id != legacyID {
		t.Fatalf("capture returned id %d, want the legacy row %d -- a second user was created", id, legacyID)
	}

	var after sql.NullInt64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_login_id FROM users WHERE id = $1`, legacyID,
	).Scan(&after); err != nil {
		t.Fatalf("read telegram_login_id: %v", err)
	}
	if !after.Valid || after.Int64 != tgID {
		t.Errorf("telegram_login_id = %v, want %d backfilled by the capture", after, tgID)
	}

	var dupes int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE github_login = $1 OR telegram_login_id = $2`, syntheticLogin, tgID,
	).Scan(&dupes); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if dupes != 1 {
		t.Errorf("%d rows carry this identity, want 1 -- the capture duplicated the legacy user", dupes)
	}

	// The point of the backfill: the lookups keyed on telegram_login_id now
	// see the user. Before the fix each of these missed it.
	gotID, err := s.UserIDByTelegramID(ctx, tgID)
	if err != nil {
		t.Fatalf("UserIDByTelegramID after backfill: %v", err)
	}
	if gotID != legacyID {
		t.Errorf("UserIDByTelegramID = %d, want %d", gotID, legacyID)
	}
	rows, err := s.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities: %v", err)
	}
	var seen bool
	for _, r := range rows {
		if r.TelegramID == tgID {
			seen = true
		}
	}
	if !seen {
		t.Errorf("ListIdentities does not include telegram id %d after backfill", tgID)
	}
}
