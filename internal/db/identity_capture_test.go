package db

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"
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
