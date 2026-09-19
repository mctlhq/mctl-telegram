package oauth

import (
	"context"
	"database/sql"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
)

// TestHandleTelegramCallback_CapturesIdentityWithProvenance is T2: a fake
// Exchange returning username + first + last name results in a users row
// with each in its own column, identity_source='telegram_oidc' and a
// non-NULL identity_captured_at — driven through the real
// /oauth/telegram/callback handler, not by calling the store directly.
func TestHandleTelegramCallback_CapturesIdentityWithProvenance(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 500100101)

	// newFakeAuthenticator's default identity already carries
	// Username="dana_tg", FirstName="Dana" (no LastName) — the Dana persona
	// from CLAUDE.md — so no new fixture identity is introduced here.
	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)
	rec := callbackWithState(t, mux, state)
	authCodeRedirect(t, rec) // asserts the callback actually succeeded

	var (
		username   sql.NullString
		firstName  sql.NullString
		lastName   sql.NullString
		source     sql.NullString
		capturedAt sql.NullTime
	)
	if err := srv.store.DB.QueryRowContext(context.Background(),
		`SELECT telegram_username, telegram_first_name, telegram_last_name, identity_source, identity_captured_at
		   FROM users WHERE telegram_login_id = $1`, int64(500100101),
	).Scan(&username, &firstName, &lastName, &source, &capturedAt); err != nil {
		t.Fatalf("read captured row: %v", err)
	}
	if username.String != "dana_tg" {
		t.Errorf("telegram_username = %q, want dana_tg", username.String)
	}
	if firstName.String != "Dana" {
		t.Errorf("telegram_first_name = %q, want Dana", firstName.String)
	}
	if lastName.Valid && lastName.String != "" {
		t.Errorf("telegram_last_name = %q, want empty (fake identity carries none)", lastName.String)
	}
	if source.String != "telegram_oidc" {
		t.Errorf("identity_source = %q, want telegram_oidc", source.String)
	}
	if !capturedAt.Valid {
		t.Error("identity_captured_at is NULL, want stamped")
	}
}

// TestHandleTelegramCallback_NoUsernameNoDisplayNameFallback is T3: an
// Exchange that supplies only a Telegram id (and no username) must leave
// telegram_username empty rather than falling back to a display name — the
// defect the whole feature exists to fix.
func TestHandleTelegramCallback_NoUsernameNoDisplayNameFallback(t *testing.T) {
	srv := newTestServer(t)
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: 500100101}
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 500100101)

	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)
	rec := callbackWithState(t, mux, state)
	authCodeRedirect(t, rec)

	var (
		username   sql.NullString
		capturedAt sql.NullTime
	)
	if err := srv.store.DB.QueryRowContext(context.Background(),
		`SELECT telegram_username, identity_captured_at FROM users WHERE telegram_login_id = $1`, int64(500100101),
	).Scan(&username, &capturedAt); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if username.Valid && username.String != "" {
		t.Errorf("telegram_username = %q, want empty — no display-name fallback", username.String)
	}
	if !capturedAt.Valid {
		t.Fatal("identity_captured_at is NULL, want stamped even with no claims supplied")
	}
}
