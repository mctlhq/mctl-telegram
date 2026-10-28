package oauth

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/notify"
)

// signInWithBotAccess drives /oauth/authorize and the Telegram callback for
// the Dana persona with the given grant signal, asserts the sign-in issued a
// code, and returns the user's reachability row count.
func signInWithBotAccess(t *testing.T, srv *Server, mux *mockRouter, signal telegramoidc.BotAccess) int64 {
	t.Helper()
	seedSession(t, srv, 500100101)
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: 500100101, Username: "dana_tg", FirstName: "Dana", BotAccess: signal}
	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)
	if loc := authCodeRedirect(t, callbackWithState(t, mux, state)); loc.Query().Get("code") == "" {
		t.Fatalf("signal %q: callback issued no code: %s", signal, loc)
	}
	var uid int64
	if err := srv.store.DB.QueryRowContext(context.Background(),
		`SELECT id FROM users WHERE telegram_login_id = $1`, int64(500100101)).Scan(&uid); err != nil {
		t.Fatalf("read user id: %v", err)
	}
	return uid
}

// T9: only an observed grant writes a reachability row; unknown
// and the zero value complete sign-in and write nothing.
func TestTelegramCallback_BotAccessGrantRecorded(t *testing.T) {
	for _, signal := range []telegramoidc.BotAccess{"", telegramoidc.BotAccessUnknown} {
		srv := newTestServer(t)
		mux := newMockRouter()
		srv.Register(mux)
		uid := signInWithBotAccess(t, srv, mux, signal)
		r, err := srv.store.GetBotReachability(context.Background(), uid)
		if err != nil {
			t.Fatal(err)
		}
		if r != nil {
			t.Errorf("signal %q wrote a reachability row: %+v", signal, r)
		}
	}

	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	uid := signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessGranted)
	r, err := srv.store.GetBotReachability(context.Background(), uid)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil || r.State != notify.StateReachable || r.Source != notify.SourceOIDCBotAccess {
		t.Fatalf("granted sign-in row = %+v, want reachable/%s", r, notify.SourceOIDCBotAccess)
	}
}

// T10: a store failure while recording the grant does not change the sign-in
// outcome.
func TestTelegramCallback_BotAccessStoreErrorDoesNotFailSignIn(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	if _, err := srv.store.DB.ExecContext(context.Background(), `DROP TABLE client_bot_reachability`); err != nil {
		t.Fatal(err)
	}
	signInWithBotAccess(t, srv, mux, telegramoidc.BotAccessGranted)
}
