package oauth

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

type grantCall struct {
	userID      int64
	clientID    string
	redirectURI string
}

// grantRecorder is a connectGrantRecorder that remembers every call.
type grantRecorder struct {
	mu    sync.Mutex
	calls []grantCall
}

func (g *grantRecorder) Granted(_ context.Context, userID int64, clientID, redirectURI string) {
	g.mu.Lock()
	g.calls = append(g.calls, grantCall{userID, clientID, redirectURI})
	g.mu.Unlock()
}

func (g *grantRecorder) snapshot() []grantCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]grantCall(nil), g.calls...)
}

// TestToken_AuthCodeRecordsConnectGrant: a successful authorization_code
// exchange tells the connect funnel who was granted what (issue #960), with
// the internal users.id the issued token authenticates as.
func TestToken_AuthCodeRecordsConnectGrant(t *testing.T) {
	const tgID int64 = 500100101 // the admin obtainAuthorizationCode signs in
	srv := newTestServer(t)
	rec := &grantRecorder{}
	srv.WithConnectFunnel(rec)
	mux := newMockRouter()
	srv.Register(mux)

	authCodeTokens(t, srv, mux)

	uid, err := srv.store.EnsureUserByTelegramID(context.Background(), tgID, "", "")
	if err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	got := rec.snapshot()
	want := []grantCall{{uid, "claude.ai", "https://claude.ai/cb"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("grants = %+v, want %+v", got, want)
	}
}

// Neither a refresh nor a refused exchange is a new grant.
func TestToken_ConnectGrantOnlyOnSuccessfulCodeExchange(t *testing.T) {
	srv := newTestServer(t)
	rec := &grantRecorder{}
	srv.WithConnectFunnel(rec)
	mux := newMockRouter()
	srv.Register(mux)

	verifier, challenge := pkceVerifierAndChallenge()
	cs := obtainAuthorizationCode(t, srv, mux, challenge)
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {cs.code}, "client_id": {"claude.ai"},
		"redirect_uri": {"https://claude.ai/cb"}, "code_verifier": {"wrong-" + verifier},
	}
	if r := doTokenRequest(t, mux, form); r.Code == http.StatusOK {
		t.Fatalf("exchange with a wrong verifier = 200, want a refusal")
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("refused exchange recorded grants %+v", got)
	}

	resp := authCodeTokens(t, srv, mux)
	refreshTok, _ := resp["refresh_token"].(string)
	r := doTokenRequest(t, mux, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshTok}, "client_id": {"claude.ai"},
	})
	if r.Code != http.StatusOK {
		t.Fatalf("refresh = %d %s", r.Code, r.Body.String())
	}
	if got := rec.snapshot(); len(got) != 1 {
		t.Fatalf("grants after one exchange and one refresh = %+v, want exactly one", got)
	}
}
