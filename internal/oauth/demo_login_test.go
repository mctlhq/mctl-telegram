package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

const (
	demoTGID     = 210408407 // matches newFakeAuthenticator + admin allowlist
	demoUser     = "openai-reviewer"
	demoPass     = "s3cret-review-pw"
	demoCliState = "client-state-abc"
)

func withDemoReviewer(c *Config) {
	c.DemoReviewerEnabled = true
	c.DemoReviewerUsername = demoUser
	c.DemoReviewerPassword = demoPass
	c.DemoReviewerTGID = demoTGID
}

var demoStateRE = regexp.MustCompile(`name="state" value="([^"]+)"`)

// demoAuthorizeState drives GET /oauth/authorize in demo mode (which renders the
// 200 chooser page rather than a 302) and extracts the server-side state from
// the reviewer form's hidden field.
func demoAuthorizeState(t *testing.T, mux *mockRouter, challenge string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {demoCliState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize (demo) status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `action="/oauth/demo/login"`) {
		t.Fatalf("chooser missing reviewer form: %s", body)
	}
	if !strings.Contains(body, "oauth.telegram.org") {
		t.Fatalf("chooser missing Telegram sign-in link: %s", body)
	}
	m := demoStateRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("chooser missing hidden state field: %s", body)
	}
	return m[1]
}

func postDemoLogin(mux *mockRouter, state, user, pass string) *httptest.ResponseRecorder {
	form := url.Values{"state": {state}, "username": {user}, "password": {pass}}
	req := httptest.NewRequest("POST", "/oauth/demo/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/demo/login", rec, req)
	return rec
}

func TestDemoLogin_HappyPath(t *testing.T) {
	srv := newTestServer(t, withDemoReviewer)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, demoTGID)

	verifier, challenge := pkceVerifierAndChallenge()
	state := demoAuthorizeState(t, mux, challenge)

	rec := postDemoLogin(mux, state, demoUser, demoPass)
	loc := authCodeRedirect(t, rec)
	if loc.Host != "claude.ai" || loc.Path != "/cb" {
		t.Errorf("redirect target = %s", loc)
	}
	if loc.Query().Get("state") != demoCliState {
		t.Errorf("state echo wrong: %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect did not include a code")
	}

	// Exchange the code; the token must resolve to the demo Telegram identity.
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var tokResp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&tokResp); err != nil {
		t.Fatalf("decode token resp: %v", err)
	}
	accessToken, _ := tokResp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("token resp missing access_token")
	}
	c, err := localjwt.Verify(accessToken, testJWTSecret, testIssuer)
	if err != nil {
		t.Fatalf("verify access_token: %v", err)
	}
	if c.TelegramID != demoTGID {
		t.Errorf("TelegramID = %d, want %d", c.TelegramID, demoTGID)
	}
}

func TestDemoLogin_WrongPasswordThenRetry(t *testing.T) {
	srv := newTestServer(t, withDemoReviewer)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, demoTGID)

	_, challenge := pkceVerifierAndChallenge()
	state := demoAuthorizeState(t, mux, challenge)

	// Wrong password: 401, form re-rendered, pending NOT consumed.
	rec := postDemoLogin(mux, state, demoUser, "wrong-pw")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-pw status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `action="/oauth/demo/login"`) {
		t.Errorf("wrong-pw did not re-render the reviewer form")
	}

	// The same state must still be redeemable with the correct password.
	rec = postDemoLogin(mux, state, demoUser, demoPass)
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Errorf("retry redirect missing code: %s", loc)
	}
}

func TestDemoLogin_WrongUsernameRejected(t *testing.T) {
	srv := newTestServer(t, withDemoReviewer)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, demoTGID)

	_, challenge := pkceVerifierAndChallenge()
	state := demoAuthorizeState(t, mux, challenge)

	rec := postDemoLogin(mux, state, "not-the-reviewer", demoPass)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-user status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDemoLogin_DisabledReturns404(t *testing.T) {
	srv := newTestServer(t) // demo mode off
	mux := newMockRouter()
	srv.Register(mux)

	// Authorize still 302s straight to Telegram (no chooser) when disabled.
	_, challenge := pkceVerifierAndChallenge()
	st := stateFromAuthorize(t, mux, challenge)
	if st == "" {
		t.Fatal("expected a Telegram redirect state when demo mode is off")
	}

	rec := postDemoLogin(mux, "any-state", demoUser, demoPass)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("demo login (disabled) status = %d, want 404", rec.Code)
	}
}

func TestDemoLogin_NotProvisioned(t *testing.T) {
	// Demo enabled but no seeded session/user for the demo id.
	srv := newTestServer(t, withDemoReviewer)
	mux := newMockRouter()
	srv.Register(mux)

	_, challenge := pkceVerifierAndChallenge()
	state := demoAuthorizeState(t, mux, challenge)

	rec := postDemoLogin(mux, state, demoUser, demoPass)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("not-provisioned status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestDemoLogin_RateLimited(t *testing.T) {
	srv := newTestServer(t, withDemoReviewer)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, demoTGID)

	_, challenge := pkceVerifierAndChallenge()
	state := demoAuthorizeState(t, mux, challenge)

	// Exhaust the per-IP budget with wrong-password attempts.
	for i := 0; i < demoRateMax; i++ {
		if rec := postDemoLogin(mux, state, demoUser, "wrong-pw"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d", i, rec.Code)
		}
	}
	if rec := postDemoLogin(mux, state, demoUser, "wrong-pw"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit status = %d, want 429", rec.Code)
	}
}
