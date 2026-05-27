package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
	_ "modernc.org/sqlite"
)

const testIssuer = "https://tg.test"

var testJWTSecret = []byte("oauth-test-secret-32-bytes!!!!!!")

// fakeAuthenticator is the in-package test double for telegramoidc.Authenticator.
// It performs no network call: AuthCodeURL echoes the server-issued state into
// a parseable URL, and Exchange returns a canned Identity while recording the
// code_verifier and nonce it received — so tests can assert the double-PKCE and
// nonce wiring without a live Telegram OP.
type fakeAuthenticator struct {
	identity    *telegramoidc.Identity
	exchangeErr error

	lastNonce         string
	lastChallenge     string
	lastCodeVerifier  string
	lastExpectedNonce string
}

func newFakeAuthenticator() *fakeAuthenticator {
	return &fakeAuthenticator{
		identity: &telegramoidc.Identity{TelegramID: 210408407, Username: "MashkovD", FirstName: "Dmitry"},
	}
}

func (f *fakeAuthenticator) AuthCodeURL(state, nonce, codeChallenge string) string {
	f.lastNonce = nonce
	f.lastChallenge = codeChallenge
	return "https://oauth.telegram.org/auth?" + url.Values{
		"state":          {state},
		"nonce":          {nonce},
		"code_challenge": {codeChallenge},
	}.Encode()
}

func (f *fakeAuthenticator) Exchange(_ context.Context, _, codeVerifier, expectedNonce string) (*telegramoidc.Identity, error) {
	f.lastCodeVerifier = codeVerifier
	f.lastExpectedNonce = expectedNonce
	if f.exchangeErr != nil {
		return nil, f.exchangeErr
	}
	return f.identity, nil
}

// authFake returns the fakeAuthenticator a test server was constructed with.
func authFake(srv *Server) *fakeAuthenticator {
	return srv.tgoidc.(*fakeAuthenticator)
}

func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

func newTestServer(t *testing.T, opts ...func(*Config)) *Server {
	t.Helper()
	cfg := Config{
		Issuer:              testIssuer,
		JWTSecret:           testJWTSecret,
		TelegramOIDC:        newFakeAuthenticator(),
		AdminTelegramIDs:    map[int64]bool{210408407: true},
		AccessTokenTTL:      1 * time.Hour,
		CodeTTL:             1 * time.Minute,
		AllowImplicitClient: true,
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(context.Background(), cfg, newTestStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// pkceVerifierAndChallenge returns a random verifier + its S256 challenge —
// the MCP *client's* PKCE leg, distinct from the Telegram-leg PKCE the server
// generates internally.
func pkceVerifierAndChallenge() (string, string) {
	v := "v_" + base64.RawURLEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz0123456789"))
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

// stateFromAuthorize runs GET /oauth/authorize with the given MCP-client PKCE
// challenge, asserts the 302 to Telegram, and returns the server-side state
// token embedded in the redirect URL.
func stateFromAuthorize(t *testing.T, mux *mockRouter, challenge string) string {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"client-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("authorize redirect parse: %v", err)
	}
	st := loc.Query().Get("state")
	if st == "" {
		t.Fatalf("authorize redirect carried no state: %s", loc)
	}
	return st
}

var interstitialHrefRe = regexp.MustCompile(`class="btnlink" href="([^"]*)"`)

// authCodeRedirect returns the client redirect target (carrying ?code=&state=)
// from a successful authorization step, accepting either the bare 302 (used for
// same-host wizard / loopback clients) or the success interstitial (200,
// rendered for external clients like claude.ai). Both deliver the browser to
// the same redirect_uri, so callers that only care about the final code/state
// are agnostic to which one was emitted.
func authCodeRedirect(t *testing.T, rec *httptest.ResponseRecorder) *url.URL {
	t.Helper()
	switch rec.Code {
	case http.StatusFound:
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatalf("302 redirect parse: %v", err)
		}
		return loc
	case http.StatusOK:
		m := interstitialHrefRe.FindStringSubmatch(rec.Body.String())
		if m == nil {
			t.Fatalf("success interstitial carried no redirect href: %s", rec.Body.String())
		}
		loc, err := url.Parse(html.UnescapeString(m[1]))
		if err != nil {
			t.Fatalf("interstitial href parse: %v", err)
		}
		return loc
	default:
		t.Fatalf("unexpected auth-code status %d: %s", rec.Code, rec.Body.String())
		return nil
	}
}

// callbackWithState runs the Telegram OIDC callback GET (?code=&state=) and
// returns the recorder.
func callbackWithState(t *testing.T, mux *mockRouter, state string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{"state": {state}, "code": {"tg-auth-code"}}
	req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/telegram/callback", rec, req)
	return rec
}

func TestFullFlow_PKCEHappyPath(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)

	// A returning admin already has an MTProto session, so the OIDC callback
	// issues a code directly. A first-time admin without one is routed through
	// enable_access instead (see enable_access_test.go).
	seedSession(t, srv, 210408407)

	// 1. /oauth/authorize — 302 to Telegram, carrying the server state.
	verifier, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)

	// 2. /oauth/telegram/callback — Telegram redirects back with code+state.
	rec := callbackWithState(t, mux, state)
	loc := authCodeRedirect(t, rec)
	if loc.Host != "claude.ai" || loc.Path != "/cb" {
		t.Errorf("redirect target = %s", loc)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("redirect did not include a code")
	}
	if loc.Query().Get("state") != "client-state-abc" {
		t.Errorf("state echo wrong: %q", loc.Query().Get("state"))
	}

	// 3. /oauth/token — exchange the code with the matching verifier.
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

	// 4. Verify the JWT.
	c, err := localjwt.Verify(accessToken, testJWTSecret, testIssuer)
	if err != nil {
		t.Fatalf("verify access_token: %v", err)
	}
	if c.TelegramID != 210408407 {
		t.Errorf("TelegramID = %d", c.TelegramID)
	}
	if c.Subject != "tg:210408407" {
		t.Errorf("Subject = %q", c.Subject)
	}
	// Admin allowlist → expect full scopes.
	if len(c.Scopes) == 0 {
		t.Error("admin user got empty scopes")
	}
}

// TestIssueAuthCode_ExternalRendersInterstitial confirms an external client
// (claude.ai) gets the 200 success interstitial — carrying the code+state in
// the fallback link and a nonce'd auto-redirect script — instead of a bare 302.
func TestIssueAuthCode_ExternalRendersInterstitial(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 210408407)

	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)
	rec := callbackWithState(t, mux, state)

	if rec.Code != http.StatusOK {
		t.Fatalf("external client status = %d, want 200 interstitial; body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "Return to Claude") {
		t.Errorf("interstitial missing the Claude return control: %s", body)
	}
	loc := authCodeRedirect(t, rec)
	if loc.Host != "claude.ai" || loc.Path != "/cb" || loc.Query().Get("code") == "" {
		t.Errorf("interstitial redirect target wrong: %s", loc)
	}
	if loc.Query().Get("state") != "client-state-abc" {
		t.Errorf("interstitial state echo = %q", loc.Query().Get("state"))
	}
	// Exactly the one nonce'd inline script (the auto-redirect) may run.
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'nonce-") {
		t.Errorf("interstitial CSP missing script nonce: %q", csp)
	}
}

func TestConnectAppName(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		{"claude.ai", "Claude"},
		{"console.anthropic.com", "Claude"},
		{"chatgpt.com", "ChatGPT"},
		{"platform.openai.com", "ChatGPT"},
		{"example.com", "your app"},
		{"claude-shim.example.com", "your app"}, // substring must not mislabel
		{"notopenai.com", "your app"},
	}
	for _, c := range cases {
		if got := connectAppName(c.host); got != c.want {
			t.Errorf("connectAppName(%q) = %q, want %q", c.host, got, c.want)
		}
	}
}

// TestDoublePKCE_LegsIndependent confirms the MCP-client PKCE and the
// Telegram-leg PKCE never cross: the verifier handed to Telegram's Exchange is
// the server-generated Telegram-leg one, and the nonce round-trips intact.
func TestDoublePKCE_LegsIndependent(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 210408407)

	clientVerifier, clientChallenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, clientChallenge)
	authCodeRedirect(t, callbackWithState(t, mux, state))

	f := authFake(srv)
	if f.lastCodeVerifier == "" {
		t.Fatal("Exchange received an empty code_verifier")
	}
	if f.lastCodeVerifier == clientVerifier || f.lastCodeVerifier == clientChallenge {
		t.Error("Telegram-leg PKCE verifier collided with the MCP client's PKCE")
	}
	// The challenge sent to Telegram is S256(Telegram-leg verifier).
	sum := sha256.Sum256([]byte(f.lastCodeVerifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); f.lastChallenge != want {
		t.Errorf("Telegram-leg challenge %q is not S256(verifier)", f.lastChallenge)
	}
	// nonce emitted at AuthCodeURL is the nonce checked at Exchange.
	if f.lastNonce == "" || f.lastNonce != f.lastExpectedNonce {
		t.Errorf("nonce mismatch: emitted %q, expected-at-exchange %q", f.lastNonce, f.lastExpectedNonce)
	}
}

// TestTelegramCallback_ErrorRedirect confirms a user who cancels at
// oauth.telegram.org gets a friendly page (not a 500) and that the pending
// state is consumed so the cancelled flow cannot be replayed.
func TestTelegramCallback_ErrorRedirect(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)

	q := url.Values{"state": {state}, "error": {"access_denied"}}
	req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/telegram/callback", rec, req)
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("error redirect produced a 500: %s", rec.Body.String())
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("error redirect status = %d, want a friendly 400 page", rec.Code)
	}

	// The pending entry must already be consumed — a replay is rejected.
	if rec2 := callbackWithState(t, mux, state); rec2.Code != http.StatusBadRequest {
		t.Errorf("state not consumed by the error redirect: replay got %d", rec2.Code)
	}
}

// TestTelegramCallback_ExchangeError_ConsumesState confirms that when the
// Telegram token exchange fails, the callback returns 401 and the pending
// state is still consumed — so a failed flow cannot be replayed.
func TestTelegramCallback_ExchangeError_ConsumesState(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)

	authFake(srv).exchangeErr = errors.New("token endpoint refused the code")
	rec := callbackWithState(t, mux, state)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on exchange error, got %d body=%s", rec.Code, rec.Body.String())
	}
	// No raw error detail leaks to the browser.
	if strings.Contains(rec.Body.String(), "token endpoint refused the code") {
		t.Errorf("raw exchange error leaked to the browser: %s", rec.Body.String())
	}
	// State must be consumed — a replay is rejected.
	if rec2 := callbackWithState(t, mux, state); rec2.Code != http.StatusBadRequest {
		t.Errorf("state not consumed on exchange error: replay got %d", rec2.Code)
	}
}

func TestToken_RejectsWrongVerifier(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	state := obtainAuthorizationCode(t, srv, mux, challenge)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", state.code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", "wrong-verifier")
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("Token endpoint accepted a wrong verifier")
	}
}

func TestToken_RejectsCodeReuse(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	verifier, challenge := pkceVerifierAndChallenge()
	state := obtainAuthorizationCode(t, srv, mux, challenge)
	tokenReq := func() *httptest.ResponseRecorder {
		form := url.Values{}
		form.Set("grant_type", "authorization_code")
		form.Set("code", state.code)
		form.Set("client_id", "claude.ai")
		form.Set("redirect_uri", "https://claude.ai/cb")
		form.Set("code_verifier", verifier)
		req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/token", rec, req)
		return rec
	}
	if rec := tokenReq(); rec.Code != http.StatusOK {
		t.Fatalf("first token exchange failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := tokenReq(); rec.Code == http.StatusOK {
		t.Fatal("code reuse was accepted")
	}
}

func TestValidPKCEString(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid 43-char", strings.Repeat("a", 43), false},
		{"valid 128-char", strings.Repeat("a", 128), false},
		{"valid mixed", "ABCdef-._~0123456789ABCdef-._~0123456789ABC", false},
		{"too short 42", strings.Repeat("a", 42), true},
		{"too long 129", strings.Repeat("a", 129), true},
		{"contains plus", strings.Repeat("a", 42) + "+", true},
		{"contains slash", strings.Repeat("a", 42) + "/", true},
		{"contains space", strings.Repeat("a", 42) + " ", true},
		{"contains equals", strings.Repeat("a", 42) + "=", true},
		{"empty", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validPKCEString(c.input)
			if (err != nil) != c.wantErr {
				t.Errorf("validPKCEString(%q) err=%v, wantErr=%v", c.input, err, c.wantErr)
			}
		})
	}
}

func TestAuthorize_RejectsWeakPKCE(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"code_challenge":        {"short"}, // <43 chars
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak challenge, got %d", rec.Code)
	}
}

func TestToken_RejectsWeakVerifier(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	state := obtainAuthorizationCode(t, srv, mux, challenge)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", state.code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", "short") // <43 chars
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for weak verifier, got %d", rec.Code)
	}
}

func TestRegister_BodySizeCap(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.MaxRegisterBodyBytes = 256 })
	mux := newMockRouter()
	srv.Register(mux)
	body := `{"client_name":"big","redirect_uris":["https://claude.ai/cb"]` +
		strings.Repeat(`,"extra":"x"`, 100) + `}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("/oauth/register accepted a body larger than MaxRegisterBodyBytes")
	}
}

func TestAuthorize_PendingCapEvictsOldest(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.MaxPendingAuth = 2 })
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	open := func() {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {"claude.ai"},
			"redirect_uri":          {"https://claude.ai/cb"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		mux.serve("GET", "/oauth/authorize", rec, req)
	}
	t0 := time.Now()
	srv.clock = func() time.Time { return t0 }
	open()
	srv.clock = func() time.Time { return t0.Add(1 * time.Second) }
	open()
	srv.clock = func() time.Time { return t0.Add(2 * time.Second) }
	open()
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if got := len(srv.pending); got != 2 {
		t.Errorf("pending len = %d, want 2 (cap)", got)
	}
}

func TestAuthorize_MissingPKCE(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {"x"},
		"redirect_uri":  {"https://x/cb"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing PKCE, got %d", rec.Code)
	}
}

func TestAuthorize_RejectsBadImplicitRedirect(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	cases := []struct {
		name     string
		redirect string
	}{
		{"non-https external", "http://attacker.example/cb"},
		{"untrusted host", "https://attacker.example/cb"},
		{"malformed", "://bad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{
				"response_type":         {"code"},
				"client_id":             {"unknown-implicit"},
				"redirect_uri":          {tc.redirect},
				"code_challenge":        {challenge},
				"code_challenge_method": {"S256"},
			}
			req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
			rec := httptest.NewRecorder()
			mux.serve("GET", "/oauth/authorize", rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %s, got %d", tc.name, rec.Code)
			}
		})
	}
}

func TestAuthorize_AllowsLoopbackHTTP(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"unknown-impl"},
		"redirect_uri":          {"http://localhost:9000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 for loopback http, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAuthorize_AllowsIPv6Loopback(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"unknown-impl"},
		"redirect_uri":          {"http://[::1]:9000/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302 for IPv6 loopback http, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"127.0.0.2", false},
		{"example.com", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopbackHost(c.host); got != c.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestTelegramCallback_CodesCapEvictsOldest(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.MaxAuthCodes = 2 })
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()

	// Drive obtainAuthorizationCode 3 times with a monotonic clock so we can
	// identify which auth_code was minted first and confirm it got evicted.
	t0 := time.Now()
	codes := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		offset := time.Duration(i) * time.Second
		srv.clock = func() time.Time { return t0.Add(offset) }
		got := obtainAuthorizationCode(t, srv, mux, challenge)
		codes = append(codes, got.code)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if got := len(srv.codes); got != 2 {
		t.Fatalf("codes len = %d, want 2 (cap)", got)
	}
	if _, ok := srv.codes[codes[0]]; ok {
		t.Errorf("oldest code %s should have been evicted", codes[0])
	}
	if _, ok := srv.codes[codes[2]]; !ok {
		t.Errorf("newest code %s missing after eviction", codes[2])
	}
}

func TestAuthorize_RejectsUnknownClient_WhenImplicitDisabled(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.AllowImplicitClient = false })
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"unknown"},
		"redirect_uri":          {"https://x/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown client when implicit disabled, got %d", rec.Code)
	}
}

func TestToken_EchoesGrantedScope(t *testing.T) {
	// Non-admin telegram id → empty scope set. Token response must reflect
	// that, not echo back whatever the client claimed it wanted.
	srv := newTestServer(t, func(c *Config) {
		c.AdminTelegramIDs = map[int64]bool{} // empty allowlist
	})
	mux := newMockRouter()
	srv.Register(mux)
	authFake(srv).identity = &telegramoidc.Identity{TelegramID: 999} // not an admin

	verifier, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)
	loc := authCodeRedirect(t, callbackWithState(t, mux, state))
	code := loc.Query().Get("code")

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if scope, ok := resp["scope"].(string); !ok {
		t.Fatal("scope field missing from token response")
	} else if scope != "" {
		t.Errorf("non-admin granted scope = %q, want empty", scope)
	}
}

func TestTelegramCallback_RejectsStaleState(t *testing.T) {
	// Fast-forward past CodeTTL between authorize and callback.
	srv := newTestServer(t, func(c *Config) { c.CodeTTL = 1 * time.Second })
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	state := stateFromAuthorize(t, mux, challenge)

	srv.clock = func() time.Time { return time.Now().Add(10 * time.Second) }

	rec := callbackWithState(t, mux, state)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale state, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRegister_RejectsUntrustedRedirect(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	body := `{"client_name":"evil","redirect_uris":["http://attacker.example/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	if rec.Code == http.StatusCreated {
		t.Fatal("registration accepted an attacker-hosted redirect_uri")
	}
}

// TestRegister_AcceptsChatGPTRedirect locks in chatgpt.com as a default
// implicit-host. ChatGPT's connector onboarding posts to /oauth/register
// with a redirect_uri on this host; removing it from the default list
// would break that flow without any other test catching it.
func TestRegister_AcceptsChatGPTRedirect(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	body := `{"client_name":"chatgpt","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestRegister_CapEvictsOldest(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.MaxRegisteredClients = 2 })
	mux := newMockRouter()
	srv.Register(mux)
	register := func(name string) string {
		body := `{"client_name":"` + name + `","redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/register", rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s: status %d body %s", name, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		_ = json.NewDecoder(rec.Body).Decode(&resp)
		return resp["client_id"].(string)
	}
	t0 := time.Now()
	srv.clock = func() time.Time { return t0 }
	id1 := register("first")
	srv.clock = func() time.Time { return t0.Add(1 * time.Second) }
	id2 := register("second")
	srv.clock = func() time.Time { return t0.Add(2 * time.Second) }
	id3 := register("third")
	srv.mu.Lock()
	defer srv.mu.Unlock()
	// The map holds MaxRegisteredClients (2) dynamic entries plus the one
	// built-in connect client, so the total is 3.
	if got := len(srv.clients); got != 3 {
		t.Fatalf("clients len = %d, want 3 (2 dynamic cap + 1 built-in)", got)
	}
	if _, ok := srv.clients[id1]; ok {
		t.Errorf("oldest entry %s should have been evicted", id1)
	}
	if _, ok := srv.clients[id2]; !ok {
		t.Errorf("entry %s missing after eviction", id2)
	}
	if _, ok := srv.clients[id3]; !ok {
		t.Errorf("entry %s missing after eviction", id3)
	}
	if _, ok := srv.clients[ConnectClientID]; !ok {
		t.Errorf("built-in connect client %s should not have been evicted", ConnectClientID)
	}
}

func TestRegister_ReturnsClientID(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	body := `{"client_name":"unit-test","redirect_uris":["http://localhost:9000/cb"]}`
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if cid, _ := resp["client_id"].(string); cid == "" {
		t.Fatal("register response missing client_id")
	}
}

func TestAuthorizationServerMetadata(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/.well-known/oauth-authorization-server", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["issuer"] != testIssuer {
		t.Errorf("issuer = %v", body["issuer"])
	}
	if body["authorization_endpoint"] != testIssuer+"/oauth/authorize" {
		t.Errorf("auth endpoint = %v", body["authorization_endpoint"])
	}
	// scopes_supported is the contract DCR clients (ChatGPT, claude.ai)
	// read to decide which scopes to request. admin:users must NOT
	// appear here: it's implicit-privileged (ResolveScopes grants it
	// based on TG_LOGIN_ADMINS), and advertising it caused client-tier
	// users to see "not all requested permissions were granted" warnings
	// because they cannot ever obtain that scope through DCR.
	scopes, _ := body["scopes_supported"].([]any)
	got := make(map[string]bool, len(scopes))
	for _, s := range scopes {
		str, _ := s.(string)
		got[str] = true
	}
	for _, want := range []string{
		"telegram:dialogs:read",
		"telegram:messages:read",
		"telegram:messages:send",
		"telegram:messages:pin",
	} {
		if !got[want] {
			t.Errorf("scopes_supported missing %q", want)
		}
	}
	if got["admin:users"] {
		t.Errorf("scopes_supported must not include admin:users (privileged, not DCR-negotiable)")
	}
	if len(scopes) != 4 {
		t.Errorf("scopes_supported len = %d, want 4", len(scopes))
	}
}

// TestConnectClient_ValidateClientAcceptsConnectRedirect confirms that the
// pre-registered mctl_self_connect client is accepted by validateClient with
// its exact redirect_uri, and rejected with any other redirect_uri.
func TestConnectClient_ValidateClientAcceptsConnectRedirect(t *testing.T) {
	srv := newTestServer(t)

	connectRedirect := testIssuer + "/telegram/connect/done"
	if err := srv.validateClient(context.Background(), ConnectClientID, connectRedirect); err != nil {
		t.Errorf("validateClient(%q, %q) returned unexpected error: %v", ConnectClientID, connectRedirect, err)
	}

	wrongRedirect := testIssuer + "/telegram/connect/evil"
	if err := srv.validateClient(context.Background(), ConnectClientID, wrongRedirect); err == nil {
		t.Errorf("validateClient(%q, %q) should have rejected a wrong redirect_uri", ConnectClientID, wrongRedirect)
	}
}

// TestConnectClient_NeverSwept confirms that the built-in connect client
// survives a sweep even when ClientRegistrationTTL has elapsed.
func TestConnectClient_NeverSwept(t *testing.T) {
	srv := newTestServer(t, func(c *Config) {
		c.ClientRegistrationTTL = 1 * time.Second
	})

	// Advance clock far past TTL and run a sweep.
	future := time.Now().Add(1 * time.Hour)
	srv.sweep(future)

	srv.mu.Lock()
	_, ok := srv.clients[ConnectClientID]
	srv.mu.Unlock()
	if !ok {
		t.Errorf("built-in connect client was swept, want it to persist indefinitely")
	}
}

// TestConnectClient_NeverEvictedByRegistrationCap confirms that registering
// enough clients to exceed MaxRegisteredClients never evicts the built-in
// connect client (zero CreatedAt is excluded from the dynamic cap and eviction).
func TestConnectClient_NeverEvictedByRegistrationCap(t *testing.T) {
	// Cap at 1 dynamic client. Registering a second dynamic client must evict
	// the first dynamic one, not the built-in connect client.
	srv := newTestServer(t, func(c *Config) {
		c.MaxRegisteredClients = 1
	})
	mux := newMockRouter()
	srv.Register(mux)

	registerClient := func(name string) {
		body := `{"client_name":"` + name + `","redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/register", rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	// Register two dynamic clients: the second evicts the first.
	registerClient("first")
	registerClient("second")

	srv.mu.Lock()
	_, ok := srv.clients[ConnectClientID]
	srv.mu.Unlock()
	if !ok {
		t.Errorf("built-in connect client was evicted by registration cap, want it to persist")
	}
}

// TestExchangeConnect_ValidFlow confirms ExchangeConnect redeems a code that
// was issued for the connect client and returns a non-empty access token.
func TestExchangeConnect_ValidFlow(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 210408407)

	// Drive authorize using the connect client.
	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {ConnectClientID},
		"redirect_uri":          {connectRedirect},
		"state":                 {"connect-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize = %d body=%s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")

	// Telegram callback — issues the authorization code.
	cq := url.Values{"state": {state}, "code": {"tg-code"}}
	req = httptest.NewRequest("GET", "/oauth/telegram/callback?"+cq.Encode(), nil)
	rec = httptest.NewRecorder()
	mux.serve("GET", "/oauth/telegram/callback", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback = %d body=%s", rec.Code, rec.Body.String())
	}
	cbLoc, _ := url.Parse(rec.Header().Get("Location"))
	code := cbLoc.Query().Get("code")
	if code == "" {
		t.Fatal("callback did not return an authorization code")
	}

	// ExchangeConnect should succeed.
	tok, err := srv.ExchangeConnect(context.Background(), code, verifier, ConnectClientID, connectRedirect)
	if err != nil {
		t.Fatalf("ExchangeConnect returned unexpected error: %v", err)
	}
	if tok == "" {
		t.Error("ExchangeConnect returned empty token on success")
	}
}

// TestExchangeConnect_WrongVerifier confirms that ExchangeConnect returns an
// error when the code_verifier does not match the code_challenge.
func TestExchangeConnect_WrongVerifier(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 210408407)

	_, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {ConnectClientID},
		"redirect_uri":          {connectRedirect},
		"state":                 {"connect-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")

	cq := url.Values{"state": {state}, "code": {"tg-code"}}
	req = httptest.NewRequest("GET", "/oauth/telegram/callback?"+cq.Encode(), nil)
	rec = httptest.NewRecorder()
	mux.serve("GET", "/oauth/telegram/callback", rec, req)
	cbLoc, _ := url.Parse(rec.Header().Get("Location"))
	code := cbLoc.Query().Get("code")

	// Use wrong verifier — 43+ chars to pass the format check but wrong value.
	wrongVerifier := strings.Repeat("z", 43)
	_, err := srv.ExchangeConnect(context.Background(), code, wrongVerifier, ConnectClientID, connectRedirect)
	if err == nil {
		t.Error("ExchangeConnect should have rejected a wrong code_verifier")
	}
}

// TestExchangeConnect_ExpiredCode confirms that ExchangeConnect returns an
// error when the authorization code's TTL has elapsed.
func TestExchangeConnect_ExpiredCode(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.CodeTTL = 1 * time.Second })
	mux := newMockRouter()
	srv.Register(mux)
	seedSession(t, srv, 210408407)

	verifier, challenge := pkceVerifierAndChallenge()
	connectRedirect := testIssuer + "/telegram/connect/done"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {ConnectClientID},
		"redirect_uri":          {connectRedirect},
		"state":                 {"connect-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	state := loc.Query().Get("state")

	cq := url.Values{"state": {state}, "code": {"tg-code"}}
	req = httptest.NewRequest("GET", "/oauth/telegram/callback?"+cq.Encode(), nil)
	rec = httptest.NewRecorder()
	mux.serve("GET", "/oauth/telegram/callback", rec, req)
	cbLoc, _ := url.Parse(rec.Header().Get("Location"))
	code := cbLoc.Query().Get("code")

	// Advance the clock past CodeTTL.
	srv.clock = func() time.Time { return time.Now().Add(10 * time.Second) }

	_, err := srv.ExchangeConnect(context.Background(), code, verifier, ConnectClientID, connectRedirect)
	if err == nil {
		t.Error("ExchangeConnect should have rejected an expired code")
	}
}

// TestExchangeConnect_UnknownCode confirms that ExchangeConnect returns an
// error when the code has never been issued.
func TestExchangeConnect_UnknownCode(t *testing.T) {
	srv := newTestServer(t)
	_, err := srv.ExchangeConnect(context.Background(), "bogus-code-value", strings.Repeat("a", 43), ConnectClientID, testIssuer+"/telegram/connect/done")
	if err == nil {
		t.Error("ExchangeConnect should have rejected an unknown code")
	}
}

// TestExchangeConnect_WrongClientID confirms that ExchangeConnect rejects any
// client_id that is not ConnectClientID.
func TestExchangeConnect_WrongClientID(t *testing.T) {
	srv := newTestServer(t)
	_, err := srv.ExchangeConnect(context.Background(), "some-code", strings.Repeat("a", 43), "other-client", testIssuer+"/telegram/connect/done")
	if err == nil {
		t.Error("ExchangeConnect should reject a client_id that is not ConnectClientID")
	}
	if !strings.Contains(err.Error(), "client_id") {
		t.Errorf("error should mention client_id, got: %v", err)
	}
}

// --- helpers ---

// codeState carries the short-lived authorization_code obtained by driving the
// authorize + Telegram-callback steps, for tests that exercise /oauth/token.
type codeState struct {
	code string
}

// obtainAuthorizationCode runs authorize + the Telegram OIDC callback and
// returns the issued authorization_code. The fake authenticator resolves the
// returning admin (210408407); seedSession gives that admin a session so the
// callback issues a code directly instead of diverting into enable_access.
func obtainAuthorizationCode(t *testing.T, srv *Server, mux *mockRouter, challenge string) codeState {
	t.Helper()
	seedSession(t, srv, 210408407)
	state := stateFromAuthorize(t, mux, challenge)
	loc := authCodeRedirect(t, callbackWithState(t, mux, state))
	return codeState{code: loc.Query().Get("code")}
}

// mockRouter is the tiniest possible chi-like router we can hand the Server
// for tests. Keeps server_test.go from depending on chi.
type mockRouter struct {
	getH  map[string]http.HandlerFunc
	postH map[string]http.HandlerFunc
}

func newMockRouter() *mockRouter {
	return &mockRouter{
		getH:  map[string]http.HandlerFunc{},
		postH: map[string]http.HandlerFunc{},
	}
}

// TestAuthorize_LongState guards the OpenAI Apps platform, whose relay state
// (openai_platform_oauth_relay__<base64 JSON>) runs ~525 bytes and once tripped
// a 512-byte cap. A realistic long state must be accepted (302 to Telegram);
// only an abusive multi-KB state is rejected.
func TestAuthorize_LongState(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)

	_, challenge := pkceVerifierAndChallenge()

	authorize := func(state string) *httptest.ResponseRecorder {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {"claude.ai"},
			"redirect_uri":          {"https://claude.ai/cb"},
			"state":                 {state},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		mux.serve("GET", "/oauth/authorize", rec, req)
		return rec
	}

	if rec := authorize("openai_platform_oauth_relay__" + strings.Repeat("a", 600)); rec.Code != http.StatusFound {
		t.Fatalf("629-byte state: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := authorize(strings.Repeat("a", 4096)); rec.Code != http.StatusFound {
		t.Fatalf("at-limit 4096-byte state: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec := authorize(strings.Repeat("a", 4097)); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "state exceeds 4096 bytes") {
		t.Fatalf("4097-byte state: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func (m *mockRouter) Get(p string, h http.HandlerFunc)  { m.getH[p] = h }
func (m *mockRouter) Post(p string, h http.HandlerFunc) { m.postH[p] = h }

func (m *mockRouter) serve(method, p string, w http.ResponseWriter, r *http.Request) {
	var h http.HandlerFunc
	switch method {
	case "GET":
		h = m.getH[p]
	case "POST":
		h = m.postH[p]
	}
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}
