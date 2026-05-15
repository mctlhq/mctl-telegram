package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
	_ "modernc.org/sqlite"
)

const (
	testBotToken    = "123456:test-bot-token"
	testBotUsername = "mctl_test_bot"
	testIssuer      = "https://tg.test"
)

var testJWTSecret = []byte("oauth-test-secret-32-bytes!!!!!!")

func newTestStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared")
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
		BotToken:            testBotToken,
		BotUsername:         testBotUsername,
		AdminTelegramIDs:    map[int64]bool{210408407: true},
		AccessTokenTTL:      1 * time.Hour,
		CodeTTL:             1 * time.Minute,
		AllowImplicitClient: true,
	}
	for _, o := range opts {
		o(&cfg)
	}
	srv, err := New(cfg, newTestStore(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// signWidget produces a valid Telegram widget hash for the given fields,
// using the same SHA256(token) + HMAC-SHA256 routine as Telegram.
func signWidget(t *testing.T, fields map[string]string) string {
	t.Helper()
	secret := sha256.Sum256([]byte(testBotToken))
	keys := make([]string, 0, len(fields))
	for k, v := range fields {
		if k == "hash" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fields[k])
	}
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(b.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// pkceVerifierAndChallenge returns a random verifier + its S256 challenge.
func pkceVerifierAndChallenge() (string, string) {
	v := "v_" + base64.RawURLEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz0123456789"))
	sum := sha256.Sum256([]byte(v))
	return v, base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestFullFlow_PKCEHappyPath(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)

	// 1. /oauth/authorize — receive HTML with serverState embedded.
	verifier, challenge := pkceVerifierAndChallenge()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"state":                 {"client-state-abc"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"telegram:dialogs:read"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authorize status = %d, body = %s", rec.Code, rec.Body.String())
	}
	serverState := extractServerStateFromHTML(t, rec.Body.String())

	// 2. /oauth/telegram/callback — submit a valid widget payload.
	now := time.Now()
	widgetFields := map[string]string{
		"id":         "210408407",
		"username":   "MashkovD",
		"first_name": "Dmitry",
		"auth_date":  strconv.FormatInt(now.Unix(), 10),
	}
	widgetFields["hash"] = signWidget(t, widgetFields)
	form := url.Values{}
	form.Set("st", serverState)
	for k, v := range widgetFields {
		form.Set(k, v)
	}
	req = httptest.NewRequest("POST", "/oauth/telegram/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/telegram/callback", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status = %d, body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("redirect parse: %v", err)
	}
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
	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	req = httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
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

func TestToken_RejectsWrongVerifier(t *testing.T) {
	srv := newTestServer(t)
	mux := newMockRouter()
	srv.Register(mux)
	// Drive flow to obtain a code.
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
	// First exchange — must succeed.
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
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for loopback http, got %d body=%s", rec.Code, rec.Body.String())
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
	verifier, challenge := pkceVerifierAndChallenge()

	// authorize with a fake "requested" scope that the user is NOT entitled to.
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"claude.ai"},
		"redirect_uri":          {"https://claude.ai/cb"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"scope":                 {"telegram:messages:send admin:users"},
	}
	req := httptest.NewRequest("GET", "/oauth/authorize?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	mux.serve("GET", "/oauth/authorize", rec, req)
	state := extractServerStateFromHTML(t, rec.Body.String())

	// widget callback with non-admin id.
	now := time.Now()
	fields := map[string]string{
		"id":        "999", // not in AdminTelegramIDs
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signWidget(t, fields)
	form := url.Values{"st": {state}}
	for k, v := range fields {
		form.Set(k, v)
	}
	req = httptest.NewRequest("POST", "/oauth/telegram/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/telegram/callback", rec, req)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	code := loc.Query().Get("code")

	// token exchange.
	form = url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", "claude.ai")
	form.Set("redirect_uri", "https://claude.ai/cb")
	form.Set("code_verifier", verifier)
	req = httptest.NewRequest("POST", "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/token", rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("token status = %d", rec.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if scope, ok := resp["scope"].(string); !ok {
		t.Fatal("scope field missing from token response")
	} else if scope != "" {
		t.Errorf("non-admin granted scope = %q, want empty (not the requested telegram:messages:send)", scope)
	}
}

func TestLookupClientName_UnregisteredNotBranded(t *testing.T) {
	srv := newTestServer(t)
	got := srv.lookupClientName("attacker-chosen-client-id")
	if strings.Contains(strings.ToLower(got), "claude") {
		t.Errorf("lookupClientName branded unregistered client as Claude: %q", got)
	}
	if !strings.Contains(strings.ToLower(got), "unknown") {
		t.Errorf("expected neutral 'unknown' label, got %q", got)
	}
}

func TestWidgetCallback_RejectsStaleState(t *testing.T) {
	// Override clock to fast-forward past CodeTTL between authorize and callback.
	srv := newTestServer(t, func(c *Config) { c.CodeTTL = 1 * time.Second })
	mux := newMockRouter()
	srv.Register(mux)
	_, challenge := pkceVerifierAndChallenge()
	// Drive only the authorize step.
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
	state := extractServerStateFromHTML(t, rec.Body.String())

	// Fast-forward time on the server's clock so the pending entry is stale.
	now := time.Now().Add(10 * time.Second)
	srv.clock = func() time.Time { return now }

	// Build a valid widget payload — verification should pass — then assert
	// the handler still rejects the request because the pending state is stale.
	widgetFields := map[string]string{
		"id":        "210408407",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	widgetFields["hash"] = signWidget(t, widgetFields)
	form := url.Values{"st": {state}}
	for k, v := range widgetFields {
		form.Set(k, v)
	}
	req = httptest.NewRequest("POST", "/oauth/telegram/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/telegram/callback", rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for stale state, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestLookupClientName_Registered(t *testing.T) {
	srv := newTestServer(t)
	srv.clients["c1"] = &clientReg{
		ClientID:     "c1",
		ClientName:   "Acme Web",
		RedirectURIs: []string{"https://acme.example/cb"},
	}
	if got := srv.lookupClientName("c1"); got != "Acme Web" {
		t.Errorf("lookupClientName(registered) = %q, want %q", got, "Acme Web")
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
}

// --- helpers ---

// obtainAuthorizationCode runs authorize + widget callback and returns the
// short-lived authorization_code, for tests that exercise /oauth/token.
type codeState struct {
	code string
}

func obtainAuthorizationCode(t *testing.T, srv *Server, mux *mockRouter, challenge string) codeState {
	t.Helper()
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
	state := extractServerStateFromHTML(t, rec.Body.String())

	now := time.Now()
	fields := map[string]string{
		"id":        "210408407",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signWidget(t, fields)
	form := url.Values{}
	form.Set("st", state)
	for k, v := range fields {
		form.Set(k, v)
	}
	req = httptest.NewRequest("POST", "/oauth/telegram/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	mux.serve("POST", "/oauth/telegram/callback", rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("callback status %d: %s", rec.Code, rec.Body.String())
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	return codeState{code: loc.Query().Get("code")}
}

func extractServerStateFromHTML(t *testing.T, body string) string {
	t.Helper()
	marker := `name="st" value="`
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("HTML did not contain st input: %s", body)
	}
	rest := body[idx+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatal("HTML st input unterminated")
	}
	return rest[:end]
}

// mockRouter is the tiniest possible chi-like router we can hand the Server
// for tests. Keeps oauth_test.go from depending on chi.
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
