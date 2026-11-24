package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const testPASecret = "pa_webhook_secret_for_tests_only_0123456789"

// paTestStore is a migrated in-memory store for one test.
func paTestStore(t *testing.T) *db.Store {
	store, _ := paTestStoreConn(t)
	return store
}

// paTestStoreConn is paTestStore with its connection, for direct reads.
func paTestStoreConn(t *testing.T) (*db.Store, *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return db.NewStore(conn, nil), conn
}

const (
	testPAEncryptionKey = "0707070707070707070707070707070707070707070707070707070707070707"
	testPASigningKey    = "pa-wiring-test-signing-key-not-real-0123456789"
	testPABaseURL       = "https://tg.example"
)

// enablePAEnv sets a complete, valid PA configuration in the environment.
func enablePAEnv(t *testing.T) {
	t.Helper()
	t.Setenv("PA_ENABLED", "true")
	t.Setenv("PA_BOT_TOKEN", "7000000001:pa-test-token-not-real-0123456789")
	t.Setenv("PA_WEBHOOK_SECRET", testPASecret)
	t.Setenv("PA_WEBHOOK_URL", "https://pa.example/pa/bot/webhook")
	t.Setenv("TELEGRAM_LOGIN_BOT_TOKEN", "7000000002:login-test-token-not-real")
	t.Setenv("ENCRYPTION_KEY", testPAEncryptionKey)
	t.Setenv("AUTH_MODE", "local-jwt")
	t.Setenv("OAUTH_JWT_SIGNING_KEY", testPASigningKey)
	t.Setenv("PUBLIC_BASE_URL", testPABaseURL)
	// The preview allowlist: the principals the wiring tests message.
	t.Setenv("PA_ALLOWED_PRINCIPALS", "4242001,4242002,4242003")
}

// paRoutes lists every PA route the router has: the webhook and anything
// under /api/pa.
func paRoutes(mux *chi.Mux) []string {
	var found []string
	_ = chi.Walk(mux, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, "/pa") || strings.HasPrefix(route, "/api/pa") {
			found = append(found, method+" "+route)
		}
		return nil
	})
	return found
}

func postPAWebhook(mux http.Handler, body string) int {
	req := httptest.NewRequest(http.MethodPost, pa.WebhookPath, strings.NewReader(body))
	req.Header.Set(pa.SecretHeader, testPASecret)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w.Code
}

// buildEnabledPA loads the enabled configuration through config.Load and
// builds the runtime on store.
func buildEnabledPA(t *testing.T, store *db.Store) (*config.Config, *paRuntime) {
	t.Helper()
	enablePAEnv(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	rt, err := buildPA(context.Background(), cfg, store, localjwt.NewRevocationCache(store, localjwt.DefaultRevocationCacheTTL), nil)
	if err != nil || rt == nil {
		t.Fatalf("PA_ENABLED on: runtime=%v err=%v", rt, err)
	}
	return cfg, rt
}

// TestBuildPA_InertByDefault: with PA_ENABLED unset (Load's fail-closed
// default) nothing is built and no PA route is registered at all.
func TestBuildPA_InertByDefault(t *testing.T) {
	store := paTestStore(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PAEnabled {
		t.Fatal("PA_ENABLED unset loaded as enabled")
	}
	rt, err := buildPA(context.Background(), cfg, store, localjwt.NewRevocationCache(store, time.Second), nil)
	if err != nil || rt != nil {
		t.Fatalf("PA_ENABLED unset: runtime=%v err=%v, want nil nil", rt, err)
	}
	mux := chi.NewRouter()
	rt.Mount(mux)
	rt.Start(context.Background())
	rt.Shutdown(time.Now().Add(time.Second))
	if r := paRoutes(mux); len(r) != 0 {
		t.Fatalf("PA_ENABLED unset: routes %v registered", r)
	}
	for _, path := range []string{pa.WebhookPath, pa.RouteClaim, pa.RouteTurn, pa.RouteReply, connector.RouteTool} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set(pa.SecretHeader, testPASecret)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("PA_ENABLED unset: %s status = %d, want 404", path, w.Code)
		}
	}
}

// TestBuildPA_EnabledRoutes: with the PA on and no PA server enabled,
// exactly the webhook and the three run-loop routes are mounted. Neither the
// connector's tool route nor any linking route is: they exist only with a
// server enabled (TestBuildPA_WiresToolsOnlyWhenEnabled).
func TestBuildPA_EnabledRoutes(t *testing.T) {
	store := paTestStore(t)
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	// Handle registers every method; compare the distinct paths.
	var routes []string
	for _, r := range paRoutes(mux) {
		routes = append(routes, r[strings.IndexByte(r, ' ')+1:])
	}
	slices.Sort(routes)
	routes = slices.Compact(routes)
	want := []string{pa.WebhookPath, pa.RouteClaim, pa.RouteTurn, pa.RouteReply}
	slices.Sort(want)
	if !slices.Equal(routes, want) {
		t.Fatalf("PA_ENABLED on: routes = %v, want %v", routes, want)
	}
	req := httptest.NewRequest(http.MethodPost, connector.RouteTool, strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("tool route: status = %d, want 404 (not mounted)", w.Code)
	}
	if code := postPAWebhook(mux, `{}`); code != http.StatusOK {
		t.Fatalf("PA_ENABLED on: status = %d, want 200 (malformed update dropped)", code)
	}

	// Through the mounted router, the secret is checked before the method:
	// any method without the secret is a 401, never a router 405 that would
	// confirm the endpoint exists.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodHead, http.MethodDelete} {
		req := httptest.NewRequest(method, pa.WebhookPath, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without secret: status = %d, want 401", method, w.Code)
		}
		req = httptest.NewRequest(method, pa.WebhookPath, nil)
		req.Header.Set(pa.SecretHeader, testPASecret)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s with secret: status = %d, want 405", method, w.Code)
		}
	}
}

// TestBuildPA_AllowlistRefusesOthers: the wired runtime carries
// PA_ALLOWED_PRINCIPALS. A principal not on it gets the fixed refusal and
// nothing else (no consent prompt, no callback); an empty list refuses the
// principal that was on it.
func TestBuildPA_AllowlistRefusesOthers(t *testing.T) {
	for name, list := range map[string]string{"other principal": "4242001,4242002", "empty list": ""} {
		t.Run(name, func(t *testing.T) {
			store, conn := paTestStoreConn(t)
			recordPASends(t)
			enablePAEnv(t)
			t.Setenv("PA_ALLOWED_PRINCIPALS", list)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			rt, err := buildPA(context.Background(), cfg, store, localjwt.NewRevocationCache(store, localjwt.DefaultRevocationCacheTTL), nil)
			if err != nil || rt == nil {
				t.Fatalf("runtime=%v err=%v", rt, err)
			}
			mux := chi.NewRouter()
			rt.Mount(mux)
			from := "4242003"
			if list == "" {
				from = "4242001"
			}
			body := `{"update_id":5001,"message":{"message_id":7,"date":1,"text":"hello",` +
				`"from":{"id":` + from + `,"is_bot":false,"first_name":"Bob"},"chat":{"id":` + from + `,"type":"private"}}}`
			if code := postPAWebhook(mux, body); code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			var callbacks, refusals, other int
			for q, dst := range map[string]*int{
				`SELECT COUNT(*) FROM pa_callbacks`:                                 &callbacks,
				`SELECT COUNT(*) FROM pa_outbox WHERE kind = 'principal_disabled'`:  &refusals,
				`SELECT COUNT(*) FROM pa_outbox WHERE kind <> 'principal_disabled'`: &other,
			} {
				if err := conn.QueryRowContext(context.Background(), q).Scan(dst); err != nil {
					t.Fatal(err)
				}
			}
			if callbacks != 0 || refusals != 1 || other != 0 {
				t.Fatalf("callbacks=%d refusals=%d other=%d, want 0 1 0", callbacks, refusals, other)
			}
		})
	}
}

// TestBuildPA_WebhookRunsConversations: a verified message from a principal
// without consent reaches the Conversations handler, which records a
// consent-prompt callback. pa.InertHandler, the handler before #1343,
// dropped every update and recorded nothing.
func TestBuildPA_WebhookRunsConversations(t *testing.T) {
	store, conn := paTestStoreConn(t)
	sent := recordPASends(t)
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	body := `{"update_id":5001,"message":{"message_id":7,"date":1,"text":"hello",` +
		`"from":{"id":4242001,"is_bot":false,"first_name":"Alice"},"chat":{"id":4242001,"type":"private"}}}`
	if code := postPAWebhook(mux, body); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	var n int
	if err := conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pa_callbacks`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pa_callbacks rows = %d, want 1 (consent prompt)", n)
	}
	// The wired Conversations queue the prompt as a conversation-level
	// outbox row (#1348), and the webhook delivers it after the commit:
	// no RunOutbox pass runs here.
	var button string
	if err := conn.QueryRowContext(context.Background(), `SELECT id FROM pa_callbacks`).Scan(&button); err != nil {
		t.Fatal(err)
	}
	rt.loop.WaitDeliveries()
	got := sent.get()
	if len(got) != 1 || got[0].chat != 4242001 || got[0].text != convo.ConsentText || got[0].button != button {
		t.Fatalf("sent = %+v, want the consent prompt with button %q", got, button)
	}
	var kind, status string
	var update int64
	if err := conn.QueryRowContext(context.Background(),
		`SELECT kind, status, update_id FROM pa_outbox WHERE principal = 4242001`).Scan(&kind, &status, &update); err != nil {
		t.Fatal(err)
	}
	if kind != "consent_prompt" || status != "sent" || update != 5001 {
		t.Fatalf("outbox row = %s %s %d", kind, status, update)
	}
	if a := sent.answers(); len(a) != 0 {
		t.Fatalf("a message update answered callbacks %v", a)
	}
	// Pressing the button: the wired AfterCommit answers the callback query
	// so the client stops its spinner.
	press := `{"update_id":5002,"callback_query":{"id":"cbq-wired","data":"` + button + `",` +
		`"from":{"id":4242001,"is_bot":false},"message":{"message_id":9,"date":1,"chat":{"id":4242001,"type":"private"}}}}`
	if code := postPAWebhook(mux, press); code != http.StatusOK {
		t.Fatalf("press: status = %d, want 200", code)
	}
	rt.loop.WaitDeliveries()
	if a := sent.answers(); !slices.Equal(a, []string{"cbq-wired"}) {
		t.Fatalf("callback answers = %v, want [cbq-wired]", a)
	}
}

// The webhook records the language of each accepted update's sender
// before it delivers anything, so the first answer is already in it.
func TestBuildPA_WebhookRecordsLanguage(t *testing.T) {
	store, _ := paTestStoreConn(t)
	sent := recordPASends(t)
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	body := `{"update_id":5101,"message":{"message_id":7,"date":1,"text":"hello",` +
		`"from":{"id":4242001,"is_bot":false,"first_name":"Alice","language_code":"ru"},"chat":{"id":4242001,"type":"private"}}}`
	if code := postPAWebhook(mux, body); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	rt.loop.WaitDeliveries()
	if sent.langs == nil || sent.langs.Of(4242001) != safetext.LangRU {
		t.Fatal("the sender's Languages did not get the update's language")
	}
}

type paSend struct {
	chat   int64
	text   string
	button string
	// buttons are every button's data, for a card sent with Send.
	buttons []string
	// webApp is the URL of a web_app button (SendWebApp).
	webApp string
}

type paSendRecorder struct {
	// langs is what buildPA handed the sender.
	langs    *output.Languages
	mu       sync.Mutex
	sent     []paSend
	answered []string
	typing   int
	// real is a production output.Sender built from the same token and
	// Mini App URL buildPA passed: SendWebApp runs every one of its
	// checks on what the wired runtime asked to send, so a test sees
	// StartLink's real URL go through checkWebAppURL. Only the Bot API
	// call itself is cut off (a cancelled context), so nothing leaves.
	real *output.Sender
	// refused collects what the real sender refused before its request.
	refused []error
}

func (r *paSendRecorder) AnswerCallback(_ context.Context, id string, _ safetext.Template) error {
	r.mu.Lock()
	r.answered = append(r.answered, id)
	r.mu.Unlock()
	return nil
}

// SendTyping counts the typing statuses the wired run loop sent.
func (r *paSendRecorder) SendTyping(context.Context, int64) error {
	r.mu.Lock()
	r.typing++
	r.mu.Unlock()
	return nil
}

func (r *paSendRecorder) answers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.answered...)
}

func (r *paSendRecorder) SendFrom(_ context.Context, chat int64, text safetext.Text, kb output.Keyboard, from int, done func(int) error) error {
	s := paSend{chat: chat, text: text.String()}
	if len(kb) == 1 && len(kb[0]) == 1 {
		s.button = kb[0][0].Data
	} else {
		// A card with several buttons (an approval card).
		for _, row := range kb {
			for _, b := range row {
				s.buttons = append(s.buttons, b.Data)
			}
		}
	}
	r.mu.Lock()
	r.sent = append(r.sent, s)
	r.mu.Unlock()
	if done != nil {
		return done(text.Parts())
	}
	return nil
}

func (r *paSendRecorder) Send(_ context.Context, chat int64, text safetext.Text, kb output.Keyboard) error {
	s := paSend{chat: chat, text: text.String()}
	for _, row := range kb {
		for _, b := range row {
			s.buttons = append(s.buttons, b.Data)
		}
	}
	r.mu.Lock()
	r.sent = append(r.sent, s)
	r.mu.Unlock()
	return nil
}

func (r *paSendRecorder) SendWebApp(_ context.Context, chat int64, text safetext.Text, label safetext.Template, appURL string) error {
	if r.real != nil {
		// A cancelled context stops the request before it is written,
		// so the only errors that can come back are the sender's own
		// refusals and "request failed: context canceled". Anything
		// else is a refusal of what the runtime built.
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := r.real.SendWebApp(cctx, chat, text, label, appURL); err == nil || !strings.Contains(err.Error(), "request failed: context canceled") {
			r.mu.Lock()
			r.refused = append(r.refused, err)
			r.mu.Unlock()
			return err
		}
	}
	r.mu.Lock()
	r.sent = append(r.sent, paSend{chat: chat, text: text.String(), webApp: appURL})
	r.mu.Unlock()
	return nil
}

func (r *paSendRecorder) refusals() []error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]error(nil), r.refused...)
}

func (r *paSendRecorder) get() []paSend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]paSend(nil), r.sent...)
}

// recordPASends makes buildPA's sender a recorder for this test.
func recordPASends(t *testing.T) *paSendRecorder {
	t.Helper()
	r := &paSendRecorder{}
	prev := newPASender
	newPASender = func(token, webAppURL string, langs *output.Languages) (paBotSender, error) {
		r.langs = langs
		if webAppURL != "" {
			real, err := output.NewSender(output.Config{Token: token, WebAppURL: webAppURL})
			if err != nil {
				return nil, err
			}
			r.real = real
		}
		return r, nil
	}
	t.Cleanup(func() { newPASender = prev })
	return r
}

// TestBuildPA_ClaimAuthenticatesPool: the mounted claim route takes a pool
// token minted with the server's signing key and issuer (204: nothing due)
// and refuses one from another issuer.
func TestBuildPA_ClaimAuthenticatesPool(t *testing.T) {
	store := paTestStore(t)
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	claim := func(issuer string) int {
		iss, err := localjwt.NewIssuer([]byte(testPASigningKey), issuer)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := iss.Mint(localjwt.Claims{
			Subject: "pool:main", Audience: []string{localjwt.PoolAudience}, Jti: "pool-jti-" + issuer,
			OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
		}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, pa.RouteClaim, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	if code := claim(testPABaseURL); code != http.StatusNoContent {
		t.Fatalf("pool token from the server's issuer: status = %d, want 204", code)
	}
	if code := claim("https://other.example"); code != http.StatusUnauthorized {
		t.Fatalf("pool token from another issuer: status = %d, want 401", code)
	}
}

// TestBuildPA_JobTokenRoundTrip drives one run through the built runtime:
// consent through the webhook, a message, a claim with a pool token and a
// turn with the pa-job token the claim minted. A minter and verifier wired
// with different keys or issuers would turn every turn into a 401 after a
// successful claim; this is the test that sees it.
func TestBuildPA_JobTokenRoundTrip(t *testing.T) {
	store, conn := paTestStoreConn(t)
	// The prompt and the replies are delivered after their commits; record
	// them rather than calling the Bot API.
	sent := recordPASends(t)
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	const user = 4242002
	update := int64(6000)
	send := func(kind, payload string) {
		t.Helper()
		update++
		body := fmt.Sprintf(`{"update_id":%d,%q:%s}`, update, kind, payload)
		if code := postPAWebhook(mux, body); code != http.StatusOK {
			t.Fatalf("%s update: status %d", kind, code)
		}
	}
	text := func(s string) {
		send("message", fmt.Sprintf(`{"message_id":7,"date":1,"text":%q,`+
			`"from":{"id":%d,"is_bot":false,"first_name":"Bob"},"chat":{"id":%d,"type":"private"}}`, s, user, user))
	}
	text("hello")
	// The prompt goes out before its button can be pressed, as it does for
	// a real principal: a prompt whose callback is already gone when it
	// comes due is not sent (button_expired).
	rt.loop.WaitDeliveries()
	var button string
	if err := conn.QueryRowContext(context.Background(), `SELECT id FROM pa_callbacks WHERE principal = ?`, user).Scan(&button); err != nil {
		t.Fatalf("consent callback: %v", err)
	}
	send("callback_query", fmt.Sprintf(`{"id":"cb","data":%q,"from":{"id":%d,"is_bot":false},`+
		`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}`, button, user, user))
	text("what is on my calendar")

	iss, err := localjwt.NewIssuer([]byte(testPASigningKey), testPABaseURL)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := iss.Mint(localjwt.Claims{
		Subject: "pool:main", Audience: []string{localjwt.PoolAudience}, Jti: "pool-jti-roundtrip",
		OriginalIssuedAt: time.Now().Add(-time.Minute).Unix(),
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	post := func(route, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, route, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	w := post(pa.RouteClaim, pool, "")
	if w.Code != http.StatusOK {
		t.Fatalf("claim: status %d, want 200 (a run is due)", w.Code)
	}
	var claim struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &claim); err != nil || claim.Token == "" {
		t.Fatalf("claim response without a job token: %v", err)
	}
	if w := post(pa.RouteTurn, claim.Token, `{"context_tokens":100}`); w.Code != http.StatusOK {
		t.Fatalf("turn with the claimed job token: status %d, want 200; body %s", w.Code, w.Body.String())
	}
	if w := post(pa.RouteTurn, pool, `{"context_tokens":100}`); w.Code != http.StatusUnauthorized {
		t.Fatalf("turn with the pool token: status %d, want 401", w.Code)
	}
	// The principal was sent the prompt with the button pressed above,
	// then the acceptance (#1348).
	rt.loop.WaitDeliveries()
	got := sent.get()
	if len(got) != 2 || got[0].text != convo.ConsentText || got[0].button != button ||
		got[1].text != safetext.ServerText(safetext.TextConsentAccepted).String() || got[1].button != "" {
		t.Fatalf("sent = %+v", got)
	}
}

// TestBuildPA_RefusesMissingSecrets: buildPA refuses a hand-built enabled
// configuration without what the run loop is keyed from.
func TestBuildPA_RefusesMissingSecrets(t *testing.T) {
	store := paTestStore(t)
	rc := localjwt.NewRevocationCache(store, time.Second)
	base := func() *config.Config {
		return &config.Config{
			PAEnabled: true, PAWebhookSecret: testPASecret, PABotToken: "7000000001:pa-test-token-not-real-0123456789",
			EncryptionKey: make([]byte, 32), OAUTHJWTSecret: testPASigningKey, OAUTHJWTSecretDedicated: true, PublicBaseURL: testPABaseURL,
			PAConversationTTL: time.Hour, PARateMessages: 20, PARateWindow: time.Hour, PAMaxContextTokens: 1000,
			PABudgetUSDJob: 0.25, PABudgetUSDDay: 2, PABudgetUSDMonth: 20, ManagedBudgetUSDGlobalDay: 20, PAMinTurnUSD: 0.005,
		}
	}
	if rt, err := buildPA(context.Background(), base(), store, rc, nil); err != nil || rt == nil {
		t.Fatalf("control: runtime=%v err=%v", rt, err)
	}
	for name, mutate := range map[string]func(*config.Config){
		"no signing key":     func(c *config.Config) { c.OAUTHJWTSecret = "" },
		"shared signing key": func(c *config.Config) { c.OAUTHJWTSecretDedicated = false },
		"no encryption key":  func(c *config.Config) { c.EncryptionKey = nil },
		"short key":          func(c *config.Config) { c.EncryptionKey = make([]byte, 16) },
		"no bot token":       func(c *config.Config) { c.PABotToken = "" },
		"no webhook secret":  func(c *config.Config) { c.PAWebhookSecret = "" },
	} {
		c := base()
		mutate(c)
		if rt, err := buildPA(context.Background(), c, store, rc, nil); err == nil || rt != nil {
			t.Fatalf("%s: runtime=%v err=%v, want refusal", name, rt, err)
		}
	}
	if _, err := buildPA(context.Background(), base(), store, nil, nil); err == nil {
		t.Fatal("no revocation cache: want refusal")
	}
}

// fakePALoop records the lifecycle calls and blocks WaitDeliveries until
// release is closed.
type fakePALoop struct {
	mu      sync.Mutex
	events  []string
	release chan struct{}
	started chan struct{}
}

func (f *fakePALoop) record(e string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
}

func (f *fakePALoop) RunOutbox(ctx context.Context, interval time.Duration) {
	f.record("run_outbox")
	close(f.started)
	<-ctx.Done()
}

func (f *fakePALoop) WaitDeliveries() {
	f.record("wait_deliveries")
	<-f.release
}

type fakeServer struct{ loop *fakePALoop }

func (s fakeServer) Shutdown(context.Context) error {
	s.loop.record("server_shutdown")
	return nil
}

// TestPARuntime_StartAndShutdownOrder: Start runs the outbox loop, and the
// shutdown stops the HTTP server first and then does not return until the
// in-flight deliveries finish, so main's deferred database close cannot
// run under them.
func TestPARuntime_StartAndShutdownOrder(t *testing.T) {
	f := &fakePALoop{release: make(chan struct{}), started: make(chan struct{})}
	rt := &paRuntime{loop: f}
	ctx, cancel := context.WithCancel(context.Background())
	rt.Start(ctx)
	select {
	case <-f.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not run the outbox loop")
	}
	cancel()
	done := make(chan struct{})
	go func() {
		gracefulShutdown(context.Background(), fakeServer{f}, rt, time.Now().Add(time.Minute))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("shutdown returned while deliveries were still running")
	case <-time.After(200 * time.Millisecond):
	}
	close(f.release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not return after deliveries finished")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	want := []string{"run_outbox", "server_shutdown", "wait_deliveries"}
	if !slices.Equal(f.events, want) {
		t.Fatalf("events = %v, want %v", f.events, want)
	}
}

// TestPARuntime_ShutdownBoundedByDeadline: a delivery that never finishes
// does not hold the process past the deadline.
func TestPARuntime_ShutdownBoundedByDeadline(t *testing.T) {
	f := &fakePALoop{release: make(chan struct{}), started: make(chan struct{})}
	defer close(f.release)
	rt := &paRuntime{loop: f}
	done := make(chan struct{})
	go func() {
		rt.Shutdown(time.Now().Add(100 * time.Millisecond))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown ignored its 100ms deadline")
	}
}
