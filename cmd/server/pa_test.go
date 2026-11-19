package main

import (
	"context"
	"database/sql"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	rt, err := buildPA(cfg, store, localjwt.NewRevocationCache(store, localjwt.DefaultRevocationCacheTTL), nil)
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
	rt, err := buildPA(cfg, store, localjwt.NewRevocationCache(store, time.Second), nil)
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

// TestBuildPA_EnabledRoutes: with the PA on, exactly the webhook and the
// three run-loop routes are mounted. The connector's tool route is not:
// it arrives with the tools slice (#1314), not here.
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

// TestBuildPA_WebhookRunsConversations: a verified message from a principal
// without consent reaches the Conversations handler, which records a
// consent-prompt callback. pa.InertHandler, the handler before #1343,
// dropped every update and recorded nothing.
func TestBuildPA_WebhookRunsConversations(t *testing.T) {
	store, conn := paTestStoreConn(t)
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

// TestBuildPA_RefusesMissingSecrets: buildPA refuses a hand-built enabled
// configuration without what the run loop is keyed from.
func TestBuildPA_RefusesMissingSecrets(t *testing.T) {
	store := paTestStore(t)
	rc := localjwt.NewRevocationCache(store, time.Second)
	base := func() *config.Config {
		return &config.Config{
			PAEnabled: true, PAWebhookSecret: testPASecret, PABotToken: "7000000001:pa-test-token-not-real-0123456789",
			EncryptionKey: make([]byte, 32), OAUTHJWTSecret: testPASigningKey, PublicBaseURL: testPABaseURL,
			PAConversationTTL: time.Hour, PARateMessages: 20, PARateWindow: time.Hour, PAMaxContextTokens: 1000,
			PABudgetUSDJob: 0.25, PABudgetUSDDay: 2, PABudgetUSDMonth: 20, ManagedBudgetUSDGlobalDay: 20, PAMinTurnUSD: 0.005,
		}
	}
	if rt, err := buildPA(base(), store, rc, nil); err != nil || rt == nil {
		t.Fatalf("control: runtime=%v err=%v", rt, err)
	}
	for name, mutate := range map[string]func(*config.Config){
		"no signing key":    func(c *config.Config) { c.OAUTHJWTSecret = "" },
		"no encryption key": func(c *config.Config) { c.EncryptionKey = nil },
		"short key":         func(c *config.Config) { c.EncryptionKey = make([]byte, 16) },
		"no bot token":      func(c *config.Config) { c.PABotToken = "" },
		"no webhook secret": func(c *config.Config) { c.PAWebhookSecret = "" },
	} {
		c := base()
		mutate(c)
		if rt, err := buildPA(c, store, rc, nil); err == nil || rt != nil {
			t.Fatalf("%s: runtime=%v err=%v, want refusal", name, rt, err)
		}
	}
	if _, err := buildPA(base(), store, nil, nil); err == nil {
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
	start := time.Now()
	rt.Shutdown(start.Add(100 * time.Millisecond))
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown took %s past a 100ms deadline", d)
	}
}

// TestPAWiring_NoToolsSliceImports: the server does not build the tools
// slice yet. Its packages (dispatcher, connections and KEK, linking) arrive
// with #1314; until then no non-test file of cmd/server may import them.
func TestPAWiring_NoToolsSliceImports(t *testing.T) {
	forbidden := []string{
		"github.com/mctlhq/mctl-telegram/internal/pa/connector",
		"github.com/mctlhq/mctl-telegram/internal/pa/connection",
		"github.com/mctlhq/mctl-telegram/internal/pa/linking",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports %s before the tools slice", name, path)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no source files read: the guard checked nothing")
	}
}
