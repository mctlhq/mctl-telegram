package linking_test

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// Test ids in this package are the threat model's S1-L1..S1-L14
// (docs/agent-runtime/personal-assistant-threat-model.md, T1). Every test
// runs the real flow over the real internal/db store, on SQLite always and
// on Postgres when TEST_DATABASE_URL is set, against a fake authorization
// server, a fake identity source and a fake messenger. No real server is
// contacted; alice is only ever tested against the fake.
//
// Personas: Alice is the principal, Bob is another Telegram user. Their ids
// are synthetic and unique per test.

const (
	paBotToken    = "7000000001:fake-pa-bot-token"
	loginBotToken = "7000000002:fake-login-bot-token"
	appURL        = "https://pa.example.test/pa/link/app"
)

func forEachDialect(t *testing.T, fn func(t *testing.T, s *db.Store)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, newSQLiteStore(t)) })
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		ctx := context.Background()
		conn, err := db.Open(ctx, dsn, 5, 2)
		if err != nil {
			t.Skipf("postgres not available: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := db.MigrateCached(ctx, conn); err != nil {
			t.Fatal(err)
		}
		fn(t, &db.Store{DB: conn})
	})
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func newSQLiteStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:pa_link_"+randHex(t, 8)+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return &db.Store{DB: conn}
}

// --- clock ---

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// --- fake authorization server ---

type grant struct {
	challenge, redirect, resource, clientID, scope string
	login                                          linking.Account
	used                                           bool
}

// fakeAS is an authorization server for both catalog servers. Its
// authorize endpoint is a function: the test says who logs in.
type fakeAS struct {
	mu        sync.Mutex
	server    connection.Server
	issuer    string
	codes     map[string]*grant
	accounts  map[string]linking.Account // access token -> account
	exchanges int
	n         int
	// grantScope overrides the scope of issued tokens when set.
	grantScope string
}

func newFakeAS(server connection.Server) *fakeAS {
	return &fakeAS{server: server, issuer: "https://as." + string(server) + ".example.test",
		codes: map[string]*grant{}, accounts: map[string]linking.Account{}}
}

// authorize is the browser's trip to the authorization endpoint: it checks
// the request, lets login sign in, and returns the callback query the
// server redirects to.
func (a *fakeAS) authorize(t *testing.T, authURL string, login linking.Account) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"response_type": "code", "code_challenge_method": "S256", "prompt": "consent",
		"resource": "https://mcp." + string(a.server) + ".example.test/mcp",
	} {
		if q.Get(k) != want {
			t.Fatalf("authorize %s = %q, want %q", k, q.Get(k), want)
		}
	}
	if len(q.Get("code_challenge")) != 43 || len(q.Get("state")) != 43 {
		t.Fatalf("authorize: challenge or state has the wrong shape")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	code := fmt.Sprintf("fake-code-%s-%d-%s", a.server, a.n, randHex(t, 4))
	a.codes[code] = &grant{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"),
		resource: q.Get("resource"), clientID: q.Get("client_id"), scope: q.Get("scope"), login: login}
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {a.issuer}}
}

func (a *fakeAS) exchangeCount() int { a.mu.Lock(); defer a.mu.Unlock(); return a.exchanges }

func (a *fakeAS) exchange(req linking.ExchangeRequest) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.exchanges++
	g := a.codes[req.Code.Reveal()]
	if g == nil || g.used {
		return nil, errors.New("invalid_grant")
	}
	g.used = true
	sum := sha256.Sum256([]byte(req.Verifier.Reveal()))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
		return nil, errors.New("invalid_grant: pkce")
	}
	if req.RedirectURI != g.redirect || req.Resource != g.resource || req.ClientID != g.clientID {
		return nil, errors.New("invalid_grant: binding")
	}
	a.n++
	at := fmt.Sprintf("fake-at-%s-%d", a.server, a.n)
	rt := fmt.Sprintf("fake-rt-%s-%d", a.server, a.n)
	a.accounts[at] = g.login
	scope := g.scope
	if a.grantScope != "" {
		scope = a.grantScope
	}
	return json.Marshal(map[string]any{"access_token": at, "refresh_token": rt, "token_type": "Bearer",
		"expires_in": 3600, "scope": scope})
}

type tokenClient struct{ as map[connection.Server]*fakeAS }

func (c tokenClient) ExchangeCode(_ context.Context, server connection.Server, req linking.ExchangeRequest) ([]byte, error) {
	return c.as[server].exchange(req)
}

// accountSource is the identity call made with the new token (tg:
// get_my_identity). err, when set, fails it; override replaces the answer.
type accountSource struct {
	as       map[connection.Server]*fakeAS
	mu       sync.Mutex
	err      error
	override *linking.Account
	calls    int
}

func (s *accountSource) Account(_ context.Context, server connection.Server, at connection.Secret) (linking.Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return linking.Account{}, s.err
	}
	if s.override != nil {
		return *s.override, nil
	}
	a := s.as[server]
	a.mu.Lock()
	defer a.mu.Unlock()
	acct, ok := a.accounts[at.Reveal()]
	if !ok {
		return linking.Account{}, errors.New("401 unknown token")
	}
	return acct, nil
}

// --- messenger, revoker ---

type sent struct {
	chat int64
	card linking.Card
}

type messenger struct {
	mu    sync.Mutex
	cards []sent
	err   error
}

func (m *messenger) SendCard(_ context.Context, chat int64, c linking.Card) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.cards = append(m.cards, sent{chat, c})
	return nil
}

func (m *messenger) all() []sent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]sent(nil), m.cards...)
}

type revoker struct {
	mu     sync.Mutex
	tokens []string
}

func (r *revoker) Revoke(_ context.Context, _ connection.Server, tok connection.Secret, _ connection.TokenHint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens = append(r.tokens, tok.Reveal())
	return nil
}

func (r *revoker) has(tok string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.tokens {
		if t == tok {
			return true
		}
	}
	return false
}

func (r *revoker) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.tokens) }

type auditor struct{}

func (auditor) RecordFenced(context.Context, connection.FenceEvent) error { return nil }

// --- harness ---

type harness struct {
	t        *testing.T
	s        *db.Store
	clock    *clock
	m        *connection.Manager
	svc      *linking.Service
	servers  map[connection.Server]linking.ServerConfig
	as       map[connection.Server]*fakeAS
	accounts *accountSource
	msgr     *messenger
	revoker  *revoker
	alice    int64
	bob      int64
}

func serverConfig(server connection.Server, enabled bool) linking.ServerConfig {
	host := "https://as." + string(server) + ".example.test"
	return linking.ServerConfig{
		Enabled: enabled, Issuer: host, RequireIss: true,
		AuthorizationEndpoint: host + "/authorize", TokenEndpoint: host + "/token",
		ClientID: "pa-client-" + string(server), RedirectURI: "https://pa.example.test/pa/oauth/callback/" + string(server),
		Resource: "https://mcp." + string(server) + ".example.test/mcp", PromptConsent: true,
	}
}

// newHarness builds the flow with tg enabled and alice at aliceEnabled.
func newHarness(t *testing.T, s *db.Store, aliceEnabled bool) *harness {
	t.Helper()
	h := &harness{t: t, s: s, clock: &clock{t: time.Now().UTC().Truncate(time.Second)},
		msgr: &messenger{}, revoker: &revoker{}}
	h.as = map[connection.Server]*fakeAS{
		connection.ServerTG: newFakeAS(connection.ServerTG), connection.ServerAlice: newFakeAS(connection.ServerAlice),
	}
	h.accounts = &accountSource{as: h.as}
	h.servers = map[connection.Server]linking.ServerConfig{
		connection.ServerTG:    serverConfig(connection.ServerTG, true),
		connection.ServerAlice: serverConfig(connection.ServerAlice, aliceEnabled),
	}
	kek, err := connection.NewLocalKEK([]byte("0123456789abcdef0123456789abcdef"), "test")
	if err != nil {
		t.Fatal(err)
	}
	h.m, err = connection.NewManager(connection.Config{Store: s, KEK: kek, Revoker: h.revoker, Auditor: auditor{}, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	h.svc, err = linking.New(linking.Config{
		BotToken: paBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
		AppURL: appURL, Servers: h.servers, Manager: h.m, Store: s, Tokens: tokenClient{h.as},
		Accounts: h.accounts, Messenger: h.msgr, Now: h.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	if err != nil {
		t.Fatal(err)
	}
	h.alice = 9_500_000_000 + n.Int64()*2
	h.bob = h.alice + 1
	t.Cleanup(func() {
		for _, p := range []int64{h.alice, h.bob} {
			_, _ = s.DB.Exec(`DELETE FROM pa_link_secrets WHERE principal = $1`, p)
			_, _ = s.DB.Exec(`DELETE FROM pa_connections WHERE principal = $1`, p)
			_, _ = s.DB.Exec(`DELETE FROM users WHERE telegram_login_id = $1`, p)
		}
	})
	return h
}

// rebuild replaces the manager's store and the token client, keeping the
// rest of the harness.
func (h *harness) rebuild(store connection.Store, tokens linking.TokenClient) {
	h.t.Helper()
	kek, err := connection.NewLocalKEK([]byte("0123456789abcdef0123456789abcdef"), "test")
	if err != nil {
		h.t.Fatal(err)
	}
	h.m, err = connection.NewManager(connection.Config{Store: store, KEK: kek, Revoker: h.revoker, Auditor: auditor{}, Now: h.clock.Now})
	if err != nil {
		h.t.Fatal(err)
	}
	h.svc, err = linking.New(linking.Config{
		BotToken: paBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
		AppURL: appURL, Servers: h.servers, Manager: h.m, Store: h.s, Tokens: tokens,
		Accounts: h.accounts, Messenger: h.msgr, Now: h.clock.Now,
	})
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) setEnabled(server connection.Server, on bool) {
	sc := h.servers[server]
	sc.Enabled = on
	h.servers[server] = sc
}

func principal(t *testing.T, id int64) pa.Principal {
	t.Helper()
	body := fmt.Sprintf(`{"update_id":1,"message":{"message_id":1,"from":{"id":%d,"is_bot":false,"first_name":"Alice"},"chat":{"id":%d,"type":"private"},"text":"/connect"}}`, id, id)
	u, outcome := pa.Filter([]byte(body))
	if outcome != pa.OutcomeAccepted {
		t.Fatalf("filter: %s", outcome)
	}
	return u.Principal()
}

// callbackUpdate is a confirm-card button press by from.
func callbackUpdate(t *testing.T, from int64, data string) pa.VerifiedUpdate {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"update_id": 2, "callback_query": map[string]any{
		"id": "cbq-1", "data": data, "from": map[string]any{"id": from, "is_bot": false, "first_name": "Alice"},
		"message": map[string]any{"message_id": 5, "chat": map[string]any{"id": from, "type": "private"}},
	}})
	u, outcome := pa.Filter(body)
	if outcome != pa.OutcomeAccepted {
		t.Fatalf("filter: %s", outcome)
	}
	return u
}

// signInitData is what Telegram does for a Mini App launch. It is written
// here from the Bot API rules, independently of the verifier.
func signInitData(token string, fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	lines := make([]string, len(keys))
	v := url.Values{}
	for i, k := range keys {
		lines[i] = k + "=" + fields[k]
		v.Set(k, fields[k])
	}
	sk := hmac.New(sha256.New, []byte("WebAppData"))
	sk.Write([]byte(token))
	m := hmac.New(sha256.New, sk.Sum(nil))
	m.Write([]byte(strings.Join(lines, "\n")))
	v.Set("hash", hex.EncodeToString(m.Sum(nil)))
	return v.Encode()
}

func initDataFields(user int64, firstName string, at time.Time, startParam string) map[string]string {
	f := map[string]string{
		"auth_date": strconv.FormatInt(at.Unix(), 10),
		"query_id":  "AAF-fake-query",
		"user":      fmt.Sprintf(`{"id":%d,"first_name":%q,"language_code":"en"}`, user, firstName),
	}
	if startParam != "" {
		f["start_param"] = startParam
	}
	return f
}

// initData is a valid launch of the PA bot's Mini App by user, now.
func (h *harness) initData(user int64, startParam string) string {
	name := "Alice"
	if user == h.bob {
		name = "Bob"
	}
	return signInitData(paBotToken, initDataFields(user, name, h.clock.Now(), startParam))
}

func linkFromURL(t *testing.T, appLink string) string {
	t.Helper()
	u, err := url.Parse(appLink)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("link")
}

func startapp(t *testing.T, deepLink string) string {
	t.Helper()
	u, err := url.Parse(deepLink)
	if err != nil || u.Host != "t.me" || u.Path != "/fake_pa_bot/link" {
		t.Fatalf("deep link %q", deepLink)
	}
	return u.Query().Get("startapp")
}

// --- flow steps ---

func (h *harness) connection(server connection.Server) connection.Connection {
	h.t.Helper()
	cs, err := h.m.List(context.Background(), h.alice)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []connection.Connection
	for _, c := range cs {
		if c.Server == server {
			out = append(out, c)
		}
	}
	if len(out) != 1 {
		h.t.Fatalf("%d %s connections, want 1", len(out), server)
	}
	return out[0]
}

func (h *harness) start(server connection.Server) string {
	h.t.Helper()
	link, err := h.svc.StartLink(context.Background(), principal(h.t, h.alice), server)
	if err != nil {
		h.t.Fatalf("start: %v", err)
	}
	return linkFromURL(h.t, link)
}

func (h *harness) begin(link string) string {
	h.t.Helper()
	authURL, err := h.svc.BeginOAuth(context.Background(), h.initData(h.alice, ""), link)
	if err != nil {
		h.t.Fatalf("begin: %v", err)
	}
	return authURL
}

// toCallback runs /connect through the authorization server, with login
// signing in, and returns the callback query.
func (h *harness) toCallback(server connection.Server, login linking.Account) url.Values {
	h.t.Helper()
	return h.as[server].authorize(h.t, h.begin(h.start(server)), login)
}

// toCompletion continues through the callback and the handoff page and
// returns the completion code.
func (h *harness) toCompletion(server connection.Server, login linking.Account) string {
	h.t.Helper()
	ctx := context.Background()
	res, err := h.svc.Callback(ctx, server, h.toCallback(server, login))
	if err != nil {
		h.t.Fatalf("callback: %v", err)
	}
	link, _, err := h.svc.Handoff(ctx, res.Handoff)
	if err != nil {
		h.t.Fatalf("handoff: %v", err)
	}
	return startapp(h.t, link)
}

// toConfirm runs the flow to the confirm card and returns its card.
func (h *harness) toConfirm(server connection.Server, login linking.Account) linking.Card {
	h.t.Helper()
	code := h.toCompletion(server, login)
	if err := h.svc.Complete(context.Background(), h.initData(h.alice, code)); err != nil {
		h.t.Fatalf("complete: %v", err)
	}
	cards := h.msgr.all()
	if len(cards) == 0 || cards[len(cards)-1].chat != h.alice {
		h.t.Fatalf("no confirm card for the principal: %+v", cards)
	}
	return cards[len(cards)-1].card
}

func (h *harness) tgLogin(id int64) linking.Account {
	return linking.Account{ID: "telegram:" + strconv.FormatInt(id, 10), TelegramID: id, DisplayName: "Alice"}
}

func (h *harness) state(server connection.Server) connection.State {
	h.t.Helper()
	return h.connection(server).State
}

func confirmData(c linking.Card) (confirm, cancel string) {
	for _, b := range c.Buttons {
		switch b.Label {
		case "Confirm":
			confirm = b.Data
		case "Cancel":
			cancel = b.Data
		}
	}
	return confirm, cancel
}
