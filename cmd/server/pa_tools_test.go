package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// The tg server's fake endpoints. Hosts only: every request is routed to
// one httptest server by paRewrite, because the egress clients refuse
// loopback and the configuration refuses anything but https on 443.
const (
	paTGIssuer   = "https://as.tg.example.test"
	paTGAuthz    = paTGIssuer + "/authorize"
	paTGToken    = paTGIssuer + "/token"
	paTGRevoke   = paTGIssuer + "/revoke"
	paTGMCP      = "https://mcp.tg.example.test/mcp"
	paTGClientID = "pa-client-tg"
)

// enablePAToolsEnv is enablePAEnv with the tg server enabled for linking
// and dispatch.
func enablePAToolsEnv(t *testing.T) {
	t.Helper()
	enablePAEnv(t)
	for k, v := range map[string]string{
		"ENV":                                 "preview",
		"PA_KEK_MODE":                         "local",
		"PA_KEK_LOCAL_KEY":                    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
		"PA_BOT_USERNAME":                     "fake_pa_bot",
		"PA_MINI_APP_NAME":                    "link",
		"PA_APP_URL":                          testPABaseURL + config.PAAppPath,
		"PA_SERVER_TG_ENABLED":                "true",
		"PA_SERVER_TG_CLIENT_ID":              paTGClientID,
		"PA_SERVER_TG_ALLOWED_HOSTS":          "as.tg.example.test,mcp.tg.example.test",
		"PA_SERVER_TG_ISSUER":                 paTGIssuer,
		"PA_SERVER_TG_AUTHORIZATION_ENDPOINT": paTGAuthz,
		"PA_SERVER_TG_TOKEN_ENDPOINT":         paTGToken,
		"PA_SERVER_TG_REVOCATION_ENDPOINT":    paTGRevoke,
		"PA_SERVER_TG_MCP_URL":                paTGMCP,
		"PA_SERVER_TG_RESOURCE":               paTGMCP,
	} {
		t.Setenv(k, v)
	}
}

// paRewrite sends every request to the httptest server behind target,
// whatever its URL says.
type paRewrite struct{ target *url.URL }

func (p paRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = p.target.Scheme, p.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

// paFakeAS is the tg authorization server: RFC 8414 metadata and the token
// endpoint. Codes are minted by authorize, the browser's trip.
type paFakeAS struct {
	mu        sync.Mutex
	metadata  map[string]any
	status    int
	codes     map[string]url.Values
	issued    []string
	exchanges int
}

func newPAFakeAS() *paFakeAS {
	return &paFakeAS{codes: map[string]url.Values{}, status: http.StatusOK, metadata: map[string]any{
		"issuer": paTGIssuer, "authorization_endpoint": paTGAuthz, "token_endpoint": paTGToken,
		"revocation_endpoint": paTGRevoke, "authorization_response_iss_parameter_supported": true,
	}}
}

func (a *paFakeAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/oauth-authorization-server":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_ = json.NewEncoder(w).Encode(a.metadata)
	case "/token":
		a.exchanges++
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		q, ok := a.codes[r.PostForm.Get("code")]
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") ||
			r.PostForm.Get("redirect_uri") != q.Get("redirect_uri") || r.PostForm.Get("client_id") != paTGClientID ||
			r.PostForm.Get("resource") != paTGMCP {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		delete(a.codes, r.PostForm.Get("code"))
		at := fmt.Sprintf("fake-at-tg-%d", a.exchanges)
		a.issued = append(a.issued, at)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": at, "refresh_token": "fake-rt-tg-" + strconv.Itoa(a.exchanges),
			"token_type": "Bearer", "expires_in": 3600, "scope": q.Get("scope")})
	default:
		http.NotFound(w, r)
	}
}

// authorize checks the authorization URL and returns the callback query.
func (a *paFakeAS) authorize(t *testing.T, authURL string) url.Values {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil || u.Scheme+"://"+u.Host+u.Path != paTGAuthz {
		t.Fatalf("authorization URL %q", authURL)
	}
	q := u.Query()
	if q.Get("client_id") != paTGClientID || q.Get("code_challenge_method") != "S256" || q.Get("resource") != paTGMCP {
		t.Fatalf("authorization request %v", q)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	code := fmt.Sprintf("fake-code-tg-%d", len(a.codes)+1)
	a.codes[code] = q
	return url.Values{"code": {code}, "state": {q.Get("state")}, "iss": {paTGIssuer}}
}

// paFakeMCP is the tg MCP endpoint: the committed tools/list, the identity
// tool answering for principal, and a text result for any other tool.
type paFakeMCP struct {
	t         *testing.T
	principal int64
	mu        sync.Mutex
	calls     []string
}

func (m *paFakeMCP) Server() string { return "tg" }

func (m *paFakeMCP) ListTools(context.Context, connection.Secret) ([][]byte, error) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		return nil, err
	}
	var snap struct {
		Tools map[string]json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, err
	}
	tools := make([]json.RawMessage, 0, len(snap.Tools))
	for _, d := range snap.Tools {
		tools = append(tools, d)
	}
	page, err := json.Marshal(map[string]any{"tools": tools})
	return [][]byte{page}, err
}

func (m *paFakeMCP) CallTool(_ context.Context, token connection.Secret, tool string, _ json.RawMessage) ([]byte, error) {
	m.mu.Lock()
	m.calls = append(m.calls, tool+" "+token.Reveal())
	m.mu.Unlock()
	if tool == "get_my_identity" {
		return []byte(fmt.Sprintf(`{"content":[{"type":"text","text":"{}"}],"structuredContent":{"telegram_id":%d,"display_name":"Carol"}}`, m.principal)), nil
	}
	return []byte(`{"content":[{"type":"text","text":"no dialogs"}]}`), nil
}

func (m *paFakeMCP) got() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

// paFakeRevoker records every revocation.
type paFakeRevoker struct {
	mu      sync.Mutex
	revoked []string
}

func (r *paFakeRevoker) Revoke(_ context.Context, server connection.Server, token connection.Secret, hint connection.TokenHint) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = append(r.revoked, string(server)+" "+string(hint)+" "+token.Reveal())
	return nil
}

func (r *paFakeRevoker) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.revoked)
}

type paToolsFakes struct {
	as      *paFakeAS
	mcp     *paFakeMCP
	revoker *paFakeRevoker
	// built counts newPAServerNet calls.
	built int
}

// fakePAServerNet points newPAServerNet at the fakes for the test.
func fakePAServerNet(t *testing.T, principal int64) *paToolsFakes {
	t.Helper()
	f := &paToolsFakes{as: newPAFakeAS(), mcp: &paFakeMCP{t: t, principal: principal}, revoker: &paFakeRevoker{}}
	srv := httptest.NewServer(f.as)
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: paRewrite{target: target}, Timeout: 5 * time.Second}
	prev := newPAServerNet
	newPAServerNet = func(s config.PAServer) (paServerNet, error) {
		f.built++
		return paServerNet{Metadata: client, Revoker: f.revoker,
			Tokens:   linking.FormTokenClient{Clients: map[connection.Server]*http.Client{s.Name: client}},
			Endpoint: f.mcp}, nil
	}
	t.Cleanup(func() { newPAServerNet = prev })
	return f
}

// paSignInitData is what Telegram does for a Mini App launch, from the Bot
// API rules (independently of linking.VerifyInitData).
func paSignInitData(user int64, startParam string) string {
	fields := map[string]string{
		"auth_date": strconv.FormatInt(time.Now().Unix(), 10),
		"query_id":  "AAF-fake-query",
		"user":      fmt.Sprintf(`{"id":%d,"first_name":"Carol","language_code":"en"}`, user),
	}
	if startParam != "" {
		fields["start_param"] = startParam
	}
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
	sk.Write([]byte(testPABotToken))
	m := hmac.New(sha256.New, sk.Sum(nil))
	m.Write([]byte(strings.Join(lines, "\n")))
	v.Set("hash", hex.EncodeToString(m.Sum(nil)))
	return v.Encode()
}

var (
	paHandoffField = regexp.MustCompile(`name="handoff" value="([A-Za-z0-9_-]+)"`)
	paStartApp     = regexp.MustCompile(`startapp=([A-Za-z0-9_-]+)`)
)

// TestBuildPA_WiresToolsOnlyWhenEnabled: with PA_SERVER_TG_ENABLED the
// linking routes and the tool route are mounted on top of the base ones;
// without it (TestBuildPA_EnabledRoutes) none of them is, and no server
// client is built.
func TestBuildPA_WiresToolsOnlyWhenEnabled(t *testing.T) {
	f := fakePAServerNet(t, 4242003)
	store := paTestStore(t)
	_, off := buildEnabledPA(t, store)
	if off.tools != nil || off.dispatcher != nil || off.Links() != nil || off.Connections() != nil || f.built != 0 {
		t.Fatalf("tools built with every server off (built %d)", f.built)
	}
	enablePAToolsEnv(t)
	_, on := buildEnabledPA(t, paTestStore(t))
	if on.tools == nil || on.dispatcher == nil || on.Links() == nil || on.Connections() == nil || f.built != 1 {
		t.Fatalf("tools not built with tg enabled (built %d)", f.built)
	}
	mux := chi.NewRouter()
	on.Mount(mux)
	got := paRoutes(mux)
	for _, want := range []string{
		"POST " + connector.RouteTool, "GET " + linking.AppPath, "POST " + linking.BeginPath,
		"POST " + linking.CompletePath, "GET " + linking.CallbackPath, "POST " + linking.HandoffPath,
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("route %s missing from %v", want, got)
		}
	}
}

// TestBuildPA_MetadataRefusesStart: the startup metadata fetch refuses to
// start on an unreadable document, another issuer, or an endpoint the
// configuration names differently, and the error names the variable.
func TestBuildPA_MetadataRefusesStart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(a *paFakeAS)
		want   string
	}{
		{"unreachable", func(a *paFakeAS) { a.status = http.StatusInternalServerError }, "PA_SERVER_TG_ISSUER"},
		{"issuer", func(a *paFakeAS) { a.metadata["issuer"] = "https://as.other.example.test" }, "PA_SERVER_TG_ISSUER"},
		{"authorization", func(a *paFakeAS) { a.metadata["authorization_endpoint"] = paTGIssuer + "/other" }, "PA_SERVER_TG_AUTHORIZATION_ENDPOINT"},
		{"authorization absent", func(a *paFakeAS) { delete(a.metadata, "authorization_endpoint") }, "PA_SERVER_TG_AUTHORIZATION_ENDPOINT"},
		{"token", func(a *paFakeAS) { a.metadata["token_endpoint"] = paTGIssuer + "/other" }, "PA_SERVER_TG_TOKEN_ENDPOINT"},
		{"revocation", func(a *paFakeAS) { a.metadata["revocation_endpoint"] = paTGIssuer + "/other" }, "PA_SERVER_TG_REVOCATION_ENDPOINT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakePAServerNet(t, 4242003)
			tc.mutate(f.as)
			enablePAToolsEnv(t)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			rt, err := buildPA(cfg, paTestStore(t), localjwt.NewRevocationCache(paTestStore(t), localjwt.DefaultRevocationCacheTTL), nil)
			if err == nil || rt != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("buildPA = %v, %v; want a refusal naming %s", rt, err, tc.want)
			}
			if tc.name != "unreachable" && tc.name != "issuer" && !errors.Is(err, errPAMetadataMismatch) {
				t.Fatalf("err = %v, want errPAMetadataMismatch", err)
			}
		})
	}
}

// TestPAToolResolver binds only active connections on enabled servers, and
// only while PA_EXTERNAL_TOOLS_ENABLED and the server flag are on. A failed
// read is a store fault, never an empty set.
func TestPAToolResolver(t *testing.T) {
	pt := &paTools{servers: []connection.Server{connection.ServerTG}}
	var err error
	if pt.pin, err = catalog.LoadPin(); err != nil {
		t.Fatal(err)
	}
	// A write tool and an approval-tier read tool are pinned too: neither
	// is ever bound at claim.
	tg := pt.pin.Servers["tg"]
	w, a := tg.Tools["list_dialogs"], tg.Tools["list_dialogs"]
	w.Class, a.Tier = catalog.ClassWrite, catalog.TierApprove
	tg.Tools["fake_write"], tg.Tools["fake_approve"] = w, a
	flags := connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}}
	var flagErr error
	pt.flags = func() (connector.Flags, error) { return flags, flagErr }
	lister := &paFakeLister{conns: []connection.Connection{
		{ID: "c-active", Server: connection.ServerTG, State: connection.StateActive, AuthorityRevision: 3},
		{ID: "c-pending", Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1},
		{ID: "c-alice", Server: connection.ServerAlice, State: connection.StateActive, AuthorityRevision: 1},
	}}
	resolve := pt.toolResolver(lister)
	ctx := context.Background()
	bound, tools, err := resolve(ctx, nil, 4242003)
	if err != nil || len(bound) != 1 || bound[0].ConnectionID != "c-active" || bound[0].AuthorityRevision != 3 {
		t.Fatalf("bound %+v err %v", bound, err)
	}
	want := []string{"tg/get_messages", "tg/get_my_identity", "tg/list_dialogs", "tg/list_folders", "tg/list_topics", "tg/search_messages"}
	if !slices.Equal(tools, want) {
		t.Fatalf("tools %v, want %v", tools, want)
	}
	for name, set := range map[string]func(){
		"external tools off": func() { flags = connector.Flags{ExternalTools: false, Servers: map[string]bool{"tg": true}} },
		"server off":         func() { flags = connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": false}} },
		"flags unreadable": func() {
			flags, flagErr = connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}}, errors.New("bad flag")
		},
	} {
		flags, flagErr = connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}}, nil
		set()
		bound, tools, err := resolve(ctx, nil, 4242003)
		if err != nil || len(bound) != 0 || len(tools) != 0 {
			t.Fatalf("%s: bound %v tools %v err %v", name, bound, tools, err)
		}
	}
	flags, flagErr = connector.Flags{ExternalTools: true, Servers: map[string]bool{"tg": true}}, nil
	lister.err = errors.New("disk")
	if _, _, err := resolve(ctx, nil, 4242003); !errors.Is(err, jobs.ErrStoreFault) {
		t.Fatalf("store fault: err = %v", err)
	}
}

type paFakeLister struct {
	conns []connection.Connection
	err   error
}

func (l *paFakeLister) ListPAConnectionsTx(context.Context, *sql.Tx, int64) ([]connection.Connection, error) {
	return l.conns, l.err
}

// TestPATools_ConnectDispatchDisconnect is the wired path end to end over
// the HTTP routes, with the authorization server and the MCP endpoint
// faked: /connect tg, the OAuth round trip and the confirm card; a run
// claimed with the tg tools bound, a tool call dispatched through the
// executor and audited; then /disconnect tg revoking at the server.
func TestPATools_ConnectDispatchDisconnect(t *testing.T) {
	const carol = 4242003
	f := fakePAServerNet(t, carol)
	store, conn := paTestStoreConn(t)
	sent := recordPASends(t)
	enablePAToolsEnv(t)
	t.Setenv("PA_EXTERNAL_TOOLS_ENABLED", "true")
	_, rt := buildEnabledPA(t, store)
	mux := chi.NewRouter()
	rt.Mount(mux)
	ctx := context.Background()

	update := int64(7000)
	send := func(kind, payload string) {
		t.Helper()
		update++
		if code := postPAWebhook(mux, fmt.Sprintf(`{"update_id":%d,%q:%s}`, update, kind, payload)); code != http.StatusOK {
			t.Fatalf("%s update: status %d", kind, code)
		}
		rt.loop.WaitDeliveries()
		rt.tools.commands.Wait()
	}
	text := func(s string) {
		send("message", fmt.Sprintf(`{"message_id":7,"date":1,"text":%q,`+
			`"from":{"id":%d,"is_bot":false,"first_name":"Carol"},"chat":{"id":%d,"type":"private"}}`, s, carol, carol))
	}
	press := func(data string) {
		send("callback_query", fmt.Sprintf(`{"id":"cb","data":%q,"from":{"id":%d,"is_bot":false},`+
			`"message":{"message_id":9,"date":1,"chat":{"id":%d,"type":"private"}}}`, data, carol, carol))
	}
	last := func() paSend {
		t.Helper()
		got := sent.get()
		if len(got) == 0 {
			t.Fatal("nothing sent")
		}
		return got[len(got)-1]
	}
	do := func(method, path, ctype, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	// Consent first: linking commands are admitted only with it.
	text("hello")
	var button string
	if err := conn.QueryRowContext(ctx, `SELECT id FROM pa_callbacks WHERE principal = ?`, carol).Scan(&button); err != nil {
		t.Fatal(err)
	}
	press(button)

	// /connect tg: the web_app button carries the link token.
	text("/connect tg")
	app := last()
	appURL, err := url.Parse(app.webApp)
	if err != nil || app.chat != carol || !strings.HasPrefix(app.webApp, testPABaseURL+linking.AppPath+"?") {
		t.Fatalf("connect button %+v", app)
	}
	begin, _ := json.Marshal(map[string]string{"init_data": paSignInitData(carol, ""), "link": appURL.Query().Get("link")})
	w := do(http.MethodPost, linking.BeginPath, "application/json", string(begin))
	var authz struct {
		URL string `json:"url"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &authz) != nil {
		t.Fatalf("begin: %d %s", w.Code, w.Body.String())
	}
	cb := f.as.authorize(t, authz.URL)
	w = do(http.MethodGet, "/pa/oauth/callback/tg?"+cb.Encode(), "", "")
	m := paHandoffField.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || m == nil {
		t.Fatalf("callback: %d", w.Code)
	}
	w = do(http.MethodPost, linking.HandoffPath, "application/x-www-form-urlencoded", url.Values{"handoff": {m[1]}}.Encode())
	m = paStartApp.FindStringSubmatch(w.Body.String())
	if w.Code != http.StatusOK || m == nil {
		t.Fatalf("handoff: %d", w.Code)
	}
	complete, _ := json.Marshal(map[string]string{"init_data": paSignInitData(carol, m[1])})
	if w := do(http.MethodPost, linking.CompletePath, "application/json", string(complete)); w.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	card := last()
	if len(card.buttons) != 2 || !strings.HasPrefix(card.buttons[0], "pa:lc:") {
		t.Fatalf("confirm card %+v", card)
	}
	press(card.buttons[0])
	if got := last().text; got != safetext.ServerText(safetext.TextConnected).String() {
		t.Fatalf("after confirm: %q", got)
	}
	conns, err := rt.Connections().List(ctx, carol)
	if err != nil || len(conns) != 1 || conns[0].State != connection.StateActive || conns[0].AccountID != "telegram:4242003" {
		t.Fatalf("connections %+v err %v", conns, err)
	}

	// A run claimed now has the tg read tools and the connection bound.
	text("what is in my dialogs")
	iss, err := localjwt.NewIssuer([]byte(testPASigningKey), testPABaseURL)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := iss.Mint(localjwt.Claims{
		Subject: "pool:main", Audience: []string{localjwt.PoolAudience}, Jti: "pool-jti-tools",
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
	w = post(pa.RouteClaim, pool, "")
	var claim struct {
		Token   string   `json:"token"`
		ToolSet []string `json:"tool_set"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &claim) != nil || claim.Token == "" {
		t.Fatalf("claim: %d %s", w.Code, w.Body.String())
	}
	if !slices.Contains(claim.ToolSet, "tg/list_dialogs") {
		t.Fatalf("tool set %v", claim.ToolSet)
	}
	call, _ := json.Marshal(map[string]any{"server": "tg", "tool": "list_dialogs", "connection_id": conns[0].ID, "arguments": map[string]any{}})
	w = post(connector.RouteTool, claim.Token, string(call))
	var res struct {
		Status string `json:"status"`
		Output string `json:"output"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.Status != "ok" {
		t.Fatalf("tool call: %d %s", w.Code, w.Body.String())
	}
	at := f.as.issued[len(f.as.issued)-1]
	if calls := f.mcp.got(); !slices.Contains(calls, "list_dialogs "+at) {
		t.Fatalf("MCP calls %v, want list_dialogs with the issued token", calls)
	}
	var audited int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_logs WHERE tool_name = ? AND call_path = ?`,
		connector.AuditToolPrefix+"tg/list_dialogs", connector.AuditCallPath).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited == 0 {
		t.Fatal("the tool call was not audited")
	}

	// /disconnect tg revokes locally and at the server.
	text("/disconnect tg")
	if got := last().text; got != safetext.ServerText(safetext.TextDisconnected).String() {
		t.Fatalf("after /disconnect: %q", got)
	}
	if rv := f.revoker.got(); len(rv) == 0 || !slices.ContainsFunc(rv, func(s string) bool { return strings.HasPrefix(s, "tg ") }) {
		t.Fatalf("revocations %v", rv)
	}
	conns, err = rt.Connections().List(ctx, carol)
	if err != nil || len(conns) != 1 || conns[0].State != connection.StateRevoked {
		t.Fatalf("after /disconnect: %+v err %v", conns, err)
	}
}
