package main

// e2e_cli_daemon_test.go is the CLI/daemon half of issue #484's Definition of
// Done (and through it #479's): the zero-admin onboarding path driven through
// the REAL client code in this package, against the REAL server handlers.
//
//	fresh config dir -> init -> login -> activate -> daemon
//	  -> read via /bridge -> owner consent -> device-signed refresh -> send
//	  -> daemon restart -> expired credential recovered by PoP (T13)
//
// internal/mcp/zero_admin_e2e_test.go proves the server side of the same
// flow by talking to the endpoints directly. This test is the complement it
// was missing: it runs `init`, `activate` and `daemon` as the shipped
// subcommands run them (runInit, runActivate, serveDaemon), lets the daemon
// dial the real /bridge websocket handler with the credential it obtained
// by itself, and routes MCP tool calls through Hub.Call to that daemon.
//
// Exactly one thing is faked, at exactly one point: the local MTProto
// client. `login` is an interactive Telegram sign-in and cannot run in CI,
// so the test writes the session row the way runLogin's tail does, and the
// daemon's dispatch to Telegram (dispatchToolCall) is replaced by a stub
// that answers list_dialogs and send_message. Nothing on the HTTP or
// websocket path is stubbed.
//
// Two properties are asserted at every step, as in the server-side test:
// telegram_accounts.session_encrypted stays NULL for this account, and the
// audit log shows no operator tool was involved.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/localbridgetest"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
)

const (
	e2eTelegramID = int64(770000484)
	e2eIssuer     = "https://tg.test"
	e2eAudience   = "mcp"
	e2ePassphrase = "correct horse battery staple"
	e2eWait       = 20 * time.Second
)

var e2eSecret = []byte("e2e-secret-value-at-least-32-bytes!!")

// e2eServer is the relevant slice of cmd/server/main.go: the OAuth/activation
// server, the /api/bridge/token exchange, the /bridge websocket handler and
// the MCP surface, all sharing one store, one Hub and one JWT secret.
type e2eServer struct {
	ts    *httptest.Server
	store *db.Store
	hub   *bridge.Hub
}

func newE2EServer(ctx context.Context, t *testing.T) *e2eServer {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "server.db")
	conn, err := db.Open(ctx, sqliteDSN(dbPath)+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", 0, 0)
	if err != nil {
		t.Fatalf("open server db: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate server db: %v", err)
	}
	store := &db.Store{DB: conn}

	oauthSrv, err := oauth.New(ctx, oauth.Config{
		Issuer:      e2eIssuer,
		JWTSecret:   e2eSecret,
		JWTAudience: e2eAudience,
		TelegramOIDC: &localbridgetest.OIDC{Identity: telegramoidc.Identity{
			TelegramID: e2eTelegramID, Username: "zeroadmin", FirstName: "Zero", LastName: "Admin",
		}},
		AccessTokenTTL: time.Hour,
		CodeTTL:        time.Minute,
	}, store)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}

	revocations := localjwt.NewRevocationCache(store, 15*time.Second)
	provider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret: e2eSecret, ExpectedIssuer: e2eIssuer, ExpectedAudience: e2eAudience,
		AudienceRequired: true, RevocationCache: revocations,
	})
	if err != nil {
		t.Fatalf("mcp provider: %v", err)
	}
	bridgeProvider, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
		Secret: e2eSecret, ExpectedIssuer: e2eIssuer, ExpectedAudience: "bridge",
		AudienceRequired: true, RevocationCache: revocations,
	})
	if err != nil {
		t.Fatalf("bridge provider: %v", err)
	}

	hub := bridge.NewHub()
	rm := auth.ResourceMetadata{BaseURL: e2eIssuer, MCPPath: "/mcp"}
	r := chi.NewRouter()
	oauthSrv.Register(r)
	r.With(auth.Middleware(provider, true, nil, rm)).Post("/api/bridge/token",
		bridge.NewBridgeTokenHandler(provider, e2eSecret, e2eIssuer))
	r.Get("/bridge", bridge.NewBridgeHandler(hub, bridgeProvider, store, ctx))
	mcpSrv := mcpapp.New(store, nil, true).WithHub(hub).WithRevocationCache(revocations)
	r.Mount("/mcp", auth.Middleware(provider, true, nil, rm)(mcpSrv.HTTPHandler()))
	// Deliberately NOT mounted: POST /api/mcp/worker-token (the admin mint).
	// The flow under test must never need it, and its absence here means it
	// cannot be reached even by accident.

	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return &e2eServer{ts: ts, store: store, hub: hub}
}

// fakeTelegram stands in for the local MTProto client at dispatchToolCall.
// It records every envelope the daemon handed it so the test can assert
// what reached the daemon (and what did not).
type fakeTelegram struct {
	server string
	mu     sync.Mutex
	calls  []bridge.Envelope
}

func (f *fakeTelegram) dispatch(ctx context.Context, cfg *localConfig, pool *tg.ClientPool, userID int64, env bridge.Envelope) bridge.Envelope {
	f.mu.Lock()
	f.calls = append(f.calls, env)
	f.mu.Unlock()
	// The daemon must hand its real state to the dispatcher: the config it
	// loaded, a live pool over the local store, and the single local user.
	if cfg == nil || cfg.Server != f.server || pool == nil || userID != 1 {
		return bridge.EncodeError(env.ID, "dispatch received unexpected daemon state")
	}
	switch env.Tool {
	case "list_dialogs":
		return bridge.EncodeResponse(env.ID, json.RawMessage(`{"dialogs":[{"peer":"user:1","title":"Alice","unread_count":0}]}`))
	case "send_message":
		var args struct {
			Peer string `json:"peer"`
			Text string `json:"text"`
			Mode string `json:"mode"`
		}
		if err := json.Unmarshal(envArgs(env), &args); err != nil {
			return bridge.EncodeError(env.ID, "send_message: bad args: "+err.Error())
		}
		mode := "draft"
		if args.Mode == "send" {
			mode = "send"
		}
		res, _ := json.Marshal(tg.SendResult{Sent: args.Mode == "send", Mode: mode, PeerInput: args.Peer, Text: args.Text})
		return bridge.EncodeResponse(env.ID, res)
	default:
		return bridge.EncodeError(env.ID, "unknown tool: "+env.Tool)
	}
}

func (f *fakeTelegram) count(tool string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c.Tool == tool {
			n++
		}
	}
	return n
}

func (f *fakeTelegram) lastArgs(tool string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.calls) - 1; i >= 0; i-- {
		if f.calls[i].Tool == tool {
			var m map[string]any
			_ = json.Unmarshal(envArgs(f.calls[i]), &m)
			return m
		}
	}
	return nil
}

// runningDaemon is one serveDaemon invocation: the process's `daemon`
// subcommand, minus the exit code.
type runningDaemon struct {
	stop context.CancelFunc
	done chan error
}

func startDaemon(parent context.Context, t *testing.T, srv *e2eServer, uid int64) *runningDaemon {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	d := &runningDaemon{stop: cancel, done: make(chan error, 1)}
	go func() { d.done <- serveDaemon(ctx) }()
	waitFor(t, "daemon registered at the hub", func() bool { return srv.hub.HasDaemon(uid) })
	return d
}

func (d *runningDaemon) stopAndWait(t *testing.T, srv *e2eServer, uid int64) {
	t.Helper()
	d.stop()
	select {
	case err := <-d.done:
		if err != nil {
			t.Fatalf("daemon exited with error: %v", err)
		}
	case <-time.After(e2eWait):
		t.Fatal("daemon did not stop after cancellation")
	}
	waitFor(t, "hub dropped the stopped daemon", func() bool { return !srv.hub.HasDaemon(uid) })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(e2eWait)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		<-tick.C
	}
}

// captureStdout redirects os.Stdout into a pipe for the duration of fn, so
// the subcommand's own prints (the user code, the "activated" line) can be
// read. onLine, if set, sees every line as it is written, which is how the
// test learns the activation code while runActivate is still polling.
func captureStdout(t *testing.T, onLine func(string), fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	var buf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			line := sc.Text()
			buf.WriteString(line + "\n")
			if onLine != nil {
				onLine(line)
			}
		}
	}()
	func() {
		defer func() {
			os.Stdout = orig
			_ = w.Close()
		}()
		fn()
	}()
	wg.Wait()
	_ = r.Close()
	return buf.String()
}

// mcpCall performs one tools/call against the MCP surface over HTTP, the
// way a real MCP client does: an initialize handshake, then the call with
// the session id it was given. Returns the HTTP status, the tool result's
// isError flag, its text content and its structured content.
type mcpResult struct {
	status     int
	isError    bool
	text       string
	structured map[string]any
}

func mcpCall(t *testing.T, base, bearer, tool string, args map[string]any) mcpResult {
	t.Helper()
	post := func(sessionID string, body any) (*http.Response, map[string]any) {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, base+"/mcp", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+bearer)
		if sessionID != "" {
			req.Header.Set("Mcp-Session-Id", sessionID)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("mcp %s: %v", tool, err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return resp, nil
		}
		payload := data
		if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "data:") {
					payload = []byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))
				}
			}
		}
		var msg map[string]any
		if err := json.Unmarshal(payload, &msg); err != nil {
			t.Fatalf("mcp %s: decode %q: %v", tool, payload, err)
		}
		return resp, msg
	}

	initResp, initMsg := post("", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26", "capabilities": map[string]any{},
			"clientInfo": map[string]any{"name": "e2e", "version": "0"},
		},
	})
	if initResp.StatusCode != http.StatusOK {
		return mcpResult{status: initResp.StatusCode}
	}
	if initMsg["error"] != nil {
		t.Fatalf("mcp initialize error: %v", initMsg["error"])
	}
	sessionID := initResp.Header.Get("Mcp-Session-Id")

	callResp, callMsg := post(sessionID, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": args},
	})
	if callResp.StatusCode != http.StatusOK {
		return mcpResult{status: callResp.StatusCode}
	}
	if callMsg["error"] != nil {
		t.Fatalf("mcp %s: rpc error: %v", tool, callMsg["error"])
	}
	result, _ := callMsg["result"].(map[string]any)
	out := mcpResult{status: http.StatusOK}
	out.isError, _ = result["isError"].(bool)
	if content, ok := result["content"].([]any); ok && len(content) > 0 {
		if first, ok := content[0].(map[string]any); ok {
			out.text, _ = first["text"].(string)
		}
	}
	out.structured, _ = result["structuredContent"].(map[string]any)
	return out
}

func jwtClaims(t *testing.T, token string) localjwt.Claims {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("credential is not a JWT (%d segments)", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var c localjwt.Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return c
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", filepath.Base(path), err)
	}
	// The file must exist on every platform — that part is checked above and is
	// the reason this is not simply skipped. The MODE, however, is a POSIX
	// concept NTFS does not implement: os.Chmod on Windows only toggles the
	// read-only attribute, so Perm() reports 0666 for a file the ACL may or may
	// not protect. Asserting 0600 there would test the Go runtime's emulation,
	// not this program. The gap itself is asserted in perms_windows_test.go.
	if runtime.GOOS == "windows" {
		return
	}
	if got := st.Mode().Perm(); got != want {
		t.Fatalf("%s has mode %o, want %o", filepath.Base(path), got, want)
	}
}

func TestZeroAdminCLIDaemon_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- a fresh config dir, and the passphrase the daemon will read ----
	home := t.TempDir()
	setHome(t, home)
	t.Setenv(passphraseEnv, e2ePassphrase)
	t.Setenv(passphraseFileEnv, "")
	cfgDir := filepath.Join(home, configDir)

	srv := newE2EServer(ctx, t)

	auditCount := func(tool string) int {
		t.Helper()
		var n int
		if err := srv.store.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM audit_logs WHERE tool_name = ? AND status = 'ok'`, tool).Scan(&n); err != nil {
			t.Fatalf("count audit rows for %s: %v", tool, err)
		}
		return n
	}
	assertNoServerSideSession := func(step string) {
		t.Helper()
		var n int
		if err := srv.store.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM telegram_accounts
			  WHERE telegram_user_id = ? AND session_encrypted IS NOT NULL`, e2eTelegramID,
		).Scan(&n); err != nil {
			t.Fatalf("%s: read session_encrypted: %v", step, err)
		}
		if n != 0 {
			t.Fatalf("%s: the server holds %d encrypted session(s) for this account; Local Bridge must hold none", step, n)
		}
	}
	assertNoServerSideSession("before anything")

	// ---- 1. init ----
	//
	// runInit reads TG_API_ID and TG_API_HASH from stdin and the passphrase
	// from the terminal; stdin is a file here and readPassword answers for
	// the terminal. Everything it derives and writes is the real thing.
	stdin := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(stdin, []byte("424242\n0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	stdinFile, err := os.Open(stdin)
	if err != nil {
		t.Fatalf("open stdin: %v", err)
	}
	defer stdinFile.Close()
	origStdin := os.Stdin
	os.Stdin = stdinFile
	origReadPassword := readPassword
	readPassword = func(string) ([]byte, error) { return []byte(e2ePassphrase), nil }
	initOut := captureStdout(t, nil, runInit)
	readPassword = origReadPassword
	os.Stdin = origStdin
	if !strings.Contains(initOut, "Initialized.") {
		t.Fatalf("init output: %q", initOut)
	}
	assertMode(t, filepath.Join(cfgDir, configFileName), 0o600)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("config after init: %v", err)
	}
	if cfg.APIID != 424242 || cfg.KeyCheck == "" || cfg.KeySalt == "" || cfg.Server != "" {
		t.Fatalf("config after init is not what init writes: %+v", cfg)
	}

	// ---- 2. login ----
	//
	// The MTProto sign-in itself (tg.Login) is the one thing that cannot run
	// here. What it leaves behind is a session row in the local, passphrase-
	// sealed store, written by runLogin's tail through the same functions;
	// that is what this writes, with the same key derivation `daemon` will
	// repeat to open it.
	{
		key := mustDeriveVerifiedKey([]byte(e2ePassphrase), cfg)
		store, closeDB, uid := openLocalStore(ctx, encryptionKeyHex(key))
		if err := store.SaveSession(ctx, uid, []byte("mtproto-session-bytes-stay-on-this-machine"), e2eTelegramID, "Zero Admin", "zeroadmin"); err != nil {
			closeDB()
			t.Fatalf("save local session: %v", err)
		}
		closeDB()
		assertMode(t, filepath.Join(cfgDir, dbFileName), 0o600)
	}
	assertNoServerSideSession("after local login")

	// ---- 3. activate ----
	//
	// runActivate prints the verification URI and the user code and polls;
	// the human's browser types the code, signs in with Telegram and
	// approves. The test plays the browser from the code it reads off
	// stdout, exactly as the docs describe the step.
	origSleep := activateSleep
	activateSleep = func(ctx context.Context, _ time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
			return nil
		}
	}
	defer func() { activateSleep = origSleep }()

	codeRe := regexp.MustCompile(`^Enter this code when prompted: (\S+)$`)
	codeCh := make(chan string, 1)
	browser := localbridgetest.NewBrowser(t)
	activateOut := captureStdout(t, func(line string) {
		if m := codeRe.FindStringSubmatch(line); m != nil {
			select {
			case codeCh <- m[1]:
			default:
			}
		}
	}, func() {
		activateDone := make(chan struct{})
		go func() {
			defer close(activateDone)
			runActivate([]string{
				"--telegram-id", strconv.FormatInt(e2eTelegramID, 10),
				"--server", srv.ts.URL,
				"--label", "e2e-laptop",
			})
		}()
		var userCode string
		select {
		case userCode = <-codeCh:
		case <-time.After(e2eWait):
			t.Fatal("activate never printed a user code")
		}
		assertNoServerSideSession("after activate/start")
		consent := localbridgetest.SignIn(t, srv.ts.URL, browser, userCode)
		assertNoServerSideSession("after the Telegram leg, before consent")
		localbridgetest.Approve(t, srv.ts.URL, browser, consent)
		select {
		case <-activateDone:
		case <-time.After(e2eWait):
			t.Fatal("activate did not finish after the browser approved")
		}
	})
	for _, want := range []string{"Device activated (device_id=", "Device is fully activated and ready."} {
		if !strings.Contains(activateOut, want) {
			t.Fatalf("activate output lacks %q:\n%s", want, activateOut)
		}
	}
	assertNoServerSideSession("after activation")
	if auditCount("local_bridge_activate") != 1 || auditCount("local_bridge_device_issue") != 1 {
		t.Fatal("activation did not go through the self-service activate + first-issuance path")
	}

	// What activate leaves on disk: one 0600 device record carrying the
	// identity and the credential, the server address it was told, and no
	// legacy bridge_token.json anywhere.
	assertMode(t, filepath.Join(cfgDir, deviceKeyName), 0o600)
	rec, err := loadDeviceRecordIfPresent()
	if err != nil || rec == nil || !deviceCredentialUsable(rec) {
		t.Fatalf("device record after activate is not a usable credential: rec=%+v err=%v", rec, err)
	}
	if _, _, ok := deviceIdentityUsable(rec.PrivateKey, rec.PublicKey); !ok {
		t.Fatal("device record after activate has unusable key material")
	}
	firstCred := jwtClaims(t, rec.WorkerToken)
	if firstCred.DeviceID != rec.DeviceID || firstCred.Jti != rec.Jti {
		t.Fatalf("credential claims do not match the record: %+v vs %+v", firstCred, rec)
	}
	if hasScope(firstCred.Scopes, "telegram:messages:send") || !hasScope(firstCred.Scopes, "telegram:messages:read") {
		t.Fatalf("first issuance must be read-only: %v", firstCred.Scopes)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, bridgeTokenName)); !os.IsNotExist(err) {
		t.Fatal("activate must not create the legacy bridge_token.json")
	}
	if cfg, err = loadConfig(); err != nil || cfg.Server != srv.ts.URL {
		t.Fatalf("activate --server must persist the server for `daemon` (docs/local-bridge.md, step 3): cfg=%+v err=%v", cfg, err)
	}

	uid, err := srv.store.UserIDByTelegramID(ctx, e2eTelegramID)
	if err != nil {
		t.Fatalf("resolve server-side user: %v", err)
	}

	// ---- 4. daemon ----
	//
	// serveDaemon refreshes the device credential by PoP, exchanges it for a
	// bridge token, opens the local store with the init passphrase, and dials
	// the real /bridge handler. The only substitution is the dispatcher.
	fake := &fakeTelegram{server: srv.ts.URL}
	origDispatch := dispatchToolCall
	dispatchToolCall = fake.dispatch
	defer func() { dispatchToolCall = origDispatch }()

	daemon := startDaemon(ctx, t, srv, uid)
	assertNoServerSideSession("after the daemon connected")
	if n := auditCount("local_bridge_device_refresh"); n != 1 {
		t.Fatalf("daemon start should refresh by PoP exactly once, saw %d refreshes", n)
	}
	// The refresh was merged into the record: this is the credential the
	// MCP client on this device presents from here on.
	if rec, err = loadDeviceRecordIfPresent(); err != nil || rec == nil {
		t.Fatalf("device record after daemon start: %v", err)
	}
	readToken := rec.WorkerToken
	if jwtClaims(t, readToken).Jti != firstCred.Jti {
		t.Fatal("daemon refresh changed the credential lineage (jti)")
	}

	// ---- read: MCP -> Hub.Call -> /bridge -> daemon -> answer ----
	res := mcpCall(t, srv.ts.URL, readToken, "list_dialogs", map[string]any{"limit": 5})
	if res.status != http.StatusOK || res.isError {
		t.Fatalf("list_dialogs over the bridge failed: status=%d isError=%v text=%q", res.status, res.isError, res.text)
	}
	if !strings.Contains(res.text, `"Alice"`) {
		t.Fatalf("list_dialogs did not return the daemon's answer: %q", res.text)
	}
	if fake.count("list_dialogs") != 1 {
		t.Fatalf("daemon dispatched list_dialogs %d times, want 1", fake.count("list_dialogs"))
	}
	if auditCount("list_dialogs") != 1 {
		t.Fatal("no audit row for the bridged read")
	}
	assertNoServerSideSession("after the first read")

	// ---- send before consent: refused server-side, daemon never asked ----
	res = mcpCall(t, srv.ts.URL, readToken, "send_message", map[string]any{"peer": "user:1", "text": "hello"})
	if res.status != http.StatusOK || res.isError {
		t.Fatalf("send_message before consent should be a dry-run, not an error: status=%d text=%q", res.status, res.text)
	}
	if sent, _ := res.structured["sent"].(bool); sent {
		t.Fatalf("a read-only credential sent for real: %v", res.structured)
	}
	if reason, _ := res.structured["dry_reason"].(string); !strings.Contains(reason, "scope") {
		t.Fatalf("dry_reason %q should name the missing scope", reason)
	}
	if fake.count("send_message") != 0 {
		t.Fatal("the daemon was contacted for a send the server had already refused")
	}

	// ---- owner grants send consent from their own session ----
	//
	// The owner's MCP session token is what the OAuth flow issues to the
	// account holder: interactive (no jti, no device), account:manage scope.
	issuer, err := localjwt.NewIssuer(e2eSecret, e2eIssuer)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ownerToken, err := issuer.Mint(localjwt.Claims{
		Subject: "tg:" + strconv.FormatInt(e2eTelegramID, 10), TelegramID: e2eTelegramID,
		Scopes: []string{"account:manage"}, Audience: []string{e2eAudience},
	}, time.Hour)
	if err != nil {
		t.Fatalf("mint owner token: %v", err)
	}
	res = mcpCall(t, srv.ts.URL, ownerToken, "set_send_consent", map[string]any{"enabled": true})
	if res.status != http.StatusOK || res.isError {
		t.Fatalf("owner could not grant send consent: status=%d text=%q", res.status, res.text)
	}
	if enabled, err := srv.store.IsSendEnabled(ctx, uid); err != nil || !enabled {
		t.Fatalf("send_enabled did not flip on the grant: %v %v", enabled, err)
	}

	// ---- device-signed refresh + daemon reconnect ----
	//
	// The send scope arrives with the next refresh, and the daemon refreshes
	// on every connection attempt. Drop its connection server-side (what a
	// relay restart does) and let the real reconnect loop bring it back.
	srv.hub.Unregister(uid)
	waitFor(t, "daemon reconnected after the server dropped it", func() bool { return srv.hub.HasDaemon(uid) })
	if n := auditCount("local_bridge_device_refresh"); n != 2 {
		t.Fatalf("reconnect should have refreshed by PoP once more (2 total), saw %d", n)
	}
	if rec, err = loadDeviceRecordIfPresent(); err != nil || rec == nil {
		t.Fatalf("device record after reconnect: %v", err)
	}
	sendToken := rec.WorkerToken
	sendCred := jwtClaims(t, sendToken)
	if !hasScope(sendCred.Scopes, "telegram:messages:send") {
		t.Fatalf("refresh after consent did not pick up the send scope: %v", sendCred.Scopes)
	}
	if sendCred.Jti != firstCred.Jti {
		t.Fatalf("refresh minted a new jti (%q -> %q); the lineage must carry forward", firstCred.Jti, sendCred.Jti)
	}
	assertNoServerSideSession("after the refresh and reconnect")

	// ---- send: gate passes, daemon is told mode=send, answers sent=true ----
	res = mcpCall(t, srv.ts.URL, sendToken, "send_message", map[string]any{"peer": "user:1", "text": "hello for real"})
	if res.status != http.StatusOK || res.isError {
		t.Fatalf("send_message after consent failed: status=%d text=%q", res.status, res.text)
	}
	if sent, _ := res.structured["sent"].(bool); !sent {
		t.Fatalf("send still not real after consent and refresh: %v", res.structured)
	}
	if fake.count("send_message") != 1 {
		t.Fatalf("daemon dispatched send_message %d times, want 1", fake.count("send_message"))
	}
	if mode, _ := fake.lastArgs("send_message")["mode"].(string); mode != "send" {
		t.Fatalf("the daemon was not told mode=send (got %q); it would have dry-run", mode)
	}
	if auditCount("send_message:via-bridge") != 1 {
		t.Fatal("no audit row for the bridged send")
	}
	assertNoServerSideSession("after the real send")

	// ---- process restart: stop, start again from the same config dir ----
	daemon.stopAndWait(t, srv, uid)
	daemon = startDaemon(ctx, t, srv, uid)
	res = mcpCall(t, srv.ts.URL, sendToken, "list_dialogs", map[string]any{})
	if res.status != http.StatusOK || res.isError || fake.count("list_dialogs") != 2 {
		t.Fatalf("read after restart failed: status=%d isError=%v dispatched=%d", res.status, res.isError, fake.count("list_dialogs"))
	}
	if n := auditCount("local_bridge_device_refresh"); n != 3 {
		t.Fatalf("restart should have refreshed by PoP (3 total), saw %d", n)
	}
	assertNoServerSideSession("after the restart")

	// ---- T13: the device access JWT has expired; nothing else is valid ----
	//
	// Overwrite the stored credential with one that expired an hour ago and
	// prove the server rejects it as a bearer, so the only way back in is
	// possession of the device key. The daemon then starts and recovers
	// through /nonce + /refresh on its own.
	daemon.stopAndWait(t, srv, uid)
	expired, err := issuer.Mint(localjwt.Claims{
		Subject: sendCred.Subject, TelegramID: e2eTelegramID, Scopes: sendCred.Scopes,
		Audience: sendCred.Audience, Jti: sendCred.Jti, OriginalIssuedAt: sendCred.OriginalIssuedAt,
		DeviceID: sendCred.DeviceID, ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	}, 0)
	if err != nil {
		t.Fatalf("mint expired credential: %v", err)
	}
	// Written directly rather than through mergeDeviceCredential, which
	// (correctly) refuses to replace a live credential with a stale one.
	if rec, err = readDeviceRecord(); err != nil {
		t.Fatalf("read device record: %v", err)
	}
	rec.WorkerToken = expired
	rec.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := writeDeviceRecord(rec); err != nil {
		t.Fatalf("install expired credential: %v", err)
	}
	if _, _, ok := deviceIdentityUsable(rec.PrivateKey, rec.PublicKey); !ok {
		t.Fatal("device key material must survive the credential swap")
	}
	if _, err := exchangeForBridgeToken(ctx, cfg, expired); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("an expired device credential must not exchange for a bridge token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, bridgeTokenName)); !os.IsNotExist(err) {
		t.Fatal("a legacy bridge_token.json appeared; the device path must never write one")
	}
	refreshesBefore := auditCount("local_bridge_device_refresh")

	daemon = startDaemon(ctx, t, srv, uid)
	if n := auditCount("local_bridge_device_refresh"); n != refreshesBefore+1 {
		t.Fatalf("recovery from an expired credential must be one PoP refresh, saw %d -> %d", refreshesBefore, n)
	}
	if rec, err = loadDeviceRecordIfPresent(); err != nil || rec == nil {
		t.Fatalf("device record after recovery: %v", err)
	}
	recovered := jwtClaims(t, rec.WorkerToken)
	if rec.WorkerToken == expired || recovered.ExpiresAt <= time.Now().Unix() {
		t.Fatal("the daemon did not replace the expired credential with a live one")
	}
	if recovered.Jti != firstCred.Jti || !hasScope(recovered.Scopes, "telegram:messages:send") {
		t.Fatalf("recovered credential lost its lineage or scopes: %+v", recovered)
	}
	res = mcpCall(t, srv.ts.URL, rec.WorkerToken, "list_dialogs", map[string]any{})
	if res.status != http.StatusOK || res.isError || fake.count("list_dialogs") != 3 {
		t.Fatalf("read after expired-credential recovery failed: status=%d isError=%v dispatched=%d", res.status, res.isError, fake.count("list_dialogs"))
	}
	assertNoServerSideSession("after recovering from an expired credential")
	daemon.stopAndWait(t, srv, uid)

	// ---- and none of it went through an operator ----
	for _, forbidden := range []string{
		"provision_local_account", "set_account_send", "set_account_mode", "mint_worker_token",
	} {
		var n int
		if err := srv.store.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM audit_logs WHERE tool_name = ?`, forbidden).Scan(&n); err != nil {
			t.Fatalf("count audit rows for %s: %v", forbidden, err)
		}
		if n != 0 {
			t.Errorf("zero-admin onboarding used the operator tool %q %d time(s)", forbidden, n)
		}
	}
	if rows, err := srv.store.DB.QueryContext(ctx, `SELECT DISTINCT tool_name FROM audit_logs WHERE status = 'ok' ORDER BY tool_name`); err == nil {
		var seen []string
		for rows.Next() {
			var name string
			_ = rows.Scan(&name)
			seen = append(seen, name)
		}
		rows.Close()
		t.Logf("audit trail: %s", strings.Join(seen, ", "))
	}
}
