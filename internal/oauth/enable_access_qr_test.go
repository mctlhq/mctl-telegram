package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gotd/td/tgerr"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const (
	desktopUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
	iPhoneUA  = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1"
	// qrTestToken stands in for the login token inside the QR URL. No page,
	// URL, log line or audit row may carry it.
	qrTestToken = "AQIDBAUGqrLoginTokenForTests"
)

// qrStub fakes telegram.LoginQR. It shows one QR URL, waits for the test to
// "scan" it (or for its QRWait to run out, like the real one), then asks for
// the 2FA password when needPw, and finally plays the identity check: the
// expected account gets its session written, any other is logged out and
// nothing is written, as the deferred session store does.
type qrStub struct {
	scan   chan struct{}
	tgID   int64
	needPw bool
	// err, when set, is returned right after the scan instead of a login.
	err error
	// stall, when set, makes the work after an accepted scan hang until the
	// flow's context ends, the way a stalled HelpGetConfig or write would.
	stall bool
	// gotWait is the LoginConfig.QRWait of the latest call.
	gotWait atomic.Int64
	// release, when set, replaces the scan: the login waits for it whatever
	// happens to its context, then hands its session over and reports a
	// success, the way a scan accepted just as the flow is cancelled would.
	release chan struct{}
	// beforeReturn, when set, runs on a released login right before it
	// returns.
	beforeReturn func()
	// pwBeforeScanHook, when set, asks for the password before reporting
	// the scan: the token import beat the update goroutine's hook.
	pwBeforeScanHook bool
	// afterScan, when set, holds the login right after the scan is reported
	// (LoginConfig.OnQRScanned) until it is closed or the context ends: the
	// import and the account check still running (#931).
	afterScan chan struct{}

	calls   atomic.Int32
	writes  atomic.Int32
	logOuts atomic.Int32
	// lateLogOuts counts the server's logouts of a held session it no
	// longer wanted; deadLogOutCtx records one made on a dead context.
	lateLogOuts   atomic.Int32
	deadLogOutCtx atomic.Bool
}

// handOver gives the login's session to the caller the way LoginQR does:
// through cfg.HoldSession when the caller set it, otherwise written
// straight to the user's row.
func (q *qrStub) handOver(ctx context.Context, store *db.Store, uid int64, cfg telegram.LoginConfig) error {
	q.writes.Add(1)
	if cfg.HoldSession != nil {
		cfg.HoldSession([]byte("fake-qr-session"))
		return nil
	}
	return store.UpdateSessionBlob(ctx, uid, []byte("fake-qr-session"))
}

func newQRStub(tgID int64) *qrStub {
	return &qrStub{scan: make(chan struct{}), tgID: tgID}
}

func (q *qrStub) fn() QRLoginFunc {
	return func(ctx context.Context, _ int, _ string, store *db.Store, uid int64,
		show func(context.Context, string, string) error,
		askPassword func(context.Context) (string, error),
		cfgs ...telegram.LoginConfig,
	) (int64, string, string, error) {
		q.calls.Add(1)
		var cfg telegram.LoginConfig
		if len(cfgs) > 0 {
			cfg = cfgs[0]
		}
		if err := show(ctx, "tg://login?token="+qrTestToken, ""); err != nil {
			return 0, "", "", err
		}
		if q.release != nil {
			<-q.release
			// The hand-over lands before the cancel does.
			if err := q.handOver(context.WithoutCancel(ctx), store, uid, cfg); err != nil {
				return 0, "", "", err
			}
			if q.beforeReturn != nil {
				q.beforeReturn()
			}
			return q.tgID, "Dana", "dana_tg", nil
		}
		waitCtx := ctx
		q.gotWait.Store(int64(cfg.QRWait))
		if cfg.QRWait > 0 {
			var cancel context.CancelFunc
			waitCtx, cancel = context.WithTimeout(ctx, cfg.QRWait)
			defer cancel()
		}
		select {
		case <-q.scan:
		case <-waitCtx.Done():
			if ctx.Err() == nil {
				return 0, "", "", telegram.ErrQRLoginExpired
			}
			return 0, "", "", ctx.Err()
		}
		if cfg.OnQRScanned != nil && !q.pwBeforeScanHook {
			cfg.OnQRScanned()
		}
		if q.afterScan != nil {
			select {
			case <-q.afterScan:
			case <-ctx.Done():
				return 0, "", "", fmt.Errorf("qr login: %w", ctx.Err())
			}
		}
		if q.err != nil {
			return 0, "", "", q.err
		}
		if q.needPw {
			if q.pwBeforeScanHook {
				// The prompt is up; the hook lands while the user types.
				go func() {
					time.Sleep(10 * time.Millisecond)
					cfg.OnQRScanned()
				}()
			}
			if _, err := askPassword(ctx); err != nil {
				return 0, "", "", err
			}
		}
		if cfg.OnQRAccepted != nil {
			cfg.OnQRAccepted()
		}
		if q.stall {
			<-ctx.Done()
			return 0, "", "", fmt.Errorf("qr login: %w", ctx.Err())
		}
		if cfg.WantTelegramID != 0 && q.tgID != cfg.WantTelegramID {
			q.logOuts.Add(1)
			return q.tgID, "Someone Else", "someoneelse", nil
		}
		if err := q.handOver(ctx, store, uid, cfg); err != nil {
			return 0, "", "", err
		}
		return q.tgID, "Dana", "dana_tg", nil
	}
}

// lockedBuffer is a bytes.Buffer safe to write from the login goroutine while
// the test reads it (CI runs with -race).
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureQRLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// flowMetrics records ObserveLoginFlow calls.
type flowMetrics struct {
	mu      sync.Mutex
	results []string
	logOuts []string
}

func (m *flowMetrics) SetOAuthPendingAuthSize(float64)             {}
func (m *flowMetrics) ObserveLoginPhoneStep(string, float64)       {}
func (m *flowMetrics) CountOAuthClientRegistration(string, string) {}
func (m *flowMetrics) CountLoginLogOut(reason, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.logOuts = append(m.logOuts, reason+"/"+outcome)
}
func (m *flowMetrics) ObserveLoginFlow(method, result string, _ float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, method+"/"+result)
}

func (m *flowMetrics) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.results...)
}

func newQRTestServer(t *testing.T, q *qrStub, enabled bool, opts ...func(*Config)) (*Server, *chi.Mux) {
	t.Helper()
	srv, mux := newEnableTestServer(t, stubLogin(false, nil), func(c *Config) {
		c.EnableAccessQREnabled = enabled
		c.TelegramAppName = "Example App"
		for _, o := range opts {
			o(c)
		}
	})
	srv.qrLoginFn = q.fn()
	srv.logOutSessionFn = func(ctx context.Context, _ []byte) error {
		if ctx.Err() != nil {
			q.deadLogOutCtx.Store(true)
		}
		q.lateLogOuts.Add(1)
		return nil
	}
	return srv, mux
}

// driveToPhoneAs is driveToPhone with the browser's User-Agent on the OIDC
// callback, which decides whether the QR button is offered. It returns the
// "es" token and the phone page.
func driveToPhoneAs(t *testing.T, mux *chi.Mux, ua string) (string, string) {
	t.Helper()
	_, challenge := pkceVerifierAndChallenge()
	state := authorizeViaChi(t, mux, challenge)
	q := url.Values{"state": {state}, "code": {"tg-auth-code"}}
	req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
	req.Header.Set("User-Agent", ua)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("callback did not render the phone step: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	return extractInputValue(t, body, "es"), body
}

// startQR posts the QR button and returns the status-page cookie.
func startQR(t *testing.T, mux *chi.Mux, es string) *http.Cookie {
	t.Helper()
	rec := postForm(t, mux, "/oauth/telegram/enable_access/qr", url.Values{"es": {es}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /qr = %d, want 303; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != enableQRStatusPath {
		t.Fatalf("POST /qr redirected to %q, want %q", loc, enableQRStatusPath)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == enableQRCookie {
			return c
		}
	}
	t.Fatal("POST /qr set no status cookie")
	return nil
}

func getQRStatus(t *testing.T, mux *chi.Mux, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", enableQRStatusPath, nil)
	if c != nil {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// pollQRStatus refreshes the status page, like its meta refresh, until the
// body contains want.
func pollQRStatus(t *testing.T, mux *chi.Mux, c *http.Cookie, want string) *httptest.ResponseRecorder {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rec := getQRStatus(t, mux, c)
		if strings.Contains(rec.Body.String(), want) {
			return rec
		}
		if time.Now().After(deadline) {
			t.Fatalf("status page never showed %q; last: %d %s", want, rec.Code, rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// auditRows returns "tool|reason|error" for every audit row of the admin.
func auditRows(t *testing.T, srv *Server) []string {
	t.Helper()
	ctx := context.Background()
	uid, err := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := srv.store.DB.QueryContext(ctx,
		`SELECT tool_name, COALESCE(reason, ''), COALESCE(error, '') FROM audit_logs WHERE user_id = $1 ORDER BY id`, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var tool, reason, msg string
		if err := rows.Scan(&tool, &reason, &msg); err != nil {
			t.Fatal(err)
		}
		out = append(out, tool+"|"+reason+"|"+msg)
	}
	return out
}

// TestEnableQR_FlagOffRefusesEveryRoute pins criterion 3 of #901: with the
// flag off the QR login is not merely hidden. The button is absent, and a
// direct request to each QR route is a 404 that starts nothing.
func TestEnableQR_FlagOffRefusesEveryRoute(t *testing.T) {
	q := newQRStub(500100101)
	_, mux := newQRTestServer(t, q, false)
	es, page := driveToPhoneAs(t, mux, desktopUA)
	if strings.Contains(page, "Sign in with a QR code") {
		t.Error("phone step offers the QR button with the flag off")
	}

	if rec := postForm(t, mux, "/oauth/telegram/enable_access/qr", url.Values{"es": {es}}); rec.Code != http.StatusNotFound {
		t.Errorf("POST /qr = %d, want 404", rec.Code)
	}
	if rec := getQRStatus(t, mux, &http.Cookie{Name: enableQRCookie, Value: es}); rec.Code != http.StatusNotFound {
		t.Errorf("GET /qr/status = %d, want 404", rec.Code)
	}
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/qr/cancel", url.Values{"es": {es}}); rec.Code != http.StatusNotFound {
		t.Errorf("POST /qr/cancel = %d, want 404", rec.Code)
	}
	if n := q.calls.Load(); n != 0 {
		t.Errorf("QR login ran %d times with the flag off", n)
	}
}

// TestEnableQR_ButtonOnlyOnDesktop: the code is scanned with the phone, so a
// phone browser is not offered it.
func TestEnableQR_ButtonOnlyOnDesktop(t *testing.T) {
	_, mux := newQRTestServer(t, newQRStub(500100101), true)
	if _, page := driveToPhoneAs(t, mux, desktopUA); !strings.Contains(page, "Sign in with a QR code") {
		t.Error("desktop browser is not offered the QR button")
	}
	if _, page := driveToPhoneAs(t, mux, iPhoneUA); strings.Contains(page, "Sign in with a QR code") {
		t.Error("phone browser is offered the QR button")
	}
}

// TestEnableQR_EndToEndWithTwoFA is criterion 5 of #901: QR, then the 2FA
// password, then the account check, then a successful connect. Along the way
// the login token stays out of the status URL, the pages' text, the logs and
// the audit.
func TestEnableQR_EndToEndWithTwoFA(t *testing.T) {
	logs := captureQRLog(t)
	q := newQRStub(500100101)
	q.needPw = true
	srv, mux := newQRTestServer(t, q, true)
	m := &flowMetrics{}
	srv.WithMetrics(m)
	es, _ := driveToPhoneAs(t, mux, desktopUA)

	c := startQR(t, mux, es)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != enableQRCookiePath {
		t.Errorf("status cookie = %+v, want HttpOnly, Secure, SameSite=Strict, Path=%s", c, enableQRCookiePath)
	}
	if strings.Contains(enableQRStatusPath, "?") {
		t.Errorf("status URL %q carries a query", enableQRStatusPath)
	}

	rec := pollQRStatus(t, mux, c, "<svg")
	page := rec.Body.String()
	for _, want := range []string{
		`http-equiv="refresh"`,
		"Scan with Telegram on your phone",
		"@dana_tg",
		"Any other account will be refused",
		"Example App",
		"tg.test",
		"/oauth/telegram/enable_access/qr/cancel",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("QR page lacks %q", want)
		}
	}
	if strings.Contains(page, qrTestToken) || strings.Contains(page, "tg://") {
		t.Error("QR page carries the login token as text")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("QR page Cache-Control = %q, want no-store", cc)
	}

	close(q.scan)
	pollQRStatus(t, mux, c, "/oauth/telegram/enable_access/password")

	rec = postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	loc := authCodeRedirect(t, rec)
	if loc.Query().Get("code") == "" {
		t.Fatalf("no authorization code in %s", loc)
	}

	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	if _, err := srv.store.CheckSessionValid(ctx, uid); err != nil {
		t.Errorf("session not valid after the QR login: %v", err)
	}
	if q.logOuts.Load() != 0 || q.writes.Load() != 1 {
		t.Errorf("logOuts=%d writes=%d, want 0 and 1", q.logOuts.Load(), q.writes.Load())
	}
	// The saved session is the user's now: the held-session logout must
	// not touch it.
	if q.lateLogOuts.Load() != 0 {
		t.Errorf("a saved sign-in was logged out %d time(s)", q.lateLogOuts.Load())
	}

	audit := strings.Join(auditRows(t, srv), "\n")
	if !strings.Contains(audit, "connect:success|qr|") {
		t.Errorf("no connect:success row with reason qr in:\n%s", audit)
	}
	if strings.Contains(audit, qrTestToken) || strings.Contains(logs.String(), qrTestToken) {
		t.Error("the login token reached the audit or the logs")
	}
	if got := m.snapshot(); len(got) != 1 || got[0] != "qr/ok" {
		t.Errorf("login flow metrics = %v, want [qr/ok]", got)
	}
}

// TestEnableQR_TwoPollsIssueOneCode: the status page finishes the sign-in,
// and two refreshes landing together must not both issue a code.
func TestEnableQR_TwoPollsIssueOneCode(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	waitForFlowDone(t, getEnableSession(t, srv, es).flowForTest(), 3*time.Second)

	var wg sync.WaitGroup
	recs := make([]*httptest.ResponseRecorder, 2)
	for i := range recs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recs[i] = getQRStatus(t, mux, c)
		}()
	}
	wg.Wait()

	codes := 0
	for _, rec := range recs {
		if strings.Contains(rec.Body.String(), "code=") {
			codes++
		}
	}
	// A refresh that found the lock busy shows the placeholder; one more
	// refresh then sees the finished session.
	for _, rec := range recs {
		if strings.Contains(rec.Body.String(), "Preparing your QR code") {
			if strings.Contains(getQRStatus(t, mux, c).Body.String(), "code=") {
				codes++
			}
		}
	}
	if codes != 1 {
		t.Errorf("authorization codes issued = %d, want 1", codes)
	}
}

// flowForTest reads es.flow under the session lock.
func (es *enableSession) flowForTest() *loginFlow {
	es.lock.Lock()
	defer es.lock.Unlock()
	return es.flow
}

// TestEnableQR_MismatchKeepsTheExistingSession is criterion 2 of #901 on the
// enable_access side: another account scanned the code, so it is refused and
// logged out, and the QR login wrote nothing. A revoke here would end the
// session the user already had, which is what the phone path does (#913).
func TestEnableQR_MismatchKeepsTheExistingSession(t *testing.T) {
	q := newQRStub(999000111)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)

	uid := seedExistingSession(t, srv)

	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	rec := pollQRStatus(t, mux, c, "different Telegram account")
	if !strings.Contains(rec.Body.String(), "Sign in with a QR code") {
		t.Error("the refusal offers no new QR code")
	}

	if q.logOuts.Load() != 1 || q.writes.Load() != 0 {
		t.Errorf("logOuts=%d writes=%d, want 1 and 0", q.logOuts.Load(), q.writes.Load())
	}
	assertExistingSessionUntouched(t, srv, uid)
}

// seedExistingSession gives Dana an existing, working hosted session and
// returns her uid.
func seedExistingSession(t *testing.T, srv *Server) int64 {
	t.Helper()
	ctx := context.Background()
	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	now := time.Now().UTC()
	if err := srv.store.UpdateSessionBlob(ctx, uid, []byte("existing-good-session")); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.store.DB.ExecContext(ctx,
		`UPDATE telegram_accounts SET telegram_user_id = $1, last_used_at = $2, expires_at = $3 WHERE user_id = $4`,
		500100101, now, now.Add(24*time.Hour), uid); err != nil {
		t.Fatal(err)
	}
	return uid
}

// assertExistingSessionUntouched checks the session seedExistingSession made
// is still the only row, active, valid and unchanged. A SaveSessionForSignIn
// would have revoked it as superseded and added a row.
func assertExistingSessionUntouched(t *testing.T, srv *Server, uid int64) {
	t.Helper()
	ctx := context.Background()
	pt, err := srv.store.LoadSession(ctx, uid)
	if err != nil || string(pt) != "existing-good-session" {
		t.Errorf("existing session = %q, %v; want it untouched", pt, err)
	}
	if _, err := srv.store.CheckSessionValid(ctx, uid); err != nil {
		t.Errorf("existing session no longer valid: %v", err)
	}
	var rows, active int
	if err := srv.store.DB.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(*) - COUNT(revoked_at) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&rows, &active); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || active != 1 {
		t.Errorf("telegram_accounts rows=%d active=%d, want the one seeded row, still active", rows, active)
	}
}

// TestEnableQR_ExpiredCodeIsAbandonment: a QR code nobody scans stops after
// enableQRWait, logs as a walked-away user at WARN with step qr_shown, and
// leaves the user a way to start over.
func TestEnableQR_ExpiredCodeIsAbandonment(t *testing.T) {
	logs := captureQRLog(t)
	prev := enableQRWait
	enableQRWait = 50 * time.Millisecond
	t.Cleanup(func() { enableQRWait = prev })

	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	m := &flowMetrics{}
	srv.WithMetrics(m)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)

	rec := pollQRStatus(t, mux, c, "not scanned in time")
	if !strings.Contains(rec.Body.String(), "Sign in with a QR code") {
		t.Error("expired page offers no new QR code")
	}
	out := logs.String()
	if !strings.Contains(out, "level=WARN msg=\"enable: onboarding abandoned\"") || !strings.Contains(out, "step=qr_shown") {
		t.Errorf("want a WARN abandonment at step qr_shown, got:\n%s", out)
	}
	if strings.Contains(out, "level=ERROR") {
		t.Errorf("an unscanned QR code logged an ERROR:\n%s", out)
	}
	if got := m.snapshot(); len(got) != 1 || got[0] != "qr/expired" {
		t.Errorf("login flow metrics = %v, want [qr/expired]", got)
	}
}

// TestEnableQR_WaitEndsWithTheSession: the scan wait never outlives the
// enable session, and the page states the wait the flow really has. Here the
// session has just under three minutes left, less than enableQRWait.
func TestEnableQR_WaitEndsWithTheSession(t *testing.T) {
	q := newQRStub(500100101)
	_, mux := newQRTestServer(t, q, true, func(c *Config) { c.CodeTTL = 3 * time.Minute })
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)

	rec := pollQRStatus(t, mux, c, "<svg")
	if !strings.Contains(rec.Body.String(), "It stops after 2 minutes.") {
		t.Errorf("the page does not state the session-bounded wait:\n%s", rec.Body.String())
	}
	if got := time.Duration(q.gotWait.Load()); got <= 2*time.Minute || got > 3*time.Minute-enableQRWaitMargin {
		t.Errorf("QRWait = %v, want what is left of the 3m session less the margin", got)
	}
	close(q.scan)
	pollQRStatus(t, mux, c, "linked")
}

// TestEnableQR_StallAfterScanIsAnError: once the scan is accepted the user
// has done their part, so a deadline in the work after it is a stall on our
// side or Telegram's, logged at ERROR, not a user who walked away.
func TestEnableQR_StallAfterScanIsAnError(t *testing.T) {
	logs := captureQRLog(t)
	q := newQRStub(500100101)
	q.stall = true
	srv, _ := newQRTestServer(t, q, true, func(c *Config) { c.CodeTTL = 100 * time.Millisecond })
	m := &flowMetrics{}
	srv.WithMetrics(m)

	lf := srv.startLoginFlow(1, 500100101, srv.qrLogin(time.Minute), false, time.Now())
	close(q.scan)
	waitForFlowDone(t, lf, 2*time.Second)

	out := logs.String()
	// lf.step is safe to read once done is closed.
	if lf.step != "qr_accepted" {
		t.Errorf("step = %q, want qr_accepted", lf.step)
	}
	if strings.Contains(out, "onboarding abandoned") || !strings.Contains(out, "level=ERROR") {
		t.Errorf("want the ERROR arm, not an abandonment, got:\n%s", out)
	}
	if got := m.snapshot(); len(got) != 1 || got[0] != "qr/error" {
		t.Errorf("login flow metrics = %v, want [qr/error]", got)
	}
}

// TestEnableQR_SecondAuthRestartEndsTheFlow is criterion 1 of #901 on the
// enable_access side. telegram.LoginQR retries AUTH_RESTART once (pinned in
// internal/telegram's TestRetryAuthRestartOnce); the second one comes back as
// the login's error, and the flow must end there with a clear message and a
// way to start over, not wait or loop.
func TestEnableQR_SecondAuthRestartEndsTheFlow(t *testing.T) {
	q := newQRStub(500100101)
	q.err = tgerr.New(500, "AUTH_RESTART")
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)

	rec := pollQRStatus(t, mux, c, "Telegram ended the sign-in session")
	body := rec.Body.String()
	if !strings.Contains(body, "Sign in with a QR code") || !strings.Contains(body, "/oauth/telegram/enable_access/start") {
		t.Error("the ended flow offers no way to start over")
	}
	if n := q.calls.Load(); n != 1 {
		t.Errorf("QR login ran %d times, want 1", n)
	}
	if step := getEnableSession(t, srv, es).stepForTest(); step != stepPhone {
		t.Errorf("es.step = %v, want stepPhone", step)
	}
}

func (es *enableSession) stepForTest() enableStep {
	es.lock.Lock()
	defer es.lock.Unlock()
	return es.step
}

// TestEnableQR_StatusNeverWaitsForTheLock: the status page is refreshed
// every few seconds, and a step handler can hold the session lock across a
// Telegram round-trip, so the page must answer at once rather than queue.
func TestEnableQR_StatusNeverWaitsForTheLock(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)

	sess := getEnableSession(t, srv, es)
	sess.lock.Lock()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- getQRStatus(t, mux, c) }()
	select {
	case rec := <-done:
		sess.lock.Unlock()
		if !strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
			t.Errorf("busy status page does not refresh itself: %s", rec.Body.String())
		}
	case <-time.After(time.Second):
		sess.lock.Unlock()
		<-done
		t.Error("status page waited for the session lock")
	}
}

// TestEnableQR_FromTheCodeStep is #901 slice 2: a desktop user whose login
// code did not arrive can switch to the QR code from the code step. The
// waiting phone flow is superseded, and the send opt-in chosen with the
// phone number survives, since the QR form there does not carry it.
func TestEnableQR_FromTheCodeStep(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	if rec := postForm(t, mux, "/oauth/telegram/enable_access/start",
		url.Values{"es": {es}, "phone": {"+14155551234"}, "send_optin": {"on"}}); !strings.Contains(rec.Body.String(), "enable_access/code") {
		t.Fatalf("start did not reach the code step: %s", rec.Body.String())
	}
	page := postForm(t, mux, "/oauth/telegram/enable_access/code", url.Values{"es": {es}, "code": {""}}).Body.String()
	if !strings.Contains(page, "get the code?") || !strings.Contains(page, `<button type="submit" class="secondary">Sign in with a QR code</button>`) {
		t.Fatalf("the code step does not offer the QR code: %s", page)
	}
	phoneFlow := getEnableSession(t, srv, es).flowForTest()

	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	waitForFlowDone(t, phoneFlow, 3*time.Second)
	if !phoneFlow.superseded.Load() {
		t.Error("the phone flow was not marked superseded")
	}
	sess := getEnableSession(t, srv, es)
	sess.lock.Lock()
	optIn := sess.sendOptIn
	sess.lock.Unlock()
	if !optIn {
		t.Error("switching to QR from the code step dropped the send opt-in")
	}

	close(q.scan)
	waitForFlowDone(t, sess.flowForTest(), 3*time.Second)
	if body := getQRStatus(t, mux, c).Body.String(); !strings.Contains(body, "code=") {
		t.Errorf("no authorization code after a QR login from the code step: %s", body)
	}
}

// TestEnableQR_CodeStepHintOnlyWhenOffered: mobile browsers, where the code
// would have to be scanned with the same phone, get no QR hint on the code
// step either.
func TestEnableQR_CodeStepHintOnlyWhenOffered(t *testing.T) {
	q := newQRStub(500100101)
	_, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, iPhoneUA)
	postForm(t, mux, "/oauth/telegram/enable_access/start", url.Values{"es": {es}, "phone": {"+14155551234"}})
	page := postForm(t, mux, "/oauth/telegram/enable_access/code", url.Values{"es": {es}, "code": {""}}).Body.String()
	if !strings.Contains(page, "enable_access/code") {
		t.Fatalf("not on the code step: %s", page)
	}
	if strings.Contains(page, "Sign in with a QR code") || strings.Contains(page, "enable_access/qr") {
		t.Error("the mobile code step offers the QR code")
	}
}

// TestEnableQR_CancelReturnsToThePhoneStep: "Use your phone number instead"
// stops the QR flow and shows the phone form.
func TestEnableQR_CancelReturnsToThePhoneStep(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	lf := getEnableSession(t, srv, es).flowForTest()

	rec := postForm(t, mux, "/oauth/telegram/enable_access/qr/cancel", url.Values{"es": {es}})
	if !strings.Contains(rec.Body.String(), "/oauth/telegram/enable_access/start") {
		t.Fatalf("cancel did not render the phone step: %s", rec.Body.String())
	}
	waitForFlowDone(t, lf, 3*time.Second)
	if q.writes.Load() != 0 {
		t.Error("a cancelled QR flow wrote a session")
	}
}

// TestEnableQR_CancelBeatsALateScan: the user cancels the QR code and the
// scan lands right after. The cancelled flow must not finish the sign-in:
// no SaveSessionForSignIn, the existing session untouched, and the status
// page no longer offers the flow. Run it under -race.
func TestEnableQR_CancelBeatsALateScan(t *testing.T) {
	q := newQRStub(500100101)
	q.release = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	uid := seedExistingSession(t, srv)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	lf := getEnableSession(t, srv, es).flowForTest()

	postForm(t, mux, "/oauth/telegram/enable_access/qr/cancel", url.Values{"es": {es}})
	close(q.release)
	waitForFlowDone(t, lf, 3*time.Second)

	if lf.err == nil {
		t.Error("the cancelled flow ended without an error")
	}
	assertExistingSessionUntouched(t, srv, uid)
	assertLateLogOut(t, q)
	if body := getQRStatus(t, mux, c).Body.String(); strings.Contains(body, "<svg") || strings.Contains(body, "linked") {
		t.Errorf("the status page still serves the cancelled flow:\n%s", body)
	}
}

// TestEnableQR_PhoneStartBeatsALateScan: the same race, with the QR flow
// superseded by a phone sign-in started from a second tab.
func TestEnableQR_PhoneStartBeatsALateScan(t *testing.T) {
	q := newQRStub(500100101)
	q.release = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	srv.loginFn = stubLoginParksAtCode()
	// Both tabs reach the phone step before the session exists, the way
	// they would for a user who had none when they opened them.
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	es2, _ := driveToPhoneAs(t, mux, desktopUA)
	uid := seedExistingSession(t, srv)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	lf := getEnableSession(t, srv, es).flowForTest()

	// The phone /start waits for its code step, which queues on the uid
	// mutex behind the QR flow, so it runs alongside; the scan lands once
	// the phone start has superseded the QR flow.
	started := make(chan struct{})
	go func() {
		defer close(started)
		req := httptest.NewRequest("POST", "/oauth/telegram/enable_access/start",
			strings.NewReader(url.Values{"es": {es2}, "phone": {"+14155551234"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mux.ServeHTTP(httptest.NewRecorder(), req)
	}()
	for deadline := time.Now().Add(3 * time.Second); !lf.superseded.Load(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the phone start never superseded the QR flow")
		}
	}
	close(q.release)
	waitForFlowDone(t, lf, 3*time.Second)
	<-started

	if !lf.superseded.Load() || lf.err == nil {
		t.Errorf("QR flow superseded=%v err=%v, want superseded with an error", lf.superseded.Load(), lf.err)
	}
	assertExistingSessionUntouched(t, srv, uid)
	assertLateLogOut(t, q)
}

// assertLateLogOut checks the late scan's authorization was logged out once,
// on a live context (#919).
func assertLateLogOut(t *testing.T, q *qrStub) {
	t.Helper()
	if q.lateLogOuts.Load() != 1 || q.deadLogOutCtx.Load() {
		t.Errorf("late-scan logouts=%d on a dead ctx=%v, want 1 on a live one", q.lateLogOuts.Load(), q.deadLogOutCtx.Load())
	}
}

// TestEnableQR_SupersededBeforeTheCancelLands pins the explicit guard after
// the login (#919): a supersede marks the flow before it cancels bgCtx, and
// a login that returns in between must not finish the sign-in, even though
// every write on bgCtx would still succeed.
func TestEnableQR_SupersededBeforeTheCancelLands(t *testing.T) {
	q := newQRStub(500100101)
	q.release = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	driveToPhoneAs(t, mux, desktopUA)
	uid := seedExistingSession(t, srv)

	lf := srv.startLoginFlow(uid, 500100101, srv.qrLogin(time.Minute), false, time.Now())
	q.beforeReturn = func() { lf.superseded.Store(true) }
	close(q.release)
	waitForFlowDone(t, lf, 3*time.Second)

	if !errors.Is(lf.err, context.Canceled) {
		t.Errorf("err = %v, want a cancelled sign-in", lf.err)
	}
	assertExistingSessionUntouched(t, srv, uid)
	assertLateLogOut(t, q)
}

// TestEnableQR_CancelAfterTheGuardStillLogsOut: a cancel that lands after the
// #919 guard makes SaveSessionForSignIn fail on bgCtx. The held session was
// never written, so no repair finds it; the flow has to log it out itself.
func TestEnableQR_CancelAfterTheGuardStillLogsOut(t *testing.T) {
	q := newQRStub(500100101)
	q.release = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	driveToPhoneAs(t, mux, desktopUA)
	uid := seedExistingSession(t, srv)

	var lf *loginFlow
	srv.beforeSignInSave = func() { lf.cancel() }
	lf = srv.startLoginFlow(uid, 500100101, srv.qrLogin(time.Minute), false, time.Now())
	close(q.release)
	waitForFlowDone(t, lf, 3*time.Second)

	if lf.err == nil || !strings.Contains(lf.err.Error(), "save session") || lf.tgUserID != 0 {
		t.Errorf("err = %v, tgUserID = %d; want a failed save", lf.err, lf.tgUserID)
	}
	assertExistingSessionUntouched(t, srv, uid)
	assertLateLogOut(t, q)
}

// TestEnableQR_RefusedSaveLogsOut: SaveSessionForSignIn refuses because the
// account was deleted while the scan was being accepted (#821). The held
// session is logged out rather than dropped.
func TestEnableQR_RefusedSaveLogsOut(t *testing.T) {
	q := newQRStub(500100101)
	q.release = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	driveToPhoneAs(t, mux, desktopUA)
	uid := seedExistingSession(t, srv)

	lf := srv.startLoginFlow(uid, 500100101, srv.qrLogin(time.Minute), false, time.Now())
	q.beforeReturn = func() {
		if _, err := srv.store.HardDeleteAccount(context.Background(), uid); err != nil {
			t.Errorf("HardDeleteAccount: %v", err)
		}
	}
	close(q.release)
	waitForFlowDone(t, lf, 3*time.Second)

	if lf.err == nil || !strings.Contains(lf.err.Error(), "save session") || lf.tgUserID != 0 {
		t.Errorf("err = %v, tgUserID = %d; want a refused save", lf.err, lf.tgUserID)
	}
	var rows int
	if err := srv.store.DB.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM telegram_accounts WHERE user_id = $1`, uid).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Errorf("%d telegram_accounts rows survive the delete", rows)
	}
	assertLateLogOut(t, q)
}

// TestEnableQR_NoOrForeignCookieGetsNothing: the status page and the QR
// POSTs without the browser's own cookie or es value render the expired
// page, leak no es value, account name or QR code, and change nothing.
func TestEnableQR_NoOrForeignCookieGetsNothing(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	lf := getEnableSession(t, srv, es).flowForTest()

	check := func(name string, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := rec.Body.String()
		if !strings.Contains(body, "sign-in session has expired") {
			t.Errorf("%s: not the expired page:\n%s", name, body)
		}
		for _, leak := range []string{es, "dana_tg", "<svg", qrTestToken} {
			if strings.Contains(body, leak) {
				t.Errorf("%s: response carries %q", name, leak)
			}
		}
	}
	check("status, no cookie", getQRStatus(t, mux, nil))
	check("status, foreign cookie", getQRStatus(t, mux, &http.Cookie{Name: enableQRCookie, Value: "not-a-session-token"}))
	check("start, no es", postForm(t, mux, "/oauth/telegram/enable_access/qr", url.Values{}))
	check("start, foreign es", postForm(t, mux, "/oauth/telegram/enable_access/qr", url.Values{"es": {"not-a-session-token"}}))
	check("cancel, no es", postForm(t, mux, "/oauth/telegram/enable_access/qr/cancel", url.Values{}))
	check("cancel, foreign es", postForm(t, mux, "/oauth/telegram/enable_access/qr/cancel", url.Values{"es": {"not-a-session-token"}}))

	if got := getEnableSession(t, srv, es).stepForTest(); got != stepQR {
		t.Errorf("step = %v, want stepQR unchanged", got)
	}
	if lf.superseded.Load() || q.calls.Load() != 1 {
		t.Errorf("superseded=%v calls=%d, want the one flow still running", lf.superseded.Load(), q.calls.Load())
	}
	select {
	case <-lf.done:
		t.Error("the flow ended")
	default:
	}
	close(q.scan)
	pollQRStatus(t, mux, c, "linked")
}

// TestEnableQR_FunnelCountsAQRSuccess: a completed QR sign-in writes the
// same plain connect:success row as the phone path, with the method only in
// its reason, so LastConnectStepFor and the runbook's connect funnel SQL
// count it like any other success.
func TestEnableQR_FunnelCountsAQRSuccess(t *testing.T) {
	q := newQRStub(500100101)
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)
	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	pollQRStatus(t, mux, c, "linked")

	rows := auditRows(t, srv)
	if !slices.Contains(rows, "connect:success|qr|") {
		t.Errorf("no plain connect:success row with reason qr in %v", rows)
	}
	for _, r := range rows {
		if strings.HasPrefix(r, "connect:success:") {
			t.Errorf("method-specific success row %q", r)
		}
	}

	ctx := context.Background()
	steps, err := srv.store.LastConnectStepFor(ctx, []int64{500100101})
	if err != nil || steps[500100101].Step != "success" {
		t.Errorf("LastConnectStepFor = %+v, %v; want step success", steps, err)
	}

	uid, _ := srv.store.EnsureUserByTelegramID(ctx, 500100101, "dana_tg", "Dana")
	var got []int64
	res, err := srv.store.DB.QueryContext(ctx, runbookSQLAfter(t, "Users whose last row is `connect:success`"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	for res.Next() {
		var id int64
		if err := res.Scan(&id); err != nil {
			t.Fatal(err)
		}
		got = append(got, id)
	}
	if !slices.Contains(got, uid) {
		t.Errorf("runbook funnel query = %v, want it to count uid %d", got, uid)
	}
	var qrUsers int
	if err := srv.store.DB.QueryRowContext(ctx, runbookSQLAfter(t, "who connected by QR:")).Scan(&qrUsers); err != nil || qrUsers != 1 {
		t.Errorf("runbook QR users query = %d, %v; want 1", qrUsers, err)
	}
}

// runbookSQLAfter returns the first ```sql block after marker in
// docs/runbook.md, so the funnel test runs the query operators run.
func runbookSQLAfter(t *testing.T, marker string) string {
	t.Helper()
	doc, err := os.ReadFile("../../docs/runbook.md")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(doc), marker)
	if !ok {
		t.Fatalf("runbook has no %q", marker)
	}
	_, rest, ok = strings.Cut(rest, "```sql\n")
	if !ok {
		t.Fatalf("no sql block after %q", marker)
	}
	query, _, _ := strings.Cut(rest, "```")
	return query
}

// TestRenderQRSVG_CarriesNoToken: the SVG draws the URL's modules and holds
// none of its text.
func TestRenderQRSVG_CarriesNoToken(t *testing.T) {
	svg := string(renderQRSVG("tg://login?token=" + qrTestToken))
	if !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, `aria-label="Telegram login QR code"`) || !strings.Contains(svg, "<path") {
		t.Fatalf("not a QR SVG: %.200s", svg)
	}
	for _, leak := range []string{"tg://", "token", qrTestToken} {
		if strings.Contains(svg, leak) {
			t.Errorf("SVG contains %q", leak)
		}
	}
}

// TestEnableQR_ConnectingPageAfterScan (#931): once Telegram reports the
// code scanned and confirmed, the status page stops showing the spent code
// and says the session is being connected, then finishes the sign-in as
// before.
func TestEnableQR_ConnectingPageAfterScan(t *testing.T) {
	q := newQRStub(500100101)
	q.afterScan = make(chan struct{})
	srv, mux := newQRTestServer(t, q, true)
	es, _ := driveToPhoneAs(t, mux, desktopUA)

	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	rec := pollQRStatus(t, mux, c, "Confirmed in Telegram")
	page := rec.Body.String()
	if strings.Contains(page, "<svg") {
		t.Error("connecting page still draws the spent QR code")
	}
	if !strings.Contains(page, `http-equiv="refresh" content="1"`) {
		t.Error("connecting page does not refresh itself every second")
	}
	if !strings.Contains(page, `role="status"`) {
		t.Error("connecting page has no status region")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("connecting page Cache-Control = %q, want no-store", cc)
	}

	close(q.afterScan)
	waitForFlowDone(t, getEnableSession(t, srv, es).flowForTest(), 3*time.Second)
	if body := getQRStatus(t, mux, c).Body.String(); !strings.Contains(body, "code=") {
		t.Errorf("no authorization code after the connecting page: %s", body)
	}
}

// TestEnableQR_StalledConnectFails (#931): the connecting page must not
// become an endless spinner. Work after a confirmed scan that does not
// finish within the stall bound fails the flow with a message that says so,
// counted as an error, not an abandonment.
func TestEnableQR_StalledConnectFails(t *testing.T) {
	q := newQRStub(500100101)
	q.afterScan = make(chan struct{}) // never closed
	srv, mux := newQRTestServer(t, q, true)
	srv.qrStallWait = 50 * time.Millisecond
	m := &flowMetrics{}
	srv.WithMetrics(m)
	es, _ := driveToPhoneAs(t, mux, desktopUA)

	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	rec := pollQRStatus(t, mux, c, "connecting the session took too long")
	if !strings.Contains(rec.Body.String(), "Sign in with a QR code") {
		t.Error("the failure page offers no new QR code")
	}
	if got := m.snapshot(); len(got) != 1 || got[0] != "qr/error" {
		t.Errorf("login flow metrics = %v, want [qr/error]", got)
	}
	audit := strings.Join(auditRows(t, srv), "\n")
	if !strings.Contains(audit, "connect:failed:qr_connect_stalled|qr|") {
		t.Errorf("no qr_connect_stalled failure row in:\n%s", audit)
	}
}

// TestEnableQR_PasswordStopsTheStallClock (#931): a 2FA account is asked for
// its password after the scan. A user typing it must not hit the connect
// stall bound.
func TestEnableQR_PasswordStopsTheStallClock(t *testing.T) {
	for _, hookLate := range []bool{false, true} {
		t.Run(fmt.Sprintf("hook_after_prompt=%v", hookLate), func(t *testing.T) {
			testPasswordStopsTheStallClock(t, hookLate)
		})
	}
}

// testPasswordStopsTheStallClock is TestEnableQR_PasswordStopsTheStallClock
// with the scan hook landing before the password prompt or, when hookLate,
// after it (#934 review).
func testPasswordStopsTheStallClock(t *testing.T, hookLate bool) {
	q := newQRStub(500100101)
	q.needPw = true
	q.pwBeforeScanHook = hookLate
	srv, mux := newQRTestServer(t, q, true)
	srv.qrStallWait = 50 * time.Millisecond
	es, _ := driveToPhoneAs(t, mux, desktopUA)

	c := startQR(t, mux, es)
	pollQRStatus(t, mux, c, "<svg")
	close(q.scan)
	pollQRStatus(t, mux, c, "/oauth/telegram/enable_access/password")
	time.Sleep(4 * srv.qrStallWait)

	rec := postForm(t, mux, "/oauth/telegram/enable_access/password",
		url.Values{"es": {es}, "password": {"hunter2"}})
	if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
		t.Fatalf("no authorization code in %s", loc)
	}
}
