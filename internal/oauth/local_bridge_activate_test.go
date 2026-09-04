package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ----- shared harness -----

// newActivationHTTPServer stands up a real httptest.Server backed by a chi
// router (not the mockRouter used elsewhere in this package) because several
// activation tests need genuine cookie-jar behaviour across requests
// (T16, T18, T23): the login-CSRF binding cookie set on POST
// /local-bridge/activate must actually be sent back on a later GET
// /oauth/telegram/callback at an unrelated path.
func newActivationHTTPServer(t *testing.T, opts ...func(*Config)) (*Server, *httptest.Server) {
	t.Helper()
	srv := newTestServer(t, opts...)
	r := chi.NewRouter()
	srv.Register(r)
	ts := httptest.NewServer(r)
	t.Cleanup(ts.Close)
	return srv, ts
}

// newActivationClient returns an http.Client with its own cookie jar that
// does not automatically follow redirects — callers inspect the 302 to
// Telegram (or elsewhere) directly instead of the client silently trying to
// dial it.
func newActivationClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func activateStart(t *testing.T, ts *httptest.Server, client *http.Client, telegramID int64, deviceKey string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"telegram_id":             telegramID,
		"device_registration_key": deviceKey,
		"device_label":            "test-laptop",
	})
	resp, err := client.Post(ts.URL+"/api/local-bridge/activate/start", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start status=%d body=%s", resp.StatusCode, b)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode start response: %v (body=%s)", err, b)
	}
	return out
}

var csrfHiddenRe = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)

func activationFormCSRF(t *testing.T, ts *httptest.Server, client *http.Client) string {
	t.Helper()
	resp, err := client.Get(ts.URL + "/local-bridge/activate")
	if err != nil {
		t.Fatalf("get form: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := csrfHiddenRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf_token in form: %s", body)
	}
	return string(m[1])
}

func activateVerify(t *testing.T, ts *httptest.Server, client *http.Client, userCode, csrfTok string) *http.Response {
	t.Helper()
	form := url.Values{"user_code": {userCode}, "csrf_token": {csrfTok}}
	resp, err := client.PostForm(ts.URL+"/local-bridge/activate", form)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return resp
}

var consentTokenRe = regexp.MustCompile(`name="consent_token" value="([^"]*)"`)
var consentUserCodeRe = regexp.MustCompile(`name="user_code" value="([^"]*)"`)

type consentFields struct {
	UserCode     string
	ConsentToken string
	Body         string
}

func extractConsent(t *testing.T, body []byte) consentFields {
	t.Helper()
	cm := consentTokenRe.FindSubmatch(body)
	um := consentUserCodeRe.FindSubmatch(body)
	if cm == nil || um == nil {
		t.Fatalf("consent page missing hidden fields: %s", body)
	}
	return consentFields{UserCode: string(um[1]), ConsentToken: string(cm[1]), Body: string(body)}
}

// stateFromLocation extracts ?state= from a redirect Location header.
func stateFromLocation(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location %q: %v", location, err)
	}
	st := u.Query().Get("state")
	if st == "" {
		t.Fatalf("redirect location carried no state: %s", location)
	}
	return st
}

// callbackFor drives GET /oauth/telegram/callback?state=&code= through client
// (so its cookie jar carries the lb_act_state cookie set by /local-bridge/activate).
func callbackFor(t *testing.T, ts *httptest.Server, client *http.Client, state string) *http.Response {
	t.Helper()
	resp, err := client.Get(ts.URL + "/oauth/telegram/callback?" + url.Values{
		"state": {state}, "code": {"tg-auth-code"},
	}.Encode())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return resp
}

// driveToConsent runs start -> GET form -> POST verify -> GET callback and
// returns the consent page's hidden fields. Fails the test unless the
// callback lands on a 200 consent page.
func driveToConsent(t *testing.T, ts *httptest.Server, client *http.Client, claimedTGID int64, deviceKey string) (start map[string]any, consent consentFields) {
	t.Helper()
	start = activateStart(t, ts, client, claimedTGID, deviceKey)
	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(verifyResp.Body)
		t.Fatalf("verify status=%d body=%s", verifyResp.StatusCode, b)
	}
	state := stateFromLocation(t, verifyResp.Header.Get("Location"))
	cbResp := callbackFor(t, ts, client, state)
	defer cbResp.Body.Close()
	body, _ := io.ReadAll(cbResp.Body)
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", cbResp.StatusCode, body)
	}
	consent = extractConsent(t, body)
	return
}

func activateApprove(t *testing.T, ts *httptest.Server, client *http.Client, userCode, consentTok string) *http.Response {
	t.Helper()
	form := url.Values{"user_code": {userCode}, "consent_token": {consentTok}, "action": {"approve"}}
	resp, err := client.PostForm(ts.URL+"/local-bridge/activate/consent", form)
	if err != nil {
		t.Fatalf("consent approve: %v", err)
	}
	return resp
}

func activateDeny(t *testing.T, ts *httptest.Server, client *http.Client, userCode, consentTok string) *http.Response {
	t.Helper()
	form := url.Values{"user_code": {userCode}, "consent_token": {consentTok}, "action": {"deny"}}
	resp, err := client.PostForm(ts.URL+"/local-bridge/activate/consent", form)
	if err != nil {
		t.Fatalf("consent deny: %v", err)
	}
	return resp
}

func activatePoll(t *testing.T, ts *httptest.Server, client *http.Client, deviceCode string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
	resp, err := client.Post(ts.URL+"/api/local-bridge/activate/poll", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func countRows(t *testing.T, srv *Server, table string) int {
	t.Helper()
	var n int
	if err := srv.store.DB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

type dbSnapshot struct{ users, accounts, devices int }

func snapshotDB(t *testing.T, srv *Server) dbSnapshot {
	t.Helper()
	return dbSnapshot{
		users:    countRows(t, srv, "users"),
		accounts: countRows(t, srv, "telegram_accounts"),
		devices:  countRows(t, srv, "local_bridge_devices"),
	}
}

// ----- T1 / T7 / T13: happy path -----

func TestActivation_HappyPath_ProvisionsAccountAndDevice(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	const claimedID = int64(210408407) // matches fakeAuthenticator's default identity
	start, consent := driveToConsent(t, ts, client, claimedID, "device-key-1")

	approveResp := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
	defer approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(approveResp.Body)
		t.Fatalf("approve status=%d body=%s", approveResp.StatusCode, b)
	}

	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "done" {
		t.Fatalf("poll after approve = %d %#v", status, poll)
	}
	deviceID, _ := poll["device_id"].(string)
	if deviceID == "" {
		t.Fatalf("poll done carried no device_id: %#v", poll)
	}
	if !strings.HasPrefix(deviceID, "dev_") {
		t.Errorf("device_id %q does not look server-generated", deviceID)
	}

	// T7: send_enabled stays false, session_encrypted stays NULL.
	var sendEnabled bool
	var sessionEncrypted []byte
	var mode string
	if err := srv.store.DB.QueryRow(
		`SELECT send_enabled, session_encrypted, mode FROM telegram_accounts WHERE telegram_user_id = $1`,
		claimedID,
	).Scan(&sendEnabled, &sessionEncrypted, &mode); err != nil {
		t.Fatalf("query account: %v", err)
	}
	if sendEnabled {
		t.Error("send_enabled = true, want false")
	}
	if sessionEncrypted != nil {
		t.Error("session_encrypted is non-NULL, want NULL")
	}
	if mode != db.ModeLocal {
		t.Errorf("mode = %q, want %q", mode, db.ModeLocal)
	}

	// T13: identity metadata (username/display name) survived the request
	// boundary between the OIDC callback and the separate consent POST.
	var username, displayName string
	if err := srv.store.DB.QueryRow(
		`SELECT username, display_name FROM telegram_accounts WHERE telegram_user_id = $1`, claimedID,
	).Scan(&username, &displayName); err != nil {
		t.Fatalf("query identity metadata: %v", err)
	}
	if username == "" || displayName == "" {
		t.Errorf("username=%q displayName=%q, want both non-empty", username, displayName)
	}

	// Exactly one device row, keyed by the CLI's idempotency key.
	var deviceCount int
	if err := srv.store.DB.QueryRow(
		`SELECT COUNT(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "device-key-1",
	).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 1 {
		t.Errorf("device rows for idempotency key = %d, want 1", deviceCount)
	}
}

// T1: idempotent retry — start twice with the same device_registration_key
// and complete the browser flow twice for the same identity; exactly one
// account row and one device row result.
func TestActivation_IdempotentRetry_SameDeviceKey(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	const claimedID = int64(210408407)

	for i := 0; i < 2; i++ {
		_, consent := driveToConsent(t, ts, client, claimedID, "retry-key")
		resp := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("approve #%d status=%d", i, resp.StatusCode)
		}
	}

	if n := countRows(t, srv, "telegram_accounts"); n != 1 {
		t.Errorf("telegram_accounts rows = %d, want 1", n)
	}
	var deviceCount int
	if err := srv.store.DB.QueryRow(
		`SELECT COUNT(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "retry-key",
	).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 1 {
		t.Errorf("device rows = %d, want 1", deviceCount)
	}
}

// ----- T2: claimed-vs-verified mismatch -----

func TestActivation_ClaimedVsVerifiedMismatch_NoWrites(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	before := snapshotDB(t, srv)

	// fakeAuthenticator's default identity verifies as 210408407; claim a
	// different id so the callback's mismatch guard fires.
	start := activateStart(t, ts, client, 999999999, "mismatch-key")
	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	defer verifyResp.Body.Close()
	state := stateFromLocation(t, verifyResp.Header.Get("Location"))

	cbResp := callbackFor(t, ts, client, state)
	defer cbResp.Body.Close()
	if cbResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(cbResp.Body)
		t.Fatalf("callback status=%d body=%s", cbResp.StatusCode, b)
	}

	after := snapshotDB(t, srv)
	if after != before {
		t.Errorf("db snapshot changed on mismatch: before=%+v after=%+v", before, after)
	}

	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "denied" {
		t.Fatalf("poll after mismatch = %d %#v, want denied", status, poll)
	}
}

// ----- T3: hosted account refused -----

func TestActivation_HostedAccountRefused(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	const claimedID = int64(210408407)

	seedSession(t, srv, claimedID) // inserts an active mode='hosted' row

	_, consent := driveToConsent(t, ts, client, claimedID, "hosted-key")
	resp := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve status=%d body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "hosted") {
		t.Errorf("denial page does not mention a hosted account: %s", body)
	}

	var deviceCount int
	if err := srv.store.DB.QueryRow(`SELECT COUNT(*) FROM local_bridge_devices`).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 0 {
		t.Errorf("local_bridge_devices rows = %d, want 0", deviceCount)
	}
}

// ----- T4 / T5: poll on unknown / not-yet-resolved codes -----

func TestActivation_Poll_UnknownDeviceCode(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	status, _ := activatePoll(t, ts, client, "does-not-exist")
	if status != http.StatusBadRequest {
		t.Errorf("poll unknown device_code status = %d, want 400", status)
	}
}

func TestActivation_Poll_BeforeBrowserLeg(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	start := activateStart(t, ts, client, 210408407, "pending-key")
	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "pending" {
		t.Errorf("poll before browser leg = %d %#v, want 200 pending", status, poll)
	}
}

// ----- T6: expiry -----

func TestActivation_Expiry(t *testing.T) {
	srv, ts := newActivationHTTPServer(t, func(c *Config) {
		c.ActivationTTL = 10 * time.Millisecond
	})
	client := newActivationClient(t)
	start := activateStart(t, ts, client, 210408407, "expiring-key")
	time.Sleep(30 * time.Millisecond)

	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusBadRequest {
		t.Errorf("poll on expired device_code = %d %#v, want 400", status, poll)
	}

	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode == http.StatusFound {
		t.Error("verify on expired user_code redirected to Telegram, want rejection")
	}

	now := time.Now().Add(time.Hour)
	srv.sweep(now)
	srv.mu.Lock()
	_, stillThere := srv.activations[start["device_code"].(string)]
	srv.mu.Unlock()
	if stillThere {
		t.Error("sweep did not remove the expired activation from s.activations")
	}
}

// ----- T9: phishing guard -----

func TestActivation_PhishingGuard_NoConsentNoWrite(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	before := snapshotDB(t, srv)

	// The attacker claims the VICTIM's telegram_id (which happens to match
	// fakeAuthenticator's canned identity) with the attacker's own device
	// key, then drives the browser leg to completion -- claimed == verified,
	// so the mismatch guard in finishActivation never fires.
	start, _ := driveToConsent(t, ts, client, 210408407, "attacker-device-key")

	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if poll["status"] == "done" {
		t.Fatalf("poll reports done before consent was ever submitted: %d %#v", status, poll)
	}

	after := snapshotDB(t, srv)
	if after != before {
		t.Errorf("db snapshot changed with no consent submitted: before=%+v after=%+v", before, after)
	}
}

// ----- T10: consent token cannot be forged or replayed -----

func TestActivation_ConsentTokenCannotBeForgedOrReplayed(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	before := snapshotDB(t, srv)

	_, consent := driveToConsent(t, ts, client, 210408407, "forge-key")

	for _, tok := range []string{"", "wrong-token", consent.ConsentToken + "x"} {
		resp := activateApprove(t, ts, client, consent.UserCode, tok)
		resp.Body.Close()
	}
	if after := snapshotDB(t, srv); after != before {
		t.Fatalf("db snapshot changed after forged tokens: before=%+v after=%+v", before, after)
	}

	// The correct token still works, and works exactly once.
	resp1 := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("approve with correct token status=%d", resp1.StatusCode)
	}
	resp2 := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
	resp2.Body.Close()

	var deviceCount int
	if err := srv.store.DB.QueryRow(
		`SELECT COUNT(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "forge-key",
	).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 1 {
		t.Errorf("device rows after replay = %d, want 1", deviceCount)
	}
}

// ----- T11: user_code brute force is bounded -----

func TestActivation_UserCodeBruteForceBounded(t *testing.T) {
	_, ts := newActivationHTTPServer(t, func(c *Config) {
		c.ActivationFailBudget = 3
		c.ActivationFailWindow = time.Minute
	})
	client := newActivationClient(t)

	csrf := activationFormCSRF(t, ts, client)
	var messages []string
	for i := 0; i < 3; i++ {
		resp := activateVerify(t, ts, client, "WRONG-CODE", csrf)
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("wrong-code submission #%d status=%d", i, resp.StatusCode)
		}
		messages = append(messages, activationErrorMessage(t, b))
	}
	// A 4th submission — budget now spent — must render the SAME message,
	// and a fresh cookie session (dropping cookies does not reset it, since
	// the limiter is keyed by IP, not by session). The rendered CSRF hidden
	// field legitimately differs per browser session, so the comparison is
	// on the user-visible rejection message, not the raw page bytes.
	client2 := newActivationClient(t)
	csrf2 := activationFormCSRF(t, ts, client2)
	resp := activateVerify(t, ts, client2, "ANOTHER-WRONG", csrf2)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	budgetMsg := activationErrorMessage(t, b)

	for i, prior := range messages {
		if prior != budgetMsg {
			t.Errorf("budget-exhausted message differs from rejection #%d message (want identical): %q vs %q", i, prior, budgetMsg)
		}
	}
	if len(messages) > 0 && (messages[0] == "" || messages[0] != activationGenericRejection) {
		t.Errorf("rejection message = %q, want the generic constant %q", messages[0], activationGenericRejection)
	}
}

var activationErrorDivRe = regexp.MustCompile(`(?s)class="error">(.*?)</div>`)

// activationErrorMessage extracts the visible error text from a rendered
// activation form page.
func activationErrorMessage(t *testing.T, body []byte) string {
	t.Helper()
	m := activationErrorDivRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no error message found in body: %s", body)
	}
	return string(m[1])
}

// ----- T12 / T22: double approval provisions once, under -race -----

func TestActivation_DoubleApprovalProvisionsOnce(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	_, consent := driveToConsent(t, ts, client, 210408407, "concurrent-key")

	var wg sync.WaitGroup
	statuses := make([]int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			form := url.Values{"user_code": {consent.UserCode}, "consent_token": {consent.ConsentToken}, "action": {"approve"}}
			resp, err := client.PostForm(ts.URL+"/local-bridge/activate/consent", form)
			if err != nil {
				t.Errorf("concurrent approve #%d: %v", i, err)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)
			statuses[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()

	var deviceCount int
	if err := srv.store.DB.QueryRow(
		`SELECT COUNT(*) FROM local_bridge_devices WHERE idempotency_key = $1`, "concurrent-key",
	).Scan(&deviceCount); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if deviceCount != 1 {
		t.Errorf("device rows after concurrent double-approve = %d, want exactly 1", deviceCount)
	}
	var accountCount int
	if err := srv.store.DB.QueryRow(`SELECT COUNT(*) FROM telegram_accounts`).Scan(&accountCount); err != nil {
		t.Fatalf("count accounts: %v", err)
	}
	if accountCount != 1 {
		t.Errorf("telegram_accounts rows after concurrent double-approve = %d, want exactly 1", accountCount)
	}
}

// ----- T14: no index leaks -----

func TestActivation_NoIndexLeaks(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	// Resolution (done).
	start, consent := driveToConsent(t, ts, client, 210408407, "leak-key-done")
	resp := activateApprove(t, ts, client, consent.UserCode, consent.ConsentToken)
	resp.Body.Close()

	srv.mu.Lock()
	_, byUserCode := srv.activationsByUserCode[consent.UserCode]
	_, byState := srv.activationsByState[""] // sanity: never populated with empty key
	act := srv.activations[start["device_code"].(string)]
	srv.mu.Unlock()
	if byUserCode {
		t.Error("resolved (done) activation still indexed by user_code")
	}
	if byState {
		t.Error("unexpected empty-state index entry")
	}
	if act == nil {
		t.Fatal("resolved activation missing from s.activations (should stay pollable until TTL)")
	}
	if act.oidcState != "" {
		srv.mu.Lock()
		_, stillIndexed := srv.activationsByState[act.oidcState]
		srv.mu.Unlock()
		if stillIndexed {
			t.Error("resolved activation's oidcState still indexed in activationsByState")
		}
	}

	// Eviction.
	srv2, ts2 := newActivationHTTPServer(t, func(c *Config) { c.MaxPendingActivations = 1 })
	client2 := newActivationClient(t)
	first := activateStart(t, ts2, client2, 1, "evict-1")
	_ = activateStart(t, ts2, client2, 2, "evict-2")
	srv2.mu.Lock()
	_, ok := srv2.activations[first["device_code"].(string)]
	n := len(srv2.activations)
	srv2.mu.Unlock()
	if ok {
		t.Error("evicted activation still present in s.activations")
	}
	if n != 1 {
		t.Errorf("s.activations size after eviction = %d, want 1", n)
	}
}

// ----- T15 / T23: race detector -----

// gatedAuthenticator wraps the fake authenticator and blocks inside
// Exchange until release is closed, letting a test drive a concurrent
// mutation of the SAME activation while the "network call" is in flight —
// this is exactly the window design.md requires copying oidcVerifier/
// oidcNonce out from under the lock for.
type gatedAuthenticator struct {
	*fakeAuthenticator
	entered chan struct{}
	release chan struct{}
}

func (g *gatedAuthenticator) Exchange(ctx context.Context, code, verifier, nonce string) (*telegramoidc.Identity, error) {
	close(g.entered)
	<-g.release
	return g.fakeAuthenticator.Exchange(ctx, code, verifier, nonce)
}

func TestActivation_RaceDetector_PollAndBrowserLegConcurrent(t *testing.T) {
	gated := &gatedAuthenticator{fakeAuthenticator: newFakeAuthenticator(), entered: make(chan struct{}), release: make(chan struct{})}
	srv, ts := newActivationHTTPServer(t, func(c *Config) { c.TelegramOIDC = gated })
	client := newActivationClient(t)

	start := activateStart(t, ts, client, 210408407, "race-key")
	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	state := stateFromLocation(t, verifyResp.Header.Get("Location"))
	verifyResp.Body.Close()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		resp := callbackFor(t, ts, client, state) // blocks inside gated.Exchange
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}()
	go func() {
		defer wg.Done()
		<-gated.entered
		for i := 0; i < 5; i++ {
			_, _ = activatePoll(t, ts, client, start["device_code"].(string))
		}
	}()
	go func() {
		defer wg.Done()
		<-gated.entered
		srv.sweep(time.Now())
		close(gated.release)
	}()
	wg.Wait()
}

func TestActivation_RaceDetector_SecondVerifyDuringExchange(t *testing.T) {
	gated := &gatedAuthenticator{fakeAuthenticator: newFakeAuthenticator(), entered: make(chan struct{}), release: make(chan struct{})}
	_, ts := newActivationHTTPServer(t, func(c *Config) { c.TelegramOIDC = gated })
	client := newActivationClient(t)

	start := activateStart(t, ts, client, 210408407, "race-key-2")
	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	state := stateFromLocation(t, verifyResp.Header.Get("Location"))
	verifyResp.Body.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		resp := callbackFor(t, ts, client, state) // blocks inside gated.Exchange
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}()
	go func() {
		defer wg.Done()
		<-gated.entered
		// A second form submission for the SAME activation while the first
		// callback's Exchange is in flight: this must not race with the
		// verifier/nonce copy made under the lock before Exchange was
		// called (T23).
		resp2 := activateVerify(t, ts, client, start["user_code"].(string), csrf)
		resp2.Body.Close()
		close(gated.release)
	}()
	wg.Wait()
}

// ----- T16 / T18: login-CSRF binding -----

func TestActivation_LoginCSRF_NotTransferableBetweenBrowsers(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	before := snapshotDB(t, srv)
	browserA := newActivationClient(t)
	browserB := newActivationClient(t)

	start := activateStart(t, ts, browserA, 210408407, "csrf-key")
	csrf := activationFormCSRF(t, ts, browserA)
	verifyResp := activateVerify(t, ts, browserA, start["user_code"].(string), csrf)
	state := stateFromLocation(t, verifyResp.Header.Get("Location"))
	verifyResp.Body.Close()

	// Replay the callback from browser B, which never submitted the
	// user_code and so never received the lb_act_state cookie.
	resp := callbackFor(t, ts, browserB, state)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "consent_token") {
		t.Fatalf("cross-browser callback reached the consent page: %s", body)
	}

	if after := snapshotDB(t, srv); after != before {
		t.Errorf("db snapshot changed on cross-browser replay: before=%+v after=%+v", before, after)
	}

	status, poll := activatePoll(t, ts, browserA, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "denied" {
		t.Errorf("poll after cross-browser replay = %d %#v, want denied", status, poll)
	}
}

// T18: the state cookie actually reaches the callback via a real CookieJar,
// and is deleted afterwards.
func TestActivation_StateCookieReachesCallback(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	_, consent := driveToConsent(t, ts, client, 210408407, "cookie-key")
	if consent.ConsentToken == "" {
		t.Fatal("expected consent page after single-jar round trip")
	}

	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse ts.URL: %v", err)
	}
	for _, c := range client.Jar.Cookies(tsURL) {
		if c.Name == activationStateCookieName {
			t.Errorf("lb_act_state cookie still present after the callback consumed it: %+v", c)
		}
	}
}

// ----- T19: rate-limit keying is trusted-proxy-aware -----

func TestActivation_RateLimitKeying_TrustedProxyAware(t *testing.T) {
	trusted := netip.MustParsePrefix("198.51.100.0/24")
	srv, _ := newActivationHTTPServer(t, func(c *Config) {
		c.TrustedProxyCIDRs = []netip.Prefix{trusted}
	})

	// Two requests from the SAME trusted-proxy peer with DIFFERENT
	// X-Forwarded-For chains get separate keys.
	r1 := httptest.NewRequest("POST", "/local-bridge/activate", nil)
	r1.RemoteAddr = "198.51.100.5:1111"
	r1.Header.Set("X-Forwarded-For", "203.0.113.10")
	k1 := srv.clientIP(r1)
	if k1 != "203.0.113.10" {
		t.Errorf("trusted-peer XFF key = %q, want 203.0.113.10", k1)
	}

	r2 := httptest.NewRequest("POST", "/local-bridge/activate", nil)
	r2.RemoteAddr = "198.51.100.5:2222"
	r2.Header.Set("X-Forwarded-For", "203.0.113.20")
	k2 := srv.clientIP(r2)
	if k2 == k1 {
		t.Errorf("two different XFF chains behind the trusted proxy resolved to the same key %q", k1)
	}

	// An UNTRUSTED peer's forged X-Forwarded-For must NOT change the key:
	// the peer address itself is the key, and rotating the header must not
	// evade the limiter.
	r3 := httptest.NewRequest("POST", "/local-bridge/activate", nil)
	r3.RemoteAddr = "203.0.113.99:3333"
	r3.Header.Set("X-Forwarded-For", "1.2.3.4")
	k3 := srv.clientIP(r3)
	if k3 != "203.0.113.99" {
		t.Errorf("untrusted-peer key = %q, want the peer address 203.0.113.99 (header must be ignored)", k3)
	}

	r4 := httptest.NewRequest("POST", "/local-bridge/activate", nil)
	r4.RemoteAddr = "203.0.113.99:4444"
	r4.Header.Set("X-Forwarded-For", "5.6.7.8") // rotated header, same untrusted peer
	k4 := srv.clientIP(r4)
	if k4 != k3 {
		t.Errorf("rotating X-Forwarded-For from an untrusted peer changed the key: %q -> %q", k3, k4)
	}
}

// ----- T20: code-form CSRF -----

func TestActivation_CodeFormCSRF(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	start := activateStart(t, ts, client, 210408407, "csrf-form-key")

	// Prime the cookie jar with a valid CSRF cookie, but post a form with NO
	// csrf_token field at all.
	activationFormCSRF(t, ts, client)
	form := url.Values{"user_code": {start["user_code"].(string)}}
	resp, err := client.PostForm(ts.URL+"/local-bridge/activate", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		t.Error("missing csrf_token still redirected to Telegram")
	}
	tsURL, _ := url.Parse(ts.URL)
	for _, c := range client.Jar.Cookies(tsURL) {
		if c.Name == activationStateCookieName {
			t.Error("a CSRF-rejected submission set the login-CSRF state cookie")
		}
	}

	// Mismatched token: also refused.
	client2 := newActivationClient(t)
	activationFormCSRF(t, ts, client2)
	form2 := url.Values{"user_code": {start["user_code"].(string)}, "csrf_token": {"not-the-cookie-value"}}
	resp2, err := client2.PostForm(ts.URL+"/local-bridge/activate", form2)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusFound {
		t.Error("mismatched csrf_token still redirected to Telegram")
	}
}

// ----- T21: poll never leaks an internal status -----

func TestActivation_PollNeverLeaksInternalStatus(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	start, _ := driveToConsent(t, ts, client, 210408407, "internal-status-key")
	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "pending" {
		t.Errorf("poll while awaiting_consent = %d %#v, want pending", status, poll)
	}
}

// ----- T24: user_code collisions regenerate, not silently overwrite -----

func TestActivation_UserCodeCollisionRegenerates(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	const dup = "DUPE-CODE"
	calls := 0
	orig := generateUserCodeFn
	t.Cleanup(func() { generateUserCodeFn = orig })
	generateUserCodeFn = func() (string, error) {
		calls++
		if calls == 1 {
			return dup, nil
		}
		return orig()
	}

	first := activateStart(t, ts, client, 1, "collide-1")
	if first["user_code"] != dup {
		t.Fatalf("first user_code = %v, want %q", first["user_code"], dup)
	}
	second := activateStart(t, ts, client, 2, "collide-2")
	if second["user_code"] == dup {
		t.Fatalf("second start reused the colliding user_code instead of regenerating")
	}
	if second["user_code"] == first["user_code"] {
		t.Fatalf("first and second activations share a user_code")
	}

	// Both remain independently reachable by their own device_code.
	for _, dc := range []string{first["device_code"].(string), second["device_code"].(string)} {
		status, poll := activatePoll(t, ts, client, dc)
		if status != http.StatusOK || poll["status"] != "pending" {
			t.Errorf("poll(%s) = %d %#v, want pending", dc, status, poll)
		}
	}
}

// ----- T25: a store failure leaves a usable retry -----

func TestActivation_StoreFailureLeavesUsableRetry(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	_, consent := driveToConsent(t, ts, client, 210408407, "retry-store-key")

	// Force EnsureUserByTelegramID (the first store call in the approve
	// path) to fail once by closing the underlying DB connection's ability
	// to serve this one query is impractical here; instead simulate a
	// transient failure by revoking write access is also impractical for
	// SQLite in-memory. Exercise the retry contract directly against the
	// activation state machine instead, mirroring what a store failure
	// would leave behind: resolving -> awaiting_consent with a fresh token.
	srv.mu.Lock()
	act := srv.activationsByUserCode[consent.UserCode]
	if act == nil {
		srv.mu.Unlock()
		t.Fatal("activation not found by user_code")
	}
	act.status = statusResolving
	act.consentToken = ""
	srv.mu.Unlock()

	srv.retryActivationAfterStoreFailure(httptest.NewRecorder(), act, "simulated transient failure")

	srv.mu.Lock()
	newStatus := act.status
	newToken := act.consentToken
	srv.mu.Unlock()
	if newStatus != statusAwaitingConsent {
		t.Fatalf("status after retry = %q, want %q", newStatus, statusAwaitingConsent)
	}
	if newToken == "" || newToken == consent.ConsentToken {
		t.Fatalf("retry did not mint a fresh consentToken (old=%q new=%q)", consent.ConsentToken, newToken)
	}

	// The fresh token works.
	resp := activateApprove(t, ts, client, consent.UserCode, newToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve with fresh retry token status=%d body=%s", resp.StatusCode, b)
	}
}

// ----- T26: reopening the code form resumes awaiting-consent -----

func TestActivation_ReopenFormResumesAwaitingConsent(t *testing.T) {
	_, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)

	start, consent1 := driveToConsent(t, ts, client, 210408407, "resume-key")

	// Submit the SAME user_code again instead of using the consent page.
	csrf := activationFormCSRF(t, ts, client)
	verifyResp := activateVerify(t, ts, client, start["user_code"].(string), csrf)
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode == http.StatusFound {
		t.Fatal("resubmitting a user_code already awaiting_consent started a second OIDC redirect")
	}
	body, _ := io.ReadAll(verifyResp.Body)
	consent2 := extractConsent(t, body)
	if consent2.ConsentToken == consent1.ConsentToken {
		t.Error("resumed consent page carries the SAME token as before, want a fresh one")
	}

	resp := activateApprove(t, ts, client, consent2.UserCode, consent2.ConsentToken)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve with resumed token status=%d body=%s", resp.StatusCode, b)
	}
}

// ----- sanity: the two error types poll returns are distinguishable -----

func TestActivation_Deny_LeavesDatabaseUntouched(t *testing.T) {
	srv, ts := newActivationHTTPServer(t)
	client := newActivationClient(t)
	before := snapshotDB(t, srv)

	start, consent := driveToConsent(t, ts, client, 210408407, "deny-key")
	resp := activateDeny(t, ts, client, consent.UserCode, consent.ConsentToken)
	resp.Body.Close()

	if after := snapshotDB(t, srv); after != before {
		t.Errorf("db snapshot changed after deny: before=%+v after=%+v", before, after)
	}
	status, poll := activatePoll(t, ts, client, start["device_code"].(string))
	if status != http.StatusOK || poll["status"] != "denied" {
		t.Errorf("poll after deny = %d %#v, want denied", status, poll)
	}
}

// ----- capacity policy: a flood may only ever displace its own activations -----

// startActivationFrom drives POST /api/local-bridge/activate/start directly
// against the handler with a chosen peer address, and returns the response
// recorder plus the minted device_code (empty when the request was refused).
func startActivationFrom(t *testing.T, srv *Server, remoteAddr, regKey string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	body := `{"telegram_id":210408407,"device_registration_key":"` + regKey + `","device_label":"l"}`
	r := httptest.NewRequest("POST", "/api/local-bridge/activate/start", strings.NewReader(body))
	r.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	srv.handleActivateStart(rec, r)
	if rec.Code != http.StatusOK {
		return rec, ""
	}
	var out struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode start response: %v", err)
	}
	return rec, out.DeviceCode
}

// The activation map is capacity-bounded because /activate/start is
// unauthenticated. With a plain oldest-evict that bound was itself the attack:
// a flood from one address pushed OTHER users' in-flight activations out, and
// their correctly typed verification codes came back as unknown in the middle
// of signing in. Capacity must only ever be reclaimed from the requester.
func TestActivateStart_FloodCannotEvictAnotherClient(t *testing.T) {
	srv, _ := newActivationHTTPServer(t, func(c *Config) {
		c.MaxPendingActivations = 4
		c.MaxActivationsPerIP = 4
	})

	// A legitimate user starts first, and is therefore the oldest entry --
	// exactly what a plain oldest-evict would sacrifice.
	_, victim := startActivationFrom(t, srv, "203.0.113.7:1000", "victim-key")
	if victim == "" {
		t.Fatal("victim activation was refused")
	}

	// The attacker floods well past the global cap from a single address.
	for i := 0; i < 40; i++ {
		rec, code := startActivationFrom(t, srv, "198.51.100.9:2000", fmt.Sprintf("flood-%d", i))
		if code == "" && rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("refusal %d used status %d, want 503", i, rec.Code)
		}
	}

	srv.mu.Lock()
	_, stillThere := srv.activations[victim]
	attacker, _ := srv.activationsForIPLocked("198.51.100.9")
	srv.mu.Unlock()
	if !stillThere {
		t.Fatal("the flood evicted the victim's activation; capacity must only be reclaimed from the requester")
	}
	if attacker > 4 {
		t.Fatalf("attacker holds %d activations, above its per-IP cap of 4", attacker)
	}
}

// The other half of the same property: when the map is globally full of OTHER
// clients' activations, a newcomer holding none of them is refused outright.
// Evicting a stranger to make room is exactly what must not happen.
func TestActivateStart_RefusesRatherThanEvictingStrangers(t *testing.T) {
	srv, _ := newActivationHTTPServer(t, func(c *Config) {
		c.MaxPendingActivations = 5
		c.MaxActivationsPerIP = 5
	})

	held := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		_, code := startActivationFrom(t, srv, fmt.Sprintf("203.0.113.%d:1000", i+1), fmt.Sprintf("k%d", i))
		if code == "" {
			t.Fatalf("start %d was refused while the map still had room", i)
		}
		held = append(held, code)
	}

	rec, code := startActivationFrom(t, srv, "198.51.100.9:2000", "newcomer")
	if code != "" {
		t.Fatal("a newcomer was admitted into a full map, which means somebody else was evicted")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("refusal status = %d, want 503", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got == "" {
		t.Error("refusal carried no Retry-After header")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for i, c := range held {
		if _, ok := srv.activations[c]; !ok {
			t.Errorf("activation %d was evicted to admit the newcomer", i)
		}
	}
}

// A single client is also capped in how much of the map it can occupy, so it
// cannot fill the map first and starve everyone arriving after it. Asking for
// one more than the cap recycles that client's OWN oldest activation.
func TestActivateStart_PerIPCapRecyclesOwnOldest(t *testing.T) {
	srv, _ := newActivationHTTPServer(t, func(c *Config) {
		c.MaxPendingActivations = 100
		c.MaxActivationsPerIP = 2
	})

	_, first := startActivationFrom(t, srv, "203.0.113.7:1000", "k1")
	_, second := startActivationFrom(t, srv, "203.0.113.7:1001", "k2")
	_, third := startActivationFrom(t, srv, "203.0.113.7:1002", "k3")
	if first == "" || second == "" || third == "" {
		t.Fatal("a start within the per-IP cap was refused")
	}

	srv.mu.Lock()
	_, haveFirst := srv.activations[first]
	_, haveSecond := srv.activations[second]
	_, haveThird := srv.activations[third]
	n, _ := srv.activationsForIPLocked("203.0.113.7")
	srv.mu.Unlock()

	if haveFirst {
		t.Error("the client's own oldest activation was not recycled at the per-IP cap")
	}
	if !haveSecond || !haveThird {
		t.Error("the two most recent activations for this client should have survived")
	}
	if n > 2 {
		t.Errorf("client holds %d activations, above the per-IP cap of 2", n)
	}
}

// The failed-submission limiter map is written from an unauthenticated path
// for whatever key clientIP derives, so it needs its own bound: a spread-out
// source never trips the per-key budget and would otherwise grow it without
// limit between sweeps.
func TestActivationFailLimiter_MapIsBounded(t *testing.T) {
	srv, _ := newActivationHTTPServer(t, func(c *Config) {
		c.MaxActivationFailKeys = 8
	})
	for i := 0; i < 200; i++ {
		srv.recordActivationFailure(fmt.Sprintf("203.0.113.%d", i%254))
	}
	srv.mu.Lock()
	n := len(srv.activationFails)
	srv.mu.Unlock()
	if n > 8 {
		t.Fatalf("activationFails holds %d keys, above the configured bound of 8", n)
	}
}
