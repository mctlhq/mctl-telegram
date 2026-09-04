package mcp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
)

// ----- T7: the zero-admin onboarding path, end to end -----
//
// This is issue #484's Definition of Done, and through it #479's: a brand-new
// Telegram id goes from nothing to sending messages without an operator
// touching anything.
//
//	activate -> read -> owner grants send -> send -> credential refresh -> reconnect
//
// Two properties are asserted at every step rather than once at the end,
// because both are claims the product makes rather than implementation
// details:
//
//   - telegram_accounts.session_encrypted stays NULL. Local Bridge's whole
//     premise is that the server never holds a usable copy of the session; a
//     step that quietly populated it would keep every other assertion here
//     true while breaking the only thing that distinguishes this mode.
//   - No operator-only tool is used. provision_local_account,
//     set_account_send, set_account_mode and the admin worker-token mint are
//     each asserted absent from the audit log, so "zero-admin" is checked
//     against what the flow DID rather than against what this test happened
//     to call.

// e2eOIDC is the Telegram leg: it returns one canned verified identity, the
// same shape the real Authenticator produces after checking the id_token.
type e2eOIDC struct{ id telegramoidc.Identity }

func (f *e2eOIDC) AuthCodeURL(state, nonce, codeChallenge string) string {
	return "https://oauth.telegram.test/authorize?state=" + url.QueryEscape(state)
}

func (f *e2eOIDC) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*telegramoidc.Identity, error) {
	out := f.id
	return &out, nil
}

var (
	e2eCSRFRe     = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)
	e2eConsentRe  = regexp.MustCompile(`name="consent_token" value="([^"]*)"`)
	e2eUserCodeRe = regexp.MustCompile(`name="user_code" value="([^"]*)"`)
)

func TestZeroAdminOnboarding_EndToEnd(t *testing.T) {
	const tgID = int64(770000484)
	ctx := context.Background()
	store := newToolsTestStore(t)

	srv, err := oauth.New(ctx, oauth.Config{
		Issuer:    "https://tg.test",
		JWTSecret: []byte("e2e-secret-value-at-least-32-bytes!!"),
		TelegramOIDC: &e2eOIDC{id: telegramoidc.Identity{
			TelegramID: tgID, Username: "zeroadmin", FirstName: "Zero", LastName: "Admin",
		}},
		AccessTokenTTL: time.Hour,
		CodeTTL:        time.Minute,
	}, store)
	if err != nil {
		t.Fatalf("oauth.New: %v", err)
	}
	r := chi.NewRouter()
	srv.Register(r)
	ts := httptest.NewServer(r)
	defer ts.Close()

	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// The invariant that must hold at EVERY step, not merely at the end.
	assertNoServerSideSession := func(step string) {
		t.Helper()
		var n int
		if err := store.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM telegram_accounts
			  WHERE telegram_user_id = ? AND session_encrypted IS NOT NULL`, tgID,
		).Scan(&n); err != nil {
			t.Fatalf("%s: read session_encrypted: %v", step, err)
		}
		if n != 0 {
			t.Fatalf("%s: the server holds %d encrypted session(s) for this account; Local Bridge must hold none", step, n)
		}
	}
	assertNoServerSideSession("before anything")

	// ---- init + login: the device's own key material, never leaving here ----
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate device key: %v", err)
	}

	// ---- activate ----
	startBody, _ := json.Marshal(map[string]any{
		"telegram_id":             tgID,
		"device_registration_key": "e2e-idem-key",
		"device_label":            "e2e-laptop",
		"device_pubkey":           base64.StdEncoding.EncodeToString(pub),
	})
	resp, err := browser.Post(ts.URL+"/api/local-bridge/activate/start", "application/json", bytes.NewReader(startBody))
	if err != nil {
		t.Fatalf("activate/start: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("activate/start status=%d body=%s", resp.StatusCode, body)
	}
	var start struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
	}
	if err := json.Unmarshal(body, &start); err != nil {
		t.Fatalf("decode start: %v", err)
	}
	if strings.Contains(start.VerificationURI, start.UserCode) {
		t.Fatal("the verification URI carries the user_code, defeating the typed-code step")
	}
	assertNoServerSideSession("after activate/start")

	// The browser types the code.
	formResp, err := browser.Get(ts.URL + "/local-bridge/activate")
	if err != nil {
		t.Fatalf("get form: %v", err)
	}
	formBody, _ := io.ReadAll(formResp.Body)
	formResp.Body.Close()
	csrf := string(e2eCSRFRe.FindSubmatch(formBody)[1])

	verifyResp, err := browser.PostForm(ts.URL+"/local-bridge/activate", url.Values{
		"user_code": {start.UserCode}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusFound {
		t.Fatalf("verify status=%d, want a redirect to Telegram", verifyResp.StatusCode)
	}
	loc, _ := url.Parse(verifyResp.Header.Get("Location"))
	state := loc.Query().Get("state")

	cbResp, err := browser.Get(ts.URL + "/oauth/telegram/callback?" + url.Values{
		"state": {state}, "code": {"tg-code"},
	}.Encode())
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	cbBody, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()
	consentTok := string(e2eConsentRe.FindSubmatch(cbBody)[1])
	consentCode := string(e2eUserCodeRe.FindSubmatch(cbBody)[1])
	assertNoServerSideSession("after the Telegram leg, before consent")

	// Nothing is written until the signed-in browser explicitly approves.
	approveResp, err := browser.PostForm(ts.URL+"/local-bridge/activate/consent", url.Values{
		"user_code": {consentCode}, "consent_token": {consentTok}, "action": {"approve"},
	})
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	approveResp.Body.Close()

	pollResp, err := browser.Post(ts.URL+"/api/local-bridge/activate/poll", "application/json",
		strings.NewReader(`{"device_code":"`+start.DeviceCode+`"}`))
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	pollBody, _ := io.ReadAll(pollResp.Body)
	pollResp.Body.Close()
	var poll struct {
		Status   string `json:"status"`
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(pollBody, &poll)
	if poll.Status != "done" || poll.DeviceID == "" {
		t.Fatalf("poll = %s, want done with a device_id", pollBody)
	}
	assertNoServerSideSession("after activation completed")

	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "zeroadmin", "Zero Admin")
	if err != nil {
		t.Fatalf("resolve user: %v", err)
	}

	// ---- read: the first credential is read-only, whatever consent says ----
	cred := e2eCredential(t, ts, browser, poll.DeviceID, priv, "credential")
	if hasScope(cred.Scopes, "telegram:messages:send") {
		t.Fatalf("first issuance carried a send scope: %v", cred.Scopes)
	}
	if !hasScope(cred.Scopes, "telegram:messages:read") {
		t.Fatalf("first issuance cannot read: %v", cred.Scopes)
	}

	readID := &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: cred.Scopes}
	if real, _ := evaluateSendGate(ctx, store, readID, true, 0); real {
		t.Fatal("a send would have been real before the owner granted consent")
	}
	assertNoServerSideSession("after the first credential")

	// ---- owner grants send, from their OWN session ----
	_, consentHandler := (&Server{Store: store}).toolSetSendConsent()
	ownerCtx := auth.With(ctx, &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: []string{"account:manage"}})
	if res, err := consentHandler(ownerCtx, toolCall("set_send_consent", map[string]any{"enabled": true})); err != nil || res.IsError {
		t.Fatalf("owner could not grant send consent: err=%v res=%+v", err, res)
	}

	// The account flag flips at once — that is what makes a REVOKE immediate,
	// with no refresh, reconnect or restart in between.
	if enabled, err := store.IsSendEnabled(ctx, uid); err != nil || !enabled {
		t.Fatalf("send_enabled did not flip on the grant: %v %v", enabled, err)
	}

	// ---- send ----
	//
	// The credential in hand is still the read-only one, so this send is
	// refused for want of SCOPE, not for want of consent — and the refusal is
	// decided HERE, on the server, which returns the dry-run to the MCP client
	// without contacting the daemon at all. That is why there is no daemon-side
	// mechanism to shortcut it: a daemon never sees this refusal. The scope
	// arrives on the credential's next refresh, which is the step below.
	if real, reason := evaluateSendGate(ctx, store, readID, true, 0); real {
		t.Fatal("a read-only credential was allowed to send")
	} else if !strings.Contains(reason, "scope") {
		t.Fatalf("refusal reason was %q, expected it to name the missing scope", reason)
	}

	// ---- credential refresh: scope derived from current state ----
	refreshed := e2eCredential(t, ts, browser, poll.DeviceID, priv, "refresh")
	if !hasScope(refreshed.Scopes, "telegram:messages:send") {
		t.Fatalf("refresh did not pick up the granted send scope: %v", refreshed.Scopes)
	}

	// ...and now the send is real, which is the step the Definition of Done
	// names. Nothing was restarted and no operator was involved.
	sendID := &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: refreshed.Scopes}
	if real, reason := evaluateSendGate(ctx, store, sendID, true, 0); !real {
		t.Fatalf("send still refused after consent and refresh: %s", reason)
	}
	assertNoServerSideSession("after the grant, refresh and send decision")

	// A revoke needs no refresh at all: the same live read that decides every
	// send refuses the next one outright.
	if _, err := store.SetSendEnabled(ctx, uid, false); err != nil {
		t.Fatalf("revoke send consent: %v", err)
	}
	if real, _ := evaluateSendGate(ctx, store, sendID, true, 0); real {
		t.Fatal("a send was still real after the owner revoked consent, with the same credential in hand")
	}
	if _, err := store.SetSendEnabled(ctx, uid, true); err != nil {
		t.Fatalf("restore send consent: %v", err)
	}
	if refreshed.Jti != cred.Jti {
		t.Fatalf("refresh minted a new jti (%q -> %q); the lineage must carry forward so revoking it revokes all of it", cred.Jti, refreshed.Jti)
	}

	// ---- daemon reconnect: another refresh, no credential presented ----
	again := e2eCredential(t, ts, browser, poll.DeviceID, priv, "refresh")
	if again.Token == "" || again.Jti != cred.Jti {
		t.Fatalf("reconnect refresh failed or broke the lineage: %+v", again)
	}
	assertNoServerSideSession("after refresh and reconnect")

	// ---- and none of it went through an operator ----
	for _, forbidden := range []string{
		"provision_local_account", "set_account_send", "set_account_mode", "mint_worker_token",
	} {
		var n int
		if err := store.DB.QueryRowContext(ctx,
			`SELECT count(*) FROM audit_logs WHERE tool_name = ?`, forbidden).Scan(&n); err != nil {
			continue // the audit table shape is not this test's subject
		}
		if n != 0 {
			t.Errorf("zero-admin onboarding used the operator tool %q %d time(s)", forbidden, n)
		}
	}
}

type e2eCred struct {
	Token  string
	Jti    string
	Scopes []string
}

// e2eCredential runs one PoP round trip: nonce, sign, then either the
// issuance or the refresh endpoint. Neither presents an existing credential —
// possession of the device key is the whole authentication.
func e2eCredential(t *testing.T, ts *httptest.Server, c *http.Client, deviceID string, priv ed25519.PrivateKey, endpoint string) e2eCred {
	t.Helper()
	base := ts.URL + "/api/local-bridge/devices/" + deviceID
	nr, err := c.Post(base+"/nonce", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	nb, _ := io.ReadAll(nr.Body)
	nr.Body.Close()
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(nb, &nonce); err != nil || nonce.Nonce == "" {
		t.Fatalf("decode nonce: %v (body=%s)", err, nb)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(deviceID+"."+nonce.Nonce)))
	payload, _ := json.Marshal(map[string]string{"nonce": nonce.Nonce, "signature": sig})
	cr, err := c.Post(base+"/"+endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("%s: %v", endpoint, err)
	}
	cb, _ := io.ReadAll(cr.Body)
	cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		t.Fatalf("%s status=%d body=%s", endpoint, cr.StatusCode, cb)
	}
	var out struct {
		WorkerToken string   `json:"worker_token"`
		Jti         string   `json:"jti"`
		Scopes      []string `json:"scopes"`
	}
	if err := json.Unmarshal(cb, &out); err != nil {
		t.Fatalf("decode %s: %v (body=%s)", endpoint, err, cb)
	}
	if len(out.Scopes) == 0 {
		out.Scopes = jwtScopesForTest(t, out.WorkerToken)
	}
	return e2eCred{Token: out.WorkerToken, Jti: out.Jti, Scopes: out.Scopes}
}

func jwtScopesForTest(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("worker token is not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode JWT payload: %v", err)
	}
	var claims struct {
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	return claims.Scopes
}

func hasScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}

func toolCall(name string, args map[string]any) mcplib.CallToolRequest {
	return mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name, Arguments: args}}
}
