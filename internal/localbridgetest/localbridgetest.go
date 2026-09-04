// Package localbridgetest holds the test-only fixtures shared by the Local
// Bridge zero-admin end-to-end tests: the server-side one in internal/mcp
// (zero_admin_e2e_test.go) and the CLI/daemon one in cmd/local
// (e2e_cli_daemon_test.go). It is a regular (non _test) package only so both
// can import it; nothing in the shipped binaries depends on it.
//
// What lives here is the part of the flow that is neither the client under
// test nor the server under test: the Telegram OIDC leg, which cannot run in
// CI and is replaced by a canned verified identity, and the human's browser,
// which types the user code, "signs in", and approves the device on the
// consent screen.
package localbridgetest

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
)

// OIDC is the Telegram leg: it returns one canned verified identity, the
// same shape the real Authenticator produces after checking the id_token.
type OIDC struct{ Identity telegramoidc.Identity }

// AuthCodeURL implements telegramoidc.Authenticator.
func (f *OIDC) AuthCodeURL(state, nonce, codeChallenge string) string {
	return "https://oauth.telegram.test/authorize?state=" + url.QueryEscape(state)
}

// Exchange implements telegramoidc.Authenticator.
func (f *OIDC) Exchange(ctx context.Context, code, codeVerifier, expectedNonce string) (*telegramoidc.Identity, error) {
	out := f.Identity
	return &out, nil
}

var (
	csrfRe     = regexp.MustCompile(`name="csrf_token" value="([^"]*)"`)
	consentRe  = regexp.MustCompile(`name="consent_token" value="([^"]*)"`)
	userCodeRe = regexp.MustCompile(`name="user_code" value="([^"]*)"`)
)

// NewBrowser returns an http.Client that behaves like the human's browser
// for the activation pages: it keeps cookies (the flow binds CSRF, state and
// consent to cookies) and does not follow redirects, so the test can inspect
// the redirect to Telegram instead of following it into the stub.
func NewBrowser(t testing.TB) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// Consent is what the signed-in browser holds after the Telegram leg: the
// consent token and the user code the consent page will post back.
type Consent struct {
	Token    string
	UserCode string
}

// SignIn drives the browser half of an activation up to, but not including,
// the consent decision: it loads the activation form, types userCode, is
// redirected to "Telegram", and comes back through the OIDC callback. It
// returns what the consent page embeds. Nothing is written server-side yet.
func SignIn(t testing.TB, baseURL string, browser *http.Client, userCode string) Consent {
	t.Helper()
	formResp, err := browser.Get(baseURL + "/local-bridge/activate")
	if err != nil {
		t.Fatalf("get activation form: %v", err)
	}
	formBody, _ := io.ReadAll(formResp.Body)
	formResp.Body.Close()
	csrfMatch := csrfRe.FindSubmatch(formBody)
	if csrfMatch == nil {
		t.Fatalf("activation form carries no csrf_token: %s", formBody)
	}

	verifyResp, err := browser.PostForm(baseURL+"/local-bridge/activate", url.Values{
		"user_code": {userCode}, "csrf_token": {string(csrfMatch[1])},
	})
	if err != nil {
		t.Fatalf("verify user code: %v", err)
	}
	verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusFound {
		t.Fatalf("verify status=%d, want a redirect to Telegram", verifyResp.StatusCode)
	}
	loc, err := url.Parse(verifyResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Telegram redirect: %v", err)
	}
	state := loc.Query().Get("state")

	cbResp, err := browser.Get(baseURL + "/oauth/telegram/callback?" + url.Values{
		"state": {state}, "code": {"tg-code"},
	}.Encode())
	if err != nil {
		t.Fatalf("oidc callback: %v", err)
	}
	cbBody, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()
	tokMatch := consentRe.FindSubmatch(cbBody)
	codeMatch := userCodeRe.FindSubmatch(cbBody)
	if tokMatch == nil || codeMatch == nil {
		t.Fatalf("callback did not render the consent page (status %d): %s", cbResp.StatusCode, cbBody)
	}
	return Consent{Token: string(tokMatch[1]), UserCode: string(codeMatch[1])}
}

// Approve posts the consent decision from the signed-in browser. This is
// the only step that writes anything server-side.
func Approve(t testing.TB, baseURL string, browser *http.Client, c Consent) {
	t.Helper()
	resp, err := browser.PostForm(baseURL+"/local-bridge/activate/consent", url.Values{
		"user_code": {c.UserCode}, "consent_token": {c.Token}, "action": {"approve"},
	})
	if err != nil {
		t.Fatalf("consent: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("consent status=%d", resp.StatusCode)
	}
}
