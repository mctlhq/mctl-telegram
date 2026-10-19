package oauth

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// cspNonce extracts the script-src nonce from a CSP header, or "" if absent.
func cspNonce(csp string) string {
	const marker = "script-src 'nonce-"
	i := strings.Index(csp, marker)
	if i < 0 {
		return ""
	}
	rest := csp[i+len(marker):]
	end := strings.IndexByte(rest, '\'')
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// The password screen carries the only inline <script> in the enable_access
// flow (the show/hide toggle). It must be authorized by a per-request CSP
// nonce — never unsafe-inline — and the <script> tag must echo that nonce.
func TestRenderEnablePassword_NonceScopedScript(t *testing.T) {
	rec := httptest.NewRecorder()
	renderEnablePassword(rec, enablePasswordPage{Issuer: "https://tg.mctl.ai", EnableToken: "tok"})

	csp := rec.Header().Get("Content-Security-Policy")
	body := rec.Body.String()

	nonce := cspNonce(csp)
	if nonce == "" {
		t.Fatalf("CSP has no script-src nonce: %q", csp)
	}
	if !strings.Contains(csp, "img-src https://ui.mctl.ai") {
		t.Fatalf("CSP must allow the CDN favicon: %q", csp)
	}
	if strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("CSP must not allow unsafe-inline scripts: %q", csp)
	}
	if !strings.Contains(body, `<script nonce="`+nonce+`">`) {
		t.Fatalf("<script> tag does not echo the CSP nonce %q", nonce)
	}
	for _, want := range []string{`id="pwtoggle"`, `class="eye-show"`, `class="eye-hide"`} {
		if !strings.Contains(body, want) {
			t.Errorf("password-toggle markup missing %q", want)
		}
	}
}

// Sending is opt-in: a new account starts read-only, as the public pages
// promise. The wizard permissions screen pre-selects the "readonly" radio and
// the non-wizard phone screen leaves the send_optin checkbox unchecked unless
// the user already chose sending.
func TestEnableUI_DefaultsToReadOnly(t *testing.T) {
	permRec := httptest.NewRecorder()
	renderEnablePermissions(permRec, enablePermissionsPage{Issuer: "https://tg.mctl.ai", EnableToken: "tok"})
	perm := permRec.Body.String()
	if !strings.Contains(perm, `value="readonly" checked`) {
		t.Errorf("permissions screen must default-select the read-only radio; body=%s", perm)
	}
	if strings.Contains(perm, `value="send" checked`) {
		t.Errorf("permissions screen must not default-select send")
	}

	phoneRec := httptest.NewRecorder()
	renderEnablePhone(phoneRec, enablePhonePage{Issuer: "https://tg.mctl.ai", EnableToken: "tok"})
	phone := phoneRec.Body.String()
	if strings.Contains(phone, `name="send_optin" value="on" checked`) {
		t.Errorf("phone screen must not pre-check the send_optin checkbox by default; body=%s", phone)
	}

	// The checkbox still reflects an explicit earlier choice.
	phoneRec = httptest.NewRecorder()
	renderEnablePhone(phoneRec, enablePhonePage{Issuer: "https://tg.mctl.ai", EnableToken: "tok", SendOptIn: true})
	if !strings.Contains(phoneRec.Body.String(), `name="send_optin" value="on" checked`) {
		t.Errorf("phone screen must pre-check the send_optin checkbox when SendOptIn=true")
	}
}

// A leaked/reused nonce would let an injected script replay it, so each
// render must mint a fresh one.
func TestRenderEnablePassword_FreshNoncePerRequest(t *testing.T) {
	render := func() string {
		rec := httptest.NewRecorder()
		renderEnablePassword(rec, enablePasswordPage{})
		return cspNonce(rec.Header().Get("Content-Security-Policy"))
	}
	if a, b := render(), render(); a == "" || a == b {
		t.Fatalf("nonce not regenerated per request: %q vs %q", a, b)
	}
}

// The script-free screens must keep the strict no-script CSP.
func TestRenderEnable_NonPasswordScreensHaveNoScriptSrc(t *testing.T) {
	rec := httptest.NewRecorder()
	renderEnablePhone(rec, enablePhonePage{})
	if csp := rec.Header().Get("Content-Security-Policy"); strings.Contains(csp, "script-src") {
		t.Fatalf("phone screen must forbid scripts entirely, got CSP: %q", csp)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "img-src https://ui.mctl.ai") {
		t.Fatalf("phone screen CSP must allow the CDN favicon: %q", csp)
	}
}
