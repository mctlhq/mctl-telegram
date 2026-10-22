package oauth

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

var deniedReturnHref = regexp.MustCompile(`<a class="btnlink" href="([^"]+)">Return to ([^<]+)</a>`)

// assertDeniedReturn checks that a refusal page offers the button back to the
// client and that it carries the RFC 6749 section 4.1.2.1 error response:
// error=access_denied, the client's state verbatim and no code.
func assertDeniedReturn(t *testing.T, body, wantState string) {
	t.Helper()
	m := deniedReturnHref.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("refusal page offers no return to the client; body=%s", body)
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatalf("return link %q: %v", m[1], err)
	}
	if u.Scheme != "https" || u.Host != "claude.ai" || u.Path != "/cb" {
		t.Errorf("return link %s does not target the client's redirect_uri", u)
	}
	q := u.Query()
	if got := q.Get("error"); got != "access_denied" {
		t.Errorf("return link error = %q, want access_denied", got)
	}
	if got := q.Get("state"); got != wantState {
		t.Errorf("return link state = %q, want %q", got, wantState)
	}
	if q.Has("code") {
		t.Errorf("return link for a refusal carries a code: %s", u)
	}
	if q.Get("error_description") == "" {
		t.Errorf("return link carries no error_description: %s", u)
	}
	if m[2] != "Claude" {
		t.Errorf("return button names %q, want Claude", m[2])
	}
}

// TestDeniedReturn_SameHostWizardGetsNoReturn pins the one redirect_uri that
// must not get the button: the self-hosted wizard's own done page, which has
// no client waiting on it and renders its own page.
func TestDeniedReturn_SameHostWizardGetsNoReturn(t *testing.T) {
	srv := newTestServer(t)
	if got, _ := srv.deniedReturn(oauthCtx{RedirectURI: connectRedirectURI(testIssuer), ClientState: "s"}, "d"); got != "" {
		t.Errorf("same-host redirect got a return link %q", got)
	}
	if got, _ := srv.deniedReturn(oauthCtx{}, "d"); got != "" {
		t.Errorf("empty redirect_uri got a return link %q", got)
	}
	got, app := srv.deniedReturn(oauthCtx{RedirectURI: "https://claude.ai/cb?keep=1", ClientState: "s t"}, "d")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	q := u.Query()
	if q.Get("keep") != "1" || q.Get("state") != "s t" || q.Get("error") != "access_denied" || app != "Claude" {
		t.Errorf("deniedReturn = %q (%s), want the redirect_uri's own query kept plus the error response", got, app)
	}
}

// TestDeniedDescription_IsRFCSafe holds every error_description to the
// character set RFC 6749 allows (%x20-21 / %x23-5B / %x5D-7E).
func TestDeniedDescription_IsRFCSafe(t *testing.T) {
	for _, err := range []error{db.ErrAccountModeConflict, db.ErrAccountDeletedSinceGrant, nil} {
		d := deniedDescription(err)
		if d == "" {
			t.Errorf("deniedDescription(%v) is empty", err)
		}
		for _, r := range d {
			if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
				t.Errorf("deniedDescription(%v) = %q has %q outside RFC 6749's error_description set", err, d, r)
			}
		}
		if strings.TrimSpace(d) != d {
			t.Errorf("deniedDescription(%v) = %q has surrounding space", err, d)
		}
	}
}
