package oauth

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// captureLog swaps slog's default handler for a text handler writing to buf,
// restoring the previous default at test cleanup, mirroring the pattern in
// internal/bridge/auth_failure_observability_test.go.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// registerReq POSTs body to /oauth/register through mux and returns the
// response recorder.
func registerReq(t *testing.T, mux *mockRouter, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "testclient/1.0")
	rec := httptest.NewRecorder()
	mux.serve("POST", "/oauth/register", rec, req)
	return rec
}

// TestRegister_RejectedClientEmitsAuditLine is T1/T2: a refused dynamic
// client registration must emit exactly one outcome=rejected audit line
// naming the reason, client_name, user_agent and the redirect's scheme/host
// — and must never leak the full redirect_uri, its path or its query. Uses a
// synthetic private-use scheme/host (never a real product's), matching the
// review's own instruction not to reuse cursor:// verbatim in a committed
// fixture.
func TestRegister_RejectedClientEmitsAuditLine(t *testing.T) {
	buf := captureLog(t)
	reg := metrics.New()
	srv := newTestServer(t)
	srv.WithMetrics(reg)
	mux := newMockRouter()
	srv.Register(mux)

	const clientName = "testclient-cli"
	const redirectURI = "testclient://anysphere.cursor-retrieval/oauth/callback?token=abc123&next=/secret/path"
	body := `{"client_name":"` + clientName + `","redirect_uris":["` + redirectURI + `"]}`
	rec := registerReq(t, mux, body)
	if rec.Code == 201 {
		t.Fatalf("expected the synthetic private-use scheme to be refused, got 201: %s", rec.Body.String())
	}

	lines := auditLines(buf.String())
	if len(lines) != 1 {
		t.Fatalf("expected exactly one audit line, got %d:\n%s", len(lines), buf.String())
	}
	line := lines[0]
	for _, want := range []string{
		`outcome=rejected`,
		`reason=redirect_scheme_not_allowed`,
		`redirect_scheme=testclient`,
		`redirect_host=anysphere.cursor-retrieval`,
		`client_name=` + clientName,
		`user_agent=testclient/1.0`,
	} {
		if !strings.Contains(line, want) {
			t.Errorf("audit line missing %q:\n%s", want, line)
		}
	}
	// T2: the full redirect_uri, its path, and its query must never appear.
	for _, forbidden := range []string{redirectURI, "/oauth/callback", "token=abc123", "/secret/path"} {
		if strings.Contains(line, forbidden) {
			t.Errorf("audit line leaked %q:\n%s", forbidden, line)
		}
	}

	if got := testutil.ToFloat64(reg.OAuthClientRegistrationsTotal.WithLabelValues("rejected", "redirect_scheme_not_allowed")); got != 1 {
		t.Errorf("mctl_oauth_client_registrations_total{outcome=rejected,reason=redirect_scheme_not_allowed} = %v, want 1", got)
	}
}

// auditLines returns every "oauth: client_registration audit" line from a
// captured log buffer.
func auditLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "oauth: client_registration audit") {
			out = append(out, line)
		}
	}
	return out
}

// TestRegister_TerminalExitsProduceExactlyOneAuditedOutcome is T3: a table
// test driving one request per terminal exit of handleClientRegistration,
// asserting the (outcome, reason) pair on both the log line and the counter,
// and that the label set matches the closed constant set exactly.
func TestRegister_TerminalExitsProduceExactlyOneAuditedOutcome(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		outcome string
		reason  string
	}{
		{
			name:    "malformed json",
			body:    `{not json`,
			outcome: "rejected",
			reason:  "malformed_body",
		},
		{
			name:    "no redirect_uris",
			body:    `{"client_name":"c"}`,
			outcome: "rejected",
			reason:  "no_redirect_uris",
		},
		{
			name:    "too many redirect_uris",
			body:    `{"client_name":"c","redirect_uris":["https://claude.ai/a","https://claude.ai/b","https://claude.ai/c"]}`,
			outcome: "rejected",
			reason:  "too_many_redirect_uris",
		},
		{
			name:    "redirect_uri too long",
			body:    `{"client_name":"c","redirect_uris":["https://claude.ai/` + strings.Repeat("a", 300) + `"]}`,
			outcome: "rejected",
			reason:  "redirect_uri_too_long",
		},
		{
			name:    "scheme not allowed",
			body:    `{"client_name":"c","redirect_uris":["testclient://anysphere.cursor-retrieval/cb"]}`,
			outcome: "rejected",
			reason:  "redirect_scheme_not_allowed",
		},
		{
			name:    "host not allowed",
			body:    `{"client_name":"c","redirect_uris":["https://attacker.example/cb"]}`,
			outcome: "rejected",
			reason:  "redirect_host_not_allowed",
		},
		{
			name:    "userinfo",
			body:    `{"client_name":"c","redirect_uris":["https://evil.com@claude.ai/cb"]}`,
			outcome: "rejected",
			reason:  "redirect_userinfo",
		},
		{
			name:    "backslash",
			body:    `{"client_name":"c","redirect_uris":["http://evil.com\\@localhost/cb"]}`,
			outcome: "rejected",
			reason:  "redirect_backslash",
		},
		{
			name:    "accepted",
			body:    `{"client_name":"c","redirect_uris":["https://claude.ai/cb"]}`,
			outcome: "accepted",
			reason:  "ok",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureLog(t)
			reg := metrics.New()
			srv := newTestServer(t, func(c *Config) { c.MaxRedirectURIs = 2; c.MaxRedirectURILength = 200 })
			srv.WithMetrics(reg)
			mux := newMockRouter()
			srv.Register(mux)

			registerReq(t, mux, tc.body)

			lines := auditLines(buf.String())
			if len(lines) != 1 {
				t.Fatalf("expected exactly one audit line, got %d:\n%s", len(lines), buf.String())
			}
			if !strings.Contains(lines[0], "outcome="+tc.outcome) {
				t.Errorf("outcome: line = %q, want outcome=%s", lines[0], tc.outcome)
			}
			if !strings.Contains(lines[0], "reason="+tc.reason) {
				t.Errorf("reason: line = %q, want reason=%s", lines[0], tc.reason)
			}
			if got := testutil.ToFloat64(reg.OAuthClientRegistrationsTotal.WithLabelValues(tc.outcome, tc.reason)); got != 1 {
				t.Errorf("mctl_oauth_client_registrations_total{outcome=%s,reason=%s} = %v, want 1", tc.outcome, tc.reason, got)
			}
		})
	}
}

// TestRegister_PersistFailureIsAuditedAsError drives the InsertClientReg
// failure exit (outcome=error, reason=persist_failed) via the DB-backed path.
func TestRegister_PersistFailureIsAuditedAsError(t *testing.T) {
	buf := captureLog(t)
	reg := metrics.New()
	srv := newTestServer(t)
	srv.WithMetrics(reg)
	srv.useDB = true
	// Close the underlying DB so InsertClientReg fails deterministically.
	if err := srv.store.DB.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	mux := newMockRouter()
	srv.Register(mux)

	rec := registerReq(t, mux, `{"client_name":"c","redirect_uris":["https://claude.ai/cb"]}`)
	if rec.Code == 201 {
		t.Fatalf("expected persist failure to produce a non-201 response, got 201: %s", rec.Body.String())
	}

	lines := auditLines(buf.String())
	if len(lines) != 1 {
		t.Fatalf("expected exactly one audit line, got %d:\n%s", len(lines), buf.String())
	}
	if !strings.Contains(lines[0], "outcome=error") || !strings.Contains(lines[0], "reason=persist_failed") {
		t.Errorf("audit line = %q, want outcome=error reason=persist_failed", lines[0])
	}
	if got := testutil.ToFloat64(reg.OAuthClientRegistrationsTotal.WithLabelValues("error", "persist_failed")); got != 1 {
		t.Errorf("mctl_oauth_client_registrations_total{outcome=error,reason=persist_failed} = %v, want 1", got)
	}
}

// TestRegister_AcceptedAndRateLimitedKeepExistingAttributes is T4: an
// accepted registration still emits outcome=accepted with client_name and
// redirect_uri_count, and a rate-limited one still emits outcome=rate_limited
// carrying no IP.
func TestRegister_AcceptedAndRateLimitedKeepExistingAttributes(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		buf := captureLog(t)
		reg := metrics.New()
		srv := newTestServer(t)
		srv.WithMetrics(reg)
		mux := newMockRouter()
		srv.Register(mux)

		rec := registerReq(t, mux, `{"client_name":"acme-cli","redirect_uris":["https://claude.ai/cb"]}`)
		if rec.Code != 201 {
			t.Fatalf("register status = %d, body = %s", rec.Code, rec.Body.String())
		}
		lines := auditLines(buf.String())
		if len(lines) != 1 {
			t.Fatalf("expected exactly one audit line, got %d:\n%s", len(lines), buf.String())
		}
		for _, want := range []string{"outcome=accepted", "reason=ok", "client_name=acme-cli", "redirect_uri_count=1"} {
			if !strings.Contains(lines[0], want) {
				t.Errorf("accepted audit line missing %q:\n%s", want, lines[0])
			}
		}
	})

	t.Run("rate_limited", func(t *testing.T) {
		buf := captureLog(t)
		reg := metrics.New()
		srv := newTestServer(t, func(c *Config) {
			c.RegisterRatePerMin = 1
			c.RegisterRateWindow = time.Minute
		})
		srv.WithMetrics(reg)
		mux := newMockRouter()
		srv.Register(mux)

		body := `{"client_name":"c","redirect_uris":["https://claude.ai/cb"]}`
		req := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.7:1234"
		rec := httptest.NewRecorder()
		mux.serve("POST", "/oauth/register", rec, req)
		if rec.Code != 201 {
			t.Fatalf("first register status = %d, body = %s", rec.Code, rec.Body.String())
		}

		buf.Reset()
		req2 := httptest.NewRequest("POST", "/oauth/register", strings.NewReader(body))
		req2.Header.Set("Content-Type", "application/json")
		req2.RemoteAddr = "198.51.100.7:1234"
		rec2 := httptest.NewRecorder()
		mux.serve("POST", "/oauth/register", rec2, req2)
		if rec2.Code != 429 {
			t.Fatalf("second register status = %d, want 429, body = %s", rec2.Code, rec2.Body.String())
		}

		lines := auditLines(buf.String())
		if len(lines) != 1 {
			t.Fatalf("expected exactly one audit line, got %d:\n%s", len(lines), buf.String())
		}
		if !strings.Contains(lines[0], "outcome=rate_limited") {
			t.Errorf("rate-limited audit line missing outcome=rate_limited:\n%s", lines[0])
		}
		if strings.Contains(lines[0], "198.51.100.7") {
			t.Errorf("rate-limited audit line leaked the caller's IP:\n%s", lines[0])
		}
		if got := testutil.ToFloat64(reg.OAuthClientRegistrationsTotal.WithLabelValues("rate_limited", "rate_limited")); got != 1 {
			t.Errorf("mctl_oauth_client_registrations_total{outcome=rate_limited,reason=rate_limited} = %v, want 1", got)
		}
	})
}

// TestRedirectOrigin unit-tests the scheme/host extraction directly: a URI
// carrying path, query, fragment, port and userinfo yields only scheme and
// hostname, and an unparseable one yields ("", "") rather than falling back
// to the raw string.
func TestRedirectOrigin(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantScheme string
		wantHost   string
	}{
		{"full uri", "https://user:pass@example.com:8443/a/b?x=1#frag", "https", "example.com"},
		{"private scheme", "testclient://anysphere.cursor-retrieval/oauth/callback", "testclient", "anysphere.cursor-retrieval"},
		{"unparseable", "http://[::1", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scheme, host := redirectOrigin(tc.raw)
			if scheme != tc.wantScheme || host != tc.wantHost {
				t.Errorf("redirectOrigin(%q) = (%q, %q), want (%q, %q)", tc.raw, scheme, host, tc.wantScheme, tc.wantHost)
			}
		})
	}
}

// TestClassifyRegistrationError pins the errors.Is classification against
// the typed sentinels, including that the wire-visible error message from
// validateRedirectURIShape/validateImplicitRedirectURI is unchanged.
func TestClassifyRegistrationError(t *testing.T) {
	srv := newTestServer(t, func(c *Config) { c.AllowedImplicitHosts = []string{"claude.ai"} })

	err := srv.validateImplicitRedirectURI("testclient://anysphere.cursor-retrieval/oauth/callback")
	if err == nil {
		t.Fatal("expected the synthetic private-use scheme to be rejected")
	}
	if got := classifyRegistrationError(err); got != regSchemeNotAllowed {
		t.Errorf("classifyRegistrationError = %q, want %q", got, regSchemeNotAllowed)
	}
	wantMsg := `redirect_uri scheme "testclient" is not allowed (must be https except for http loopback)`
	if err.Error() != wantMsg {
		t.Errorf("err.Error() = %q, want %q (must stay byte-identical on the wire)", err.Error(), wantMsg)
	}

	hostErr := srv.validateImplicitRedirectURI("https://attacker.example/cb")
	if classifyRegistrationError(hostErr) != regHostNotAllowed {
		t.Errorf("classifyRegistrationError(host) = %q, want %q", classifyRegistrationError(hostErr), regHostNotAllowed)
	}
}
