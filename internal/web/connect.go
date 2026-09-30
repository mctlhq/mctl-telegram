package web

// connect.go implements the browser-based Telegram account onboarding flow.
//
// GET /telegram/connect  — landing page; generates PKCE + state, renders a
//                          "Connect with Telegram" button pointing at
//                          /oauth/authorize.
// GET /telegram/connect/done — success page; redeems the authorization code
//                              via oauth.Server.ExchangeConnect and confirms
//                              that the MTProto session is live.
//
// Both routes are mounted only when AUTH_MODE=local-jwt (see cmd/server/main.go).

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// OAuthExchanger is the minimal interface ConnectServer needs from oauth.Server.
// Defined here so the web package avoids a direct import cycle with internal/oauth.
type OAuthExchanger interface {
	ExchangeConnect(ctx context.Context, code, verifier, clientID, redirectURI string) (string, error)
}

// ConnectIdentifier reports whether the request carries a credential this
// server should treat as an already-connected browser session. Satisfied by
// auth.Provider (in particular localjwt.Provider, which also accepts the
// mctl_connect_token cookie — see internal/auth/localjwt/issuer.go). Defined
// locally, mirroring OAuthExchanger, so this package need not import the
// concrete provider package.
type ConnectIdentifier interface {
	Authenticate(r *http.Request) (*auth.Identity, error)
}

// Reason vocabulary for logConnectReject / the prefetch-refusal log line.
// Duplicated (not shared) in internal/oauth/server.go for the same reason
// OAuthExchanger exists: internal/web must not import internal/oauth.
const (
	reasonMissingState      = "missing_state"
	reasonMissingCode       = "missing_code"
	reasonUnknownState      = "unknown_state"
	reasonExpiredState      = "expired_state"
	reasonExchangeFailed    = "exchange_failed"
	reasonOIDCError         = "oidc_error"
	reasonPrefetchRefused   = "prefetch_refused"
	reasonRecoveredRedirect = "recovered_redirect"
)

// isPrefetch reports whether r looks like a browser or crawler prefetch
// rather than a real navigation, per the Sec-Purpose / legacy Purpose
// request headers. Sec-Purpose is a structured list so it is matched by
// substring; Purpose is the legacy bare-token header so it is matched
// exactly (case-insensitively, trimmed).
//
// Best-effort. Safari sends no prefetch-purpose header at all, and Firefox's
// legacy X-moz: prefetch is not matched, so a 204 here proves a prefetch but
// a 200 does not prove a real navigation.
func isPrefetch(r *http.Request) bool {
	if strings.Contains(strings.ToLower(r.Header.Get("Sec-Purpose")), "prefetch") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Purpose")), "prefetch")
}

// logConnectReject emits one WARN line for a rejected /telegram/connect/done
// request. Attributes are deliberately limited to route, reason and the
// prefetch boolean — never code, state, or a cookie value. prefetch is always
// false here — the guard above returns 204 before any reject path — and is
// retained deliberately so one prefetch= query matches every line both
// routes emit.
func logConnectReject(r *http.Request, reason string) {
	slog.Warn("connect: request rejected",
		"route", "/telegram/connect/done",
		"reason", reason,
		"prefetch", isPrefetch(r))
}

// ConnectConfig holds the construction parameters for ConnectServer.
type ConnectConfig struct {
	// Issuer is the canonical public base URL of mctl-telegram (no trailing slash).
	Issuer string
	// OAuthServer is used to redeem the authorization code in HandleConnectDone.
	OAuthServer OAuthExchanger
	// CodeTTL bounds how long a pending connect session lives in memory.
	// Uses the same default as the main OAuth server (10 minutes).
	CodeTTL time.Duration
	// ClaudeAIConnectorURL is the link rendered on the success page.
	// Defaults to "https://claude.ai/settings/integrations".
	ClaudeAIConnectorURL string
	// ClientID is the OAuth client_id for the self-connect flow. Pass
	// oauth.ConnectClientID from the call site; no default is applied so a
	// missing value surfaces immediately at link generation.
	ClientID string
	// MCPPath is the path component of the MCP URL shown on the success page.
	// Defaults to "/mcp" when empty.
	MCPPath string
	// MaxSessions caps the number of pending connect sessions held in memory.
	// When > 0 and the cap is reached, the oldest session is evicted to make
	// room. 0 means no cap.
	MaxSessions int
	// Identifier, when non-nil, is consulted by HandleConnectDone on a
	// reused/expired state to check whether the browser already carries a
	// valid session credential (the mctl_connect_token cookie). When it
	// does, the request is redirected to /telegram/connect/manage instead of
	// showing the "link already used" page. nil (the zero value) degrades to
	// always showing that page — never a panic, never a redirect.
	Identifier ConnectIdentifier
	// clock is injectable for tests; nil means time.Now.
	clock func() time.Time
}

// connectSession holds the PKCE verifier for one pending /telegram/connect flow.
type connectSession struct {
	verifier  string
	createdAt time.Time
}

// ConnectServer handles the two /telegram/connect routes.
type ConnectServer struct {
	issuer      string
	redirectURI string // issuer + "/telegram/connect/done"
	oauthSrv    OAuthExchanger
	codeTTL     time.Duration
	claudeURL   string
	clientID    string
	mcpPath     string
	maxSessions int
	identifier  ConnectIdentifier
	clock       func() time.Time

	mu       sync.Mutex
	sessions map[string]*connectSession // keyed by state token
}

// NewConnectServer constructs a ConnectServer from cfg.
func NewConnectServer(cfg ConnectConfig) *ConnectServer {
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 10 * time.Minute
	}
	if cfg.ClaudeAIConnectorURL == "" {
		cfg.ClaudeAIConnectorURL = "https://claude.ai/settings/integrations"
	}
	if cfg.MCPPath == "" {
		cfg.MCPPath = "/mcp"
	}
	clk := cfg.clock
	if clk == nil {
		clk = time.Now
	}
	return &ConnectServer{
		issuer:      cfg.Issuer,
		redirectURI: cfg.Issuer + "/telegram/connect/done",
		oauthSrv:    cfg.OAuthServer,
		codeTTL:     cfg.CodeTTL,
		claudeURL:   cfg.ClaudeAIConnectorURL,
		clientID:    cfg.ClientID,
		mcpPath:     cfg.MCPPath,
		maxSessions: cfg.MaxSessions,
		identifier:  cfg.Identifier,
		clock:       clk,
		sessions:    map[string]*connectSession{},
	}
}

// alreadyConnected reports whether r carries a credential the configured
// Identifier accepts as an already-connected browser session. Returns true
// only for a non-nil Identifier that yields a non-nil identity and a nil
// error — a nil Identifier (shared-hmac mode, or a test that wires none)
// always degrades to false, never a panic.
func (s *ConnectServer) alreadyConnected(r *http.Request) bool {
	if s.identifier == nil {
		return false
	}
	id, err := s.identifier.Authenticate(r)
	if err != nil {
		// Authenticate returns (nil, nil) when no credential is present, so
		// an error means a credential was sent and rejected: expired,
		// revoked, or an infrastructure failure (DB, revocation cache). Stay
		// fail-closed, but make the "redirect did not happen" case
		// attributable. The error never carries the token value.
		slog.Warn("connect: session credential rejected on reused link",
			"route", "/telegram/connect/done",
			"err", err)
		return false
	}
	return id != nil
}

// HandleConnect renders the landing page with a "Connect with Telegram" button.
// On every call it generates a fresh PKCE verifier+challenge and a state token,
// stores them, and embeds the resulting /oauth/authorize URL in the button.
func (s *ConnectServer) HandleConnect(w http.ResponseWriter, r *http.Request) {
	s.sweepExpired()

	verifier, challenge := pkceConnectChallenge()
	state := connectRandomToken(16)

	s.mu.Lock()
	if s.maxSessions > 0 && len(s.sessions) >= s.maxSessions {
		// Evict the oldest pending session to stay within the cap.
		var oldestKey string
		var oldestTime time.Time
		for k, sess := range s.sessions {
			if oldestKey == "" || sess.createdAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = sess.createdAt
			}
		}
		delete(s.sessions, oldestKey)
	}
	s.sessions[state] = &connectSession{
		verifier:  verifier,
		createdAt: s.clock(),
	}
	s.mu.Unlock()

	authorizeURL := s.issuer + "/oauth/authorize?" + url.Values{
		"client_id":             {s.clientID},
		"redirect_uri":          {s.redirectURI},
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}.Encode()

	renderConnectPage(w, connectLandingData{
		AuthorizeURL: authorizeURL,
	})
}

// HandleConnectDone exchanges the authorization code for an access token (to
// confirm the MTProto session is live) and renders either the success page or
// an error page.
func (s *ConnectServer) HandleConnectDone(w http.ResponseWriter, r *http.Request) {
	// Prefetch refusal comes before anything else touches s.sessions: a
	// browser or crawler prefetch of this single-use URL must not consume the
	// pending state the user's own click still needs.
	if isPrefetch(r) {
		slog.Info("connect: request rejected",
			"route", "/telegram/connect/done",
			"reason", reasonPrefetchRefused,
			"prefetch", true)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Vary", "Sec-Purpose, Purpose")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	q := r.URL.Query()

	// Surface Telegram OIDC errors (e.g. user cancelled at oauth.telegram.org).
	if oidcErr := q.Get("error"); oidcErr != "" {
		logConnectReject(r, reasonOIDCError)
		renderConnectError(w, "Telegram sign-in was not completed. Please try again.", s.issuer+"/telegram/connect")
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
		reason := reasonMissingState
		if state != "" {
			reason = reasonMissingCode
		}
		logConnectReject(r, reason)
		renderConnectError(w, "Missing authorization code or state. Please start again.", s.issuer+"/telegram/connect")
		return
	}

	s.mu.Lock()
	sess, ok := s.sessions[state]
	if ok {
		delete(s.sessions, state)
	}
	s.mu.Unlock()

	if !ok || s.clock().Sub(sess.createdAt) > s.codeTTL {
		if s.alreadyConnected(r) {
			// Not a failure: the browser still holds a valid
			// mctl_connect_token, so a reopened single-use link lands on
			// /manage. Logged at Info under its own reason so the
			// unknown_state count keeps measuring only real failures.
			slog.Info("connect: request recovered",
				"route", "/telegram/connect/done",
				"reason", reasonRecoveredRedirect,
				"prefetch", isPrefetch(r))
			http.Redirect(w, r, "/telegram/connect/manage", http.StatusSeeOther)
			return
		}
		reason := reasonUnknownState
		if ok {
			reason = reasonExpiredState
		}
		logConnectReject(r, reason)
		renderConnectReused(w, s.issuer+"/telegram/connect")
		return
	}

	tok, err := s.oauthSrv.ExchangeConnect(r.Context(), code, sess.verifier, s.clientID, s.redirectURI)
	if err != nil {
		slog.Error("connect: request rejected",
			"route", "/telegram/connect/done",
			"reason", reasonExchangeFailed,
			"prefetch", isPrefetch(r),
			"err", err)
		renderConnectError(w, "Could not confirm your Telegram session. Please try again.", s.issuer+"/telegram/connect")
		return
	}

	// Set an HttpOnly session cookie so the browser can authenticate against
	// the /telegram/connect/manage routes without receiving the JWT in-page.
	// Path=/telegram/connect restricts delivery to this subtree only.
	// Secure is derived from the issuer scheme so local HTTP dev does not
	// silently drop the cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "mctl_connect_token",
		Value:    tok,
		Path:     "/telegram/connect",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(s.issuer, "https://"),
	})

	renderConnectSuccess(w, connectSuccessData{
		ClaudeURL: s.claudeURL,
		MCPURL:    s.issuer + s.mcpPath,
	})
}

// sweepExpired removes pending sessions older than codeTTL. Called at the top
// of HandleConnect so abandoned sessions do not accumulate indefinitely.
func (s *ConnectServer) sweepExpired() {
	now := s.clock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if now.Sub(sess.createdAt) > s.codeTTL {
			delete(s.sessions, k)
		}
	}
}

// pkceConnectChallenge generates an S256 PKCE verifier+challenge pair.
// 32 random bytes base64url-encoded is 43 characters, satisfying RFC 7636's
// 43–128 unreserved-character syntax.
func pkceConnectChallenge() (verifier, challenge string) {
	verifier = connectRandomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// connectRandomToken returns a base64url-encoded string of n random bytes.
func connectRandomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("web/connect: rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// ----- HTML templates -----

// The connect pages share the lite (strict-CSP) chrome from internal/ui:
// inlined design tokens + component CSS + auth-card CSS, the static topbar,
// and the footer. No external CSS/JS, matching the existing CSP. The tab icon
// loads from ui.mctl.ai (allow-listed on img-src).

var connectHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect Telegram account</title>
  ` + ui.FaviconLink + `
  <style>` + ui.TokensCSS + ui.ComponentsCSS + ui.AuthCSS + `</style>
</head>
<body>
  <div class="wrap">
` + ui.TopbarLite + `
  <main class="auth-main">
    <div class="card">
`

var connectFoot = `    </div>
  </main>
` + ui.FooterLite + `
  </div>
</body>
</html>`

// connectLandingData is the template data for the landing page.
type connectLandingData struct {
	AuthorizeURL string
}

// connectSuccessData is the template data for the success page.
type connectSuccessData struct {
	ClaudeURL string
	MCPURL    string
}

// connectErrorData is the template data for the error page.
type connectErrorData struct {
	Message  string
	RetryURL string
}

var connectLandingTemplate = template.Must(template.New("connectLanding").Parse(connectHead + `    <ol class="flow-steps">
      <li class="active">Sign in with Telegram</li>
      <li>Permissions</li>
      <li>Phone number</li>
      <li>Done</li>
    </ol>
    <h1>Step 1 of 4 &#8212; Connect your Telegram account</h1>
    <p>Click the button below to sign in with Telegram and link your account to this MCP connector.
       You will be asked to enter your phone number and a one-time code sent by Telegram.</p>
    <p>No password is stored. An encrypted Telegram session is saved on this server so the
       connector can read your messages on behalf of your MCP client.</p>
    <a class="btn" href="{{.AuthorizeURL}}">Connect with Telegram</a>
    <p class="meta">Already connected? You can reconnect at any time by returning to this page.</p>
` + connectFoot))

var connectSuccessTemplate = template.Must(template.New("connectSuccess").Parse(connectHead + `    <ol class="flow-steps">
      <li>Sign in with Telegram</li>
      <li>Permissions</li>
      <li>Phone number</li>
      <li class="active">Done</li>
    </ol>
    <h1>Step 4 of 4 &#8212; Done</h1>
    <p>Your Telegram account is now connected to this MCP connector.</p>
    <p>To start using it with Claude, open the Claude.ai connector settings and add the MCP URL:</p>
    <p class="url">{{.MCPURL}}</p>
    <p class="meta">A new session called &#8220;mctl Telegram Assistant&#8221; will appear in
       your Telegram&#8217;s <strong>Active Sessions</strong> (Settings &#8594; Privacy and Security
       &#8594; Active Sessions). This is normal &#8212; it is the session this connector uses to
       read your messages.</p>
    <p class="meta"><a href="{{.ClaudeURL}}">Go to Claude.ai connector settings</a> &#183;
       <a href="/telegram/connect/manage">Manage your session</a></p>
` + connectFoot))

var connectErrorTemplate = template.Must(template.New("connectError").Parse(connectHead + `    <h1>Connection failed</h1>
    <div class="error">{{.Message}}</div>
    <p class="meta"><a href="{{.RetryURL}}">Try again</a></p>
` + connectFoot))

// connectReusedTemplate is shown instead of connectErrorTemplate when a
// connect link is unknown or already consumed and the browser carries no
// valid session credential — a correct answer to a well-formed request about
// an expired link, hence status 200 rather than 400 (see renderConnectReused).
var connectReusedTemplate = template.Must(template.New("connectReused").Parse(connectHead + `    <h1>Link already used</h1>
    <p>{{.Message}}</p>
    <p class="meta"><a class="btn" href="{{.RetryURL}}">Start again</a></p>
` + connectFoot))

func renderConnectPage(w http.ResponseWriter, data connectLandingData) {
	renderConnect(w, http.StatusOK, connectLandingTemplate, data)
}

func renderConnectSuccess(w http.ResponseWriter, data connectSuccessData) {
	renderConnect(w, http.StatusOK, connectSuccessTemplate, data)
}

func renderConnectError(w http.ResponseWriter, msg, retryURL string) {
	renderConnect(w, http.StatusBadRequest, connectErrorTemplate, connectErrorData{
		Message:  msg,
		RetryURL: retryURL,
	})
}

// renderConnectReused renders the "this link was already used" page at 200 —
// a correct answer about an expired/reused link, not a client error. Names
// no state or code value in the body.
func renderConnectReused(w http.ResponseWriter, retryURL string) {
	renderConnect(w, http.StatusOK, connectReusedTemplate, connectErrorData{
		Message:  "This link was already used. Connect links work once. Start again if you still need to connect.",
		RetryURL: retryURL,
	})
}

// renderConnect executes the template into a buffer before writing the
// response so a template error cannot leave a half-written body under an
// already-sent 200. Matches the renderEnable pattern in
// internal/oauth/enable_access_page.go.
func renderConnect(w http.ResponseWriter, status int, t *template.Template, data any) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		http.Error(w, "template execute: "+err.Error(), http.StatusInternalServerError)
		return
	}
	const csp = "default-src 'none'; style-src 'unsafe-inline'; img-src https://ui.mctl.ai; form-action 'self'; base-uri 'none'"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
