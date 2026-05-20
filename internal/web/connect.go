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
	"sync"
	"time"
)

// OAuthExchanger is the minimal interface ConnectServer needs from oauth.Server.
// Defined here so the web package avoids a direct import cycle with internal/oauth.
type OAuthExchanger interface {
	ExchangeConnect(ctx context.Context, code, verifier, clientID, redirectURI string) (string, error)
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
		clock:       clk,
		sessions:    map[string]*connectSession{},
	}
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
	q := r.URL.Query()

	// Surface Telegram OIDC errors (e.g. user cancelled at oauth.telegram.org).
	if oidcErr := q.Get("error"); oidcErr != "" {
		renderConnectError(w, "Telegram sign-in was not completed. Please try again.", s.issuer+"/telegram/connect")
		return
	}

	code := q.Get("code")
	state := q.Get("state")
	if code == "" || state == "" {
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
		renderConnectError(w, "This connect session has expired or is unknown. Please start again.", s.issuer+"/telegram/connect")
		return
	}

	_, err := s.oauthSrv.ExchangeConnect(r.Context(), code, sess.verifier, s.clientID, s.redirectURI)
	if err != nil {
		slog.Error("connect: ExchangeConnect failed", "err", err)
		renderConnectError(w, "Could not confirm your Telegram session. Please try again.", s.issuer+"/telegram/connect")
		return
	}

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

// The landing and success pages share the CSS palette defined in
// internal/oauth/enable_access_page.go (enableHead / enableFoot). The
// templates are inlined here so the web package is self-contained.

const connectHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Connect Telegram account</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root { color-scheme: light dark; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
           background: #f6f8fa; color: #1f2328; margin: 0; padding: 40px 20px; }
    .card { max-width: 460px; margin: 0 auto; background: #ffffff; border: 1px solid #d0d7de;
            border-radius: 12px; padding: 32px 28px; box-shadow: 0 1px 3px rgba(27,31,36,0.04); }
    h1 { font-size: 22px; margin: 0 0 12px; font-weight: 600; }
    p { line-height: 1.5; margin: 8px 0; }
    .meta { font-size: 13px; color: #57606a; margin-top: 20px; }
    .url { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 13px; }
    .btn { display: inline-block; margin-top: 20px; width: 100%; box-sizing: border-box;
           font-size: 15px; font-weight: 600; padding: 10px 14px; text-align: center;
           border: 1px solid rgba(27,31,36,0.15); border-radius: 6px; background: #1f883d;
           color: #ffffff; text-decoration: none; }
    .btn:hover { background: #1a7f37; }
    .error { background: #ffebe9; border: 1px solid #ff818266; border-radius: 6px;
             padding: 10px 12px; font-size: 13px; color: #cf222e; margin: 12px 0; }
    .steps { display: flex; list-style: none; padding: 0; margin: 0 0 20px; gap: 0; }
    .steps li { flex: 1; text-align: center; font-size: 12px; padding: 6px 4px;
                border-bottom: 2px solid #d0d7de; color: #57606a; }
    .steps li.active { border-bottom-color: #1f883d; color: #1f883d; font-weight: 600; }
    @media (prefers-color-scheme: dark) {
      body { background: #0d1117; color: #e6edf3; }
      .card { background: #161b22; border-color: #30363d; box-shadow: 0 1px 3px rgba(0,0,0,0.4); }
      h1 { color: #e6edf3; }
      .meta { color: #8b949e; }
      .url { color: #58a6ff; }
      .error { background: #2d1314; border-color: #6b3030; color: #f85149; }
      .steps li { border-bottom-color: #30363d; color: #8b949e; }
      .steps li.active { border-bottom-color: #3fb950; color: #3fb950; }
    }
  </style>
</head>
<body>
  <div class="card">
`

const connectFoot = `  </div>
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

var connectLandingTemplate = template.Must(template.New("connectLanding").Parse(connectHead + `    <ol class="steps">
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

var connectSuccessTemplate = template.Must(template.New("connectSuccess").Parse(connectHead + `    <ol class="steps">
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
	const csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'"
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", csp)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
