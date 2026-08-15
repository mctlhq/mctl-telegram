package oauth

// demo_login.go implements the reviewer/demo auth-mode used for the ChatGPT App
// Directory review. When cfg.DemoReviewerEnabled is set, /oauth/authorize renders
// a chooser (see handleAuthorize) offering both the normal Telegram sign-in and a
// password-gated reviewer form that posts here. A correct username/password
// authenticates as the pre-provisioned demo Telegram identity (cfg.DemoReviewerTGID)
// directly — no live Telegram OIDC login, no phone/SMS. The demo account is a
// throwaway with a pre-seeded MTProto session and send_enabled=false, so every
// send stays a dry-run preview.
//
// The feature is off by default and only the route is registered unconditionally;
// the handler 404s unless the mode is enabled.

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/netctx"
	"github.com/mctlhq/mctl-telegram/internal/ui"
)

// Per-IP throttle on the reviewer login form. Lenient enough for a reviewer who
// fat-fingers the password a few times, tight enough that the static credential
// cannot be brute-forced.
const (
	demoRateMax     = 10
	demoRateWindow  = 5 * time.Minute
	demoMaxIPWindow = 10000 // cap on tracked IPs before opportunistic pruning
)

// demoRateLimiter is a fixed-window per-key counter. Created only when the
// reviewer/demo auth-mode is enabled.
type demoRateLimiter struct {
	now     func() time.Time
	mu      sync.Mutex
	windows map[string]*demoWindow
}

type demoWindow struct {
	count int
	reset time.Time
}

func newDemoRateLimiter(now func() time.Time) *demoRateLimiter {
	return &demoRateLimiter{now: now, windows: map[string]*demoWindow{}}
}

// allow records an attempt for key and reports whether it is within the window
// budget. The first attempt in a fresh window always passes.
func (l *demoRateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.windows) >= demoMaxIPWindow {
		for k, w := range l.windows {
			if now.After(w.reset) {
				delete(l.windows, k)
			}
		}
	}
	w := l.windows[key]
	if w == nil || now.After(w.reset) {
		// Refuse to track a brand-new key once the map is full (all live), so a
		// burst from many distinct source IPs cannot grow windows without bound
		// on this unauthenticated endpoint.
		if w == nil && len(l.windows) >= demoMaxIPWindow {
			return false
		}
		l.windows[key] = &demoWindow{count: 1, reset: now.Add(demoRateWindow)}
		return true
	}
	if w.count >= demoRateMax {
		return false
	}
	w.count++
	return true
}

// handleDemoLogin authenticates the reviewer credentials and, on success, issues
// an authorization code bound to the demo Telegram identity — bypassing the
// Telegram OIDC leg. On failure it re-renders the reviewer form so the same
// (still-valid) state can be retried; the pending entry is consumed only on
// success.
func (s *Server) handleDemoLogin(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DemoReviewerEnabled {
		http.NotFound(w, r)
		return
	}
	// Bound the body before ParseForm reads it: the form only ever carries a
	// short state token, username, and password. Without this an unauthenticated
	// caller could stream a large body (ParseForm has no built-in cap for
	// urlencoded bodies) before the per-IP limiter below fires, and it bounds the
	// ConstantTimeCompare input length. Mirrors handleClientRegistration.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		renderEnableError(w, "Invalid form submission. Close this page and reconnect from your MCP client.")
		return
	}
	state := r.FormValue("state")
	username := r.FormValue("username")
	password := r.FormValue("password")
	if state == "" {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}

	ip := clientIP(r)
	if s.demoLimiter != nil && !s.demoLimiter.allow(ip) {
		// Do not consume the pending entry — the reviewer can retry once the
		// window resets.
		renderDemoChooserStatus(w, http.StatusTooManyRequests, demoChooserPage{
			Issuer: s.cfg.Issuer,
			State:  state,
			Error:  "Too many attempts. Wait a few minutes and try again.",
		})
		return
	}

	// Constant-time compare both fields; the bitwise AND avoids short-circuit
	// timing that would leak which field was wrong.
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte(s.cfg.DemoReviewerUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(password), []byte(s.cfg.DemoReviewerPassword)) == 1
	if !(userOK && passOK) {
		slog.Warn("oauth: demo reviewer login rejected", "ip", ip)
		renderDemoChooserStatus(w, http.StatusUnauthorized, demoChooserPage{
			Issuer: s.cfg.Issuer,
			State:  state,
			Error:  "Invalid reviewer credentials.",
		})
		return
	}

	// Credentials accepted: consume the single-use pending entry and issue the
	// authorization code as the demo identity.
	pending, ok := s.consumePending(r.Context(), state)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}

	uid, err := s.store.UserIDByTelegramID(r.Context(), s.cfg.DemoReviewerTGID)
	if errors.Is(err, db.ErrUserNotFound) {
		// Operator misconfiguration, not a client error — surface as 5xx so it
		// is distinguishable in monitoring from a malformed/expired request.
		slog.Error("oauth: demo reviewer account not provisioned", "tg_id", s.cfg.DemoReviewerTGID)
		renderDemoServerError(w, "The demo account is not provisioned on this server. Contact the operator.")
		return
	}
	if err != nil {
		slog.Error("oauth: demo reviewer user lookup failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, serr := s.store.CheckSessionValid(r.Context(), uid); serr != nil {
		slog.Error("oauth: demo reviewer session not usable", "err", serr)
		renderDemoServerError(w, "The demo account has no active Telegram session. Contact the operator.")
		return
	}

	s.store.LogToolCall(r.Context(), uid, "connect:demo_reviewer", "", "ok", "", "")
	s.issueAuthCode(w, r, oauthCtx{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		ClientState:   pending.State,
		Scope:         pending.Scope,
		TelegramID:    s.cfg.DemoReviewerTGID,
	})
}

// consumePending atomically removes and returns the pending-authorize entry for
// state, mirroring the consume logic in handleTelegramCallback across both the
// DB-backed and in-memory stores. ok is false when the entry is missing or has
// outlived CodeTTL.
func (s *Server) consumePending(ctx context.Context, state string) (*pendingAuth, bool) {
	if s.useDB {
		dbPA, err := s.store.ConsumeOAuthPending(ctx, state, s.cfg.CodeTTL)
		if errors.Is(err, db.ErrOAuthNotFound) {
			return nil, false
		}
		if err != nil {
			// An unexpected DB error must not look like "state not found": log it
			// so a transient outage during a review session leaves a trace
			// instead of a misleading "session expired" page. Mirrors
			// handleTelegramCallback.
			slog.Error("oauth: consume demo pending failed", "err", err)
			return nil, false
		}
		return &pendingAuth{
			ClientID:            dbPA.ClientID,
			RedirectURI:         dbPA.RedirectURI,
			State:               dbPA.ClientState,
			CodeChallenge:       dbPA.CodeChallenge,
			CodeChallengeMethod: dbPA.ChallengeMethod,
			Scope:               dbPA.Scope,
			Nonce:               dbPA.Nonce,
			TGCodeVerifier:      dbPA.TGCodeVerifier,
			CreatedAt:           dbPA.CreatedAt,
		}, true
	}
	s.mu.Lock()
	p, found := s.pending[state]
	delete(s.pending, state)
	s.mu.Unlock()
	if !found {
		return nil, false
	}
	if s.clock().Sub(p.CreatedAt) > s.cfg.CodeTTL {
		return nil, false
	}
	return p, true
}

// clientIP returns the trusted source IP for rate-limiting the brute-force gate.
//
// It keys on the real TCP socket peer captured by the http.Server ConnContext
// hook (internal/netctx), NOT r.RemoteAddr. The server runs chi middleware.RealIP
// globally, which rewrites r.RemoteAddr from client-controllable X-Forwarded-For
// / X-Real-IP headers — so keying on r.RemoteAddr would let an attacker rotate
// that header to mint a fresh rate-limit bucket per request and defeat the limit.
// The socket peer is set before any middleware runs and cannot be forged.
//
// Falls back to r.RemoteAddr only when the ConnContext peer is absent (tests that
// construct requests directly).
func clientIP(r *http.Request) string {
	addr := netctx.Peer(r.Context())
	if addr == "" {
		addr = r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

// ----- reviewer chooser / login page -----

type demoChooserPage struct {
	Issuer string
	// TelegramURL, when non-empty, renders the "Sign in with Telegram" button.
	// Empty on the post-failure re-render so only the reviewer form shows.
	TelegramURL string
	State       string
	Error       string
}

const demoExtraCSS = `
  a.tg-btn { display:block; text-align:center; text-decoration:none; margin-top:16px;
             font-family: var(--font-display), system-ui, sans-serif; font-size:15px; font-weight:600;
             padding:11px 16px; border-radius: var(--mctl-radius-md); background: var(--accent); color:#0a0b0d; }
  a.tg-btn:hover { filter: brightness(.92); }
  .divider { margin:22px 0 4px; font-size:12px; font-weight:600; text-transform:uppercase;
             letter-spacing:.05em; color: var(--text-dim); text-align:center; }
`

var demoHead = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Connect Telegram</title>
  ` + ui.FaviconLink + `
  <style>` + ui.TokensCSS + ui.ComponentsCSS + ui.AuthCSS + enableExtraCSS + demoExtraCSS + `</style>
</head>
<body>
  <div class="wrap">
` + ui.TopbarLite + `
  <main class="auth-main">
    <div class="card">
`

var demoChooserTemplate = template.Must(template.New("demoChooser").Parse(demoHead + `    <h1>Connect your Telegram account</h1>
    <p>Sign in with Telegram to connect <span class="url">{{.Issuer}}</span> to your account.</p>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    {{if .TelegramURL}}<a class="tg-btn" href="{{.TelegramURL}}">Sign in with Telegram</a>
    <div class="divider">Reviewer access</div>{{end}}
    <form method="POST" action="/oauth/demo/login" autocomplete="off">
      <input type="hidden" name="state" value="{{.State}}">
      <label class="field">
        <span>Username</span>
        <input name="username" type="text" autocomplete="off" required{{if not .TelegramURL}} autofocus{{end}}>
      </label>
      <label class="field">
        <span>Password</span>
        <input name="password" type="password" autocomplete="off" required>
      </label>
      <button type="submit">Continue as reviewer</button>
    </form>
    <p class="meta">Reviewer access signs in to a sandboxed demo account. Sending is preview-only &#8212;
       no real messages are delivered.</p>
` + enableFoot))

func renderDemoChooser(w http.ResponseWriter, p demoChooserPage) {
	renderEnable(w, http.StatusOK, demoChooserTemplate, p, "")
}

func renderDemoChooserStatus(w http.ResponseWriter, status int, p demoChooserPage) {
	renderEnable(w, status, demoChooserTemplate, p, "")
}

// renderDemoServerError renders the shared error page at HTTP 500. Used for
// operator-side misconfiguration (demo account not provisioned / no active
// session) so the status reflects a server-side problem rather than a malformed
// request, while the reviewer still sees a friendly message.
func renderDemoServerError(w http.ResponseWriter, msg string) {
	renderEnable(w, http.StatusInternalServerError, enableErrorTemplate, enableErrorPage{Message: msg}, "")
}
