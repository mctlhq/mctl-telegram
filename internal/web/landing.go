// Package web serves the human-facing landing page that explains how
// to connect mctl-telegram via ChatGPT Apps, Claude.ai, and other MCP clients.
package web

import (
	_ "embed"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/ui"
)

//go:embed landing.html
var landingHTML string

//go:embed favicon.svg
var faviconSVG []byte

//go:embed og.png
var ogPNG []byte

// Favicon returns the SVG favicon at /favicon.svg and /favicon.ico.
func Favicon() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(faviconSVG)
	}
}

// OGImage serves the social-share preview image referenced by the og:image and
// twitter:image meta tags at /og.png. PNG rather than SVG: major crawlers
// (Twitter/X, Facebook, LinkedIn, Slack) do not rasterize SVG for link
// previews, so an SVG og:image renders as a broken image everywhere.
func OGImage() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(ogPNG)
	}
}

// alignLandingPrivacyClaims keeps the short landing-page copy consistent with
// the long-form /privacy and /security pages. Ordinary MCP read results are
// transient, but listener-enabled Communication Agent accounts durably store
// encrypted message/event and action content. Absolute "message text is never
// persisted" claims therefore must not reach the rendered page.
func alignLandingPrivacyClaims(html string) string {
	return strings.NewReplacer(
		`<li><strong>Stored on this server:</strong> an AES-256-GCM encrypted Telegram session blob per account, plus audit metadata (tool name, redacted peer reference — never message text).</li>`,
		`<li><strong>Stored on this server:</strong> an AES-256-GCM encrypted Telegram session blob per account and audit metadata without message text. When Communication Agent is enabled, relevant incoming message/event content and proposed action payloads are also stored encrypted at rest.</li>`,
		`<li><strong>Not stored:</strong> message bodies, phone numbers, 2FA passwords, or OAuth tokens in logs.</li>`,
		`<li><strong>Not stored in logs or audit history:</strong> message bodies, phone numbers, 2FA passwords, or OAuth tokens.</li>`,
		`<li><strong>No message text, phone numbers, or 2FA passwords are ever logged or persisted</strong> — enforced by the slog redaction handler.</li>`,
		`<li><strong>Message text is never written to logs or audit history.</strong> Communication Agent message and action content is encrypted at rest and retained according to the policy in <a href="/privacy">/privacy</a>.</li>`,
		`This server stores only an encrypted session blob and audit metadata — see <a href="/privacy">/privacy</a>.`,
		`For ordinary MCP calls, this server stores an encrypted session blob and audit metadata. Listener-enabled Communication Agent accounts additionally store encrypted message and action content as described in <a href="/privacy">/privacy</a>.`,
		`<dd>Only an encrypted session blob per account. No message text is ever stored or logged. The audit log records tool names and redacted peer references only.</dd>`,
		`<dd>An encrypted session blob and metadata are stored per account. When Communication Agent is enabled, relevant incoming messages/events and proposed action payloads are stored encrypted at rest; logs and audit history still exclude message bodies. See <a href="/privacy">/privacy</a> for retention details.</dd>`,
	).Replace(html)
}

var landingTmpl = ui.New("landing", alignLandingPrivacyClaims(landingHTML))

// landingData is shared by the landing and docs pages: it embeds the shared
// chrome data (Title, NavActive, PublicBaseURL) and adds the deployment URLs
// both templates render.
type landingData struct {
	ui.Data
	MCPURL       string
	WellKnownURL string
	AuthServer   string
}

// Landing renders the product landing page at PublicBaseURL/.
// MCPPath is rendered into the page so users see the exact URL
// to paste into ChatGPT Apps or a custom MCP connector dialog.
//
// authServer is the issuer URL used by the OAuth flow. For the Telegram-native
// auth model this is the same as publicBaseURL — mctl-telegram is its own
// authorization server. The legacy "shared-hmac" mode points it at
// https://api.mctl.ai; main.go decides which one to pass in.
//
// showManage gates the "manage" nav/footer link: /telegram/connect/manage is
// only mounted in local-jwt mode, so main.go passes false for shared-hmac
// deployments to avoid a 404.
func Landing(publicBaseURL, mcpPath, authServer string, showManage bool) http.HandlerFunc {
	base := strings.TrimRight(publicBaseURL, "/")
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	if authServer == "" {
		authServer = base
	}
	data := landingData{
		Data: ui.Data{
			Title:         "mctl-telegram — Your Telegram, inside your AI assistant",
			Description:   "Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarise unread chats, draft and review replies, and search your full history — no extra apps, encrypted and revocable any time.",
			NavActive:     "home",
			PublicBaseURL: base,
			ShowManage:    showManage,
		},
		MCPURL:       base + mcpPath,
		WellKnownURL: base + "/.well-known/oauth-protected-resource",
		AuthServer:   authServer,
	}
	return chromePage(landingTmpl, "landing", data)
}

// BrowserRedirect wraps an MCP Streamable-HTTP handler so that a plain
// browser navigation to /mcp (Accept: text/html, no JSON-RPC body) is
// bounced to the landing page instead of returning an empty SSE stream.
// MCP clients send Accept: application/json, text/event-stream — those
// fall through to the real handler unchanged.
func BrowserRedirect(next http.Handler, landingPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && isBrowserGet(r.Header.Get("Accept")) {
			http.Redirect(w, r, landingPath, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isBrowserGet(accept string) bool {
	if accept == "" {
		return false
	}
	a := strings.ToLower(accept)
	if !strings.Contains(a, "text/html") {
		return false
	}
	// MCP clients announce JSON and SSE explicitly — if either is present,
	// it's a real client and we must not redirect.
	if strings.Contains(a, "application/json") || strings.Contains(a, "text/event-stream") {
		return false
	}
	return true
}
