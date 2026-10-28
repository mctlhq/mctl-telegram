// Package web serves the human-facing landing page that explains how
// to connect MCTL to Claude, ChatGPT, and other MCP clients.
package web

import (
	_ "embed"
	"encoding/json"
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

var landingTmpl = ui.New("landing", landingHTML)

// landingData is shared by the landing and docs pages: it embeds the shared
// chrome data (Title, NavActive, PublicBaseURL) and adds the deployment URLs
// both templates render.
type landingData struct {
	ui.Data
	MCPURL       string
	WellKnownURL string
	AuthServer   string
	// BotAccessRequested shows the "Allow messages" sign-in hint (docs only)
	// while the telegram:bot_access scope is requested.
	BotAccessRequested bool
}

// Landing renders the product landing page at PublicBaseURL/.
// MCPPath is rendered into the page so users see the exact URL
// to paste into a custom connector dialog in Claude or another MCP client.
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
			Title:         "MCTL — Your Telegram, inside your AI assistant",
			Description:   "Connect Telegram to Claude, ChatGPT, or any AI assistant. Summarise unread chats, draft and review replies, and search your full history — no extra apps, encrypted and revocable any time.",
			NavActive:     "home",
			PublicBaseURL: base,
			ShowManage:    showManage,
			CanonicalPath: "/",
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

// RootPostHint answers a POST / with a JSON-RPC 2.0 error object naming the
// real MCP endpoint, instead of chi's default bare 405 with an empty body —
// the response an MCP client sees when it is misconfigured with the bare
// origin instead of mcpPath. Status stays 405 (a client keying on the status
// alone is unaffected); only the body changes from empty to informative.
// GET / is untouched — this handler is registered only for POST.
func RootPostHint(mcpPath string) http.HandlerFunc {
	mcpPath = "/" + strings.TrimLeft(mcpPath, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// RFC 9110 15.5.6: a 405 must list the methods the target resource
		// supports. POST / is registered alongside GET / (cmd/server/main.go),
		// so chi's own 405 for PUT/DELETE/HEAD lists both — this handler must
		// agree. Listing POST while answering 405 to POST is intentional: the
		// method is routed, this handler just refuses it with a hint.
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      nil,
			"error": map[string]any{
				"code":    -32600,
				"message": "This is not the MCP endpoint. Use " + mcpPath + " instead.",
			},
		})
	}
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
