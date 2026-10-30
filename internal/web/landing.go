// Package web serves the human-facing landing page that explains how
// to connect MCTL to Claude, ChatGPT, and other MCP clients.
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

// RootMCP serves the bare origin both to people and to MCP clients that were
// configured with the origin instead of mcpPath ("https://tg.mctl.ai" rather
// than ".../mcp"). Such a client completes OAuth anyway, because discovery
// lives at the origin, and then fails on its first JSON-RPC call; ChatGPT
// reports that as "Authentication succeeded, action discovery failed". POST
// and DELETE, and a GET that asks for an event stream, go to the MCP handler;
// every other GET gets the landing page.
//
// mcp must be the same handler instance that serves mcpPath, so a session
// opened on one path stays valid on the other. The 401 challenge and the
// protected-resource metadata are already path-aware (auth.ResourceMetadata,
// protectedResource in cmd/server), so a client on the origin is told the
// resource is the origin and its token is accepted on both paths.
//
// count, when non-nil, is called once for every request served as MCP, with
// a bounded method (rootMCPMethod) and User-Agent family (UAFamily), so the
// alias's use is measurable (mctl_root_mcp_requests_total). Landing-page
// loads are not counted.
func RootMCP(landing, mcp http.Handler, count func(method, uaFamily string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && !wantsEventStream(r.Header.Get("Accept")) {
			landing.ServeHTTP(w, r)
			return
		}
		if count != nil {
			count(rootMCPMethod(r.Method), UAFamily(r.UserAgent()))
		}
		mcp.ServeHTTP(w, r)
	})
}

// rootMCPMethod bounds the method label of mctl_root_mcp_requests_total to
// GET, POST, DELETE and other.
func rootMCPMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
		return m
	}
	return "other"
}

// UA family labels, the closed ua_family set of mctl_root_mcp_requests_total.
const (
	UAFamilyClaude     = "claude"
	UAFamilyChatGPT    = "chatgpt"
	UAFamilyPerplexity = "perplexity"
	UAFamilyCanary     = "canary"
	UAFamilyOther      = "other"
)

// UAFamily maps a User-Agent to a bounded family label. Matching is a
// case-insensitive substring test on tokens the connectors send (Claude-User,
// ChatGPT-User, openai-mcp, Perplexity-User) and on the canary's own
// mctl-telegram-canary/<version>; anything else, including an empty or
// spoofed value, is "other". It is a label for counting, never a trust
// decision.
func UAFamily(ua string) string {
	u := strings.ToLower(ua)
	switch {
	case strings.Contains(u, "mctl-telegram-canary"):
		return UAFamilyCanary
	case strings.Contains(u, "claude"), strings.Contains(u, "anthropic"):
		return UAFamilyClaude
	case strings.Contains(u, "chatgpt"), strings.Contains(u, "openai"):
		return UAFamilyChatGPT
	case strings.Contains(u, "perplexity"):
		return UAFamilyPerplexity
	}
	return UAFamilyOther
}

// wantsEventStream reports whether a GET is an MCP client opening its
// Streamable-HTTP SSE stream rather than a page load: it accepts
// text/event-stream and does not ask for HTML.
func wantsEventStream(accept string) bool {
	a := strings.ToLower(accept)
	return strings.Contains(a, "text/event-stream") && !strings.Contains(a, "text/html")
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
