// Package mcp wires the three Telegram-user-account MCP tools onto an mcp-go
// streamable HTTP server.
package mcp

import (
	"context"
	"net/http"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type Server struct {
	Store     *db.Store
	Pool      *telegram.ClientPool
	AllowSend bool
	Confirms  *ConfirmStore
	// Limiter is the per-identity / per-peer write-action limiter.
	// Optional: when nil, AllowPeer checks are skipped.
	Limiter *audit.RateLimiter
	// Hub routes MCP tool calls to Local Bridge daemons. When nil, all
	// tools fall back to Pool.Borrow (hosted mode only).
	Hub *bridge.Hub
	// Metrics is optional; when non-nil, tool invocation counters and
	// duration histograms are recorded.
	Metrics *metrics.Registry
	// PeerCache is an optional in-memory cache for resolved Telegram peers.
	// When nil (default), every call resolves the peer fresh via the Telegram API.
	PeerCache *telegram.PeerCache
	// DemoReviewerTGID, when non-zero, forces every send from that Telegram
	// identity to a dry-run preview regardless of the per-account send_enabled
	// flag (set by WithDemoReviewer only when reviewer mode is enabled). This is
	// the authoritative barrier for the ChatGPT App Directory reviewer account:
	// the connect flow re-enables send_enabled and ChatGPT may auto-execute the
	// send tool, so neither is a dependable preview-only guarantee on its own.
	DemoReviewerTGID int64
	// ToolFilter controls which MCP tools are registered. "all" (default)
	// registers every tool; "read-only" registers only tools with
	// ReadOnlyHint=true (set via WithToolFilter).
	ToolFilter string
	// MediaStore holds pending media download references keyed by confirmation_id.
	MediaStore *MediaStore
	// MediaDownloadMaxBytes is the maximum number of bytes allowed per get_media
	// download. 0 means no cap.
	MediaDownloadMaxBytes int64
	// MediaUploadMaxBytes is the maximum number of bytes allowed per send_media
	// upload (file_url fetch or file_base64 decode). 0 means no cap.
	MediaUploadMaxBytes int64
}

func New(store *db.Store, pool *telegram.ClientPool, allowSend bool) *Server {
	return &Server{
		Store:      store,
		Pool:       pool,
		AllowSend:  allowSend,
		Confirms:   NewConfirmStore(),
		MediaStore: NewMediaStore(),
	}
}

// WithLimiter wires a shared *audit.RateLimiter so destructive tools can
// take a per-(identity, peer) tap on the same bucket store used by HTTP
// middleware. Returns the receiver for chaining.
func (s *Server) WithLimiter(l *audit.RateLimiter) *Server {
	s.Limiter = l
	return s
}

// WithHub wires the Local Bridge Hub so that tools dispatched for a
// local-mode user are forwarded to the daemon instead of Pool.Borrow.
// Returns the receiver for chaining.
func (s *Server) WithHub(h *bridge.Hub) *Server {
	s.Hub = h
	return s
}

// WithMetrics wires a *metrics.Registry so tool invocations are counted and
// their durations are histogrammed. Returns the receiver for chaining.
func (s *Server) WithMetrics(m *metrics.Registry) *Server {
	s.Metrics = m
	return s
}

// WithPeerCache wires an in-memory peer resolution cache to reduce repeated
// ContactsResolveUsername calls. Returns the receiver for chaining.
func (s *Server) WithPeerCache(pc *telegram.PeerCache) *Server {
	s.PeerCache = pc
	return s
}

// WithDemoReviewer pins the demo/reviewer Telegram id whose sends are forced to
// dry-run previews. Pass 0 (the default) to disable. Returns the receiver for
// chaining.
func (s *Server) WithDemoReviewer(tgID int64) *Server {
	s.DemoReviewerTGID = tgID
	return s
}

// WithToolFilter sets the MCP tool registration filter. "all" registers every
// tool; "read-only" registers only tools annotated with ReadOnlyHint=true,
// providing an operator-level gate that prevents write tools from appearing in
// the MCP tool list regardless of OAuth scopes. Returns the receiver for chaining.
func (s *Server) WithToolFilter(f string) *Server {
	s.ToolFilter = f
	return s
}

// toolPassesFilter reports whether a tool should be registered given the
// active filter mode. An unrecognised filter is treated as "all" (safe default).
func toolPassesFilter(tool mcplib.Tool, filter string) bool {
	if filter != "read-only" {
		return true
	}
	return tool.Annotations.ReadOnlyHint != nil && *tool.Annotations.ReadOnlyHint
}

// addTool registers a (tool, handler) pair unless ToolFilter excludes the tool.
// The pair arguments match the two-value return of s.toolXxx() builder methods.
func (s *Server) addTool(srv *mcpserver.MCPServer, tool mcplib.Tool, handler mcpserver.ToolHandlerFunc) {
	if toolPassesFilter(tool, s.ToolFilter) {
		srv.AddTool(tool, handler)
	}
}

func (s *Server) HTTPHandler() http.Handler {
	srv := mcpserver.NewMCPServer(
		"mctl-telegram",
		"0.7.0",
		mcpserver.WithToolCapabilities(true),
	)
	{t, h := s.toolListDialogs(); s.addTool(srv, t, h)}
	{t, h := s.toolGetUnreadMessages(); s.addTool(srv, t, h)}
	{t, h := s.toolGetMessages(); s.addTool(srv, t, h)}
	{t, h := s.toolSendMessage(); s.addTool(srv, t, h)}
	{t, h := s.toolPreparePinMessage(); s.addTool(srv, t, h)}
	{t, h := s.toolPinMessage(); s.addTool(srv, t, h)}
	{t, h := s.toolPrepareGetMedia(); s.addTool(srv, t, h)}
	{t, h := s.toolGetMedia(); s.addTool(srv, t, h)}
	{t, h := s.toolSendMedia(); s.addTool(srv, t, h)}
	{t, h := s.toolDisconnectAccount(); s.addTool(srv, t, h)}
	{t, h := s.toolDeleteAccount(); s.addTool(srv, t, h)}
	{t, h := s.toolGetMyAuditLog(); s.addTool(srv, t, h)}
	{t, h := s.toolListIdentities(); s.addTool(srv, t, h)}
	{t, h := s.toolSetAccess(); s.addTool(srv, t, h)}
	{t, h := s.toolSetAccountSend(); s.addTool(srv, t, h)}
	{t, h := s.toolGetUserAuditLog(); s.addTool(srv, t, h)}
	{t, h := s.toolRevokeSession(); s.addTool(srv, t, h)}
	{t, h := s.toolEditMessage(); s.addTool(srv, t, h)}
	{t, h := s.toolDeleteMessages(); s.addTool(srv, t, h)}
	{t, h := s.toolForwardMessages(); s.addTool(srv, t, h)}
	{t, h := s.toolSearchMessages(); s.addTool(srv, t, h)}
	{t, h := s.toolSetReaction(); s.addTool(srv, t, h)}

	return mcpserver.NewStreamableHTTPServer(
		srv,
		mcpserver.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return r.Context()
		}),
	)
}

// Tiny helper used by tool implementations.
func toolErr(format string, a ...any) *mcplib.CallToolResult {
	return mcplib.NewToolResultError(formatErr(format, a...))
}

func formatErr(format string, a ...any) string {
	if len(a) == 0 {
		return format
	}
	return sprintf(format, a...)
}

// sprintf is a thin wrapper to avoid importing fmt in tools.go duplicates.
func sprintf(format string, a ...any) string {
	return fmtSprintfImpl(format, a...)
}
