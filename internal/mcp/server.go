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
}

func New(store *db.Store, pool *telegram.ClientPool, allowSend bool) *Server {
	return &Server{
		Store:     store,
		Pool:      pool,
		AllowSend: allowSend,
		Confirms:  NewConfirmStore(),
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

func (s *Server) HTTPHandler() http.Handler {
	srv := mcpserver.NewMCPServer(
		"mctl-telegram",
		"0.7.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(s.toolListDialogs())
	srv.AddTool(s.toolGetUnreadMessages())
	srv.AddTool(s.toolGetMessages())
	srv.AddTool(s.toolSendMessage())
	srv.AddTool(s.toolPreparePinMessage())
	srv.AddTool(s.toolPinMessage())
	srv.AddTool(s.toolDisconnectAccount())
	srv.AddTool(s.toolDeleteAccount())
	srv.AddTool(s.toolGetMyAuditLog())
	srv.AddTool(s.toolListIdentities())
	srv.AddTool(s.toolSetAccess())
	srv.AddTool(s.toolSetAccountSend())
	srv.AddTool(s.toolGetUserAuditLog())
	srv.AddTool(s.toolRevokeSession())

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
