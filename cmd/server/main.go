package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localdev"
	"github.com/mctlhq/mctl-telegram/internal/auth/sharedhmac"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/sweeper"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/mctlhq/mctl-telegram/internal/web"
)

func main() {
	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slog.SetDefault(slog.New(audit.NewRedactingHandler(inner)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load", "err", err)
		os.Exit(1)
	}
	slog.Info("starting",
		"auth_mode", cfg.AuthMode,
		"auth_required", cfg.AuthRequired,
		"allow_send", cfg.AllowSend,
		"mcp_path", cfg.MCPPath,
		"addr", cfg.Addr,
		"telegram_configured", cfg.TGAPIID != 0 && cfg.TGAPIHash != "",
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rawDB, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		slog.Error("db open", "err", err)
		os.Exit(1)
	}
	defer rawDB.Close()
	if err := db.Migrate(ctx, rawDB); err != nil {
		slog.Error("db migrate", "err", err)
		os.Exit(1)
	}
	cryp, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		slog.Error("crypto init", "err", err)
		os.Exit(1)
	}
	if !cryp.Enabled() {
		slog.Warn("ENCRYPTION_KEY not set — session bytes stored UNENCRYPTED (acceptable only for local-dev)")
	}
	store := db.NewStore(rawDB, cryp)
	pool := telegram.NewClientPool(cfg.TGAPIID, cfg.TGAPIHash, cfg.IdleClientTimeout, store)
	defer pool.Shutdown()

	// Periodic background job that revokes sessions whose idle (30d) or
	// absolute (90d) TTL has elapsed. CheckSessionValid on every Borrow
	// is the authoritative gate; this sweeper just bounds how long an
	// abandoned row sits as a live record before being marked.
	go sweeper.Sessions(ctx, store)
	// Audit-log retention: trims rows older than AUDIT_RETENTION_DAYS
	// (default 90). AUDIT_RETENTION_DAYS=0 keeps rows forever.
	go sweeper.AuditLog(ctx, store, time.Duration(cfg.AuditRetentionDays)*24*time.Hour)

	mux := chi.NewRouter()
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Timeout(60 * time.Second))

	mux.Get("/healthz", healthz)
	mux.Get("/readyz", healthz)
	mux.Get("/.well-known/oauth-protected-resource", protectedResource(cfg))
	mux.Get("/favicon.svg", web.Favicon())
	mux.Get("/favicon.ico", web.Favicon())
	mux.Get("/", web.Landing(cfg.PublicBaseURL, cfg.MCPPath))
	mux.Get("/security", web.Security())
	mux.Get("/privacy", web.Privacy())

	provider := selectProvider(cfg, store)

	// Account endpoints — self-service disconnect/delete + status.
	// Mounted behind the same auth middleware as MCP so anon traffic gets 401.
	accountMux := chi.NewRouter()
	accountHandlers := web.NewAccountHandlers(store, pool)
	accountHandlers.Register(accountMux)
	mux.Mount("/api/account", auth.Middleware(provider, true)(accountMux))

	limiter := audit.NewRateLimiter(cfg.RateLimitPerUser)
	mcpSrv := mcpapp.New(store, pool, cfg.AllowSend).WithLimiter(limiter)

	// Bridge token endpoint: authenticated users exchange their MCP JWT for
	// a short-lived bridge JWT (aud=bridge, 1h TTL) that the local daemon
	// uses to register its websocket connection at GET /bridge.
	if secret := cfg.OAUTHJWTSecret; secret != "" {
		mux.With(auth.Middleware(provider, true)).Post("/api/bridge/token",
			bridge.NewBridgeTokenHandler(provider, []byte(secret)))
	}

	// Websocket bridge endpoint: Local Bridge daemons connect here.
	// Uses a separate provider that enforces aud=bridge so regular MCP
	// tokens cannot be used to hijack the bridge channel.
	hub := bridge.NewHub()
	bridgeProvider := selectBridgeProvider(cfg, store)
	mux.Get("/bridge", bridge.NewBridgeHandler(hub, bridgeProvider, store, ctx))

	// Wire the hub into the MCP server so tool calls for local-mode users
	// are forwarded to their daemon instead of the hosted MTProto pool.
	mcpSrv = mcpSrv.WithHub(hub)

	// Browser-GET to MCP_PATH is bounced to the landing page BEFORE auth
	// runs, so unauthenticated humans still see instructions instead of
	// a 401. MCP clients (Accept: application/json, text/event-stream)
	// fall through and hit the full auth+ratelimit+MCP chain.
	mcpHandler := auth.Middleware(provider, cfg.AuthRequired)(
		limiter.Middleware()(mcpSrv.HTTPHandler()),
	)
	mux.Mount(cfg.MCPPath, web.BrowserRedirect(mcpHandler, "/"))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		slog.Info("listening", "addr", cfg.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	case err := <-errCh:
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// selectProvider picks the auth.Provider implementation based on AUTH_MODE.
// "local-dev" is the operator-fixed bypass (safe only behind 127.0.0.1).
// "shared-hmac" reuses mctl-api's OAUTH_JWT_SECRET to verify JWTs in-band —
// see SECURITY.md for the documented coupling caveat.
func selectProvider(cfg *config.Config, store *db.Store) auth.Provider {
	switch strings.ToLower(cfg.AuthMode) {
	case "shared-hmac":
		p, err := sharedhmac.New(store, sharedhmac.Config{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   "https://api.mctl.ai",
			ExpectedAudience: cfg.OAUTHJWTAudience,
			AudienceRequired: cfg.OAUTHJWTAudReq,
		})
		if err != nil {
			slog.Error("shared-hmac init failed; refusing to start", "err", err)
			os.Exit(1)
		}
		return p
	case "local-dev":
		return localdev.New(store, cfg.OperatorLogin)
	default:
		slog.Warn("unknown AUTH_MODE, falling back to local-dev", "auth_mode", cfg.AuthMode)
		return localdev.New(store, cfg.OperatorLogin)
	}
}

// selectBridgeProvider builds an auth.Provider for the /bridge websocket
// endpoint. It behaves like selectProvider but enforces AudienceRequired=true
// and ExpectedAudience="bridge" so only tokens issued by NewBridgeTokenHandler
// are accepted. Regular MCP tokens (no aud or aud != "bridge") are rejected,
// preventing cross-channel token reuse.
//
// In local-dev mode, the bridge endpoint falls back to the same localdev
// bypass — useful when running without a real JWT secret.
func selectBridgeProvider(cfg *config.Config, store *db.Store) auth.Provider {
	switch strings.ToLower(cfg.AuthMode) {
	case "shared-hmac":
		if cfg.OAUTHJWTSecret == "" {
			slog.Warn("bridge: OAUTH_JWT_SECRET not set, bridge endpoint will reject all connections")
			return localdev.New(store, cfg.OperatorLogin)
		}
		p, err := sharedhmac.New(store, sharedhmac.Config{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   "https://api.mctl.ai",
			ExpectedAudience: "bridge",
			AudienceRequired: true,
		})
		if err != nil {
			slog.Error("bridge: shared-hmac init failed; bridge endpoint disabled", "err", err)
			os.Exit(1)
		}
		return p
	default:
		return localdev.New(store, cfg.OperatorLogin)
	}
}

// protectedResource serves the RFC 9728 OAuth Protected Resource Metadata so
// claude.ai's connector knows api.mctl.ai is the authorization server even
// though tg-mcp lives on a different host.
func protectedResource(cfg *config.Config) http.HandlerFunc {
	body := []byte(fmt.Sprintf(
		`{"resource":%q,"authorization_servers":["https://api.mctl.ai"],"scopes_supported":["mctl","telegram:dialogs:read","telegram:messages:read","telegram:messages:send","telegram:messages:pin"]}`,
		cfg.PublicBaseURL,
	))
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
