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
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
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

	provider := selectProvider(cfg, store)

	mcpSrv := mcpapp.New(store, pool, cfg.AllowSend)
	limiter := audit.NewRateLimiter(cfg.RateLimitPerUser)

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
			Secret:         []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer: "https://api.mctl.ai",
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
