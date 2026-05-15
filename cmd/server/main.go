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
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/auth/sharedhmac"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
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

	// Authorization server URL — for the Telegram-native local-jwt path
	// (default), this is the same as PublicBaseURL: mctl-telegram is its own
	// issuer. The legacy shared-hmac-legacy path keeps pointing at
	// api.mctl.ai.
	authServer := selectAuthServer(cfg)

	mux.Get("/healthz", healthz)
	mux.Get("/readyz", healthz)
	mux.Get("/.well-known/oauth-protected-resource", protectedResource(cfg, authServer))
	mux.Get("/favicon.svg", web.Favicon())
	mux.Get("/favicon.ico", web.Favicon())
	mux.Get("/", web.Landing(cfg.PublicBaseURL, cfg.MCPPath, authServer))
	mux.Get("/security", web.Security())
	mux.Get("/privacy", web.Privacy())

	// Wire the OAuth issuer when we're running in local-jwt mode. This adds
	// /oauth/authorize, /oauth/telegram/callback, /oauth/token,
	// /oauth/register, and /.well-known/oauth-authorization-server. The
	// shared-hmac-legacy path leaves these unmounted — Claude.ai then talks
	// to api.mctl.ai as before.
	if strings.EqualFold(cfg.AuthMode, "local-jwt") {
		if err := registerOAuth(cfg, store, mux); err != nil {
			slog.Error("oauth init failed; refusing to start", "err", err)
			os.Exit(1)
		}
	}

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
	//
	// Issuer parity matters here: bridge token iss MUST match what
	// selectBridgeProvider configures as ExpectedIssuer, or every minted
	// token would be rejected at /bridge. selectBridgeIssuer maps the same
	// AUTH_MODE switch as selectBridgeProvider.
	if secret := cfg.OAUTHJWTSecret; secret != "" {
		mux.With(auth.Middleware(provider, true)).Post("/api/bridge/token",
			bridge.NewBridgeTokenHandler(provider, []byte(secret), selectBridgeIssuer(cfg)))
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
//
//   - "local-dev" — fixed-identity bypass (safe only behind 127.0.0.1).
//   - "local-jwt" — mctl-telegram is its own OAuth issuer (Telegram Login
//     Widget → JWT with iss=PublicBaseURL, verified by localjwt.Provider).
//   - "shared-hmac-legacy" — backwards compat for deployments that still
//     trust JWTs signed by api.mctl.ai via the shared OAUTH_JWT_SECRET.
//     "shared-hmac" is accepted as an alias for the legacy mode for the
//     duration of one minor release.
func selectProvider(cfg *config.Config, store *db.Store) auth.Provider {
	switch strings.ToLower(cfg.AuthMode) {
	case "local-jwt":
		// Use the canonicalised issuer (trailing slash stripped) so the
		// minting path in registerOAuth and the verify path here always
		// agree, regardless of whether the operator wrote PUBLIC_BASE_URL
		// with or without a trailing slash. Without this normalization a
		// values.yaml change from "https://tg.mctl.ai" to "https://tg.mctl.ai/"
		// would silently break every bearer token because iss claim and
		// expected issuer would differ by one byte.
		p, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   strings.TrimRight(cfg.PublicBaseURL, "/"),
			ExpectedAudience: cfg.OAUTHJWTAudience,
			AudienceRequired: cfg.OAUTHJWTAudReq,
		})
		if err != nil {
			slog.Error("local-jwt init failed; refusing to start", "err", err)
			os.Exit(1)
		}
		return p
	case "shared-hmac", "shared-hmac-legacy":
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

// selectAuthServer returns the canonical authorization server URL for this
// deployment. local-jwt → self (PublicBaseURL); shared-hmac → api.mctl.ai.
func selectAuthServer(cfg *config.Config) string {
	switch strings.ToLower(cfg.AuthMode) {
	case "shared-hmac", "shared-hmac-legacy":
		return "https://api.mctl.ai"
	default:
		return strings.TrimRight(cfg.PublicBaseURL, "/")
	}
}

// selectBridgeIssuer returns the iss value to stamp into bridge tokens minted
// at POST /api/bridge/token. Must match the ExpectedIssuer configured on the
// bridge auth.Provider via selectBridgeProvider — keep these two in lockstep
// or every bridge token will be rejected as "unexpected JWT issuer".
func selectBridgeIssuer(cfg *config.Config) string {
	switch strings.ToLower(cfg.AuthMode) {
	case "shared-hmac", "shared-hmac-legacy":
		return "https://api.mctl.ai"
	default:
		return strings.TrimRight(cfg.PublicBaseURL, "/")
	}
}

// registerOAuth wires the Telegram-native OAuth issuer onto the router.
// Called only when AUTH_MODE=local-jwt.
func registerOAuth(cfg *config.Config, store *db.Store, mux *chi.Mux) error {
	if cfg.OAUTHJWTSecret == "" {
		return fmt.Errorf("OAUTH_JWT_SECRET is required when AUTH_MODE=local-jwt")
	}
	if cfg.TelegramLoginBotToken == "" {
		return fmt.Errorf("TELEGRAM_LOGIN_BOT_TOKEN is required when AUTH_MODE=local-jwt")
	}
	if cfg.TelegramLoginBotUsername == "" {
		return fmt.Errorf("TELEGRAM_LOGIN_BOT_USERNAME is required when AUTH_MODE=local-jwt")
	}
	admins := map[int64]bool{}
	for _, id := range cfg.TGLoginAdmins {
		admins[id] = true
	}
	srv, err := oauth.New(oauth.Config{
		Issuer:              strings.TrimRight(cfg.PublicBaseURL, "/"),
		JWTSecret:           []byte(cfg.OAUTHJWTSecret),
		JWTAudience:         cfg.OAUTHJWTAudience,
		BotToken:            cfg.TelegramLoginBotToken,
		BotUsername:         cfg.TelegramLoginBotUsername,
		AdminTelegramIDs:    admins,
		AccessTokenTTL:      cfg.OAUTHAccessTokenTTL,
		CodeTTL:             cfg.OAUTHCodeTTL,
		AllowImplicitClient: cfg.OAUTHAllowImplicitClient,
	}, store)
	if err != nil {
		return err
	}
	srv.Register(mux)
	stopSweep := make(chan struct{})
	srv.StartSweeper(stopSweep, 1*time.Minute)
	slog.Info("oauth issuer enabled",
		"issuer", cfg.PublicBaseURL,
		"bot_username", cfg.TelegramLoginBotUsername,
		"admin_count", len(admins),
		"implicit_clients", cfg.OAUTHAllowImplicitClient,
	)
	return nil
}

// selectBridgeProvider builds an auth.Provider for the /bridge websocket
// endpoint. It behaves like selectProvider but enforces AudienceRequired=true
// and ExpectedAudience="bridge" so only tokens issued by NewBridgeTokenHandler
// are accepted. Regular MCP tokens (no aud or aud != "bridge") are rejected,
// preventing cross-channel token reuse.
//
// Mode parity with selectProvider: the bridge endpoint must use the same
// signing key + issuer convention as the MCP path, otherwise a switch to
// AUTH_MODE=local-jwt would silently downgrade /bridge to localdev (any
// connection accepted, daemon registers as fixed operator). Each non-local-
// dev mode therefore has an explicit branch here.
func selectBridgeProvider(cfg *config.Config, store *db.Store) auth.Provider {
	mode := strings.ToLower(cfg.AuthMode)
	switch mode {
	case "local-jwt":
		if cfg.OAUTHJWTSecret == "" {
			slog.Warn("bridge: OAUTH_JWT_SECRET not set, bridge endpoint will reject all connections")
			return localdev.New(store, cfg.OperatorLogin)
		}
		p, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   strings.TrimRight(cfg.PublicBaseURL, "/"),
			ExpectedAudience: "bridge",
			AudienceRequired: true,
		})
		if err != nil {
			slog.Error("bridge: local-jwt init failed; bridge endpoint disabled", "err", err)
			os.Exit(1)
		}
		return p
	case "shared-hmac", "shared-hmac-legacy":
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
// claude.ai's connector knows which authorization server to talk to. In the
// Telegram-native local-jwt mode this is the same service (PublicBaseURL);
// in shared-hmac-legacy mode it stays pointed at api.mctl.ai.
func protectedResource(cfg *config.Config, authServer string) http.HandlerFunc {
	body := []byte(fmt.Sprintf(
		`{"resource":%q,"authorization_servers":[%q],"scopes_supported":["mctl","telegram:dialogs:read","telegram:messages:read","telegram:messages:send","telegram:messages:pin","admin:users"]}`,
		cfg.PublicBaseURL,
		authServer,
	))
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
