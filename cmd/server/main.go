package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	"github.com/mctlhq/mctl-telegram/internal/digest"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/sweeper"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/mctlhq/mctl-telegram/internal/web"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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

	rawDB, err := db.Open(ctx, cfg.DatabaseURL, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns)
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
	// Construct the metrics registry early so all subsystems can be wired
	// before any goroutine or handler is started.
	m := metrics.New()

	store := db.NewStore(rawDB, cryp).WithMetrics(m)
	pool := telegram.NewClientPool(cfg.TGAPIID, cfg.TGAPIHash, cfg.IdleClientTimeout, store).
		WithMaxSessions(cfg.TelegramMaxSessions).
		WithMetrics(m)
	defer pool.Shutdown()

	// Set the pool-capacity gauge. -1 when uncapped so a Prometheus expression
	// pool_size / pool_capacity correctly indicates "no cap" (-1) vs a real value.
	if cfg.TelegramMaxSessions > 0 {
		m.TelegramPoolCapacity.Set(float64(cfg.TelegramMaxSessions))
		slog.Info("session pool cap configured", "max_sessions", cfg.TelegramMaxSessions)
	} else {
		m.TelegramPoolCapacity.Set(-1)
	}

	// Set the replica-identity info gauge and emit a structured startup log.
	// replica_id is sourced from REPLICA_ID env var, falling back to POD_NAME,
	// then to "unknown". In Kubernetes, wire POD_NAME via the downward API:
	//   env:
	//     - name: POD_NAME
	//       valueFrom:
	//         fieldRef:
	//           fieldPath: metadata.name
	m.TelegramReplicaID.WithLabelValues(cfg.ReplicaID).Set(1)
	slog.Info("replica identity", "replica_id", cfg.ReplicaID)

	// Periodic background job that revokes sessions whose idle (30d) or
	// absolute (90d) TTL has elapsed. CheckSessionValid on every Borrow
	// is the authoritative gate; this sweeper just bounds how long an
	// abandoned row sits as a live record before being marked.
	go sweeper.Sessions(ctx, store)
	// Audit-log retention: trims rows older than AUDIT_RETENTION_DAYS
	// (default 90). AUDIT_RETENTION_DAYS=0 keeps rows forever.
	go sweeper.AuditLog(ctx, store, time.Duration(cfg.AuditRetentionDays)*24*time.Hour)
	// OAuth refresh-token cleanup: deletes rows past their absolute expiry so
	// the table stays bounded. LookupRefreshToken is the authoritative gate.
	go sweeper.RefreshTokens(ctx, store)
	// Active session gauge sampler: refreshes mctl_sessions_active every minute.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := store.CountActiveSessions(ctx)
				if err != nil {
					// Log so a persistent DB failure leaves a trail —
					// otherwise the gauge silently goes stale.
					slog.Warn("active-session gauge sample failed", "err", err)
					continue
				}
				m.SessionsActiveGauge.Set(float64(n))
			}
		}
	}()

	mux := chi.NewRouter()
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	// HTTPMiddleware is placed before Recoverer so that panics recovered as
	// HTTP 500 by Recoverer are still captured in mctl_http_requests_total.
	// Recoverer writes the 500 status, which the metrics responseWriter wrapper
	// sees because it sits on the outside of the Recoverer layer.
	mux.Use(m.HTTPMiddleware())
	mux.Use(middleware.Recoverer)
	mux.Use(middleware.Timeout(60 * time.Second))

	// Authorization server URL — for the Telegram-native local-jwt path
	// (default), this is the same as PublicBaseURL: mctl-telegram is its own
	// issuer. The legacy shared-hmac-legacy path keeps pointing at
	// api.mctl.ai.
	authServer := selectAuthServer(cfg)

	mux.Get("/healthz", healthz)
	mux.Get("/readyz", healthz)
	mux.Get("/metrics", metricsHandler(m, cfg.MetricsAllowCIDR))
	mux.Get("/.well-known/oauth-protected-resource", protectedResource(cfg, authServer))
	mux.Get("/favicon.svg", web.Favicon())
	mux.Get("/favicon.ico", web.Favicon())
	mux.Get("/", web.Landing(cfg.PublicBaseURL, cfg.MCPPath, authServer))
	mux.Get("/security", web.Security(cfg.PublicBaseURL))
	mux.Get("/privacy", web.Privacy(cfg.PublicBaseURL))
	mux.Get("/docs", web.Docs(cfg.PublicBaseURL, cfg.MCPPath, authServer))

	// Wire the OAuth issuer when we're running in local-jwt mode. This adds
	// /oauth/authorize, /oauth/telegram/callback, /oauth/token,
	// /oauth/register, and /.well-known/oauth-authorization-server. The
	// shared-hmac-legacy path leaves these unmounted — Claude.ai then talks
	// to api.mctl.ai as before.
	if strings.EqualFold(cfg.AuthMode, "local-jwt") {
		oauthSrv, err := registerOAuth(ctx, cfg, store, mux, m)
		if err != nil {
			slog.Error("oauth init failed; refusing to start", "err", err)
			os.Exit(1)
		}
		// Browser-based Telegram account onboarding. Only meaningful when the
		// OAuth issuer is active (local-jwt mode); returns 404 otherwise.
		connectSrv := web.NewConnectServer(web.ConnectConfig{
			Issuer:               strings.TrimRight(cfg.PublicBaseURL, "/"),
			OAuthServer:          oauthSrv,
			CodeTTL:              cfg.OAUTHCodeTTL,
			ClaudeAIConnectorURL: "https://claude.ai/settings/integrations",
			ClientID:             oauth.ConnectClientID,
			MCPPath:              cfg.MCPPath,
			MaxSessions:          500,
		})
		mux.Get("/telegram/connect", connectSrv.HandleConnect)
		mux.Get("/telegram/connect/done", connectSrv.HandleConnectDone)
	}

	provider, err := selectProvider(cfg, store)
	if err != nil {
		slog.Error("invalid AUTH_MODE; refusing to start", "err", err)
		os.Exit(1)
	}

	// Session management dashboard — only mounted in local-jwt mode alongside
	// the self-connect wizard. Requires auth so only the session owner can
	// manage their own session.
	if strings.EqualFold(cfg.AuthMode, "local-jwt") {
		manageSrv := web.NewManageServer(store, pool, strings.TrimRight(cfg.PublicBaseURL, "/"))
		mux.With(auth.Middleware(provider, true, m)).
			Get("/telegram/connect/manage", manageSrv.HandleManage)
		mux.With(auth.Middleware(provider, true, m)).
			Post("/telegram/connect/manage/disconnect", manageSrv.HandleDisconnect)
		mux.With(auth.Middleware(provider, true, m)).
			Post("/telegram/connect/manage/toggle-send", manageSrv.HandleToggleSend)
	}

	// Account endpoints — self-service disconnect/delete + status.
	// Mounted behind the same auth middleware as MCP so anon traffic gets 401.
	accountMux := chi.NewRouter()
	accountHandlers := web.NewAccountHandlers(store, pool)
	accountHandlers.Register(accountMux)
	mux.Mount("/api/account", auth.Middleware(provider, true, m)(accountMux))

	limiter := audit.NewRateLimiter(cfg.RateLimitPerUser).WithMetrics(m)
	mcpSrv := mcpapp.New(store, pool, cfg.AllowSend).WithLimiter(limiter).WithMetrics(m)

	// Bridge token endpoint: authenticated users exchange their MCP JWT for
	// a short-lived bridge JWT (aud=bridge, 1h TTL) that the local daemon
	// uses to register its websocket connection at GET /bridge.
	//
	// Issuer parity matters here: bridge token iss MUST match what
	// selectBridgeProvider configures as ExpectedIssuer, or every minted
	// token would be rejected at /bridge. selectBridgeIssuer maps the same
	// AUTH_MODE switch as selectBridgeProvider.
	if secret := cfg.OAUTHJWTSecret; secret != "" {
		mux.With(auth.Middleware(provider, true, m)).Post("/api/bridge/token",
			bridge.NewBridgeTokenHandler(provider, []byte(secret), selectBridgeIssuer(cfg)))
	}

	// Websocket bridge endpoint: Local Bridge daemons connect here.
	// Uses a separate provider that enforces aud=bridge so regular MCP
	// tokens cannot be used to hijack the bridge channel.
	hub := bridge.NewHub().WithMetrics(m)
	bridgeProvider := selectBridgeProvider(cfg, store)
	mux.Get("/bridge", bridge.NewBridgeHandler(hub, bridgeProvider, store, ctx))

	// Wire the hub into the MCP server so tool calls for local-mode users
	// are forwarded to their daemon instead of the hosted MTProto pool.
	mcpSrv = mcpSrv.WithHub(hub)

	// Browser-GET to MCP_PATH is bounced to the landing page BEFORE auth
	// runs, so unauthenticated humans still see instructions instead of
	// a 401. MCP clients (Accept: application/json, text/event-stream)
	// fall through and hit the full auth+ratelimit+MCP chain.
	mcpHandler := auth.Middleware(provider, cfg.AuthRequired, m)(
		limiter.Middleware()(mcpSrv.HTTPHandler()),
	)
	mux.Mount(cfg.MCPPath, web.BrowserRedirect(mcpHandler, "/"))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// ConnContext stores the TCP peer address in the request context before
		// any middleware runs. metricsHandler reads socketPeerKey to enforce the
		// CIDR allowlist against the real socket address — not the r.RemoteAddr
		// value that middleware.RealIP rewrites from X-Forwarded-For headers.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, socketPeerKey{}, c.RemoteAddr().String())
		},
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

// metricsHandler wraps the Prometheus exposition handler with an optional CIDR
// allowlist guard. When allowCIDR is empty the endpoint is open (suitable for
// Kubernetes PodMonitor scrape patterns where NetworkPolicy provides isolation).
// When set, requests from outside the CIDR receive HTTP 403.
//
// The CIDR check uses the real TCP socket peer address stored in context by the
// http.Server ConnContext hook — not r.RemoteAddr, which middleware.RealIP
// rewrites from X-Forwarded-For / X-Real-IP headers. A client cannot bypass
// the CIDR guard by forging those headers. The authoritative control MUST
// still be a NetworkPolicy that restricts ingress to /metrics to the monitoring
// namespace; the CIDR check is a secondary belt.
//
// A misconfigured allowCIDR fails CLOSED — the endpoint rejects every request
// rather than silently exposing platform metrics.
func metricsHandler(m *metrics.Registry, allowCIDR string) http.HandlerFunc {
	h := promhttp.HandlerFor(m.Prometheus, promhttp.HandlerOpts{})
	if allowCIDR == "" {
		return h.ServeHTTP
	}
	_, ipNet, err := net.ParseCIDR(allowCIDR)
	if err != nil {
		slog.Error("METRICS_ALLOW_CIDR is invalid — /metrics endpoint will reject ALL requests until fixed", "cidr", allowCIDR, "err", err)
		return func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// Use the real socket peer stored by ConnContext — not r.RemoteAddr,
		// which middleware.RealIP may have overwritten with a header value.
		// A client that forges X-Forwarded-For cannot bypass the CIDR check
		// because the TCP-level address is set before any request handling.
		rawAddr, _ := r.Context().Value(socketPeerKey{}).(string)
		if rawAddr == "" {
			rawAddr = r.RemoteAddr // fallback for tests that bypass ConnContext
		}
		host, _, splitErr := net.SplitHostPort(rawAddr)
		if splitErr != nil {
			host = rawAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ipNet.Contains(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}
}

// socketPeerKey is the context key used by the http.Server ConnContext hook to
// store the real TCP peer address before middleware.RealIP can overwrite
// r.RemoteAddr with X-Forwarded-For values.
type socketPeerKey struct{}

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
func selectProvider(cfg *config.Config, store *db.Store) (auth.Provider, error) {
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
			return nil, fmt.Errorf("local-jwt init failed: %w", err)
		}
		return p, nil
	case "shared-hmac", "shared-hmac-legacy":
		p, err := sharedhmac.New(store, sharedhmac.Config{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   "https://api.mctl.ai",
			ExpectedAudience: cfg.OAUTHJWTAudience,
			AudienceRequired: cfg.OAUTHJWTAudReq,
		})
		if err != nil {
			return nil, fmt.Errorf("shared-hmac init failed: %w", err)
		}
		return p, nil
	case "local-dev":
		return localdev.New(store, cfg.OperatorLogin), nil
	default:
		return nil, fmt.Errorf("unknown AUTH_MODE %q: must be one of local-jwt, shared-hmac, local-dev", cfg.AuthMode)
	}
}

// selectAuthServer returns the canonical authorization server URL for this
// deployment. Returns empty string for modes where the OAuth routes are not
// mounted — advertising an authorization_server that has no endpoints confuses
// OAuth clients that discover the metadata before trying to authenticate.
func selectAuthServer(cfg *config.Config) string {
	switch strings.ToLower(cfg.AuthMode) {
	case "local-jwt":
		return strings.TrimRight(cfg.PublicBaseURL, "/")
	case "shared-hmac", "shared-hmac-legacy":
		return "https://api.mctl.ai"
	default: // local-dev: OAuth routes are not mounted
		return ""
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
// Called only when AUTH_MODE=local-jwt. Returns the constructed *oauth.Server
// so the caller can pass it to web.NewConnectServer.
func registerOAuth(ctx context.Context, cfg *config.Config, store *db.Store, mux *chi.Mux, m *metrics.Registry) (*oauth.Server, error) {
	if cfg.OAUTHJWTSecret == "" {
		return nil, fmt.Errorf("OAUTH_JWT_SIGNING_KEY is required when AUTH_MODE=local-jwt")
	}
	if cfg.TelegramOIDCClientID == "" {
		return nil, fmt.Errorf("TELEGRAM_OIDC_CLIENT_ID is required when AUTH_MODE=local-jwt")
	}
	if cfg.TelegramOIDCClientSecret == "" {
		return nil, fmt.Errorf("TELEGRAM_OIDC_CLIENT_SECRET is required when AUTH_MODE=local-jwt")
	}
	admins := map[int64]bool{}
	for _, id := range cfg.TGLoginAdmins {
		admins[id] = true
	}
	clients := map[int64]bool{}
	for _, id := range cfg.TGLoginClients {
		clients[id] = true
	}
	// oauth.New performs OIDC discovery against Telegram — a network call at
	// boot. It is fail-closed: a discovery failure aborts startup rather than
	// running a server that cannot authenticate anyone.
	useDBForOAuth := strings.HasPrefix(cfg.DatabaseURL, "postgres://") ||
		strings.HasPrefix(cfg.DatabaseURL, "postgresql://")
	srv, err := oauth.New(ctx, oauth.Config{
		Issuer:                   strings.TrimRight(cfg.PublicBaseURL, "/"),
		JWTSecret:                []byte(cfg.OAUTHJWTSecret),
		JWTAudience:              cfg.OAUTHJWTAudience,
		TelegramOIDCClientID:     cfg.TelegramOIDCClientID,
		TelegramOIDCClientSecret: cfg.TelegramOIDCClientSecret,
		TelegramOIDCIssuerURL:    cfg.TelegramOIDCIssuerURL,
		TelegramOIDCRedirectURL:  cfg.TelegramOIDCRedirectURL,
		TelegramOIDCSigningAlgs:  cfg.TelegramOIDCSigningAlgs,
		AdminTelegramIDs:         admins,
		ClientTelegramIDs:        clients,
		AutoApproveClients:       cfg.AutoApproveClients,
		AccessTokenTTL:           cfg.OAUTHAccessTokenTTL,
		RefreshTokenTTL:          cfg.OAUTHRefreshTokenTTL,
		CodeTTL:                  cfg.OAUTHCodeTTL,
		AllowImplicitClient:      cfg.OAUTHAllowImplicitClient,
		TGAPIID:                  cfg.TGAPIID,
		TGAPIHash:                cfg.TGAPIHash,
		UseDBForOAuth:            useDBForOAuth,
	}, store)
	if err != nil {
		return nil, err
	}
	srv.WithMetrics(m)
	srv.Register(mux)
	// ctx.Done() is a <-chan struct{} — the sweeper exits on shutdown.
	srv.StartSweeper(ctx.Done(), 1*time.Minute)
	// Once-a-day Telegram digest of new clients — keeps the operator informed
	// while onboarding stays hands-off. Recipients are the admin allowlist;
	// the goroutine exits with ctx. The bot token is no longer load-bearing
	// for authentication (OIDC replaced the widget), so an unset token only
	// disables the digest rather than failing startup.
	if cfg.TelegramLoginBotToken == "" {
		slog.Warn("TELEGRAM_LOGIN_BOT_TOKEN unset — the daily new-client digest will not be delivered")
	}
	digest.StartDailyDigest(ctx, store, cfg.TelegramLoginBotToken, cfg.TGLoginAdmins, cfg.DigestHourUTC, cfg.AutoApproveClients)
	slog.Info("oauth issuer enabled",
		"issuer", cfg.PublicBaseURL,
		"oidc_issuer", cfg.TelegramOIDCIssuerURL,
		"oidc_client_id", cfg.TelegramOIDCClientID,
		"admin_count", len(admins),
		"client_count", len(clients),
		"auto_approve_clients", cfg.AutoApproveClients,
		"implicit_clients", cfg.OAUTHAllowImplicitClient,
	)
	return srv, nil
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
//
// Fail-closed posture: when AUTH_MODE expects a JWT but OAUTH_JWT_SECRET is
// missing, we DO NOT fall back to localdev — that would let an unauthenticated
// remote client register a bridge daemon as the fixed operator account in
// `local` mode. Instead we return rejectAllProvider so every /bridge request
// gets 401 and the operator sees the misconfiguration loudly. localdev
// fallback is reserved for AUTH_MODE=local-dev (developer-only).
func selectBridgeProvider(cfg *config.Config, store *db.Store) auth.Provider {
	mode := strings.ToLower(cfg.AuthMode)
	switch mode {
	case "local-jwt":
		if cfg.OAUTHJWTSecret == "" {
			slog.Error("bridge: OAUTH_JWT_SECRET not set in local-jwt mode; /bridge will fail closed")
			return rejectAllProvider("bridge auth: OAUTH_JWT_SECRET not configured")
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
			slog.Error("bridge: OAUTH_JWT_SECRET not set in shared-hmac mode; /bridge will fail closed")
			return rejectAllProvider("bridge auth: OAUTH_JWT_SECRET not configured")
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
		// AUTH_MODE=local-dev. Unknown modes are rejected earlier by
		// selectProvider, so this branch only runs in developer-bypass mode.
		// Using localdev on /bridge as well keeps the local CLI workflow
		// functional without re-introducing a production fail-open.
		return localdev.New(store, cfg.OperatorLogin)
	}
}

// rejectAllProvider returns an auth.Provider that fails every request with a
// fixed error. Used as the fail-closed fallback when a deployment requests
// JWT-based auth but never supplied a signing secret — better to lock the
// endpoint than to silently downgrade to a developer-bypass identity.
func rejectAllProvider(reason string) auth.Provider {
	return rejectProvider{reason: reason}
}

type rejectProvider struct{ reason string }

func (p rejectProvider) Authenticate(_ *http.Request) (*auth.Identity, error) {
	return nil, errors.New(p.reason)
}

// protectedResource serves the RFC 9728 OAuth Protected Resource Metadata so
// claude.ai's connector knows which authorization server to talk to. In the
// Telegram-native local-jwt mode this is the same service (PublicBaseURL);
// in shared-hmac-legacy mode it stays pointed at api.mctl.ai; in local-dev
// mode authServer is empty and the authorization_servers array is omitted so
// OAuth clients do not discover endpoints that are not mounted.
func protectedResource(cfg *config.Config, authServer string) http.HandlerFunc {
	var authServersJSON string
	if authServer != "" {
		authServersJSON = fmt.Sprintf("[%q]", authServer)
	} else {
		authServersJSON = "[]"
	}
	body := []byte(fmt.Sprintf(
		`{"resource":%q,"authorization_servers":%s,"scopes_supported":["mctl","telegram:dialogs:read","telegram:messages:read","telegram:messages:send","telegram:messages:pin","admin:users"]}`,
		cfg.PublicBaseURL,
		authServersJSON,
	))
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
