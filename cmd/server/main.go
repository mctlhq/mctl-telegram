package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gotd/contrib/middleware/ratelimit"
	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/mctlhq/mctl-telegram/internal/agent/control"
	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/agent/listener"
	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/agent/queue"
	"github.com/mctlhq/mctl-telegram/internal/agentapi"
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
	"github.com/mctlhq/mctl-telegram/internal/netctx"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/sweeper"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"github.com/mctlhq/mctl-telegram/internal/web"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
)

// version is set via -ldflags "-X main.version=..." at build time (see
// Dockerfile), matching every other binary in this repo.
var version = "dev"

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
		"allowed_origins", cfg.AllowedOrigins,
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
	if err := db.Migrate(ctx, rawDB, cfg.SessionTTLExemptTGIDs...); err != nil {
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

	store := db.NewStore(rawDB, cryp).WithMetrics(m).
		WithAbsoluteTTLExempt(cfg.SessionTTLExemptTGIDs)
	// Runs after Migrate on purpose. Migrate owns the re-arm direction — an
	// identity dropped from the list is no longer excluded from its backfill,
	// so it gets its deadline back — while this clears the deadline for rows
	// that are newly exempt. Only ever widening a lifetime here, so unlike the
	// backfill it cannot expose an already-past deadline to another replica.
	if cleared, err := store.ReconcileTTLExemptions(ctx); err != nil {
		slog.Error("reconcile session ttl exemptions", "err", err)
		os.Exit(1)
	} else if cleared > 0 {
		slog.Info("session ttl exemptions applied",
			"rows_cleared", cleared, "identities", len(cfg.SessionTTLExemptTGIDs))
	}
	agentQueue := queue.New(store, cfg.ReplicaID, m)
	agentListener := listener.New(store, agentQueue, nil, m)
	limiter := audit.NewRateLimiter(cfg.RateLimitPerUser).WithMetrics(m)
	peerCache := telegram.NewPeerCache()
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				peerCache.Sweep()
			}
		}
	}()

	// api_id-wide MTProto rate limiter. One instance shared by the pool and the
	// interactive login client (via oauth.WithLoginConfig) so all sessions —
	// across every user account — throttle against one TG_API_ID budget. This
	// caps the aggregate that could otherwise get the shared app credentials
	// flood-banned. nil (TG_API_RATE_PER_SEC<=0) leaves throughput unchanged.
	var globalTGLimiter gotdtelegram.Middleware
	if cfg.TGAPIRatePerSec > 0 {
		burst := cfg.TGAPIRateBurst
		if burst <= 0 {
			burst = int(math.Ceil(cfg.TGAPIRatePerSec))
		}
		if burst < 1 {
			burst = 1
		}
		globalTGLimiter = ratelimit.New(rate.Limit(cfg.TGAPIRatePerSec), burst)
		slog.Info("api_id-wide MTProto rate limit configured",
			"rate_per_sec", cfg.TGAPIRatePerSec, "burst", burst)
	}

	pool := telegram.NewClientPool(cfg.TGAPIID, cfg.TGAPIHash, cfg.IdleClientTimeout, store).
		WithMaxSessions(cfg.TelegramMaxSessions).
		WithGlobalMiddleware(globalTGLimiter).
		WithMetrics(m).
		WithAgentRuntime(agentListener)
	defer pool.Shutdown()

	// Communication-agent control plane: the executor sends approved replies
	// (crash-safely — see internal/agent/executor's package doc), the
	// notifier delivers summaries/approval requests to Saved Messages, and
	// the router turns the owner's /mctl commands into calls on both. Built
	// here (not above, alongside agentListener) because all three need
	// `pool` to actually reach Telegram — hence agentListener.Router is
	// assigned after construction rather than passed into listener.New.
	// This MUST happen before go listener.RunSupervisor below: the
	// supervisor goroutine reads agentListener.Router the moment an update
	// dispatches, so assigning it after the goroutine starts is a data race
	// (and a window where an early Saved Messages command silently no-ops
	// against a nil router).
	// Read at call time by both the executor and the notifier — never a
	// snapshot — so a redeploy that flips AGENT_KILL_SWITCH takes effect on
	// the very next send/delivery attempt of an already-running process, not
	// just newly-started ones.
	agentGlobalKill := func() bool { return cfg.AgentKillSwitch }
	agentExecutor := executor.New(store, &poolSender{pool: pool, store: store, peerCache: peerCache}, agentGlobalKill, m)
	agentExecutor.CrashAfterReserve = cfg.AgentTestCrashAfterReserve
	if cfg.AgentTestCrashAfterReserve {
		slog.Warn("communication agent TEST-ONLY crash-after-reserve fault injection is ENABLED — every send on this pod will hard-exit before reaching Telegram; must only be set for a deliberate drill window")
	}
	demoReviewerTGID := int64(0)
	if cfg.DemoReviewerEnabled {
		demoReviewerTGID = cfg.DemoReviewerTGID
	}
	executorGate := &agentSendGate{
		store:              store,
		allowSend:          cfg.AllowSend,
		demoReviewerTGID:   demoReviewerTGID,
		adminTelegramIDs:   telegramIDSet(cfg.TGLoginAdmins),
		clientTelegramIDs:  telegramIDSet(cfg.TGLoginClients),
		autoApproveClients: cfg.AutoApproveClients,
		limiter:            limiter,
	}
	agentExecutor.SendGate = executorGate.Allow
	// A Codex finding on #307 caught that Approve() had no TTL check of its
	// own: the bulk ExpireStaleAgentActions sweeper runs on its own
	// minute-scale interval, so an owner could still approve a code already
	// past AGENT_APPROVAL_TTL if the sweeper simply hadn't reached it yet.
	agentExecutor.ApprovalTTL = cfg.AgentApprovalTTL
	agentNotifier := control.NewNotifier(store, &poolSelfSender{pool: pool})
	agentNotifier.GlobalKill = agentGlobalKill
	// Wire the notification retry horizon to the SAME configured approval
	// TTL the executor/sweeper use (cfg.AgentApprovalTTL), not the
	// constructor's own 24h default — a Codex finding on #307 caught that
	// with AGENT_APPROVAL_TTL configured above 24h, an approval notification
	// could be retired as permanently failed while its linked action was
	// still genuinely approvable, so the owner would never receive a code
	// that was still live.
	if cfg.AgentApprovalTTL > 0 {
		agentNotifier.MaxPendingAge = cfg.AgentApprovalTTL
	}
	agentListener.Router = control.NewRouter(store, agentExecutor, agentNotifier)

	// Runtime profile reads are always tenant-scoped and DB-backed. Missing
	// documents are allowed (the worker endpoint returns 404 and the
	// restricted-field check has nothing to enforce), while malformed or
	// undecryptable stored documents fail closed before a send.
	agentProfileProvider := profile.NewTenantProvider(store)
	agentExecutor.Profile = agentProfileProvider

	// AGENT_PROFILE_PATH is a backwards-compatible one-time import only. It
	// populates the configured account's encrypted DB document if missing and
	// never overwrites an admin-managed profile. The mounted file is no longer
	// a process-wide runtime source of truth.
	if path := cfg.AgentProfilePath; path != "" {
		legacyProvider, err := profile.Load(path)
		if err != nil {
			slog.Error("agent profile load failed; refusing to start", "path", path, "err", err)
			os.Exit(1)
		}
		userID, err := store.UserIDByTelegramID(ctx, cfg.AgentProfileOwnerTGID)
		if err != nil {
			slog.Error("legacy agent profile owner resolution failed; refusing to start",
				"path", path, "telegram_id", cfg.AgentProfileOwnerTGID, "err", err)
			os.Exit(1)
		}
		if err := store.EnsureAgentProfile(ctx, userID); err != nil {
			slog.Error("legacy agent profile row initialization failed; refusing to start",
				"path", path, "user_id", userID, "err", err)
			os.Exit(1)
		}
		document, err := legacyProvider.CanonicalJSON()
		if err != nil {
			slog.Error("legacy agent profile serialization failed; refusing to start", "path", path, "err", err)
			os.Exit(1)
		}
		imported, err := store.SetAgentOwnerProfileIfMissing(ctx, userID, document)
		if err != nil {
			slog.Error("legacy agent profile import failed; refusing to start", "path", path, "user_id", userID, "err", err)
			os.Exit(1)
		}
		slog.Info("legacy agent owner profile migration checked",
			"path", path, "user_id", userID, "imported", imported)
	}

	go listener.RunSupervisor(ctx, agentListener, pool, listener.StoreResolver{Store: store}, 15*time.Second)

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
	// Communication-agent message retention: deletes stored incoming_events /
	// conversation_messages older than AGENT_RETENTION_DAYS (default 30).
	// Privacy control, not just hygiene — these rows carry third-party
	// message content. AGENT_RETENTION_DAYS=0 keeps rows forever.
	go sweeper.AgentRetention(ctx, store, time.Duration(cfg.AgentRetentionDays)*24*time.Hour)
	// Communication-agent queue maintenance: requeues jobs whose claim
	// outlived AGENT_JOB_VISIBILITY (worker crash recovery) and expires
	// pending approvals past AGENT_APPROVAL_TTL. No-op on empty tables.
	go sweeper.AgentJobs(ctx, agentQueue, cfg.AgentJobVisibility, cfg.AgentApprovalTTL)
	// Communication-agent executor: retries sends stuck in `executing` past
	// their grace window (crash recovery) and sends guarded-mode actions
	// that landed as `approved` with no owner to type /mctl approve.
	go sweeper.AgentExecutor(ctx, agentExecutor)
	// Communication-agent notifier: delivers pending owner_notifications
	// (summaries, approval requests) to Saved Messages.
	go sweeper.AgentNotifier(ctx, agentNotifier)
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
	// /telegram/connect/manage is only mounted below in local-jwt mode; every
	// chrome-rendered page needs to know this up front so it can hide the
	// "manage" nav/footer link rather than link to a 404 in shared-hmac mode.
	showManage := strings.EqualFold(cfg.AuthMode, "local-jwt")
	resourceMeta := auth.ResourceMetadata{BaseURL: cfg.PublicBaseURL, MCPPath: cfg.MCPPath}

	mux.Get("/healthz", healthz)
	mux.Get("/readyz", healthz)
	mux.Get("/metrics", metricsHandler(m, cfg.MetricsAllowCIDR))
	prmHandler := protectedResource(cfg, authServer)
	mux.Get("/.well-known/oauth-protected-resource", prmHandler)
	mux.Get("/.well-known/oauth-protected-resource"+cfg.MCPPath, prmHandler)
	mux.Get("/.well-known/openai-apps-challenge", web.OpenAIAppsChallenge())
	mux.Get("/favicon.svg", web.Favicon())
	mux.Get("/favicon.ico", web.Favicon())
	mux.Get("/og.png", web.OGImage())
	mux.Get("/", web.Landing(cfg.PublicBaseURL, cfg.MCPPath, authServer, showManage))
	mux.Get("/security", web.Security(cfg.PublicBaseURL, showManage))
	mux.Get("/privacy", web.Privacy(cfg.PublicBaseURL, showManage))
	mux.Get("/terms", web.Terms(cfg.PublicBaseURL, showManage))
	mux.Get("/demo", web.Demo(cfg.PublicBaseURL, cfg.DemoVideoURL, showManage))
	mux.Get("/demo/walkthrough.mp4", web.DemoWalkthrough())
	mux.Get("/docs", web.Docs(cfg.PublicBaseURL, cfg.MCPPath, authServer, showManage))

	// Wire the OAuth issuer when we're running in local-jwt mode. This adds
	// /oauth/authorize, /oauth/telegram/callback, /oauth/token,
	// /oauth/revoke, /oauth/register, and
	// /.well-known/oauth-authorization-server. The shared-hmac-legacy path
	// leaves these unmounted — Claude.ai then talks to api.mctl.ai as before.
	if strings.EqualFold(cfg.AuthMode, "local-jwt") {
		oauthSrv, err := registerOAuth(ctx, cfg, store, mux, m)
		if err != nil {
			slog.Error("oauth init failed; refusing to start", "err", err)
			os.Exit(1)
		}
		// Share the api_id-wide limiter with the interactive login client so a
		// first-time connect (auth.sendCode) — the most flood-sensitive call on
		// the shared TG_API_ID — throttles against the same budget as the pool.
		oauthSrv.WithLoginConfig(telegram.LoginConfig{GlobalMiddleware: globalTGLimiter})
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
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).
			Get("/telegram/connect/manage", manageSrv.HandleManage)
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).
			Post("/telegram/connect/manage/disconnect", manageSrv.HandleDisconnect)
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).
			Post("/telegram/connect/manage/toggle-send", manageSrv.HandleToggleSend)
	}

	// Account endpoints — self-service disconnect/delete + status.
	// Mounted behind the same auth middleware as MCP so anon traffic gets 401.
	accountMux := chi.NewRouter()
	accountHandlers := web.NewAccountHandlers(store, pool)
	accountHandlers.Register(accountMux)
	mux.Mount("/api/account", auth.Middleware(provider, true, m, resourceMeta)(accountMux))

	mcpSrv := mcpapp.New(store, pool, cfg.AllowSend).WithVersion(version).WithLimiter(limiter).WithMetrics(m).WithPeerCache(peerCache).WithToolFilter(cfg.ToolFilter)
	mcpSrv.MediaDownloadMaxBytes = cfg.MediaDownloadMaxBytes
	mcpSrv.MediaUploadMaxBytes = cfg.MediaUploadMaxBytes
	// Force the reviewer/demo account's sends to dry-run previews. Only armed
	// when reviewer mode is enabled, so a leftover DEMO_REVIEWER_TG_ID cannot
	// silently gag a real account once the review feature is turned off.
	if cfg.DemoReviewerEnabled {
		mcpSrv = mcpSrv.WithDemoReviewer(cfg.DemoReviewerTGID)
	}

	// Bridge token endpoint: authenticated users exchange their MCP JWT for
	// a short-lived bridge JWT (aud=bridge, 1h TTL) that the local daemon
	// uses to register its websocket connection at GET /bridge.
	//
	// Issuer parity matters here: bridge token iss MUST match what
	// selectBridgeProvider configures as ExpectedIssuer, or every minted
	// token would be rejected at /bridge. selectBridgeIssuer maps the same
	// AUTH_MODE switch as selectBridgeProvider.
	if secret := cfg.OAUTHJWTSecret; secret != "" {
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).Post("/api/bridge/token",
			bridge.NewBridgeTokenHandler(provider, []byte(secret), selectBridgeIssuer(cfg)))
	}

	// Read-only MCP worker token endpoint: an admin mints a bounded,
	// read-only-scoped bearer token (aud=mcp-worker-ro) for a headless MCP
	// worker such as the canary. Unlike the agent/bridge pair above, the
	// minted token is verified by the same plain MCP `provider` already
	// mounted at /mcp (see internal/workertoken.NewHandler's doc comment for
	// why no dedicated auth.Provider is needed) — it just carries a
	// restricted scope set and a bounded TTL, with per-tool requireScope
	// enforcement doing the rest. Gated on OAUTH_JWT_SECRET like the two
	// mints above; reuses selectAgentIssuer since it already computes "the
	// issuer this deployment's locally-issued JWTs use" with no dependency
	// on the agent feature despite the name.
	if secret := cfg.OAUTHJWTSecret; secret != "" {
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).Post("/api/mcp/worker-token",
			workertoken.NewHandler([]byte(secret), selectAgentIssuer(cfg), cfg.OAUTHJWTAudience))
	}

	// Websocket bridge endpoint: Local Bridge daemons connect here.
	// Uses a separate provider that enforces aud=bridge so regular MCP
	// tokens cannot be used to hijack the bridge channel.
	hub := bridge.NewHub().WithMetrics(m)
	bridgeProvider := selectBridgeProvider(cfg, store)
	mux.Get("/bridge", bridge.NewBridgeHandler(hub, bridgeProvider, store, ctx))

	// Communication-agent HTTP surface: off by default like every other
	// agent PR (AGENT_ENABLED). Two auth boundaries, same shape as the
	// bridge pair above: an admin-scoped mint endpoint under the regular MCP
	// provider, and the agent surface itself under a provider that only
	// accepts aud=agent tokens.
	if cfg.AgentEnabled {
		if secret := cfg.OAUTHJWTSecret; secret != "" {
			mux.With(auth.Middleware(provider, true, m, resourceMeta)).Post("/api/agent/token",
				agentapi.NewAgentTokenHandler([]byte(secret), selectAgentIssuer(cfg)))
		}
		// Admin-scoped agent_profiles management. Same provider/scope as the
		// token mint above — an agent worker's own aud=agent token must never
		// reach this route. Previously the only way to create or change this
		// row was a direct SQL insert; this is the managed opt-in path an
		// operator uses for enable/disable, test-account rotation, and future
		// production onboarding.
		mux.With(auth.Middleware(provider, true, m, resourceMeta)).Put("/api/admin/agent/profile",
			agentapi.NewAdminAgentProfileHandler(store))
		agentProvider := selectAgentProvider(cfg, store)
		agentSrv := agentapi.New(store, agentQueue, cfg.AgentJobVisibility, m)
		agentSrv.GlobalKill = cfg.AgentKillSwitch
		agentSrv.AllowLegacyJobCompletion = cfg.AgentAllowLegacyCompletion
		agentSrv.WithProfile(agentProfileProvider)
		agentMux := chi.NewRouter()
		agentSrv.Register(agentMux)
		mux.Mount("/api/agent/v1", auth.Middleware(agentProvider, true, m, resourceMeta)(agentMux))
		slog.Info("communication agent HTTP surface enabled", "path", "/api/agent/v1", "kill_switch", cfg.AgentKillSwitch)
	}

	// Wire the hub into the MCP server so tool calls for local-mode users
	// are forwarded to their daemon instead of the hosted MTProto pool.
	mcpSrv = mcpSrv.WithHub(hub)

	// Browser-GET to MCP_PATH is bounced to the landing page BEFORE auth
	// runs, so unauthenticated humans still see instructions instead of
	// a 401. MCP clients (Accept: application/json, text/event-stream)
	// fall through and hit the full auth+ratelimit+MCP chain.
	mcpHandler := auth.Middleware(provider, cfg.AuthRequired, m, resourceMeta)(
		limiter.Middleware()(mcpSrv.HTTPHandler()),
	)
	// OriginGuard runs before auth: a present browser Origin must be on the
	// allowlist (DNS-rebinding protection); no-Origin server-to-server clients
	// pass through. BrowserRedirect stays outermost so human GETs still land on
	// the instructions page.
	guarded := web.OriginGuard(mcpHandler, cfg.AllowedOrigins)
	mux.Mount(cfg.MCPPath, web.BrowserRedirect(guarded, "/"))

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		// ConnContext stores the TCP peer address in the request context before
		// any middleware runs. metricsHandler reads socketPeerKey to enforce the
		// CIDR allowlist against the real socket address — not the r.RemoteAddr
		// value that middleware.RealIP rewrites from X-Forwarded-For headers.
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return netctx.WithPeer(ctx, c.RemoteAddr().String())
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
		rawAddr := netctx.Peer(r.Context())
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
		AllowedImplicitHosts:     cfg.OAUTHAllowedImplicitHosts,
		TGAPIID:                  cfg.TGAPIID,
		TGAPIHash:                cfg.TGAPIHash,
		UseDBForOAuth:            useDBForOAuth,
		DemoReviewerEnabled:      cfg.DemoReviewerEnabled,
		DemoReviewerUsername:     cfg.DemoReviewerUsername,
		DemoReviewerPassword:     cfg.DemoReviewerPassword,
		DemoReviewerTGID:         cfg.DemoReviewerTGID,
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
		"demo_reviewer", cfg.DemoReviewerEnabled,
	)
	if cfg.DemoReviewerEnabled {
		slog.Warn("DEMO_REVIEWER_ENABLED is on — /oauth/authorize exposes a password-gated reviewer login; disable after the review",
			"demo_tg_id", cfg.DemoReviewerTGID)
	}
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

// selectAgentIssuer returns the iss value for tokens minted at POST
// /api/agent/token. Mirrors selectBridgeIssuer — must stay in lockstep with
// selectAgentProvider's ExpectedIssuer or every minted agent token is
// rejected as "unexpected JWT issuer".
func selectAgentIssuer(cfg *config.Config) string {
	switch strings.ToLower(cfg.AuthMode) {
	case "shared-hmac", "shared-hmac-legacy":
		return "https://api.mctl.ai"
	default:
		return strings.TrimRight(cfg.PublicBaseURL, "/")
	}
}

// selectAgentProvider builds an auth.Provider for /api/agent/v1/*. Behaves
// like selectBridgeProvider but enforces ExpectedAudience="agent" so only
// tokens issued by NewAgentTokenHandler are accepted — a bridge token or a
// regular MCP token must not authenticate against the agent surface, and
// vice versa. Same fail-closed posture as selectBridgeProvider: a JWT-based
// AUTH_MODE with no signing secret returns rejectAllProvider rather than
// silently downgrading to localdev.
func selectAgentProvider(cfg *config.Config, store *db.Store) auth.Provider {
	mode := strings.ToLower(cfg.AuthMode)
	switch mode {
	case "local-jwt":
		if cfg.OAUTHJWTSecret == "" {
			slog.Error("agent: OAUTH_JWT_SECRET not set in local-jwt mode; /api/agent/v1 will fail closed")
			return rejectAllProvider("agent auth: OAUTH_JWT_SECRET not configured")
		}
		p, err := localjwt.NewProvider(store, localjwt.ProviderConfig{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   strings.TrimRight(cfg.PublicBaseURL, "/"),
			ExpectedAudience: "agent",
			AudienceRequired: true,
		})
		if err != nil {
			slog.Error("agent: local-jwt init failed; agent endpoint disabled", "err", err)
			os.Exit(1)
		}
		return p
	case "shared-hmac", "shared-hmac-legacy":
		if cfg.OAUTHJWTSecret == "" {
			slog.Error("agent: OAUTH_JWT_SECRET not set in shared-hmac mode; /api/agent/v1 will fail closed")
			return rejectAllProvider("agent auth: OAUTH_JWT_SECRET not configured")
		}
		p, err := sharedhmac.New(store, sharedhmac.Config{
			Secret:           []byte(cfg.OAUTHJWTSecret),
			ExpectedIssuer:   "https://api.mctl.ai",
			ExpectedAudience: "agent",
			AudienceRequired: true,
		})
		if err != nil {
			slog.Error("agent: shared-hmac init failed; agent endpoint disabled", "err", err)
			os.Exit(1)
		}
		return p
	default:
		// AUTH_MODE=local-dev. Same developer-bypass rationale as
		// selectBridgeProvider.
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

type protectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// protectedResource serves the RFC 9728 OAuth Protected Resource Metadata so
// claude.ai's connector knows which authorization server to talk to. In the
// Telegram-native local-jwt mode this is the same service (PublicBaseURL);
// in shared-hmac-legacy mode it stays pointed at api.mctl.ai; in local-dev
// mode authServer is empty and the authorization_servers array is omitted so
// OAuth clients do not discover endpoints that are not mounted.
//
// Registered at both /.well-known/oauth-protected-resource and its
// cfg.MCPPath-suffixed alias — the "resource" field reflects which was
// requested, mirroring the resource_metadata hint set by
// auth.Middleware/auth.ResourceMetadata. scopes_supported is
// oauth.DCRNegotiableScopes, identical to what
// handleAuthorizationServerMetadata advertises: it excludes "mctl" (never
// granted by ResolveScopes) and "admin:users" (implicit-privileged, not
// DCR-negotiable) per that handler's documented rationale.
func protectedResource(cfg *config.Config, authServer string) http.HandlerFunc {
	var authServers []string
	if authServer != "" {
		authServers = []string{authServer}
	}
	base := strings.TrimRight(cfg.PublicBaseURL, "/")
	mcpAlias := "/.well-known/oauth-protected-resource" + cfg.MCPPath
	return func(w http.ResponseWriter, r *http.Request) {
		resource := base
		if r.URL.Path == mcpAlias {
			resource = base + cfg.MCPPath
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(protectedResourceMetadata{
			Resource:             resource,
			AuthorizationServers: authServers,
			ScopesSupported:      oauth.DCRNegotiableScopes,
		})
	}
}
