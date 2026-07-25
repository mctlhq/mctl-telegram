package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr          string
	PublicBaseURL string
	MCPPath       string
	// AllowedOrigins is the Origin-header allowlist for the /mcp endpoint
	// (DNS-rebinding protection). Requests with no Origin header are always
	// allowed — server-to-server MCP clients (claude.ai, MCP Inspector, curl)
	// send none, and an over-strict check would break them. A present Origin
	// must match one of these entries (scheme://host[:port]) or the request is
	// rejected with 403. Set via ALLOWED_ORIGINS (comma-separated); defaults to
	// the PUBLIC_BASE_URL origin.
	AllowedOrigins     []string
	AuthMode           string
	AuthRequired       bool
	OperatorLogin      string
	DatabaseURL        string
	OAUTHJWTSecret     string // HS256 signing key; see OAUTH_JWT_SIGNING_KEY
	OAUTHJWTAudience   string // expected `aud` claim; empty disables the check
	OAUTHJWTAudReq     bool   // when true, tokens without aud are rejected
	TGAPIID            int
	TGAPIHash          string
	EncryptionKey      []byte
	AllowSend          bool
	IdleClientTimeout  time.Duration
	RateLimitPerUser   int
	AuditRetentionDays int
	LogLevel           string
	// Telegram-native OAuth (local-jwt mode):
	TelegramLoginBotToken string  // bot token used to send the daily new-client digest
	TGLoginAdmins         []int64 // allowlist of Telegram ids granted platform-admins scopes
	TGLoginClients        []int64 // allowlist of Telegram ids granted telegram:* scopes (no admin:users)
	// Telegram OpenID Connect (Relying Party — replaces the legacy widget):
	TelegramOIDCClientID     string   // OIDC client id = the login bot's numeric id; not secret
	TelegramOIDCClientSecret string   // OIDC client secret from BotFather; sourced from Vault
	TelegramOIDCIssuerURL    string   // OIDC issuer; default https://oauth.telegram.org
	TelegramOIDCRedirectURL  string   // OIDC callback URL; empty → derived from PublicBaseURL
	TelegramOIDCSigningAlgs  []string // accepted id_token signing algs; empty → RS256
	OAUTHCodeTTL             time.Duration
	OAUTHAccessTokenTTL      time.Duration
	OAUTHRefreshTokenTTL     time.Duration // absolute lifetime of an issued refresh token
	OAUTHAllowImplicitClient bool          // accept unregistered client_ids (eases Claude.ai onboarding)
	AutoApproveClients       bool          // open registration: every widget login auto-gets the client tier
	DigestHourUTC            int           // UTC hour (0-23) for the daily new-client digest; default 9
	// Observability:
	// MetricsAllowCIDR restricts /metrics to requests whose remote IP falls
	// within the given CIDR (e.g. "10.0.0.0/8"). When empty the endpoint is
	// open without authentication — suitable for Kubernetes PodMonitor scrape
	// patterns where network policy provides the access control.
	MetricsAllowCIDR string // METRICS_ALLOW_CIDR, optional
	// TelegramMaxSessions caps the number of concurrently live MTProto client
	// pool entries. 0 means no cap (default). Set via TELEGRAM_MAX_SESSIONS.
	TelegramMaxSessions int // TELEGRAM_MAX_SESSIONS, 0 = no cap
	// TGAPIRatePerSec is the api_id-wide MTProto RPC ceiling shared across every
	// live client (the pool plus the short-lived login client), expressed in
	// requests per second. All sessions authenticate under one TG_API_ID, so a
	// burst across many user accounts can get the *app credentials* flood-banned
	// even though each account's own per-account budget is fine. This bounds the
	// aggregate. 0 (default) disables the limiter — non-breaking. Set via
	// TG_API_RATE_PER_SEC.
	TGAPIRatePerSec float64
	// TGAPIRateBurst is the token-bucket burst size for the api_id-wide limiter.
	// Ignored when TGAPIRatePerSec <= 0. 0 falls back to ceil(TGAPIRatePerSec)
	// (at least 1). Set via TG_API_RATE_BURST.
	TGAPIRateBurst int
	// DBMaxOpenConns caps the Postgres connection pool. 0 means keep the
	// prior default of 10. Set via DB_MAX_OPEN_CONNS.
	DBMaxOpenConns int
	// DBMaxIdleConns sets the Postgres idle connection count. 0 means keep
	// the prior default of 2. Set via DB_MAX_IDLE_CONNS.
	DBMaxIdleConns int
	// ReplicaID identifies this pod for observability. Sourced from
	// REPLICA_ID env var; falls back to POD_NAME; falls back to "unknown".
	ReplicaID string
	// DemoVideoURL is the walkthrough video shown on the public /demo page
	// (for the ChatGPT App Directory review). Empty → the page renders a
	// "coming soon" placeholder. Accepts a YouTube/Loom share URL or a direct
	// .mp4/.webm URL; see internal/web.classifyDemoVideo. Set via
	// DEMO_VIDEO_URL.
	DemoVideoURL string
	// Reviewer/demo auth-mode for the ChatGPT App Directory review. When
	// DemoReviewerEnabled is true the /oauth/authorize page offers a
	// password-gated "reviewer access" path that authenticates as a single
	// pre-provisioned demo Telegram identity, bypassing the live Telegram
	// OIDC login (no phone/SMS). The demo account is expected to be a
	// throwaway with a pre-seeded MTProto session and send_enabled=false so
	// every send stays a dry-run preview. Off by default; enabled only during
	// review and disabled again after approval. See internal/oauth.
	DemoReviewerEnabled  bool   // DEMO_REVIEWER_ENABLED
	DemoReviewerUsername string // DEMO_REVIEWER_USERNAME
	DemoReviewerPassword string // DEMO_REVIEWER_PASSWORD; compared in constant time, never logged
	DemoReviewerTGID     int64  // DEMO_REVIEWER_TG_ID; numeric Telegram id of the demo account
	// ToolFilter restricts which MCP tools are registered at startup.
	// "all" (default) registers every tool; "read-only" registers only tools
	// annotated with ReadOnlyHint=true. Set via MCP_TOOL_FILTER.
	ToolFilter string // MCP_TOOL_FILTER
	// MediaDownloadMaxBytes caps get_media downloads. 0 means no cap (use with
	// care). Default 20 MiB. Set via MEDIA_DOWNLOAD_MAX_BYTES.
	MediaDownloadMaxBytes int64 // MEDIA_DOWNLOAD_MAX_BYTES
	// MediaUploadMaxBytes caps send_media uploads (both the file_url fetch and
	// the file_base64 decode). 0 means no cap (use with care). Default 20 MiB,
	// independently configurable from MediaDownloadMaxBytes since upload and
	// download are different trust/cost boundaries. Set via
	// MEDIA_UPLOAD_MAX_BYTES.
	MediaUploadMaxBytes int64 // MEDIA_UPLOAD_MAX_BYTES
	// AgentRetentionDays bounds how long the communication agent's stored
	// message content (incoming_events, conversation_messages) is kept before
	// the retention sweeper deletes it. Unlike audit rows this is third-party
	// message content, so the default is deliberately short. 0 keeps rows
	// forever. Set via AGENT_RETENTION_DAYS.
	AgentRetentionDays int // AGENT_RETENTION_DAYS, default 30
	// AgentJobVisibility is how long a claimed (processing) agent job may sit
	// before the sweeper assumes the worker died and requeues it. Must exceed
	// the worst-case model round-trip for one job. Set via AGENT_JOB_VISIBILITY.
	AgentJobVisibility time.Duration // AGENT_JOB_VISIBILITY, default 5m
	// AgentApprovalTTL is how long an agent action waits in pending_approval
	// before expiring. Set via AGENT_APPROVAL_TTL.
	AgentApprovalTTL time.Duration // AGENT_APPROVAL_TTL, default 24h
	// AgentEnabled gates whether the agent-facing HTTP surface (/api/agent/v1,
	// POST /api/agent/token) is mounted at all. Off by default like every other
	// communication-agent PR — the underlying tables/queue/listener can be
	// present in a deployment without exposing the surface an external worker
	// talks to. Set via AGENT_ENABLED.
	AgentEnabled bool
	// AgentKillSwitch is the global, env-only kill switch the policy engine
	// checks on every evaluated action. Deliberately not a DB row (like
	// AgentProfile.AutopilotPaused) so an operator can cut the agent off by
	// redeploying config even if the database is unreachable or compromised.
	// Set via AGENT_KILL_SWITCH.
	AgentKillSwitch bool
	// AgentProfilePath points at the owner's YAML profile (identity, public
	// bio, skills, preferences, restricted section) mounted into the
	// container. Optional even with AGENT_ENABLED=true — see its call site
	// in cmd/server/main.go for what happens when it's unset. Set via
	// AGENT_PROFILE_PATH.
	AgentProfilePath string
	// AgentProfileOwnerTGID is the Telegram id of the account
	// AgentProfilePath's profile belongs to. mctl-telegram is multi-tenant
	// and POST /api/agent/token can mint an aud=agent token for ANY account
	// it hosts, not just this deployment's intended communication-agent
	// owner — without this, GET /recruiters/{peer} would hand that owner's
	// identity/skills/preferences to a worker authenticated as an unrelated
	// account. Required whenever AgentProfilePath is set; ignored otherwise.
	// Set via AGENT_PROFILE_OWNER_TG_ID.
	AgentProfileOwnerTGID int64
}

func Load() (*Config, error) {
	authMode := envOr("AUTH_MODE", "local-dev")
	c := &Config{
		Addr:                     envOr("ADDR", ":8080"),
		PublicBaseURL:            envOr("PUBLIC_BASE_URL", "http://localhost:8080"),
		MCPPath:                  envOr("MCP_PATH", "/mcp"),
		AuthMode:                 authMode,
		AuthRequired:             envBool("AUTH_REQUIRED", false),
		OperatorLogin:            envOr("OPERATOR_GITHUB_LOGIN", "operator"),
		DatabaseURL:              envOr("DATABASE_URL", "file:mctl-telegram.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"),
		OAUTHJWTSecret:           jwtSigningKey(authMode),
		OAUTHJWTAudience:         os.Getenv("OAUTH_JWT_AUDIENCE"),
		OAUTHJWTAudReq:           envBool("OAUTH_JWT_AUDIENCE_REQUIRED", false),
		TGAPIHash:                os.Getenv("TG_API_HASH"),
		AllowSend:                envBool("ALLOW_SEND", false),
		IdleClientTimeout:        envDuration("IDLE_CLIENT_TIMEOUT", 10*time.Minute),
		RateLimitPerUser:         envInt("RATE_LIMIT_PER_USER", 30),
		AuditRetentionDays:       envInt("AUDIT_RETENTION_DAYS", 90),
		AgentRetentionDays:       envInt("AGENT_RETENTION_DAYS", 30),
		AgentJobVisibility:       envDuration("AGENT_JOB_VISIBILITY", 5*time.Minute),
		AgentApprovalTTL:         envDuration("AGENT_APPROVAL_TTL", 24*time.Hour),
		AgentEnabled:             envBool("AGENT_ENABLED", false),
		AgentKillSwitch:          envBool("AGENT_KILL_SWITCH", false),
		AgentProfilePath:         os.Getenv("AGENT_PROFILE_PATH"),
		AgentProfileOwnerTGID:    envInt64("AGENT_PROFILE_OWNER_TG_ID", 0),
		LogLevel:                 envOr("LOG_LEVEL", "info"),
		TelegramLoginBotToken:    os.Getenv("TELEGRAM_LOGIN_BOT_TOKEN"),
		TelegramOIDCClientID:     os.Getenv("TELEGRAM_OIDC_CLIENT_ID"),
		TelegramOIDCClientSecret: os.Getenv("TELEGRAM_OIDC_CLIENT_SECRET"),
		TelegramOIDCIssuerURL:    envOr("TELEGRAM_OIDC_ISSUER", "https://oauth.telegram.org"),
		TelegramOIDCRedirectURL:  os.Getenv("TELEGRAM_OIDC_REDIRECT_URL"),
		OAUTHCodeTTL:             envDuration("OAUTH_CODE_TTL", 10*time.Minute),
		OAUTHAccessTokenTTL:      envDuration("OAUTH_ACCESS_TOKEN_TTL", 1*time.Hour),
		OAUTHRefreshTokenTTL:     envDuration("OAUTH_REFRESH_TOKEN_TTL", 720*time.Hour),
		OAUTHAllowImplicitClient: envBool("OAUTH_ALLOW_IMPLICIT_CLIENT", true),
		AutoApproveClients:       envBool("AUTO_APPROVE_CLIENTS", false),
		DigestHourUTC:            envInt("DIGEST_HOUR_UTC", 9),
	}
	c.MetricsAllowCIDR = os.Getenv("METRICS_ALLOW_CIDR")
	c.TelegramMaxSessions = envInt("TELEGRAM_MAX_SESSIONS", 0)
	c.TGAPIRatePerSec = envFloat("TG_API_RATE_PER_SEC", 0)
	c.TGAPIRateBurst = envInt("TG_API_RATE_BURST", 0)
	c.DBMaxOpenConns = envInt("DB_MAX_OPEN_CONNS", 0)
	c.DBMaxIdleConns = envInt("DB_MAX_IDLE_CONNS", 0)
	c.ReplicaID = envOr("REPLICA_ID", envOr("POD_NAME", "unknown"))
	c.DemoVideoURL = envOr("DEMO_VIDEO_URL", "")
	c.DemoReviewerEnabled = envBool("DEMO_REVIEWER_ENABLED", false)
	c.DemoReviewerUsername = os.Getenv("DEMO_REVIEWER_USERNAME")
	c.DemoReviewerPassword = os.Getenv("DEMO_REVIEWER_PASSWORD")
	if v := os.Getenv("DEMO_REVIEWER_TG_ID"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("DEMO_REVIEWER_TG_ID must be integer: %w", err)
		}
		c.DemoReviewerTGID = n
	}
	if c.DemoReviewerEnabled {
		if c.DemoReviewerUsername == "" || c.DemoReviewerPassword == "" || c.DemoReviewerTGID == 0 {
			return nil, fmt.Errorf("DEMO_REVIEWER_ENABLED requires DEMO_REVIEWER_USERNAME, DEMO_REVIEWER_PASSWORD and DEMO_REVIEWER_TG_ID")
		}
	}
	// AgentProfileOwnerTGID's doc comment documents it as required whenever
	// AgentProfilePath is set — a missing or malformed value silently
	// defaulted to 0, so the profile loaded successfully at startup but
	// handleRecruiterProfile then returned 403 for every account (owner ID
	// zero is explicitly forbidden there), leaving a seemingly enabled
	// endpoint permanently unusable with no loud failure anywhere. Fail
	// closed here instead, matching this function's existing DemoReviewer
	// validation immediately above.
	if c.AgentProfilePath != "" && c.AgentProfileOwnerTGID <= 0 {
		return nil, fmt.Errorf("AGENT_PROFILE_OWNER_TG_ID must be set to a positive Telegram id when AGENT_PROFILE_PATH is set")
	}
	c.ToolFilter = envOr("MCP_TOOL_FILTER", "all")
	if c.ToolFilter != "all" && c.ToolFilter != "read-only" {
		return nil, fmt.Errorf("MCP_TOOL_FILTER must be \"all\" or \"read-only\", got %q", c.ToolFilter)
	}
	c.MediaDownloadMaxBytes = int64(envInt("MEDIA_DOWNLOAD_MAX_BYTES", 20971520))
	c.MediaUploadMaxBytes = int64(envInt("MEDIA_UPLOAD_MAX_BYTES", 20971520))
	c.AllowedOrigins = parseStringCSV(os.Getenv("ALLOWED_ORIGINS"))
	if len(c.AllowedOrigins) == 0 {
		if origin := originOf(c.PublicBaseURL); origin != "" {
			c.AllowedOrigins = []string{origin}
		} else {
			slog.Warn("ALLOWED_ORIGINS is empty and PUBLIC_BASE_URL has no parseable origin; "+
				"the /mcp Origin guard is disabled (all origins allowed)",
				"public_base_url", c.PublicBaseURL)
		}
	}
	c.TGLoginAdmins = parseInt64CSV(os.Getenv("TG_LOGIN_ADMINS"))
	c.TGLoginClients = parseInt64CSV(os.Getenv("TG_LOGIN_CLIENTS"))
	c.TelegramOIDCSigningAlgs = parseStringCSV(os.Getenv("TELEGRAM_OIDC_SIGNING_ALGS"))

	if v := os.Getenv("TG_API_ID"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("TG_API_ID must be integer: %w", err)
		}
		c.TGAPIID = n
	}

	if v := os.Getenv("ENCRYPTION_KEY"); v != "" {
		if len(v) != 64 {
			return nil, fmt.Errorf("ENCRYPTION_KEY must be 64 hex chars (32 bytes), got %d chars", len(v))
		}
		decoded, err := hexDecode(v)
		if err != nil {
			return nil, fmt.Errorf("ENCRYPTION_KEY hex decode: %w", err)
		}
		c.EncryptionKey = decoded
	}

	return c, nil
}

// jwtSigningKey resolves the HS256 key for OAuth/MCP JWTs, honouring AUTH_MODE.
//
// In local-jwt mode mctl-telegram signs its own tokens: the dedicated
// OAUTH_JWT_SIGNING_KEY is preferred, sourced from mctl-telegram's own Vault
// path. The legacy OAUTH_JWT_SECRET stays as a fallback for one transition
// window — historically it was wired to api.mctl.ai's shared secret, so a
// rotation in mctl-api would silently invalidate every mctl-telegram token.
//
// In shared-hmac(-legacy) mode the service VERIFIES tokens signed by
// api.mctl.ai, so the correct key is that service's shared OAUTH_JWT_SECRET —
// never the dedicated key. Preferring OAUTH_JWT_SIGNING_KEY there would break
// all authentication with "invalid JWT signature"; we use OAUTH_JWT_SECRET and
// warn loudly if a dedicated key was set by mistake (e.g. a partial rollout).
func jwtSigningKey(authMode string) string {
	dedicated := os.Getenv("OAUTH_JWT_SIGNING_KEY")
	legacy := os.Getenv("OAUTH_JWT_SECRET")
	switch strings.ToLower(authMode) {
	case "shared-hmac", "shared-hmac-legacy":
		if dedicated != "" {
			slog.Warn("OAUTH_JWT_SIGNING_KEY is set but AUTH_MODE is shared-hmac; " +
				"that mode verifies tokens signed by api.mctl.ai — using OAUTH_JWT_SECRET instead")
		}
		return legacy
	default:
		if dedicated != "" {
			return dedicated
		}
		if legacy != "" {
			slog.Warn("OAUTH_JWT_SECRET is deprecated; set OAUTH_JWT_SIGNING_KEY instead " +
				"(a dedicated mctl-telegram signing key, not the shared mctl-api secret)")
			return legacy
		}
		return ""
	}
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	switch v {
	case "1", "true", "TRUE", "True", "yes":
		return true
	case "0", "false", "FALSE", "False", "no":
		return false
	default:
		return def
	}
}

func envInt(key string, def int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envInt64(key string, def int64) int64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func hexDecode(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexNib(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexNib(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// parseInt64CSV splits a comma-separated list of integer ids, ignoring
// whitespace, empty entries, and non-numeric values (with a slog warning).
// Used for TG_LOGIN_ADMINS.
func parseInt64CSV(s string) []int64 {
	if s == "" {
		return nil
	}
	parts := []int64{}
	for _, raw := range splitTrim(s) {
		if raw == "" {
			continue
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			continue
		}
		parts = append(parts, n)
	}
	return parts
}

// originOf returns the scheme://host[:port] origin of a base URL, matching the
// shape of a browser Origin header. Returns "" if rawURL has no scheme/host.
func originOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// parseStringCSV splits a comma-separated list, trimming whitespace and
// dropping empty entries. Used for TELEGRAM_OIDC_SIGNING_ALGS and ALLOWED_ORIGINS.
func parseStringCSV(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{}
	for _, raw := range splitTrim(s) {
		if raw != "" {
			out = append(out, raw)
		}
	}
	return out
}

// splitTrim is strings.Split + TrimSpace per element. Kept private — the
// stdlib strings.Split is fine but the trim removes accidental newlines and
// blanks that K8s configmap multiline values often introduce.
func splitTrim(s string) []string {
	out := []string{}
	cur := []byte{}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' || c == '\n' {
			out = append(out, trimASCII(string(cur)))
			cur = cur[:0]
			continue
		}
		cur = append(cur, c)
	}
	if len(cur) > 0 {
		out = append(out, trimASCII(string(cur)))
	}
	return out
}

func trimASCII(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func hexNib(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char %q", b)
}
