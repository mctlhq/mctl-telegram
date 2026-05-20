package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr               string
	PublicBaseURL      string
	MCPPath            string
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
	// ReplicaID identifies this pod for observability. Sourced from
	// REPLICA_ID env var; falls back to POD_NAME; falls back to "unknown".
	ReplicaID string
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
	c.ReplicaID = envOr("REPLICA_ID", envOr("POD_NAME", "unknown"))
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

// parseStringCSV splits a comma-separated list, trimming whitespace and
// dropping empty entries. Used for TELEGRAM_OIDC_SIGNING_ALGS.
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
