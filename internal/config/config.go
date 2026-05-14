package config

import (
	"fmt"
	"os"
	"strconv"
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
	OAUTHJWTSecret     string
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
}

func Load() (*Config, error) {
	c := &Config{
		Addr:               envOr("ADDR", ":8080"),
		PublicBaseURL:      envOr("PUBLIC_BASE_URL", "http://localhost:8080"),
		MCPPath:            envOr("MCP_PATH", "/mcp"),
		AuthMode:           envOr("AUTH_MODE", "local-dev"),
		AuthRequired:       envBool("AUTH_REQUIRED", false),
		OperatorLogin:      envOr("OPERATOR_GITHUB_LOGIN", "operator"),
		DatabaseURL:        envOr("DATABASE_URL", "file:mctl-telegram.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"),
		OAUTHJWTSecret:     os.Getenv("OAUTH_JWT_SECRET"),
		OAUTHJWTAudience:   os.Getenv("OAUTH_JWT_AUDIENCE"),
		OAUTHJWTAudReq:     envBool("OAUTH_JWT_AUDIENCE_REQUIRED", false),
		TGAPIHash:          os.Getenv("TG_API_HASH"),
		AllowSend:          envBool("ALLOW_SEND", false),
		IdleClientTimeout:  envDuration("IDLE_CLIENT_TIMEOUT", 10*time.Minute),
		RateLimitPerUser:   envInt("RATE_LIMIT_PER_USER", 30),
		AuditRetentionDays: envInt("AUDIT_RETENTION_DAYS", 90),
		LogLevel:           envOr("LOG_LEVEL", "info"),
	}

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
