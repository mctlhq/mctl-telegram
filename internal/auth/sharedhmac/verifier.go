// Package sharedhmac validates JWTs issued by mctl-api using the same
// OAUTH_JWT_SECRET. We intentionally do NOT import mctl-api as a Go module —
// the secret-sharing coupling is documented in SECURITY.md as a deliberate
// MVP shortcut until mctl-api grows RS256/JWKS support; pulling the verify
// logic in here keeps the surface small (~40 lines) and inspectable.
package sharedhmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

type Provider struct {
	Secret         []byte
	ExpectedIssuer string
	Store          *db.Store
	Groups2Scopes  map[string][]string
	// Allowed groups gate the entire MCP endpoint; identity must intersect
	// with at least one. Empty slice ⇒ no group gating (any valid JWT passes).
	AllowedGroups []string
}

// Config captures everything Provider needs at construction time.
type Config struct {
	Secret         []byte
	ExpectedIssuer string
	AllowedGroups  []string
	Groups2Scopes  map[string][]string
}

func New(store *db.Store, cfg Config) (*Provider, error) {
	if len(cfg.Secret) == 0 {
		return nil, errors.New("shared-hmac: OAUTH_JWT_SECRET required")
	}
	if cfg.ExpectedIssuer == "" {
		cfg.ExpectedIssuer = "https://api.mctl.ai"
	}
	if cfg.Groups2Scopes == nil {
		cfg.Groups2Scopes = DefaultGroupScopes()
	}
	return &Provider{
		Secret:         cfg.Secret,
		ExpectedIssuer: cfg.ExpectedIssuer,
		Store:          store,
		Groups2Scopes:  cfg.Groups2Scopes,
		AllowedGroups:  cfg.AllowedGroups,
	}, nil
}

// DefaultGroupScopes maps GitHub team / mctl-tenant names to scope sets.
// platform-admins inherits everything plus admin:users.
func DefaultGroupScopes() map[string][]string {
	return map[string][]string{
		"telegram-mcp-readers": {
			"telegram:dialogs:read",
			"telegram:messages:read",
		},
		"telegram-mcp-senders": {
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
		},
		"platform-admins": {
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"admin:users",
		},
	}
}

func (p *Provider) Authenticate(r *http.Request) (*auth.Identity, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, nil // anonymous; middleware decides whether to reject
	}
	if !strings.HasPrefix(hdr, "Bearer ") {
		return nil, errors.New("Authorization header must use Bearer scheme")
	}
	tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	payload, err := verifyJWT(tok, p.Secret, p.ExpectedIssuer)
	if err != nil {
		return nil, err
	}
	if len(p.AllowedGroups) > 0 && !intersect(payload.Groups, p.AllowedGroups) {
		return nil, fmt.Errorf("none of identity groups %v are allowed", payload.Groups)
	}
	scopes := deriveScopes(payload.Groups, p.Groups2Scopes)
	uid, err := p.Store.EnsureUser(r.Context(), payload.Subject, "", "mctl-api")
	if err != nil {
		return nil, fmt.Errorf("ensure user: %w", err)
	}
	return &auth.Identity{
		UserID:      uid,
		GitHubLogin: payload.Subject,
		Provider:    "mctl-api",
		Groups:      payload.Groups,
		Scopes:      scopes,
	}, nil
}

func deriveScopes(groups []string, mapping map[string][]string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, g := range groups {
		for _, s := range mapping[g] {
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func intersect(a, b []string) bool {
	set := make(map[string]struct{}, len(b))
	for _, x := range b {
		set[x] = struct{}{}
	}
	for _, x := range a {
		if _, ok := set[x]; ok {
			return true
		}
	}
	return false
}

// jwtPayload mirrors the shape signed by mctl-api/internal/auth/oauth_server.go.
type jwtPayload struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Groups    []string `json:"groups"`
	IssuedAt  int64    `json:"iat"`
	ExpiresAt int64    `json:"exp"`
}

func verifyJWT(token string, secret []byte, expectedIssuer string) (*jwtPayload, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, errors.New("invalid JWT signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	var p jwtPayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	if p.Issuer != expectedIssuer {
		return nil, fmt.Errorf("unexpected JWT issuer: %q", p.Issuer)
	}
	if time.Now().Unix() > p.ExpiresAt {
		return nil, errors.New("JWT expired")
	}
	return &p, nil
}

// IssueTestToken is exported strictly for tests that need to forge a token
// signed by the same secret. Production code never calls this.
func IssueTestToken(secret []byte, issuer, subject string, groups []string, ttl time.Duration) (string, error) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	p := jwtPayload{
		Issuer:    issuer,
		Subject:   subject,
		Groups:    groups,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	bodyB64 := base64.RawURLEncoding.EncodeToString(body)
	sigInput := hdr + "." + bodyB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig, nil
}
