// Package sharedhmac validates JWTs issued by mctl-api using the same
// OAUTH_JWT_SECRET. We intentionally do NOT import mctl-api as a Go module —
// the secret-sharing coupling is documented in SECURITY.md as a deliberate
// MVP shortcut until mctl-api grows RS256/JWKS support; pulling the verify
// logic in here keeps the surface small (~40 lines) and inspectable.
package sharedhmac

import (
	"bytes"
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
	Secret           []byte
	ExpectedIssuer   string
	ExpectedAudience string
	AudienceRequired bool
	Store            *db.Store
	Groups2Scopes    map[string][]string
	// Allowed groups gate the entire MCP endpoint; identity must intersect
	// with at least one. Empty slice ⇒ no group gating (any valid JWT passes).
	AllowedGroups []string
}

// Config captures everything Provider needs at construction time.
//
// ExpectedAudience and AudienceRequired together drive a phased rollout of
// the JWT `aud` claim check:
//
//   - ExpectedAudience == ""                 ⇒ no aud check at all (legacy default)
//   - ExpectedAudience != "" && !Required    ⇒ if the token carries an aud, it
//     must equal ExpectedAudience; tokens without aud still pass (transitional
//     mode while mctl-api is rolling out aud emission)
//   - ExpectedAudience != "" && Required     ⇒ strict: aud MUST be present AND
//     MUST equal ExpectedAudience
//
// Flip Required to true only once mctl-api is observed to emit aud on every
// freshly issued token.
type Config struct {
	Secret           []byte
	ExpectedIssuer   string
	ExpectedAudience string
	AudienceRequired bool
	AllowedGroups    []string
	Groups2Scopes    map[string][]string
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
		Secret:           cfg.Secret,
		ExpectedIssuer:   cfg.ExpectedIssuer,
		ExpectedAudience: cfg.ExpectedAudience,
		AudienceRequired: cfg.AudienceRequired,
		Store:            store,
		Groups2Scopes:    cfg.Groups2Scopes,
		AllowedGroups:    cfg.AllowedGroups,
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
			"telegram:messages:pin",
			"admin:users",
		},
		// mctl-api issues "admins" for org admins (IsAdmin check in ResolveGroups).
		"admins": {
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"telegram:messages:pin",
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
	if err := checkAudience(payload.Audience, p.ExpectedAudience, p.AudienceRequired); err != nil {
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

// checkAudience implements the phased aud-claim policy described on Config.
// audClaim is the parsed list of audiences from the JWT (zero-length when
// the token has no aud at all).
func checkAudience(audClaim []string, expected string, required bool) error {
	if expected == "" {
		return nil // no policy configured
	}
	if len(audClaim) == 0 {
		if required {
			return errors.New("JWT missing required audience claim")
		}
		return nil // transitional: missing is tolerated
	}
	for _, a := range audClaim {
		if a == expected {
			return nil
		}
	}
	return fmt.Errorf("JWT audience %v does not match expected %q", audClaim, expected)
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
// The Audience field is captured as json.RawMessage because RFC 7519 allows
// `aud` to be either a single string or an array of strings; we normalise
// the result via audienceList() before the policy check.
type jwtPayload struct {
	Issuer      string          `json:"iss"`
	Subject     string          `json:"sub"`
	Groups      []string        `json:"groups"`
	IssuedAt    int64           `json:"iat"`
	ExpiresAt   int64           `json:"exp"`
	AudienceRaw json.RawMessage `json:"aud,omitempty"`
	Audience    []string        `json:"-"`
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
	aud, err := audienceList(p.AudienceRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT audience claim: %w", err)
	}
	p.Audience = aud
	return &p, nil
}

// audienceList normalises the polymorphic `aud` claim into a string slice.
// RFC 7519 §4.1.3 permits two shapes: a single string or an array of
// strings. We also accept absent / null / explicit-empty as a synonym for
// "no audience". Anything else (number, object, mixed-type array, array of
// empty strings) is a malformed claim and returns a non-nil error so the
// caller can reject the JWT outright instead of silently treating it as
// absent — which would bypass the transitional audience policy.
func audienceList(raw json.RawMessage) ([]string, error) {
	// Absent claim — len 0 reflects "no aud key in payload".
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	// Single string form.
	var single string
	if err := json.Unmarshal(trimmed, &single); err == nil {
		if single == "" {
			return nil, errors.New("audience must not be an empty string")
		}
		return []string{single}, nil
	}
	// Array form. Require every element to be a non-empty string.
	var arr []json.RawMessage
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return nil, fmt.Errorf("audience must be a string or array of strings, got %s", raw)
	}
	if len(arr) == 0 {
		return nil, nil // explicit empty array == absent
	}
	out := make([]string, 0, len(arr))
	for i, elem := range arr {
		var s string
		if err := json.Unmarshal(elem, &s); err != nil {
			return nil, fmt.Errorf("audience[%d] is not a string", i)
		}
		if s == "" {
			return nil, fmt.Errorf("audience[%d] is an empty string", i)
		}
		out = append(out, s)
	}
	return out, nil
}

// IssueTestToken is exported strictly for tests that need to forge a token
// signed by the same secret. Production code never calls this. The
// audience argument may be empty (no aud claim emitted), a single value
// (string aud), or multiple values (array aud) — IssueTestTokenWithAudience
// covers the latter.
func IssueTestToken(secret []byte, issuer, subject string, groups []string, ttl time.Duration) (string, error) {
	return IssueTestTokenWithAudience(secret, issuer, subject, groups, nil, ttl)
}

// IssueTestTokenWithAudience extends IssueTestToken to include an explicit
// `aud` claim. Pass nil/empty to omit the claim entirely.
func IssueTestTokenWithAudience(secret []byte, issuer, subject string, groups, audiences []string, ttl time.Duration) (string, error) {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now()
	type signedPayload struct {
		Issuer    string   `json:"iss"`
		Subject   string   `json:"sub"`
		Groups    []string `json:"groups"`
		IssuedAt  int64    `json:"iat"`
		ExpiresAt int64    `json:"exp"`
		Audience  any      `json:"aud,omitempty"`
	}
	p := signedPayload{
		Issuer:    issuer,
		Subject:   subject,
		Groups:    groups,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
	switch len(audiences) {
	case 0:
		// no aud claim
	case 1:
		p.Audience = audiences[0]
	default:
		p.Audience = audiences
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
