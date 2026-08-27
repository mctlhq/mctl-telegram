// Package localjwt mints and verifies HS256 JWTs that mctl-telegram signs
// with its own secret. Issuer is the service's PublicBaseURL — by default
// "https://tg.mctl.ai". A localjwt.Provider implements auth.Provider so the
// /mcp middleware can authenticate Bearer tokens that this same service
// issued during the /oauth/token exchange.
//
// This package replaces the cross-service "shared-hmac" coupling: instead of
// trusting JWTs signed by api.mctl.ai, mctl-telegram becomes its own OAuth
// authorization server and signs+verifies tokens locally.
package localjwt

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

// Claims is the body of a localjwt token. The Subject is always of the form
// "tg:<telegram_id>" so an external observer can tell the identity provider
// at a glance.
type Claims struct {
	Issuer           string   `json:"iss"`
	Subject          string   `json:"sub"`
	TelegramID       int64    `json:"tg_id"`
	TelegramUsername string   `json:"tg_username,omitempty"`
	Groups           []string `json:"groups,omitempty"`
	Scopes           []string `json:"scopes,omitempty"`
	IssuedAt         int64    `json:"iat"`
	ExpiresAt        int64    `json:"exp"`
	// OriginalIssuedAt anchors a renewable credential to the moment a human
	// first minted it, surviving every subsequent renewal. Without it a
	// renew endpoint that copies claims forward extends a credential without
	// bound: each renewal is individually within maxWorkerTokenTTL, yet the
	// chain never has to end. Only internal/workertoken sets and enforces it
	// today; tokens minted before it existed simply omit it, and readers are
	// expected to fall back to IssuedAt (see workertoken.originAnchor).
	OriginalIssuedAt int64           `json:"orig_iat,omitempty"`
	AudienceRaw      json.RawMessage `json:"aud,omitempty"`
	Audience         []string        `json:"-"`
}

// Issuer signs Claims into compact JWTs. Construct with NewIssuer.
type Issuer struct {
	Secret []byte
	Issuer string
}

// NewIssuer returns an Issuer ready to mint tokens. issuer is the iss claim
// (e.g. "https://tg.mctl.ai"). The secret must be at least 32 bytes; shorter
// secrets are accepted in tests but rejected in production by NewIssuerStrict.
func NewIssuer(secret []byte, issuer string) (*Issuer, error) {
	if len(secret) == 0 {
		return nil, errors.New("localjwt: secret required")
	}
	if issuer == "" {
		return nil, errors.New("localjwt: issuer required")
	}
	return &Issuer{Secret: secret, Issuer: issuer}, nil
}

// Mint signs the supplied claims. Issuer is overwritten from i.Issuer to
// prevent forgery via caller-supplied "iss". IssuedAt/ExpiresAt are
// overwritten when zero so callers can pass partially-populated structs.
func (i *Issuer) Mint(c Claims, ttl time.Duration) (string, error) {
	if i == nil {
		return "", errors.New("localjwt: nil issuer")
	}
	if c.Subject == "" {
		return "", errors.New("localjwt: subject required")
	}
	now := time.Now()
	c.Issuer = i.Issuer
	if c.IssuedAt == 0 {
		c.IssuedAt = now.Unix()
	}
	if c.ExpiresAt == 0 {
		c.ExpiresAt = now.Add(ttl).Unix()
	}
	// Audience marshaling: support empty (omit), single (string), multi (array).
	if len(c.Audience) > 0 {
		switch len(c.Audience) {
		case 1:
			c.AudienceRaw, _ = json.Marshal(c.Audience[0])
		default:
			c.AudienceRaw, _ = json.Marshal(c.Audience)
		}
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	bodyB64 := base64.RawURLEncoding.EncodeToString(body)
	sigInput := hdr + "." + bodyB64
	mac := hmac.New(sha256.New, i.Secret)
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig, nil
}

// Verify decodes and validates the signature, issuer, and expiry of a token.
// Does not check audience — call CheckAudience separately when needed.
func Verify(token string, secret []byte, expectedIssuer string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT")
	}
	sigInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigInput))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, errors.New("invalid JWT signature")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	var c Claims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return nil, errors.New("malformed JWT payload")
	}
	if c.Issuer != expectedIssuer {
		return nil, fmt.Errorf("unexpected JWT issuer: %q", c.Issuer)
	}
	if time.Now().Unix() > c.ExpiresAt {
		return nil, errors.New("JWT expired")
	}
	aud, err := audienceList(c.AudienceRaw)
	if err != nil {
		return nil, fmt.Errorf("invalid audience claim: %w", err)
	}
	c.Audience = aud
	return &c, nil
}

// CheckAudience returns nil when the token's aud satisfies the policy.
//   - expected=="" disables the check entirely.
//   - required==false tolerates a missing aud (transitional rollout).
//   - required==true rejects tokens without aud.
//
// When a non-empty aud is present it must equal expected.
func CheckAudience(audClaim []string, expected string, required bool) error {
	if expected == "" {
		return nil
	}
	if len(audClaim) == 0 {
		if required {
			return errors.New("JWT missing required audience claim")
		}
		return nil
	}
	for _, a := range audClaim {
		if a == expected {
			return nil
		}
	}
	return fmt.Errorf("JWT audience %v does not match expected %q", audClaim, expected)
}

// Provider is the auth.Provider implementation that verifies tokens minted by
// this same service. Bearer-only.
type Provider struct {
	Secret           []byte
	ExpectedIssuer   string
	ExpectedAudience string
	AudienceRequired bool
	Store            *db.Store
}

// ProviderConfig is the constructor input for NewProvider.
type ProviderConfig struct {
	Secret           []byte
	ExpectedIssuer   string
	ExpectedAudience string
	AudienceRequired bool
}

// NewProvider validates inputs and returns a Provider that will reject any
// token whose signature, issuer, or audience does not match.
func NewProvider(store *db.Store, cfg ProviderConfig) (*Provider, error) {
	if len(cfg.Secret) == 0 {
		return nil, errors.New("localjwt: OAUTH_JWT_SECRET required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("localjwt: expected issuer required")
	}
	return &Provider{
		Secret:           cfg.Secret,
		ExpectedIssuer:   cfg.ExpectedIssuer,
		ExpectedAudience: cfg.ExpectedAudience,
		AudienceRequired: cfg.AudienceRequired,
		Store:            store,
	}, nil
}

// Authenticate satisfies the auth.Provider interface. Returns (nil, nil) for
// anonymous requests so the caller (middleware) decides whether to 401.
// In addition to a Bearer token in the Authorization header, accepts the
// "mctl_connect_token" HttpOnly cookie so that browser-driven flows under
// /telegram/connect can reach the manage routes. The cookie is set with
// Path=/telegram/connect, so it is never delivered to /mcp or other endpoints.
func (p *Provider) Authenticate(r *http.Request) (*auth.Identity, error) {
	tok := ""
	hdr := r.Header.Get("Authorization")
	switch {
	case hdr != "" && strings.HasPrefix(hdr, "Bearer "):
		tok = strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	case hdr != "":
		return nil, errors.New("Authorization header must use Bearer scheme")
	default:
		if ck, err := r.Cookie("mctl_connect_token"); err == nil {
			tok = ck.Value
		}
	}
	if tok == "" {
		return nil, nil
	}
	c, err := Verify(tok, p.Secret, p.ExpectedIssuer)
	if err != nil {
		return nil, err
	}
	if err := CheckAudience(c.Audience, p.ExpectedAudience, p.AudienceRequired); err != nil {
		return nil, err
	}
	// Persist/find the user row by telegram id. EnsureUserByTelegramID is the
	// canonical way to map a Telegram identity to an internal user id; legacy
	// rows where the user predates the column get bound here on the first
	// authenticated request after schema migration.
	uid, err := p.Store.EnsureUserByTelegramID(r.Context(), c.TelegramID, c.TelegramUsername, "")
	if err != nil {
		return nil, fmt.Errorf("ensure user: %w", err)
	}
	return &auth.Identity{
		UserID:           uid,
		Subject:          c.Subject,
		TelegramID:       c.TelegramID,
		TelegramUsername: c.TelegramUsername,
		Provider:         "tg-mcp",
		Groups:           c.Groups,
		Scopes:           c.Scopes,
	}, nil
}

// audienceList normalises the polymorphic `aud` claim into a string slice.
// RFC 7519 §4.1.3 allows two shapes (single string, array of strings); we
// also accept absent/null/empty as "no audience".
func audienceList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}
	var single string
	if err := json.Unmarshal(trimmed, &single); err == nil {
		if single == "" {
			return nil, errors.New("audience must not be an empty string")
		}
		return []string{single}, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return nil, fmt.Errorf("audience must be a string or array of strings, got %s", raw)
	}
	if len(arr) == 0 {
		return nil, nil
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
