// Package authn validates mctl-api-issued bearer tokens for the Glovo facade
// (ADR 0010 checkpoint 1) and serves the RFC 9728 protected-resource
// metadata. The facade is a resource server only: it holds no signing or
// shared secret, and it never decides the tenant itself.
package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const skew = 60 * time.Second

// Failure reasons: a closed set, safe as metric label values.
const (
	ReasonMissing     = "missing"
	ReasonMalformed   = "malformed"
	ReasonUnknownKey  = "unknown_kid"
	ReasonSignature   = "signature"
	ReasonIssuer      = "issuer"
	ReasonAudience    = "audience"
	ReasonExpired     = "expired"
	ReasonNotYetValid = "not_yet_valid"
	ReasonSubject     = "subject"
	ReasonNoScope     = "insufficient_scope"
	ReasonQueryToken  = "query_token"
	ReasonJWKSDown    = "jwks_unavailable"
	ReasonFormToken   = "form_token"
	ReasonUnsupported = "unsupported_scheme"
)

// Error is a refused token. Reason is the closed-set code; it never carries
// token material.
type Error struct {
	Reason string
	Status int
}

func (e *Error) Error() string { return "authn: " + e.Reason }

// Principal is the verified caller. Tenant is the token's selected-tenant
// claim, untrusted until mctl-api re-verifies it against the server-owned
// grant on every call.
type Principal struct {
	Subject   string
	Tenant    string
	Scopes    []string
	TokenID   string
	TokenHash string // short hash of the token, for correlation only
}

// HasScope reports whether the principal holds scope.
func (p *Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Config configures a Verifier.
type Config struct {
	Issuer      string
	Resource    string
	JWKSURL     string
	GlovoScopes []string // scopes_supported from the contract
	HTTPClient  *http.Client
	Now         func() time.Time
}

// Verifier verifies bearer tokens against the mctl-api JWKS.
type Verifier struct {
	cfg  Config
	jwks *jwksCache
	now  func() time.Time
}

// New builds a Verifier.
func New(cfg Config) *Verifier {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Verifier{cfg: cfg, now: now, jwks: newJWKSCache(cfg.JWKSURL, cfg.HTTPClient, now)}
}

// Refresh fetches the JWKS now (used at startup and by readiness).
func (v *Verifier) Refresh(ctx context.Context) error { return v.jwks.refresh(ctx) }

// JWKSLoaded reports whether a JWKS has been fetched.
func (v *Verifier) JWKSLoaded() bool { return v.jwks.Loaded() }

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

type claims struct {
	jwt.Claims
	Scope  string `json:"scope"`
	Tenant string `json:"mctl_tenant"`
}

// Verify validates token. It makes no network call except a cached JWKS
// fetch.
func (v *Verifier) Verify(ctx context.Context, token string) (*Principal, error) {
	if token == "" {
		return nil, &Error{ReasonMissing, http.StatusUnauthorized}
	}
	tok, err := jwt.ParseSigned(token, allowedAlgs)
	if err != nil || len(tok.Headers) != 1 {
		return nil, &Error{ReasonMalformed, http.StatusUnauthorized}
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return nil, &Error{ReasonUnknownKey, http.StatusUnauthorized}
	}
	key, err := v.jwks.key(ctx, kid)
	if err != nil {
		return nil, &Error{ReasonJWKSDown, http.StatusUnauthorized}
	}
	if key == nil {
		return nil, &Error{ReasonUnknownKey, http.StatusUnauthorized}
	}
	var c claims
	if err := tok.Claims(key, &c); err != nil {
		return nil, &Error{ReasonSignature, http.StatusUnauthorized}
	}
	now := v.now()
	switch {
	case c.Issuer != v.cfg.Issuer:
		return nil, &Error{ReasonIssuer, http.StatusUnauthorized}
	case !c.Audience.Contains(v.cfg.Resource):
		return nil, &Error{ReasonAudience, http.StatusUnauthorized}
	case c.Expiry == nil || !now.Before(c.Expiry.Time()):
		return nil, &Error{ReasonExpired, http.StatusUnauthorized}
	case c.NotBefore != nil && c.NotBefore.Time().After(now.Add(skew)),
		c.IssuedAt != nil && c.IssuedAt.Time().After(now.Add(skew)):
		return nil, &Error{ReasonNotYetValid, http.StatusUnauthorized}
	case strings.TrimSpace(c.Subject) == "":
		return nil, &Error{ReasonSubject, http.StatusUnauthorized}
	}
	var scopes []string
	for _, s := range strings.Fields(c.Scope) {
		for _, g := range v.cfg.GlovoScopes {
			if s == g {
				scopes = append(scopes, s)
			}
		}
	}
	if len(scopes) == 0 {
		return nil, &Error{ReasonNoScope, http.StatusForbidden}
	}
	sum := sha256.Sum256([]byte(token))
	return &Principal{
		Subject: c.Subject, Tenant: c.Tenant, Scopes: scopes, TokenID: c.ID,
		TokenHash: hex.EncodeToString(sum[:8]),
	}, nil
}

type ctxKey int

const (
	principalKey ctxKey = iota
	tokenKey
	requestIDKey
)

// WithPrincipal stores the verified principal and the raw token. The raw
// token is reachable only through SubjectToken, which exists for the mctlapi
// client to forward for re-verification and must not be used elsewhere.
func WithPrincipal(ctx context.Context, p *Principal, rawToken string) context.Context {
	ctx = context.WithValue(ctx, principalKey, p)
	return context.WithValue(ctx, tokenKey, rawToken)
}

// FromContext returns the verified principal, or nil.
func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey).(*Principal)
	return p
}

// SubjectToken returns the caller's raw access token for forwarding to
// mctl-api. Only internal/glovo/mctlapi may call it.
func SubjectToken(ctx context.Context) string {
	s, _ := ctx.Value(tokenKey).(string)
	return s
}

// WithRequestID / RequestID carry the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestID returns the request id, or "".
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey).(string)
	return s
}
