// Package k8ssa authenticates one in-cluster workload to /mcp with its
// Kubernetes projected ServiceAccount token instead of a minted worker token.
//
// It exists for the prod canary. A worker token is a long-lived bearer
// credential that has to be minted by hand, kept in a Secret outside git and
// renewed by the canary itself, and a revoke_worker_token by telegram_id
// silently kills it along with every other token of that account (which is
// how the canary went down on 2026-11-13). A projected ServiceAccount token
// has none of those properties: kubelet issues it per pod for a dedicated
// audience, rotates it, and it dies with the pod. The mapping from the
// ServiceAccount to a Telegram account is server configuration, so the whole
// credential is declared in gitops and nothing secret is stored anywhere.
//
// Verification is local, against the cluster's own JWKS (the
// service-account-issuer-discovery endpoint every ServiceAccount may read), so
// the server needs no cluster-wide RBAC such as system:auth-delegator.
//
// The identity it produces is deliberately narrow: exactly one ServiceAccount
// subject, one Telegram id, and read-only scopes fixed in code. It is wired in
// front of /mcp only and is never consulted for any other route.
package k8ssa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// ProviderName is Identity.Provider for a ServiceAccount-authenticated call.
const ProviderName = "k8s-sa"

// DefaultMaxLifetime bounds exp-iat. kubelet issues projected tokens for at
// most the requested expirationSeconds; anything longer than this is not a
// projected pod token and is refused.
const DefaultMaxLifetime = time.Hour

const leeway = 30 * time.Second

// Scopes is the fixed, read-only grant of a ServiceAccount identity. It is not
// configurable on purpose: widening it would turn a probe credential into an
// account credential that no revocation tool can reach.
var Scopes = []string{"telegram:dialogs:read", "telegram:messages:read"}

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.ES256}

// KeySource returns the cluster's token signing keys. refresh asks for a fresh
// fetch, used once when a token names a key id the cached set lacks.
type KeySource interface {
	Keys(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error)
}

// UserStore is the subset of *db.Store the provider needs.
type UserStore interface {
	EnsureUserByTelegramID(ctx context.Context, tgID int64, username, displayName string) (int64, error)
}

// Config describes the one ServiceAccount this provider admits.
type Config struct {
	// Issuer must equal the token's iss exactly. It is also what routes a
	// bearer token to this provider rather than to the next one.
	Issuer string
	// Audience must be present in the token's aud. It must be dedicated to
	// this purpose, never the API server's own audience, so a token kubelet
	// mounts for talking to Kubernetes cannot be replayed here.
	Audience string
	// Subject is the exact sub, "system:serviceaccount:<ns>:<name>".
	Subject string
	// TelegramID is the account the identity acts as.
	TelegramID int64
	// MaxLifetime bounds exp-iat; zero means DefaultMaxLifetime.
	MaxLifetime time.Duration
	Keys        KeySource
	Store       UserStore
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func (c Config) validate() error {
	switch {
	case c.Issuer == "":
		return errors.New("issuer is required")
	case c.Audience == "":
		return errors.New("audience is required")
	case !strings.HasPrefix(c.Subject, "system:serviceaccount:") || strings.Count(c.Subject, ":") != 3:
		return fmt.Errorf("subject %q is not system:serviceaccount:<namespace>:<name>", c.Subject)
	case c.TelegramID <= 0:
		return errors.New("telegram id must be positive")
	case c.Keys == nil:
		return errors.New("key source is required")
	case c.Store == nil:
		return errors.New("user store is required")
	}
	return nil
}

// Provider authenticates bearer tokens issued by Config.Issuer and hands every
// other request to Next unchanged.
type Provider struct {
	cfg  Config
	next auth.Provider
}

// Wrap returns a provider that admits the configured ServiceAccount and
// delegates everything else to next.
func Wrap(next auth.Provider, cfg Config) (*Provider, error) {
	if next == nil {
		return nil, errors.New("k8ssa: next provider is required")
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("k8ssa: %w", err)
	}
	if cfg.MaxLifetime <= 0 {
		cfg.MaxLifetime = DefaultMaxLifetime
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Provider{cfg: cfg, next: next}, nil
}

// Unwrap implements auth.Wrapper so auth metrics keep the wrapped provider's
// label. Refusals of cluster tokens are rare (one canary) and share it.
func (p *Provider) Unwrap() auth.Provider { return p.next }

// kubernetesClaims is the private "kubernetes.io" claim of a projected token.
type kubernetesClaims struct {
	K8s struct {
		Namespace string `json:"namespace"`
		Pod       *struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
	} `json:"kubernetes.io"`
}

// Authenticate implements auth.Provider.
func (p *Provider) Authenticate(r *http.Request) (*auth.Identity, error) {
	raw, ok := bearer(r)
	if !ok || unverifiedIssuer(raw) != p.cfg.Issuer {
		return p.next.Authenticate(r)
	}
	// From here on the token claims to be ours: it is either accepted or
	// refused, never passed on to the next provider.
	id, err := p.verify(r.Context(), raw)
	if err != nil {
		return nil, fmt.Errorf("kubernetes service account token: %w", err)
	}
	return id, nil
}

func (p *Provider) verify(ctx context.Context, raw string) (*auth.Identity, error) {
	tok, err := jwt.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(tok.Headers) != 1 {
		return nil, errors.New("expected exactly one signature")
	}
	key, err := p.key(ctx, tok.Headers[0].KeyID)
	if err != nil {
		return nil, err
	}
	var std jwt.Claims
	var k8s kubernetesClaims
	if err := tok.Claims(key, &std, &k8s); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	now := p.cfg.Now()
	if std.Expiry == nil || std.IssuedAt == nil {
		return nil, errors.New("token must carry exp and iat")
	}
	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer:      p.cfg.Issuer,
		Subject:     p.cfg.Subject,
		AnyAudience: jwt.Audience{p.cfg.Audience},
		Time:        now,
	}, leeway); err != nil {
		return nil, err
	}
	if life := std.Expiry.Time().Sub(std.IssuedAt.Time()); life > p.cfg.MaxLifetime {
		return nil, fmt.Errorf("token lifetime %s exceeds %s: not a projected pod token", life, p.cfg.MaxLifetime)
	}
	// A projected token is bound to the pod that requested it. Requiring the
	// binding refuses legacy Secret-based and TokenRequest tokens that are not
	// tied to a running pod.
	if k8s.K8s.Pod == nil || k8s.K8s.Pod.UID == "" {
		return nil, errors.New("token is not bound to a pod")
	}
	uid, err := p.cfg.Store.EnsureUserByTelegramID(ctx, p.cfg.TelegramID, "", "")
	if err != nil {
		return nil, fmt.Errorf("ensure user: %w", err)
	}
	return &auth.Identity{
		UserID:     uid,
		Subject:    "tg:" + strconv.FormatInt(p.cfg.TelegramID, 10),
		TelegramID: p.cfg.TelegramID,
		Provider:   ProviderName,
		Scopes:     append([]string(nil), Scopes...),
		Jti:        std.ID,
	}, nil
}

func (p *Provider) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	for _, refresh := range []bool{false, true} {
		set, err := p.cfg.Keys.Keys(ctx, refresh)
		if err != nil {
			return nil, fmt.Errorf("signing keys: %w", err)
		}
		if k := pick(set, kid); k != nil {
			return k, nil
		}
	}
	return nil, fmt.Errorf("no signing key with kid %q", kid)
}

func pick(set *jose.JSONWebKeySet, kid string) *jose.JSONWebKey {
	if set == nil {
		return nil
	}
	if kid != "" {
		if ks := set.Key(kid); len(ks) > 0 {
			return &ks[0]
		}
		return nil
	}
	// No kid: accept only an unambiguous single-key set.
	if len(set.Keys) == 1 {
		return &set.Keys[0]
	}
	return nil
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(h[len(prefix):]), true
}

// unverifiedIssuer reads iss without verifying anything. It only routes the
// token; acceptance is decided by verify.
func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	return c.Iss
}
