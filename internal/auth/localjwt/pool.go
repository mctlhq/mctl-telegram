package localjwt

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// PoolAudience is the aud value of the managed-runtime pool credential: a
// claim-only token that lets the platform's own worker claim jobs across
// managed accounts (docs/adr/0008-managed-runtime.md).
const PoolAudience = "agent-pool"

// PoolSubjectPrefix prefixes the subject of a pool credential.
const PoolSubjectPrefix = "pool:"

var poolNameRE = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,62}$")

// ValidPoolName reports whether name is an acceptable pool name. Shared by
// the mint handler and the verifier so there is one rule.
func ValidPoolName(name string) bool { return poolNameRE.MatchString(name) }

// PoolProvider authenticates "agent-pool" credentials. It is deliberately a
// separate type from Provider: the pool belongs to no account, so it never
// resolves a user row, and its shape rules must not drift with Provider.
type PoolProvider struct {
	Secret          []byte
	ExpectedIssuer  string
	RevocationCache *RevocationCache
}

// PoolProviderConfig is the constructor input for NewPoolProvider.
type PoolProviderConfig struct {
	Secret          []byte
	ExpectedIssuer  string
	RevocationCache *RevocationCache
}

// NewPoolProvider validates inputs. A pool with no revocation path must not
// exist, so a nil RevocationCache is refused.
func NewPoolProvider(cfg PoolProviderConfig) (*PoolProvider, error) {
	if len(cfg.Secret) == 0 {
		return nil, errors.New("localjwt: pool provider secret required")
	}
	if cfg.ExpectedIssuer == "" {
		return nil, errors.New("localjwt: pool provider issuer required")
	}
	if cfg.RevocationCache == nil {
		return nil, errors.New("localjwt: pool provider requires a revocation cache")
	}
	return &PoolProvider{Secret: cfg.Secret, ExpectedIssuer: cfg.ExpectedIssuer, RevocationCache: cfg.RevocationCache}, nil
}

// checkPoolShape rejects any claim an account- or job-shaped token carries.
func checkPoolShape(c *Claims) (string, error) {
	switch {
	case c.TelegramID != 0:
		return "", errors.New("pool token must not carry a telegram id")
	case c.TelegramUsername != "":
		return "", errors.New("pool token must not carry a telegram username")
	case c.JobID != 0 || c.JobAttempt != 0 || c.ConversationID != 0 || len(c.JobTools) > 0:
		return "", errors.New("pool token must not carry job claims")
	case c.DeviceID != "" || c.ClientID != "" || c.Profile != "":
		return "", errors.New("pool token must not carry device, client or profile claims")
	case c.Jti == "":
		return "", errors.New("pool token requires a jti")
	case !strings.HasPrefix(c.Subject, PoolSubjectPrefix):
		return "", errors.New("pool token subject must start with pool:")
	}
	name := strings.TrimPrefix(c.Subject, PoolSubjectPrefix)
	if !ValidPoolName(name) {
		return "", errors.New("pool token has an invalid pool name")
	}
	return name, nil
}

// Authenticate accepts a Bearer token only (no cookie fallback: the pool is a
// headless credential). Returns (nil, nil) when no token is presented.
func (p *PoolProvider) Authenticate(r *http.Request) (*auth.Identity, error) {
	hdr := r.Header.Get("Authorization")
	if hdr == "" {
		return nil, nil
	}
	if !strings.HasPrefix(hdr, "Bearer ") {
		return nil, errors.New("Authorization header must use Bearer scheme")
	}
	tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	if tok == "" {
		return nil, nil
	}
	c, err := VerifyWithClaims(tok, p.Secret, p.ExpectedIssuer)
	if err != nil {
		if c != nil {
			return nil, &auth.AttributedError{Attr: attrFrom(c), Err: err}
		}
		return nil, err
	}
	if err := CheckAudience(c.Audience, PoolAudience, true); err != nil {
		return nil, &auth.AttributedError{Attr: attrFrom(c), Err: err}
	}
	name, err := checkPoolShape(c)
	if err != nil {
		return nil, &auth.AttributedError{Attr: attrFrom(c), Err: err}
	}
	// Telegram id 0: a blanket revocation (which refuses id <= 0) can never
	// match, so only the jti denylist can revoke the pool.
	revoked, err := p.RevocationCache.IsRevoked(r.Context(), c.Jti, 0, originAnchor(c))
	if err != nil {
		return nil, &auth.AttributedError{Attr: attrFrom(c), Err: fmt.Errorf("check pool token revocation: %w", err)}
	}
	if revoked {
		return nil, &auth.AttributedError{Attr: attrFrom(c), Err: errors.New("pool token revoked")}
	}
	return &auth.Identity{
		Subject:          c.Subject,
		Pool:             name,
		Provider:         "tg-mcp-pool",
		Jti:              c.Jti,
		OriginalIssuedAt: c.OriginalIssuedAt,
	}, nil
}
