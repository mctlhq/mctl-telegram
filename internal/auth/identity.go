package auth

import (
	"context"
	"net/http"
)

// Identity captures everything the MCP middleware needs to know about a
// caller. Subject is the canonical identifier — for Telegram-issued tokens it
// is "tg:<telegram_id>"; for the legacy GitHub-OAuth path it is the GitHub
// login. GitHubLogin remains a separate field for backwards compatibility
// with code that already reads it, but new code should prefer Subject and
// TelegramID/TelegramUsername.
type Identity struct {
	UserID           int64
	Subject          string
	GitHubLogin      string
	TelegramID       int64
	TelegramUsername string
	Email            string
	Provider         string
	Groups           []string
	Scopes           []string
	// Jti and OriginalIssuedAt carry the *credential's* revocation identity,
	// not the user's. They are populated by the local-jwt provider from the
	// verified token's claims and exist so that a handler which mints a
	// derived credential from this one (POST /api/bridge/token) can stamp the
	// child with its parent's identity. Without that, revoking the parent
	// leaves every child it already spawned valid for the child's whole TTL —
	// which is exactly the containment gap revoke_worker_token exists to
	// close. Empty/zero for credentials that carry neither claim.
	Jti              string
	OriginalIssuedAt int64
}

func (i *Identity) HasScope(s string) bool {
	if i == nil {
		return false
	}
	for _, sc := range i.Scopes {
		if sc == s {
			return true
		}
	}
	return false
}

// Provider resolves an Identity from an incoming HTTP request. Implementations
// MUST return (nil, nil) for anonymous (when allowed by caller) and a non-nil
// Identity on success. An error means the request looks authenticated but the
// credential is malformed/invalid.
type Provider interface {
	Authenticate(r *http.Request) (*Identity, error)
}

type ctxKey struct{}

func With(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

func From(ctx context.Context) *Identity {
	v, _ := ctx.Value(ctxKey{}).(*Identity)
	return v
}
