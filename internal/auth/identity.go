package auth

import (
	"context"
	"net/http"
)

type Identity struct {
	UserID      int64
	GitHubLogin string
	Email       string
	Provider    string
	Groups      []string
	Scopes      []string
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
