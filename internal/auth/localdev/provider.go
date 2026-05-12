// Package localdev is an auth.Provider that always returns a single, fixed
// Identity. Intended ONLY for local development with AUTH_REQUIRED=false; not
// safe to mount in any environment a non-operator can reach.
package localdev

import (
	"context"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

type Provider struct {
	Login string
	store *db.Store
}

func New(store *db.Store, login string) *Provider {
	return &Provider{store: store, Login: login}
}

func (p *Provider) Authenticate(r *http.Request) (*auth.Identity, error) {
	uid, err := p.store.EnsureUser(r.Context(), p.Login, "", "local-dev")
	if err != nil {
		return nil, err
	}
	return &auth.Identity{
		UserID:      uid,
		GitHubLogin: p.Login,
		Provider:    "local-dev",
		Groups:      []string{"platform-admins"},
		Scopes: []string{
			"telegram:dialogs:read",
			"telegram:messages:read",
			"telegram:messages:send",
			"admin:users",
		},
	}, nil
}

// EnsureSeedUser pre-creates the operator user so login flows can reference it
// before the first HTTP request lands.
func (p *Provider) EnsureSeedUser(ctx context.Context) (int64, error) {
	return p.store.EnsureUser(ctx, p.Login, "", "local-dev")
}
