package main

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/auth"

	"github.com/mctlhq/mctl-telegram/internal/config"
)

func workspaceOAuthScopes(cfg *config.Config) []string {
	if cfg.ToolFilter == config.TelegramWorkspaceReadOnly {
		return []string{"telegram:dialogs:read", "telegram:messages:read"}
	}
	return nil
}

func workspaceTelegramID(cfg *config.Config) int64 {
	if cfg.ToolFilter == config.TelegramWorkspaceReadOnly {
		return cfg.TGLoginClients[0]
	}
	return 0
}

// Match exact paths at the listener boundary, before any route or redirect
// can handle the request. Account setup uses the operator's separate path.
func serverRoutes(cfg *config.Config, next http.Handler) http.Handler {
	if cfg.ToolFilter != config.TelegramWorkspaceReadOnly {
		return next
	}
	resourceHost, issuerHost := "", ""
	if cfg.MCPResourceBaseURL != "" {
		resourceHost = strings.TrimPrefix(cfg.MCPResourceBaseURL, "https://")
		issuerHost = strings.TrimPrefix(strings.TrimRight(cfg.PublicBaseURL, "/"), "https://")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var expectedHost string
		switch r.URL.EscapedPath() {
		case cfg.MCPPath, "/.well-known/oauth-protected-resource" + cfg.MCPPath:
			expectedHost = resourceHost
		case "/.well-known/oauth-protected-resource":
			if resourceHost != "" {
				http.NotFound(w, r)
				return
			}
		case "/.well-known/oauth-authorization-server", "/oauth/authorize", "/oauth/telegram/callback", "/oauth/token", "/oauth/revoke", "/oauth/register":
			expectedHost = issuerHost
		case "/healthz", "/readyz":
		default:
			http.NotFound(w, r)
			return
		}
		if expectedHost != "" && !strings.EqualFold(r.Host, expectedHost) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type workspaceProvider struct {
	next       auth.Provider
	telegramID int64
	scopes     []string
}

func workspaceMCPProvider(cfg *config.Config, next auth.Provider) auth.Provider {
	if cfg.ToolFilter != config.TelegramWorkspaceReadOnly {
		return next
	}
	return workspaceProvider{next: next, telegramID: workspaceTelegramID(cfg), scopes: workspaceOAuthScopes(cfg)}
}

func (p workspaceProvider) Authenticate(r *http.Request) (*auth.Identity, error) {
	id, err := p.next.Authenticate(r)
	if err != nil || id == nil {
		return id, err
	}
	if id.TelegramID != p.telegramID || len(id.Groups) != 0 || len(id.Scopes) == 0 {
		return nil, errors.New("credential is outside the Workspace identity policy")
	}
	for _, scope := range id.Scopes {
		if !slices.Contains(p.scopes, scope) {
			return nil, errors.New("credential is outside the Workspace scope policy")
		}
	}
	return id, nil
}
