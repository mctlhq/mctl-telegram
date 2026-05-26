package web

import (
	"net/http"
	"strings"
)

// OriginGuard wraps the MCP handler with Origin-header validation
// (DNS-rebinding protection, required by Anthropic's connector directory).
//
// Policy:
//   - No Origin header → ALLOW. Server-to-server MCP clients (claude.ai,
//     MCP Inspector, curl) send no browser Origin; rejecting them would break
//     the connector. DNS-rebinding only applies to browser-originated requests,
//     which always carry an Origin.
//   - Origin present and in the allowlist → ALLOW.
//   - Origin present and not allowed → 403.
//
// allowed entries are origins (scheme://host[:port]); comparison is
// case-insensitive and ignores a trailing slash. An empty allowlist allows all
// origins (no-op) — callers default it to the PUBLIC_BASE_URL origin.
func OriginGuard(next http.Handler, allowed []string) http.Handler {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allowSet[normalizeOrigin(o)] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && len(allowSet) > 0 {
			if _, ok := allowSet[normalizeOrigin(origin)]; !ok {
				http.Error(w, "forbidden origin", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func normalizeOrigin(o string) string {
	return strings.ToLower(strings.TrimRight(strings.TrimSpace(o), "/"))
}
