package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// Middleware authenticates each request through the provider. When required is
// false and the provider returns (nil, nil), the request proceeds with no
// Identity in context (anonymous mode for local-dev).
//
// m is optional (nil-safe): when non-nil, authentication failures are
// classified and counted in mctl_auth_failures_total{reason, provider}.
func Middleware(p Provider, required bool, m *metrics.Registry) func(http.Handler) http.Handler {
	providerLabel := providerName(p)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := p.Authenticate(r)
			if err != nil {
				slog.Warn("auth failed", "err", err)
				if m != nil {
					m.AuthFailuresTotal.WithLabelValues(classifyAuthError(err.Error()), providerLabel).Inc()
				}
				writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			if id == nil && required {
				if m != nil {
					m.AuthFailuresTotal.WithLabelValues("no_token", providerLabel).Inc()
				}
				w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram"`)
				writeJSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if id != nil {
				r = r.WithContext(With(r.Context(), id))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// classifyAuthError maps a well-known error string to one of the standard
// reason labels. The error strings are stable literals defined in
// sharedhmac/verifier.go and localjwt/issuer.go.
func classifyAuthError(msg string) string {
	switch {
	case strings.Contains(msg, "JWT expired"):
		return "jwt_expired"
	case strings.Contains(msg, "invalid JWT signature"):
		return "jwt_invalid_signature"
	case strings.Contains(msg, "unexpected JWT issuer"):
		return "jwt_invalid_issuer"
	case strings.Contains(msg, "JWT missing required audience"):
		return "jwt_missing_audience"
	case strings.Contains(msg, "JWT audience") && strings.Contains(msg, "does not match"):
		return "jwt_wrong_audience"
	case strings.Contains(msg, "Bearer"):
		return "bearer_scheme_error"
	default:
		return "other"
	}
}

// providerName returns a human-readable label for the Provider implementation.
// Used as the "provider" label in auth failure metrics. The result is derived
// from the concrete type name so it stays stable across deployments without
// requiring each Provider to implement an extra interface.
func providerName(p Provider) string {
	if p == nil {
		return "unknown"
	}
	// %T yields something like "*localjwt.Provider" or "*sharedhmac.Provider".
	t := strings.ToLower(fmt.Sprintf("%T", p))
	switch {
	case strings.Contains(t, "localjwt"):
		return "local-jwt"
	case strings.Contains(t, "sharedhmac"):
		return "shared-hmac"
	case strings.Contains(t, "localdev"):
		return "local-dev"
	default:
		return t
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
