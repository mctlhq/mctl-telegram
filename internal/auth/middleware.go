package auth

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Middleware authenticates each request through the provider. When required is
// false and the provider returns (nil, nil), the request proceeds with no
// Identity in context (anonymous mode for local-dev).
func Middleware(p Provider, required bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := p.Authenticate(r)
			if err != nil {
				slog.Warn("auth failed", "err", err)
				writeJSONError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			if id == nil && required {
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

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
