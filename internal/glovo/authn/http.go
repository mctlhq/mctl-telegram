package authn

import (
	"encoding/json"
	"mime"
	"net/http"
	"strings"
)

// MetadataPath is the RFC 9728 path for the /mcp resource.
const MetadataPath = "/.well-known/oauth-protected-resource/mcp"

// MetadataHandler serves RFC 9728 protected-resource metadata. The
// authorization server serves its own discovery; the facade only points to it.
func MetadataHandler(resource, authorizationServer string, scopes []string) http.Handler {
	body, _ := json.Marshal(map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{authorizationServer},
		"scopes_supported":         scopes,
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "mctl Glovo MCP",
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}

// Middleware authenticates the request, stores the principal in the context
// and refuses otherwise. onFailure receives a closed-set reason.
func Middleware(v *Verifier, metadataURL string, scopes []string, onFailure func(reason string)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fail := func(e *Error) {
				if onFailure != nil {
					onFailure(e.Reason)
				}
				writeChallenge(w, e, metadataURL, scopes)
			}
			// RFC 6750 allows the token in the query or form body; this
			// resource refuses both, and never reads the query for anything.
			if _, ok := r.URL.Query()["access_token"]; ok {
				if onFailure != nil {
					onFailure(ReasonQueryToken)
				}
				http.Error(w, "bearer token must be sent in the Authorization header", http.StatusBadRequest)
				return
			}
			if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt == "application/x-www-form-urlencoded" {
				if onFailure != nil {
					onFailure(ReasonFormToken)
				}
				http.Error(w, "unsupported content type", http.StatusBadRequest)
				return
			}
			h := r.Header.Get("Authorization")
			scheme, tok, ok := strings.Cut(h, " ")
			if h == "" || !ok || !strings.EqualFold(scheme, "Bearer") {
				e := &Error{ReasonMissing, http.StatusUnauthorized}
				if h != "" {
					e.Reason = ReasonUnsupported
				}
				fail(e)
				return
			}
			p, err := v.Verify(r.Context(), strings.TrimSpace(tok))
			if err != nil {
				e, _ := err.(*Error)
				if e == nil {
					e = &Error{ReasonMalformed, http.StatusUnauthorized}
				}
				fail(e)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p, strings.TrimSpace(tok))))
		})
	}
}

func writeChallenge(w http.ResponseWriter, e *Error, metadataURL string, scopes []string) {
	var h string
	switch {
	case e.Status == http.StatusForbidden:
		h = `Bearer error="insufficient_scope", scope="` + strings.Join(scopes, " ") + `", resource_metadata="` + metadataURL + `"`
	case e.Reason == ReasonMissing || e.Reason == ReasonUnsupported:
		h = `Bearer resource_metadata="` + metadataURL + `"`
	default:
		h = `Bearer error="invalid_token", resource_metadata="` + metadataURL + `"`
	}
	w.Header().Set("WWW-Authenticate", h)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(e.Status), e.Status)
}
