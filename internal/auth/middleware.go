package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// ResourceMetadata carries the base URL and MCP mount path needed to point a
// 401 at this resource's RFC 9728 Protected Resource Metadata document via
// the WWW-Authenticate resource_metadata parameter. Zero value (BaseURL=="")
// omits resource_metadata entirely — matches prior behavior for any caller
// that doesn't wire one.
type ResourceMetadata struct {
	BaseURL string
	MCPPath string
}

// wwwAuthenticate builds the Bearer challenge for a 401. Extra RFC 6750 §3
// auth-param strings (e.g. `error="invalid_token"`) are appended in order, so
// the whole challenge grammar stays owned by this one function.
func (rm ResourceMetadata) wwwAuthenticate(requestPath string, params ...string) string {
	challenge := `Bearer realm="mctl-telegram"`
	if rm.BaseURL != "" {
		metadataURL := strings.TrimRight(rm.BaseURL, "/") + "/.well-known/oauth-protected-resource"
		if rm.MCPPath != "" && (requestPath == rm.MCPPath || strings.HasPrefix(requestPath, rm.MCPPath+"/")) {
			metadataURL += rm.MCPPath
		}
		challenge += `, resource_metadata="` + metadataURL + `"`
	}
	for _, p := range params {
		challenge += ", " + p
	}
	return challenge
}

// bearerErrorCode maps an authentication failure to its RFC 6750 §3.1 error
// code. A request whose Authorization header does not even use the Bearer
// scheme is a malformed request, not a bad token; everything else reaching
// this point is a token that failed to verify (expired, bad signature, wrong
// audience) and must tell the client to re-run the OAuth flow.
func bearerErrorCode(err error) string {
	if classifyAuthError(err.Error()) == "bearer_scheme_error" {
		return `error="invalid_request"`
	}
	return `error="invalid_token"`
}

// Machine-facing 401 messages. Exported so an UnauthorizedRenderer can
// branch on which rejection it is asked to present without re-matching the
// literal string: a reword here then breaks compilation at every renderer
// instead of silently flipping the rendered copy.
const (
	// MsgInvalidCredentials is the 401 for a token that failed to verify
	// (expired, bad signature, wrong audience) — the caller had credentials.
	MsgInvalidCredentials = "invalid credentials"
	// MsgAuthRequired is the 401 for a request that carried no credentials.
	MsgAuthRequired = "authentication required"
)

// UnauthorizedRenderer writes a non-JSON 401 body for browser navigations.
// The status and machine-facing msg match writeJSONError so HTML and JSON
// callers see the same rejection; only the presentation changes.
type UnauthorizedRenderer func(w http.ResponseWriter, r *http.Request, status int, msg string)

// Middleware authenticates each request through the provider. When required is
// false and the provider returns (nil, nil), the request proceeds with no
// Identity in context (anonymous mode for local-dev).
//
// m is optional (nil-safe): when non-nil, authentication failures are
// classified and counted in mctl_auth_failures_total{reason, provider}.
func Middleware(p Provider, required bool, m *metrics.Registry, rm ResourceMetadata) func(http.Handler) http.Handler {
	return middleware(p, required, m, rm, nil)
}

// MiddlewareWithHTML is Middleware plus an HTML 401 renderer for browser
// navigations (Accept: text/html without application/json). API clients
// keep the JSON {"error":...} contract: Accept: application/json,
// X-Requested-With: XMLHttpRequest, empty Accept, or */*.
func MiddlewareWithHTML(p Provider, required bool, m *metrics.Registry, rm ResourceMetadata, html UnauthorizedRenderer) func(http.Handler) http.Handler {
	return middleware(p, required, m, rm, html)
}

func middleware(p Provider, required bool, m *metrics.Registry, rm ResourceMetadata, html UnauthorizedRenderer) func(http.Handler) http.Handler {
	providerLabel := providerName(p)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := p.Authenticate(r)
			if err != nil {
				slog.Warn("auth failed", "err", err)
				if m != nil {
					m.AuthFailuresTotal.WithLabelValues(classifyAuthError(err.Error()), providerLabel).Inc()
				}
				w.Header().Set("WWW-Authenticate", rm.wwwAuthenticate(r.URL.Path, bearerErrorCode(err)))
				writeUnauthorized(w, r, http.StatusUnauthorized, MsgInvalidCredentials, html)
				return
			}
			if id == nil && required {
				if m != nil {
					m.AuthFailuresTotal.WithLabelValues("no_token", providerLabel).Inc()
				}
				w.Header().Set("WWW-Authenticate", rm.wwwAuthenticate(r.URL.Path))
				writeUnauthorized(w, r, http.StatusUnauthorized, MsgAuthRequired, html)
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

func writeUnauthorized(w http.ResponseWriter, r *http.Request, code int, msg string, html UnauthorizedRenderer) {
	if html == nil {
		writeJSONError(w, code, msg)
		return
	}
	// The body for this URL now depends on the request headers WantsJSON
	// reads. 401 is not heuristically cacheable and the HTML branch sets
	// Cache-Control: no-store, but a proxy configured to cache error
	// responses would otherwise be free to serve one representation to a
	// caller that asked for the other.
	AddNegotiationVary(w)
	if !WantsJSON(r) {
		html(w, r, code, msg)
		return
	}
	writeJSONError(w, code, msg)
}

// AddNegotiationVary declares the request headers WantsJSON inspects, so a
// cache keys the HTML and JSON representations of the same URL separately.
func AddNegotiationVary(w http.ResponseWriter) {
	w.Header().Add("Vary", "Accept")
	w.Header().Add("Vary", "X-Requested-With")
}

// WantsJSON reports whether the caller asked for a JSON error body rather
// than an HTML page. Browser navigations send Accept: text/html and must
// get HTML on human routes such as /telegram/connect/manage. API clients
// keep JSON when they send Accept: application/json, X-Requested-With:
// XMLHttpRequest, omit Accept, or send */* (curl's default).
func WantsJSON(r *http.Request) bool {
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true
	}
	a := strings.ToLower(accept)
	hasHTML := strings.Contains(a, "text/html")
	hasJSON := strings.Contains(a, "application/json")
	if hasHTML && !hasJSON {
		return false
	}
	return true
}
