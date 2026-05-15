package bridge

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/sharedhmac"
)

const bridgeTokenTTL = time.Hour

// bridgeTokenResponse is the JSON body returned by POST /api/bridge/token.
type bridgeTokenResponse struct {
	BridgeToken string `json:"bridge_token"`
	ExpiresAt   string `json:"expires_at"`
}

// NewBridgeTokenHandler returns an http.HandlerFunc for POST /api/bridge/token.
//
// The caller must already be authenticated by the standard MCP JWT (using the
// auth.Middleware wired in main.go). This handler issues a new, short-lived JWT
// with aud="bridge" that the Local Bridge daemon uses to authenticate its
// websocket connection to GET /bridge.
//
// issuer is the value embedded in the JWT iss claim. It MUST match the
// ExpectedIssuer configured on the bridge auth.Provider in main.go,
// otherwise the bridge will reject every token this handler hands out. For
// AUTH_MODE=shared-hmac-legacy that is "https://api.mctl.ai"; for
// AUTH_MODE=local-jwt it is the deployment's PublicBaseURL (with trailing
// slash stripped). main.go calls selectBridgeIssuer to derive it.
//
// Signing reuses the HMAC routine from internal/auth/sharedhmac — it is the
// same canonical-JSON + HMAC-SHA256 algorithm regardless of which provider
// later verifies the token, so we can hand the same primitive out to both
// modes without depending on each provider's package.
func NewBridgeTokenHandler(provider auth.Provider, secret []byte, issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := auth.From(r.Context())
		if id == nil {
			// Should never reach here when Middleware(required=true) is in the
			// chain, but guard defensively.
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// Subject preference matches Identity's canonical-identifier order:
		// localjwt-issued tokens set Subject (e.g. "tg:<id>"); legacy
		// shared-hmac tokens populate GitHubLogin. Without this fallback a
		// local-jwt-authed caller would get an empty `sub` in the bridge
		// token and the bridge would later reject it because EnsureUser
		// rejects an empty login.
		subject := id.Subject
		if subject == "" {
			subject = id.GitHubLogin
		}

		tok, err := sharedhmac.IssueTestTokenWithAudience(
			secret,
			issuer,
			subject,
			id.Groups,
			[]string{"bridge"},
			bridgeTokenTTL,
		)
		if err != nil {
			slog.Error("bridge token: sign failed", "user_id", id.UserID, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to issue bridge token")
			return
		}

		expiresAt := time.Now().Add(bridgeTokenTTL).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(bridgeTokenResponse{
			BridgeToken: tok,
			ExpiresAt:   expiresAt,
		})
	}
}

// writeJSONError writes a JSON {"error": msg} body with the given status code.
// Duplicates the helper in internal/auth to avoid a cross-package dependency in
// the bridge package (which must not import internal/auth's middleware directly).
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
