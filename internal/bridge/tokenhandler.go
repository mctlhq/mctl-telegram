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
// Signing uses IssueTestTokenWithAudience from the sharedhmac package — despite
// the "Test" in the name the HMAC-SHA256 logic is identical to what mctl-api
// issues for normal MCP JWTs, just with a different audience and shorter TTL.
func NewBridgeTokenHandler(provider auth.Provider, secret []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := auth.From(r.Context())
		if id == nil {
			// Should never reach here when Middleware(required=true) is in the
			// chain, but guard defensively.
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// Derive the issuer from the provider if possible. We use the same
		// value that sharedhmac.New defaults to so tokens are accepted by a
		// bridge Provider configured with the same issuer.
		issuer := "https://api.mctl.ai"

		tok, err := sharedhmac.IssueTestTokenWithAudience(
			secret,
			issuer,
			id.GitHubLogin,
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
