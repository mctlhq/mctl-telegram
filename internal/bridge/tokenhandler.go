package bridge

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
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
// The minting always uses localjwt.Issuer, which produces an HS256 JWT
// carrying:
//   - iss = issuer (must match the bridge verifier's ExpectedIssuer)
//   - aud = "bridge"
//   - sub = Identity.Subject (falls back to GitHubLogin for legacy
//     identities)
//   - tg_id, tg_username = Identity.TelegramID / .TelegramUsername
//
// The tg_id field is REQUIRED in local-jwt mode: the bridge verifier
// (localjwt.Provider) looks up the user via EnsureUserByTelegramID(tg_id),
// and an unset value would resolve to 0 → "telegram id must be positive"
// → daemon registration rejected. Bridge tokens shared the sharedhmac
// signer previously, which never carried tg_id, breaking /bridge under
// local-jwt mode.
//
// Signing is HS256, identical algorithm to the legacy sharedhmac path —
// shared-hmac-legacy bridge verifiers accept these tokens as long as the
// issuer + audience + secret match.
func NewBridgeTokenHandler(provider auth.Provider, secret []byte, issuer string) http.HandlerFunc {
	signer, signerErr := localjwt.NewIssuer(secret, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if signerErr != nil {
			slog.Error("bridge token: signer init failed", "err", signerErr)
			writeJSONError(w, http.StatusInternalServerError, "bridge token signer not configured")
			return
		}
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

		tok, err := signer.Mint(localjwt.Claims{
			Subject:          subject,
			TelegramID:       id.TelegramID,
			TelegramUsername: id.TelegramUsername,
			Groups:           id.Groups,
			Audience:         []string{"bridge"},
			// Carry the parent credential's revocation identity into the
			// child. A bridge token is a delegation of the MCP token that
			// requested it, so revoking that token must revoke the bridge
			// tokens it already spawned — otherwise dropping a compromised
			// daemon's socket only makes it reconnect, and containment waits
			// out bridgeTokenTTL. orig_iat travels with jti so the blanket
			// revoke-by-telegram_id path still anchors the child to when the
			// credential chain actually started, not to this mint.
			Jti:              id.Jti,
			OriginalIssuedAt: id.OriginalIssuedAt,
			// DeviceID (issue-483): a bridge token minted from a device-bound
			// credential must carry the device_id into the child too, for the
			// same stated reason Jti/OriginalIssuedAt are copied above -- the
			// child is a delegation of the parent. Without this line the
			// daemon connects to the Hub with an empty deviceID,
			// hub.EvictDevice matches nothing, and device revocation
			// "succeeds" while the revoked daemon stays connected for the
			// bridge token's full 1-hour TTL. Empty when id.DeviceID is empty
			// (every non-device credential), same as the other two fields.
			DeviceID: id.DeviceID,
		}, bridgeTokenTTL)
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
