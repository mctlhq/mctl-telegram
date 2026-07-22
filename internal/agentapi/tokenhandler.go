package agentapi

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// defaultAgentTokenTTL and maxAgentTokenTTL bound the lifetime of a minted
// agent token. Unlike a bridge token (1h, re-minted by an interactive user
// every session) an agent token is a long-lived worker credential — a
// headless process has no browser session to re-authenticate from — so the
// default is weeks, not hours. maxAgentTokenTTL still bounds it: an operator
// who wants to run a worker forever should re-mint, not carry an eternal
// token that a leaked env var would make eternal for an attacker too.
const (
	defaultAgentTokenTTL = 30 * 24 * time.Hour
	maxAgentTokenTTL     = 90 * 24 * time.Hour
)

type mintAgentTokenRequest struct {
	// TelegramID is the TARGET account the minted token authenticates as —
	// i.e. the owner whose communication agent a worker will operate for.
	// This is deliberately NOT the calling admin's own identity: an admin
	// provisions a credential for a deployed worker, they do not mint one for
	// themselves to use interactively (that is what /api/bridge/token is
	// for).
	TelegramID int64 `json:"telegram_id"`
	TTLHours   int   `json:"ttl_hours,omitempty"`
}

type agentTokenResponse struct {
	AgentToken string `json:"agent_token"`
	ExpiresAt  string `json:"expires_at"`
}

// NewAgentTokenHandler returns the http.HandlerFunc for POST
// /api/agent/token. Admin-scoped: the caller must be authenticated by the
// standard MCP auth chain (auth.Middleware(provider, true, m), same as every
// other admin-only route in this codebase) AND their Telegram id must be in
// adminTGIDs — the same allowlist that grants platform-admins scopes
// elsewhere (TG_LOGIN_ADMINS). This endpoint is intentionally NOT reachable
// by the agent surface itself: an agent worker cannot mint its own
// replacement or escalate to a different account's token.
func NewAgentTokenHandler(secret []byte, issuer string, adminTGIDs map[int64]bool) http.HandlerFunc {
	signer, signerErr := localjwt.NewIssuer(secret, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if signerErr != nil {
			slog.Error("agent token: signer init failed", "err", signerErr)
			writeJSONError(w, http.StatusInternalServerError, "agent token signer not configured")
			return
		}
		id := auth.From(r.Context())
		if id == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !adminTGIDs[id.TelegramID] {
			writeJSONError(w, http.StatusForbidden, "admin scope required")
			return
		}
		var req mintAgentTokenRequest
		if err := decodeStrict(r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.TelegramID <= 0 {
			writeJSONError(w, http.StatusBadRequest, "telegram_id required")
			return
		}
		ttl := defaultAgentTokenTTL
		if req.TTLHours > 0 {
			ttl = time.Duration(req.TTLHours) * time.Hour
			if ttl > maxAgentTokenTTL {
				ttl = maxAgentTokenTTL
			}
		}

		tok, err := signer.Mint(localjwt.Claims{
			Subject:    "tg:" + strconv.FormatInt(req.TelegramID, 10),
			TelegramID: req.TelegramID,
			Audience:   []string{"agent"},
		}, ttl)
		if err != nil {
			slog.Error("agent token: sign failed", "admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to issue agent token")
			return
		}
		slog.Info("agent token minted", "admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "ttl", ttl)
		writeJSON(w, http.StatusOK, agentTokenResponse{
			AgentToken: tok,
			ExpiresAt:  time.Now().Add(ttl).UTC().Format(time.RFC3339),
		})
	}
}
