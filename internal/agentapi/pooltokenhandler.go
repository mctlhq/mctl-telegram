package agentapi

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

type mintPoolTokenRequest struct {
	PoolName string `json:"pool_name"`
	TTLHours int    `json:"ttl_hours,omitempty"`
}

type poolTokenResponse struct {
	PoolToken string `json:"pool_token"`
	ExpiresAt string `json:"expires_at"`
	Jti       string `json:"jti"`
}

// poolTokenTTL clamps ttl_hours in hours rather than comparing the product
// of time.Duration, which overflows for absurd inputs and would mint an
// already-expired token.
func poolTokenTTL(hours int) time.Duration {
	if hours <= 0 {
		return defaultAgentTokenTTL
	}
	if int64(hours) > int64(maxAgentTokenTTL/time.Hour) {
		return maxAgentTokenTTL
	}
	return time.Duration(hours) * time.Hour
}

// NewPoolTokenHandler returns the http.HandlerFunc for POST
// /api/agent/pool-token: an admin (scope admin:users) mints the claim-only
// managed-runtime pool credential (aud=agent-pool). The token carries a jti
// so revoke_worker_token can kill it, and every job token derived from it.
func NewPoolTokenHandler(secret []byte, issuer string) http.HandlerFunc {
	signer, signerErr := localjwt.NewIssuer(secret, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if signerErr != nil {
			slog.Error("pool token: signer init failed", "err", signerErr)
			writeJSONError(w, http.StatusInternalServerError, "pool token signer not configured")
			return
		}
		id := auth.From(r.Context())
		if id == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !id.HasScope("admin:users") {
			writeJSONError(w, http.StatusForbidden, "admin scope required")
			return
		}
		var req mintPoolTokenRequest
		if err := decodeStrict(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !localjwt.ValidPoolName(req.PoolName) {
			writeJSONError(w, http.StatusBadRequest, "invalid pool_name")
			return
		}
		ttl := poolTokenTTL(req.TTLHours)
		jti, err := workertoken.GenerateJti()
		if err != nil {
			slog.Error("pool token: jti failed", "admin_user_id", id.UserID, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to issue pool token")
			return
		}
		now := time.Now()
		tok, err := signer.Mint(localjwt.Claims{
			Subject:          localjwt.PoolSubjectPrefix + req.PoolName,
			Audience:         []string{localjwt.PoolAudience},
			Jti:              jti,
			IssuedAt:         now.Unix(),
			OriginalIssuedAt: now.Unix(),
		}, ttl)
		if err != nil {
			slog.Error("pool token: sign failed", "admin_user_id", id.UserID, "pool", req.PoolName, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to issue pool token")
			return
		}
		expires := now.Add(ttl).UTC()
		slog.Info("pool token minted",
			"admin_user_id", id.UserID,
			"via", "http",
			"pool", req.PoolName,
			"ttl", ttl,
			"expires_at", expires.Format(time.RFC3339),
			"audience_marker", localjwt.PoolAudience,
			"jti", jti,
		)
		writeJSON(w, http.StatusOK, poolTokenResponse{
			PoolToken: tok,
			ExpiresAt: expires.Format(time.RFC3339),
			Jti:       jti,
		})
	}
}
