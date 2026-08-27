// Package workertoken mints bounded, read-only bearer tokens for headless MCP
// workers (the canary, and any future non-interactive read-only client). It
// exists to replace hand-signing a year-long JWT with OAUTH_JWT_SIGNING_KEY
// for that use case: this path is admin-scoped, restricted to a fixed
// allowlist of read-only scopes, bounded by a TTL ceiling, and logged the
// same way every other admin mint is logged.
//
// This is intentionally its own package rather than living in internal/
// agentapi: the agent-token handler there is one admin action inside the
// larger communication-agent feature area (job queue, profiles, kill
// switch). A read-only MCP worker token is unrelated to that feature — it
// authenticates at /mcp, not /api/agent/v1 — so it gets its own small
// package, the same way internal/bridge has its own token handler file
// separate from internal/agentapi despite both being "admin mints a scoped
// JWT" patterns.
package workertoken

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// defaultWorkerTokenTTL and maxWorkerTokenTTL bound the lifetime of a minted
// worker token. Copied from internal/agentapi/tokenhandler.go's
// defaultAgentTokenTTL/maxAgentTokenTTL rather than invented fresh: that is
// the one place in this codebase that has already made the "how long should
// a non-interactive, admin-minted worker credential live" judgment call, and
// both numbers are orders of magnitude smaller than the year-long token this
// package replaces.
const (
	defaultWorkerTokenTTL = 30 * 24 * time.Hour
	maxWorkerTokenTTL     = 90 * 24 * time.Hour
)

// allowedReadOnlyScopes is the fixed allowlist a worker token's Scopes must
// be a subset of. It is deliberately kept local to this package rather than
// shared with internal/oauth/scopes.go's DCRNegotiableScopes: that list also
// contains write scopes ("telegram:messages:send", "telegram:messages:pin")
// and is scoped to the DCR-advertisement use case, not admin-mint
// validation — coupling the two would let a write scope silently reach this
// allowlist if DCRNegotiableScopes ever grew one. If a future PR adds a new
// telegram:*:read-shaped scope to DCRNegotiableScopes, add it here too or
// this endpoint will fail closed (reject a legitimate read-only request)
// rather than fail open.
var allowedReadOnlyScopes = []string{
	"telegram:dialogs:read",
	"telegram:messages:read",
}

// mintWorkerTokenRequest is the POST /api/mcp/worker-token request body.
type mintWorkerTokenRequest struct {
	// TelegramID is the TARGET account the minted token authenticates as,
	// matching mintAgentTokenRequest's TelegramID semantics: the calling
	// admin provisions a credential for a deployed worker, not for
	// themselves.
	TelegramID int64 `json:"telegram_id"`
	// Scopes, if supplied, must be a subset of allowedReadOnlyScopes. Omit
	// to get the default read-only scope set.
	Scopes   []string `json:"scopes,omitempty"`
	TTLHours int      `json:"ttl_hours,omitempty"`
}

// workerTokenResponse is the JSON body returned by POST /api/mcp/worker-token.
type workerTokenResponse struct {
	WorkerToken string `json:"worker_token"`
	ExpiresAt   string `json:"expires_at"`
}

// NewHandler returns the http.HandlerFunc for POST /api/mcp/worker-token.
// Admin-scoped: the caller must be authenticated by the standard MCP auth
// chain (auth.Middleware(provider, true, m), the same plain MCP provider
// mounted at /mcp — not selectAgentProvider/selectBridgeProvider) AND carry
// the "admin:users" scope, identical to NewAgentTokenHandler's gate.
//
// Minted tokens carry Audience: []string{"mcp-worker-ro"}. This aud value is
// new and distinct from the interactive flow's "no aud" and from
// "agent"/"bridge" — it is not used to route to a different endpoint (the
// token is verified by the same selectProvider provider already mounted at
// /mcp, exactly like any other locally-issued JWT), its purpose is forensic
// and future-proofing: it lets a log line, an audit query, or a future
// revocation list identify "this credential was minted by the bounded
// worker path" versus a normal user session. Because /mcp's OAUTH_JWT_AUDIENCE
// defaults to "" (audience check disabled) and OAUTH_JWT_AUDIENCE_REQUIRED
// defaults to false, this works with no config change today. When an
// operator does tighten OAUTH_JWT_AUDIENCE for defense-in-depth, the /mcp
// provider requires every token's aud list to CONTAIN that configured value
// (localjwt.CheckAudience), so mcpAudience — cfg.OAUTHJWTAudience at the
// wiring site — is included alongside "mcp-worker-ro" whenever it is set,
// the same way oauth.Server.mintAccessToken carries cfg.JWTAudience. Keep
// this in lockstep with cmd/server/main.go's selectProvider /
// cfg.OAUTHJWTAudience, the same way selectBridgeIssuer/selectAgentIssuer's
// doc comments flag their own issuer lockstep requirement.
func NewHandler(secret []byte, issuer, mcpAudience string) http.HandlerFunc {
	signer, signerErr := localjwt.NewIssuer(secret, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if signerErr != nil {
			slog.Error("worker token: signer init failed", "err", signerErr)
			writeJSONError(w, http.StatusInternalServerError, "worker token signer not configured")
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
		var req mintWorkerTokenRequest
		if err := decodeStrict(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.TelegramID <= 0 {
			writeJSONError(w, http.StatusBadRequest, "telegram_id required")
			return
		}

		scopes := req.Scopes
		if len(scopes) == 0 {
			scopes = allowedReadOnlyScopes
		}
		for _, s := range scopes {
			if !isAllowedReadOnlyScope(s) {
				writeJSONError(w, http.StatusBadRequest, "scope not in read-only allowlist: "+s)
				return
			}
		}

		ttl := defaultWorkerTokenTTL
		if req.TTLHours > 0 {
			ttl = time.Duration(req.TTLHours) * time.Hour
			if ttl > maxWorkerTokenTTL {
				ttl = maxWorkerTokenTTL
			}
		}

		audience := []string{workerAudience}
		if mcpAudience != "" {
			audience = append(audience, mcpAudience)
		}
		// OriginalIssuedAt anchors the renewal chain (see NewRenewHandler's
		// maxRenewalChain). Setting it here, at the one point where a human
		// admin is in the loop, is what lets the renew path extend this
		// credential without extending it forever.
		tok, err := signer.Mint(localjwt.Claims{
			Subject:          "tg:" + strconv.FormatInt(req.TelegramID, 10),
			TelegramID:       req.TelegramID,
			Scopes:           scopes,
			Audience:         audience,
			OriginalIssuedAt: time.Now().Unix(),
		}, ttl)
		if err != nil {
			slog.Error("worker token: sign failed", "admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to issue worker token")
			return
		}
		slog.Info("worker token minted", "admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "scopes", scopes, "ttl", ttl)
		writeJSON(w, http.StatusOK, workerTokenResponse{
			WorkerToken: tok,
			ExpiresAt:   time.Now().Add(ttl).UTC().Format(time.RFC3339),
		})
	}
}

func isAllowedReadOnlyScope(scope string) bool {
	for _, s := range allowedReadOnlyScopes {
		if s == scope {
			return true
		}
	}
	return false
}
