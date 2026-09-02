package workertoken

import (
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// maxRenewalChain bounds how long a single human-minted worker credential may
// be kept alive by renewals, measured from the moment it was first minted
// (Claims.OriginalIssuedAt, falling back to IssuedAt for tokens minted before
// that claim existed).
//
// This constant is the whole reason the renew path is safe to expose. Renewal
// on its own is unbounded extension: every individual renewal respects
// maxWorkerTokenTTL, but nothing stops the chain from continuing forever, so a
// leaked worker token would outlive the bound that #412 deliberately
// introduced. Anchoring to the original mint restores that bound — the
// credential still dies on a schedule a human controls, the schedule is just
// annual instead of monthly. When it expires, an admin re-mints through
// NewHandler exactly as before.
//
// A year is chosen to be long enough that renewal genuinely removes the
// operational chore this endpoint exists to remove, and short enough that a
// credential nobody remembers cannot outlive the deployment that issued it.
const maxRenewalChain = 365 * 24 * time.Hour

// workerAudience is the audience value that marks a token as minted by this
// package. Only tokens carrying it may be renewed: the middleware's generic
// audience policy (OAUTH_JWT_AUDIENCE) defaults to disabled and therefore
// cannot be relied on to tell a worker token from an ordinary user session.
// Without this check any authenticated interactive user could trade their
// session for a long-lived headless credential.
const workerAudience = "mcp-worker-ro"

// workerBridgeAudience is the audience value that marks a token as minted
// by this package with purpose "local-bridge" — a send-and-pin-capable
// worker token for a Local Bridge daemon. Like workerAudience, only tokens
// carrying it (or workerAudience) may be renewed, and which of the two is
// present determines which allowlist (allowedReadOnlyScopes vs
// allowedLocalBridgeScopes) governs the defense-in-depth scope check below.
const workerBridgeAudience = "mcp-worker-bridge"

// renewWorkerTokenRequest is the POST /api/mcp/worker-token/renew body. The
// body is optional; an empty request renews at defaultWorkerTokenTTL.
//
// There is deliberately no TelegramID or Scopes field: identity and
// privileges are copied from the presented token and cannot be influenced by
// the caller. That absence is the security property this endpoint rests on,
// and decodeStrict rejects unknown fields, so a client that tries to send
// either gets a 400 rather than having it silently ignored.
type renewWorkerTokenRequest struct {
	TTLHours int `json:"ttl_hours,omitempty"`
}

// NewRenewHandler returns the http.HandlerFunc for POST
// /api/mcp/worker-token/renew: a worker exchanges its own still-valid token
// for a fresh one with the same identity and scopes.
//
// Mounted behind the same plain MCP provider as NewHandler, but gated
// differently. NewHandler requires "admin:users" because it mints for an
// arbitrary target account; this handler requires no scope at all, because it
// cannot mint for anyone but the bearer. Every privilege-carrying field —
// subject, telegram id, scopes, audience — is taken from the verified claims
// of the presented token, so the endpoint is incapable of escalation: it
// cannot change identity, cannot widen scopes, and cannot exceed the mint
// path's own TTL ceiling. That is what makes it safe to hand to a headless
// worker, unlike granting that worker "admin:users" so it could call
// NewHandler on its own behalf — which would let a compromised worker mint a
// token for any Telegram account in the system.
//
// secret and issuer must match the values NewHandler was constructed with;
// they are re-verified here rather than read off auth.Identity because
// auth.Identity carries neither the audience nor the expiry, and both are
// needed to decide whether this particular credential may be renewed.
func NewRenewHandler(secret []byte, issuer, mcpAudience string) http.HandlerFunc {
	signer, signerErr := localjwt.NewIssuer(secret, issuer)
	return func(w http.ResponseWriter, r *http.Request) {
		if signerErr != nil {
			slog.Error("worker token renew: signer init failed", "err", signerErr)
			writeJSONError(w, http.StatusInternalServerError, "worker token signer not configured")
			return
		}
		if id := auth.From(r.Context()); id == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}

		// Re-read the raw bearer. auth.Middleware has already verified it
		// (signature, issuer, expiry) and would have returned 401 otherwise;
		// this second pass is only to recover the fields auth.Identity drops.
		raw := bearerToken(r)
		if raw == "" {
			writeJSONError(w, http.StatusUnauthorized, "bearer token required")
			return
		}
		claims, err := localjwt.Verify(raw, secret, issuer)
		if err != nil {
			// Reaching here means the token verified for the middleware but
			// not for us, which should be impossible; treat as unauthorized
			// rather than assuming why.
			slog.Warn("worker token renew: presented token failed re-verification", "err", err)
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}

		var (
			marker        string
			allowlist     []string
			allowlistName string
		)
		switch {
		case hasAudience(claims.Audience, workerAudience):
			marker = workerAudience
			allowlist = allowedReadOnlyScopes
			allowlistName = "read-only"
		case hasAudience(claims.Audience, workerBridgeAudience):
			marker = workerBridgeAudience
			allowlist = allowedLocalBridgeScopes
			allowlistName = "local-bridge"
		default:
			writeJSONError(w, http.StatusForbidden, "token is not a worker token")
			return
		}
		if claims.TelegramID <= 0 {
			writeJSONError(w, http.StatusForbidden, "token carries no telegram identity")
			return
		}
		// Defense in depth: a worker token should never hold a scope outside
		// its purpose's allowlist, but if one ever did, renewal must not be
		// the path that perpetuates it.
		for _, s := range claims.Scopes {
			if !isAllowedScope(s, allowlist) {
				slog.Warn("worker token renew: refusing token with scope outside allowlist",
					"target_tg_id", claims.TelegramID, "scope", s, "purpose_audience", marker)
				writeJSONError(w, http.StatusForbidden, "token carries a scope outside the "+allowlistName+" allowlist")
				return
			}
		}

		var req renewWorkerTokenRequest
		if r.ContentLength != 0 {
			if err := decodeStrict(w, r, &req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid request body")
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

		// Enforce the absolute ceiling, and clamp rather than reject when the
		// requested TTL would only overshoot it. Clamping matters: it means
		// the final renewal before the deadline still yields a usable token
		// and the worker keeps probing right up to the cutoff, instead of the
		// credential dying early because a renewal was refused wholesale.
		origin := originAnchor(claims)
		deadline := origin.Add(maxRenewalChain)
		now := time.Now()
		if !now.Before(deadline) {
			slog.Warn("worker token renew: refused, renewal chain exhausted",
				"target_tg_id", claims.TelegramID,
				"original_issued_at", origin.UTC().Format(time.RFC3339),
				"deadline", deadline.UTC().Format(time.RFC3339))
			writeJSONError(w, http.StatusForbidden,
				"renewal window exhausted; an administrator must mint a new worker token")
			return
		}
		if remaining := deadline.Sub(now); ttl > remaining {
			ttl = remaining
		}

		// Rebuild the audience from configuration rather than copying the
		// presented token's, so a deployment that later sets
		// OAUTH_JWT_AUDIENCE does not keep reissuing tokens without it. The
		// purpose marker present on the presented token (workerAudience or
		// workerBridgeAudience) is always carried forward, which is what
		// keeps the renewed token renewable in turn and preserves its
		// purpose.
		audience := []string{marker}
		if mcpAudience != "" {
			audience = append(audience, mcpAudience)
		}
		// Jti is carried forward unchanged so revoking it also revokes every
		// renewal of this credential. A token minted before Jti existed
		// presents claims.Jti == "" — this is the one point where such a
		// legacy token gains a jti, after which every subsequent renewal
		// carries that value forward in turn.
		jti := claims.Jti
		if jti == "" {
			var err error
			jti, err = generateJti()
			if err != nil {
				slog.Error("worker token renew: jti generation failed", "target_tg_id", claims.TelegramID, "err", err)
				writeJSONError(w, http.StatusInternalServerError, "failed to renew worker token")
				return
			}
		}
		tok, err := signer.Mint(localjwt.Claims{
			Subject:          "tg:" + strconv.FormatInt(claims.TelegramID, 10),
			TelegramID:       claims.TelegramID,
			Scopes:           claims.Scopes,
			Audience:         audience,
			OriginalIssuedAt: origin.Unix(),
			Jti:              jti,
		}, ttl)
		if err != nil {
			slog.Error("worker token renew: sign failed", "target_tg_id", claims.TelegramID, "err", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to renew worker token")
			return
		}
		expiresAt := now.Add(ttl).UTC().Format(time.RFC3339)
		// Same reasoning as the mint log: purpose is explicit so a renewed
		// send-capable credential stays greppable, not inferred. jti is
		// logged so a revocation issued against the original mint's jti is
		// still traceable through every renewal in the audit trail.
		slog.Info("worker token renewed",
			"target_tg_id", claims.TelegramID,
			"scopes", claims.Scopes,
			"ttl", ttl,
			"expires_at", expiresAt,
			"purpose", allowlistName,
			"audience_marker", marker,
			"original_issued_at", origin.UTC().Format(time.RFC3339),
			"chain_deadline", deadline.UTC().Format(time.RFC3339),
			"jti", jti)
		writeJSON(w, http.StatusOK, workerTokenResponse{
			WorkerToken: tok,
			ExpiresAt:   expiresAt,
		})
	}
}

// originAnchor returns the moment the credential chain started. Tokens minted
// before OriginalIssuedAt existed — including the one the production canary is
// running on today — carry only iat, so they anchor to their own issue time
// and get a full renewal window from there. That is the intended migration
// path: no operator action is needed for an in-flight token, and the first
// renewal writes the anchor forward explicitly.
func originAnchor(c *localjwt.Claims) time.Time {
	if c.OriginalIssuedAt > 0 {
		return time.Unix(c.OriginalIssuedAt, 0)
	}
	return time.Unix(c.IssuedAt, 0)
}

// bearerToken extracts the credential from an Authorization header, matching
// the scheme comparison auth.Middleware itself performs.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func hasAudience(aud []string, want string) bool {
	for _, a := range aud {
		if a == want {
			return true
		}
	}
	return false
}
