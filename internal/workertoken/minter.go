package workertoken

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
)

// ErrInvalidMintRequest wraps every rejection that is the CALLER's fault —
// an unknown purpose, a scope outside the selected allowlist, a missing
// telegram id. Transports map it to their own "bad request" (HTTP 400, an
// MCP tool error); anything else from Mint is an internal failure.
var ErrInvalidMintRequest = errors.New("invalid worker token mint request")

// MintRequest is the transport-independent form of a worker-token mint.
// Field meanings are identical to mintWorkerTokenRequest's, which is now a
// thin JSON shell around this.
type MintRequest struct {
	// TelegramID is the TARGET account the minted token authenticates as:
	// an admin provisions a credential for a worker or a Local Bridge
	// daemon, not for themselves.
	TelegramID int64
	// Scopes, when non-empty, must be a subset of the allowlist the Purpose
	// selects. Empty means "that purpose's defaults".
	Scopes []string
	// TTLHours <= 0 means DefaultTTL; anything above MaxTTL is clamped down
	// rather than rejected, matching the agent-token handler.
	TTLHours int
	// Purpose selects allowlist, defaults and audience marker. "" is the
	// read-only path; "local-bridge" adds send and pin. Any other value is
	// an ErrInvalidMintRequest — never a silent fall back to read-only.
	Purpose string
}

// Minted is everything a caller needs to hand a credential to a human and to
// find it again later: the token itself, when it dies, and the jti that
// revokes it.
type Minted struct {
	// TelegramID echoes the target the token authenticates as, so callers
	// can log and audit it without re-parsing the subject.
	TelegramID int64
	Token      string
	ExpiresAt  time.Time
	TTL        time.Duration
	Jti        string
	Scopes     []string
	// Purpose is the human-readable allowlist name ("read-only" /
	// "local-bridge") that the mint log line and the runbook use to tell a
	// send-capable credential from a read-only one.
	Purpose  string
	Audience []string
}

// Minter issues worker tokens. It exists so that the HTTP endpoint and the
// MCP tool are two transports over ONE policy rather than two implementations
// of the same policy: the scope allowlists, the TTL ceiling, the audience
// marker and the orig_iat/jti anchoring are security decisions, and a second
// copy of them is a second copy that can drift. Construct with NewMinter.
type Minter struct {
	signer      *localjwt.Issuer
	mcpAudience string
	now         func() time.Time
}

// NewMinter returns a Minter, or an error if the signing material is unusable
// — the same failure NewHandler used to defer until the first request.
func NewMinter(secret []byte, issuer, mcpAudience string) (*Minter, error) {
	signer, err := localjwt.NewIssuer(secret, issuer)
	if err != nil {
		return nil, fmt.Errorf("worker token signer: %w", err)
	}
	return &Minter{signer: signer, mcpAudience: mcpAudience, now: time.Now}, nil
}

// Mint validates req against this package's policy and issues the token.
// Caller-caused rejections wrap ErrInvalidMintRequest.
func (m *Minter) Mint(req MintRequest) (*Minted, error) {
	if req.TelegramID <= 0 {
		return nil, fmt.Errorf("%w: telegram_id required", ErrInvalidMintRequest)
	}

	var allowlist, defaultScopes []string
	var audienceMarker, purposeName string
	switch req.Purpose {
	case "":
		allowlist, defaultScopes = allowedReadOnlyScopes, allowedReadOnlyScopes
		audienceMarker, purposeName = workerAudience, "read-only"
	case "local-bridge":
		allowlist, defaultScopes = allowedLocalBridgeScopes, allowedLocalBridgeScopes
		audienceMarker, purposeName = workerBridgeAudience, "local-bridge"
	default:
		return nil, fmt.Errorf("%w: unknown purpose: %s", ErrInvalidMintRequest, req.Purpose)
	}

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = defaultScopes
	}
	for _, s := range scopes {
		if !isAllowedScope(s, allowlist) {
			return nil, fmt.Errorf("%w: scope not in %s allowlist: %s", ErrInvalidMintRequest, purposeName, s)
		}
	}

	ttl := defaultWorkerTokenTTL
	if req.TTLHours > 0 {
		ttl = time.Duration(req.TTLHours) * time.Hour
		if ttl > maxWorkerTokenTTL {
			ttl = maxWorkerTokenTTL
		}
	}

	audience := []string{audienceMarker}
	if m.mcpAudience != "" {
		audience = append(audience, m.mcpAudience)
	}
	jti, err := generateJti()
	if err != nil {
		return nil, err
	}
	issuedAt := m.now()
	// OriginalIssuedAt anchors the renewal chain (see NewRenewHandler's
	// maxRenewalChain): set once, at the point where a human admin is in the
	// loop, so renewals can extend this credential without extending it
	// forever. Jti is generated here and carried forward unchanged by every
	// renewal, so revoking it revokes the whole lineage.
	tok, err := m.signer.Mint(localjwt.Claims{
		Subject:          "tg:" + strconv.FormatInt(req.TelegramID, 10),
		TelegramID:       req.TelegramID,
		Scopes:           scopes,
		Audience:         audience,
		OriginalIssuedAt: issuedAt.Unix(),
		Jti:              jti,
	}, ttl)
	if err != nil {
		return nil, fmt.Errorf("sign worker token: %w", err)
	}
	return &Minted{
		TelegramID: req.TelegramID,
		Token:      tok,
		ExpiresAt:  issuedAt.Add(ttl).UTC(),
		TTL:        ttl,
		Jti:        jti,
		Scopes:     scopes,
		Purpose:    purposeName,
		Audience:   audience,
	}, nil
}

// LogMinted writes the canonical "worker token minted" line. Shared so that a
// token minted through the MCP tool is as findable in the logs as one minted
// over HTTP — an operator greps for one string, not two. purpose is its own
// field rather than inferred from the scope list because docs/runbook.md
// points at it to tell a send-capable credential from a read-only one, and
// jti is logged so an operator reading only the trail can still revoke this
// specific credential later.
func LogMinted(adminUserID int64, via string, mt *Minted) {
	slog.Info("worker token minted",
		"admin_user_id", adminUserID,
		"via", via,
		"target_tg_id", mt.TelegramID,
		"scopes", mt.Scopes,
		"ttl", mt.TTL,
		"expires_at", mt.ExpiresAt.Format(time.RFC3339),
		"purpose", mt.Purpose,
		"audience_marker", mt.Audience[0],
		"jti", mt.Jti,
	)
}
