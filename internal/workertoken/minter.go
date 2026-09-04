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

	ttl := clampTTL(req.TTLHours)

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

// DeviceMintRequest is the transport-independent form of a self-service
// Local Bridge device-credential mint (issue-483). Unlike MintRequest, the
// caller supplies Jti and OriginalIssuedAt directly rather than having Mint
// generate them: a PoP refresh has to stamp the SAME lineage values every
// time (local_bridge_devices.current_jti / credential_issued_at), and a
// MintForDevice that generated its own would silently reintroduce a fresh
// jti per refresh -- reopening exactly the "previous credential survives
// revocation for its remaining TTL" gap this design exists to close. The
// caller (internal/oauth's issuance/refresh handlers) passes a freshly
// generated jti only at first issuance, and the stored one on every later
// refresh.
type DeviceMintRequest struct {
	// TelegramID is the device's OWNING account -- the identity the minted
	// credential authenticates as.
	TelegramID int64
	// DeviceID names the local_bridge_devices row this credential is bound
	// to. Always stamped into Claims.DeviceID.
	DeviceID string
	// Scopes is the FULL, caller-computed scope set -- no purpose-default
	// lookup here, unlike Mint. First issuance always passes
	// allowedReadOnlyScopes regardless of the account's send_enabled value
	// (T3); refresh derives it fresh from a live send_enabled read every
	// call (T5). Every entry must be a member of allowedLocalBridgeScopes.
	Scopes []string
	// Jti is carried into the token UNCHANGED -- see the type doc comment.
	// Required.
	Jti string
	// OriginalIssuedAt is carried into the token UNCHANGED -- the anchor
	// written once at first issuance and read back from
	// local_bridge_devices.credential_issued_at on every refresh. Required
	// (non-zero).
	OriginalIssuedAt time.Time
	// TTLHours <= 0 means defaultDeviceCredentialTTL; anything above
	// maxDeviceCredentialTTL/time.Hour is clamped down, matching Mint's
	// clampTTL contract but against the device-scale ceiling.
	TTLHours int
}

// MintForDevice issues a self-service Local Bridge device credential: an
// hours-scale-TTL, device-bound token distinguishable at the audience level
// from both admin-minted worker-token purposes (see workerDeviceAudience in
// renewhandler.go). Shares allowedLocalBridgeScopes validation and most of
// the Claims construction with Mint, but never calls NewHandler's admin-only
// HTTP path and is reachable only from internal/oauth's PoP-gated issuance/
// refresh endpoints.
func (m *Minter) MintForDevice(req DeviceMintRequest) (*Minted, error) {
	if req.TelegramID <= 0 {
		return nil, fmt.Errorf("%w: telegram_id required", ErrInvalidMintRequest)
	}
	if req.DeviceID == "" {
		return nil, fmt.Errorf("%w: device_id required", ErrInvalidMintRequest)
	}
	if req.Jti == "" {
		return nil, fmt.Errorf("%w: jti required", ErrInvalidMintRequest)
	}
	if req.OriginalIssuedAt.IsZero() {
		return nil, fmt.Errorf("%w: original_issued_at required", ErrInvalidMintRequest)
	}
	for _, s := range req.Scopes {
		if !isAllowedScope(s, allowedLocalBridgeScopes) {
			return nil, fmt.Errorf("%w: scope not in local-bridge allowlist: %s", ErrInvalidMintRequest, s)
		}
	}

	ttl := clampDeviceTTL(req.TTLHours)

	audience := []string{workerDeviceAudience}
	if m.mcpAudience != "" {
		audience = append(audience, m.mcpAudience)
	}
	tok, err := m.signer.Mint(localjwt.Claims{
		Subject:          "tg:" + strconv.FormatInt(req.TelegramID, 10),
		TelegramID:       req.TelegramID,
		Scopes:           req.Scopes,
		Audience:         audience,
		OriginalIssuedAt: req.OriginalIssuedAt.Unix(),
		Jti:              req.Jti,
		DeviceID:         req.DeviceID,
	}, ttl)
	if err != nil {
		return nil, fmt.Errorf("sign device credential: %w", err)
	}
	issuedAt := m.now()
	return &Minted{
		TelegramID: req.TelegramID,
		Token:      tok,
		ExpiresAt:  issuedAt.Add(ttl).UTC(),
		TTL:        ttl,
		Jti:        req.Jti,
		Scopes:     req.Scopes,
		Purpose:    "local-bridge-device",
		Audience:   audience,
	}, nil
}

// clampDeviceTTL is clampTTL's device-credential-scale counterpart: same
// overflow-safety reasoning (compare in hours, not the multiplied
// nanosecond product), different ceiling.
func clampDeviceTTL(hours int) time.Duration {
	if hours <= 0 {
		return defaultDeviceCredentialTTL
	}
	if int64(hours) > int64(maxDeviceCredentialTTL/time.Hour) {
		return maxDeviceCredentialTTL
	}
	return time.Duration(hours) * time.Hour
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

// clampTTL turns an admin-supplied ttl_hours into a bounded lifetime.
// The ceiling is compared in hours rather than against the product, because
// time.Duration(hours) * time.Hour overflows int64 nanoseconds somewhere above
// 2.5M hours and wraps negative — which sails past a "> maxWorkerTokenTTL"
// check and mints a token that is already expired. A caller asking for an
// absurd lifetime should get the ceiling, the same as one asking for a merely
// excessive one.
func clampTTL(hours int) time.Duration {
	if hours <= 0 {
		return defaultWorkerTokenTTL
	}
	if int64(hours) > int64(maxWorkerTokenTTL/time.Hour) {
		return maxWorkerTokenTTL
	}
	return time.Duration(hours) * time.Hour
}
