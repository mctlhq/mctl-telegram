package oauth

// local_bridge_credential.go implements self-service Local Bridge device
// credential issuance and PoP refresh (issue #483, sub-issue 3 of 4 in the
// Local Bridge / M4 effort). It depends on #481's local_bridge_devices
// registry and #482's activation flow (local_bridge_activate.go), which
// registers a device row with a public key but stops short of ever handing
// the device a usable credential.
//
// Three unauthenticated-but-device_id-scoped endpoints:
//
//   - POST /api/local-bridge/devices/{device_id}/nonce mints a fresh,
//     single-use, short-lived nonce for that device_id.
//   - POST /api/local-bridge/devices/{device_id}/credential is FIRST
//     issuance: presents {nonce, signature}, verified against the device's
//     stored Ed25519 public key. On success it atomically claims the
//     device's ONE credential lineage slot (local_bridge_devices.current_jti)
//     and mints an hours-scale-TTL, device-bound, ALWAYS-read-only
//     credential -- regardless of the account's current send_enabled value.
//   - POST /api/local-bridge/devices/{device_id}/refresh is every
//     SUBSEQUENT credential for that device: same PoP primitive, but
//     scopes are derived FRESH from a live send_enabled read every call,
//     and the jti/OriginalIssuedAt are the ones claimed at first issuance,
//     carried forward unchanged -- never regenerated.
//
// See platform-gitops/agents-state/mctl-telegram/proposals/
// issue-483-feat-local-bridge-owner-send-consent-dev/design.md for the full
// rationale, especially "Issuance: self-service device credential mint" and
// "Refresh: PoP-gated, state-derived scopes".

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/workertoken"
)

// deviceReadOnlyScopes / deviceSendPinScopes mirror internal/workertoken's
// allowedReadOnlyScopes / the send+pin subset of allowedLocalBridgeScopes.
// Deliberately duplicated rather than exported+imported -- internal/
// workertoken already treats its allowlists as private mint-validation
// policy (see that package's own doc comment on why it does not share
// DCRNegotiableScopes), and MintForDevice's own allowlist check is what
// actually enforces the boundary regardless of what this package computes;
// a drift here would fail closed (MintForDevice rejects), not open.
var (
	deviceReadOnlyScopes = []string{"telegram:dialogs:read", "telegram:messages:read"}
	deviceSendPinScopes  = []string{"telegram:messages:send", "telegram:messages:pin"}
)

// devicePoPGenericRejection is the single, byte-identical message returned
// for every PoP rejection at /credential and /refresh: unknown device,
// revoked device, expired/replayed/wrong-device nonce, malformed or absent
// stored public key, or a signature that fails to verify. Deliberately
// generic -- see T4/T4b -- so none of these distinguishable failure modes
// becomes an oracle for probing device_id existence or key material.
const devicePoPGenericRejection = "invalid or revoked device"

// errDevicePoPFailed is the internal sentinel verifyDevicePoP returns for
// every rejection reason; handlers never inspect it beyond "did this fail",
// which is what keeps the generic-rejection property enforced by
// construction rather than by every call site remembering to collapse
// distinct errors into one message.
var errDevicePoPFailed = errors.New("device proof-of-possession failed")

// deviceNonce is one pending, unconsumed PoP nonce. Server.deviceNonces is
// keyed by device_id: at most one live nonce per device at a time, so
// minting a new one supersedes whatever was pending (a device that abandons
// a nonce mid-flow does not leak a slot -- the next mint call reclaims it).
type deviceNonce struct {
	value     string
	createdAt time.Time
	expiresAt time.Time
}

// devicePoPRequest is the body of both /credential and /refresh: the nonce
// obtained from /nonce, and an Ed25519 signature over
// device_id + "." + nonce using the device's private key, base64
// (standard, padded) encoded.
type devicePoPRequest struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// deviceCredentialResponse is the JSON body returned by both /credential and
// /refresh -- shaped like workertoken's own mint response, since this IS a
// worker-token mint under the hood, just device-scoped.
type deviceCredentialResponse struct {
	WorkerToken string `json:"worker_token"`
	ExpiresAt   string `json:"expires_at"`
	Jti         string `json:"jti"`
}

// ----- POST /api/local-bridge/devices/{device_id}/nonce -----

func (s *Server) handleDeviceNonce(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	if deviceID == "" || len(deviceID) > 128 {
		s.writeActivateError(w, http.StatusBadRequest, "invalid device_id")
		return
	}
	ip := s.clientIP(r)
	if s.activationFailBudgetSpent(ip) {
		s.writeActivateError(w, http.StatusForbidden, devicePoPGenericRejection)
		return
	}
	// Resolve the device BEFORE minting anything. Without this the endpoint
	// hands a nonce to any string at all, and the capacity bound below turns
	// into the attack: an attacker cycling through random device_id values
	// fills the map and then evicts a legitimate nonce with every further
	// request, so no real device can ever complete a PoP round trip. Issuance
	// and refresh both stop working, for everyone, from an unauthenticated
	// endpoint. A device_id is 128 bits of crypto/rand, so requiring a real
	// one is what makes the flood cost the attacker something.
	//
	// Failures here are indistinguishable from every other failure on this
	// path, and are charged to the caller's budget: probing device_id values
	// is exactly what the budget is for.
	device, derr := s.store.GetDevice(r.Context(), deviceID)
	known := derr == nil && device.RevokedAt == nil
	if !known {
		// Charge the probe. The response itself is unchanged -- see below.
		s.recordActivationFailure(ip)
	}

	nonce := randomToken(24)
	ttl := s.cfg.DeviceNonceTTL
	now := s.clock()

	if !known {
		// An unknown or revoked device_id still gets a well-formed nonce, and
		// it is deliberately NOT stored. Two properties have to hold at once
		// and only this shape gives both:
		//
		//   - No oracle. Answering differently here would let an attacker
		//     learn which device_id values exist from the nonce endpoint
		//     alone, one step earlier than the credential endpoint, which
		//     collapses "unknown device" and "wrong key" into one generic
		//     rejection precisely so it cannot be told apart. The handed-out
		//     nonce fails at that step exactly as it did before.
		//   - No flood. Storing it is what made the capacity bound an attack:
		//     an attacker cycling random device_id values filled the map and
		//     then evicted a live nonce with every further request, so no real
		//     device could complete a PoP round trip -- issuance and refresh
		//     dead for everyone, from an unauthenticated endpoint. A
		//     device_id is 128 bits of crypto/rand, so occupying a slot now
		//     requires already knowing one.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"nonce":      nonce,
			"expires_in": int(ttl.Seconds()),
		})
		return
	}

	s.mu.Lock()
	// Bound the map before adding to it -- this endpoint is unauthenticated
	// by necessity (see the package doc comment), so an attacker cycling
	// through distinct device_id values could otherwise grow process memory
	// without limit. Evicting the GLOBAL oldest entry (not scoped to this
	// requester, unlike activation's per-IP-first eviction) is acceptable
	// here: a nonce is a few seconds of state for a device that has not yet
	// completed a PoP round trip, so evicting a stranger's costs them one
	// retried nonce mint, not a stranded multi-step flow.
	if s.cfg.MaxPendingDeviceNonces > 0 && len(s.deviceNonces) >= s.cfg.MaxPendingDeviceNonces {
		if _, exists := s.deviceNonces[deviceID]; !exists {
			// Expired entries first: they are already dead and evicting one
			// costs nobody anything. Only if none are expired is the map
			// genuinely full, and then a newcomer is refused rather than
			// allowed to displace a live nonce -- the same rule
			// handleActivateStart follows, for the same reason. Evicting the
			// global oldest instead would mean whoever asks last always wins,
			// which is the flood's whole mechanism.
			var evicted bool
			for k, n := range s.deviceNonces {
				if now.After(n.expiresAt) {
					delete(s.deviceNonces, k)
					evicted = true
					break
				}
			}
			if !evicted {
				s.mu.Unlock()
				w.Header().Set("Retry-After", "5")
				s.writeActivateError(w, http.StatusServiceUnavailable,
					"too many device verifications in progress, try again shortly")
				return
			}
		}
	}
	s.deviceNonces[deviceID] = &deviceNonce{
		value:     nonce,
		createdAt: now,
		expiresAt: now.Add(ttl),
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nonce":      nonce,
		"expires_in": int(ttl.Seconds()),
	})
}

// ----- shared PoP verification (credential + refresh) -----

// verifyDevicePoP consumes deviceID's pending nonce (single lookup+delete,
// so a nonce is spent exactly once regardless of outcome) and verifies
// signatureB64 is a valid Ed25519 signature over device_id+"."+nonce under
// the device's stored public key. Every failure -- unknown device, revoked
// device, expired/replayed/wrong-device nonce, malformed/absent stored key,
// bad signature -- returns errDevicePoPFailed and nothing else, so a caller
// cannot distinguish "wrong key" from "unknown device" from "expired nonce".
//
// The stored public key's length AND algorithm are checked BEFORE calling
// ed25519.Verify: that primitive panics (not a returned error) when the key
// is not exactly ed25519.PublicKeySize bytes, so a row whose device_pubkey
// is NULL, truncated, or over-long -- reachable by anyone who can name a
// device_id -- would take the handler down instead of rejecting the
// request. See T4b.
func (s *Server) verifyDevicePoP(r *http.Request, deviceID, nonce, signatureB64 string) (*db.Device, error) {
	if deviceID == "" || nonce == "" || signatureB64 == "" {
		return nil, errDevicePoPFailed
	}

	s.mu.Lock()
	n, ok := s.deviceNonces[deviceID]
	if ok {
		delete(s.deviceNonces, deviceID)
	}
	s.mu.Unlock()
	if !ok || s.clock().After(n.expiresAt) || !constantTimeStringEqual(n.value, nonce) {
		return nil, errDevicePoPFailed
	}

	device, err := s.store.GetDevice(r.Context(), deviceID)
	if err != nil {
		// Covers db.ErrDeviceNotFound and any other lookup failure alike --
		// neither is disclosed beyond the generic rejection.
		return nil, errDevicePoPFailed
	}
	if device.RevokedAt != nil {
		return nil, errDevicePoPFailed
	}
	// Guard BEFORE ed25519.Verify -- see the doc comment above. A row that
	// should not exist (no pubkey, wrong length, unrecognised algo) is
	// rejected here, not panicked on.
	if device.DevicePubkeyAlgo != "ed25519" || len(device.DevicePubkey) != ed25519.PublicKeySize {
		return nil, errDevicePoPFailed
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errDevicePoPFailed
	}
	msg := []byte(deviceID + "." + nonce)
	if !ed25519.Verify(ed25519.PublicKey(device.DevicePubkey), msg, sig) {
		return nil, errDevicePoPFailed
	}
	return device, nil
}

// decodeDevicePoPRequest reads and validates the {nonce, signature} body
// shared by /credential and /refresh. Returns a user-facing 400 message
// (empty when the body decoded fine) so callers can distinguish a
// malformed-request 400 from a PoP-verification 403.
func decodeDevicePoPRequest(r *http.Request) (devicePoPRequest, string) {
	var req devicePoPRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&req); err != nil {
		return req, "invalid JSON body"
	}
	if strings.TrimSpace(req.Nonce) == "" || strings.TrimSpace(req.Signature) == "" {
		return req, "nonce and signature are required"
	}
	return req, ""
}

// ----- POST /api/local-bridge/devices/{device_id}/credential (issuance) -----

func (s *Server) handleDeviceCredential(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	req, badReq := decodeDevicePoPRequest(r)
	if badReq != "" {
		s.writeActivateError(w, http.StatusBadRequest, badReq)
		return
	}

	ip := s.clientIP(r)
	if s.activationFailBudgetSpent(ip) {
		s.writeActivateError(w, http.StatusForbidden, devicePoPGenericRejection)
		return
	}

	device, err := s.verifyDevicePoP(r, deviceID, req.Nonce, req.Signature)
	if err != nil {
		s.recordActivationFailure(ip)
		s.store.LogToolCall(r.Context(), 0, "local_bridge_device_issue", "", "error", devicePoPGenericRejection, "")
		s.writeActivateError(w, http.StatusForbidden, devicePoPGenericRejection)
		return
	}

	telegramID, err := s.store.GetTelegramID(r.Context(), device.UserID)
	if err != nil || telegramID <= 0 {
		slog.Error("local bridge device issue: resolve telegram id failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// randomToken panics on a crypto/rand failure, matching this package's
	// existing convention (see randomToken's doc comment) rather than
	// threading an error return through every caller in this file.
	jti := randomToken(16)
	issuedAt := s.clock()

	// The conditional claim IS the concurrency control: two concurrent first
	// issuances for the same device_id both pass PoP (a nonce is consumed by
	// only one of them in practice, but even if both somehow reached here,
	// e.g. via two different valid nonces minted back to back) race this
	// UPDATE, and exactly one wins. The row is the lock -- nothing here
	// depends on both requests reaching this process. See T5d/T5e and
	// db.Store.ClaimDeviceCredentialLineage's doc comment.
	won, err := s.store.ClaimDeviceCredentialLineage(r.Context(), deviceID, jti, issuedAt)
	if err != nil {
		slog.Error("local bridge device issue: claim lineage failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !won {
		// Lost the claim (a concurrent first issuance already won) or the
		// device was revoked in the same instant (the conditional UPDATE's
		// revoked_at IS NULL predicate catches both, T5e). Refuse with no
		// credential minted; the device retries and, if it already has a
		// lineage, the refresh endpoint is the path forward.
		s.store.LogToolCall(r.Context(), device.UserID, "local_bridge_device_issue", "", "error", "lineage already claimed or device revoked", "")
		s.writeActivateError(w, http.StatusConflict, "device credential already issued for this device, or the device was just revoked -- retry via the refresh endpoint")
		return
	}

	mt, err := s.deviceMinter.MintForDevice(workertoken.DeviceMintRequest{
		TelegramID: telegramID,
		DeviceID:   deviceID,
		// ALWAYS read-only at first issuance, regardless of the account's
		// current send_enabled -- T3. State-derived send/pin scope is what
		// refresh is for.
		Scopes:           deviceReadOnlyScopes,
		Jti:              jti,
		OriginalIssuedAt: issuedAt,
	})
	if err != nil {
		// Should not happen: deviceReadOnlyScopes is a subset of
		// allowedLocalBridgeScopes by construction. Surface as an internal
		// error rather than silently downgrading.
		slog.Error("local bridge device issue: mint failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.store.LogToolCall(r.Context(), device.UserID, "local_bridge_device_issue", "", "ok", "", "")
	writeDeviceCredentialResponse(w, mt)
}

// ----- POST /api/local-bridge/devices/{device_id}/refresh -----

func (s *Server) handleDeviceRefresh(w http.ResponseWriter, r *http.Request) {
	deviceID := chi.URLParam(r, "device_id")
	req, badReq := decodeDevicePoPRequest(r)
	if badReq != "" {
		s.writeActivateError(w, http.StatusBadRequest, badReq)
		return
	}

	ip := s.clientIP(r)
	if s.activationFailBudgetSpent(ip) {
		s.writeActivateError(w, http.StatusForbidden, devicePoPGenericRejection)
		return
	}

	device, err := s.verifyDevicePoP(r, deviceID, req.Nonce, req.Signature)
	if err != nil {
		s.recordActivationFailure(ip)
		s.store.LogToolCall(r.Context(), 0, "local_bridge_device_refresh", "", "error", devicePoPGenericRejection, "")
		s.writeActivateError(w, http.StatusForbidden, devicePoPGenericRejection)
		return
	}

	// T5g: a device that has never completed first issuance has no lineage
	// to refresh. Refusing here -- rather than minting a credential with an
	// empty jti/anchor -- is what keeps "every live credential is named by
	// current_jti" true; see db.Store.ClaimDeviceCredentialLineage's doc
	// comment and design.md's "Refresh refuses a device that has never
	// issued".
	if device.CurrentJti == "" || device.CredentialIssuedAt == nil {
		s.store.LogToolCall(r.Context(), device.UserID, "local_bridge_device_refresh", "", "error", "no credential lineage -- first issuance required", "")
		s.writeActivateError(w, http.StatusConflict, "this device has not completed first issuance -- call the credential endpoint first")
		return
	}

	sendEnabled, err := s.store.IsSendEnabled(r.Context(), device.UserID)
	if err != nil {
		slog.Error("local bridge device refresh: read send_enabled failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// Scopes are derived FRESH from live state every call -- never copied
	// forward from a presented token (there is none to copy from: refresh
	// takes no bearer, only PoP). T5.
	scopes := append([]string{}, deviceReadOnlyScopes...)
	if sendEnabled {
		scopes = append(scopes, deviceSendPinScopes...)
	}

	telegramID, err := s.store.GetTelegramID(r.Context(), device.UserID)
	if err != nil || telegramID <= 0 {
		slog.Error("local bridge device refresh: resolve telegram id failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}

	mt, err := s.deviceMinter.MintForDevice(workertoken.DeviceMintRequest{
		TelegramID: telegramID,
		DeviceID:   deviceID,
		Scopes:     scopes,
		// Jti/OriginalIssuedAt are the ones claimed at FIRST issuance,
		// carried forward UNCHANGED -- never regenerated. This is what
		// keeps local_bridge_devices.current_jti naming the device's entire
		// live credential set, so denylisting it revokes all of them
		// (T5c/T5f).
		Jti:              device.CurrentJti,
		OriginalIssuedAt: *device.CredentialIssuedAt,
	})
	if err != nil {
		slog.Error("local bridge device refresh: mint failed", "device_id", deviceID, "err", err)
		s.writeActivateError(w, http.StatusInternalServerError, "internal error")
		return
	}

	s.store.LogToolCall(r.Context(), device.UserID, "local_bridge_device_refresh", "", "ok", "", "")
	writeDeviceCredentialResponse(w, mt)
}

func writeDeviceCredentialResponse(w http.ResponseWriter, mt *workertoken.Minted) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(deviceCredentialResponse{
		WorkerToken: mt.Token,
		ExpiresAt:   mt.ExpiresAt.Format(time.RFC3339),
		Jti:         mt.Jti,
	})
}
