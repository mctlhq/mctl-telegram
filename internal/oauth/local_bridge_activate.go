package oauth

// local_bridge_activate.go implements self-service Local Bridge device
// activation (issue #482): an RFC-8628-device-authorization-grant-shaped
// flow that lets a Local Bridge CLI prove Telegram identity and register a
// device without an operator running provision_local_account by hand.
//
// The flow, end to end:
//  1. POST /api/local-bridge/activate/start (unauthenticated) — the CLI
//     claims a telegram_id and supplies a device_registration_key; gets back
//     a device_code, a short human-typable user_code, and a verification_uri
//     that carries no query parameter.
//  2. GET/POST /local-bridge/activate — the browser-driven user_code entry
//     form. A valid, still-pending user_code starts the existing Telegram
//     OIDC leg (internal/auth/telegramoidc.Authenticator, the same one
//     handleAuthorize uses) and binds the resulting redirect to this browser
//     via the lb_act_state cookie.
//  3. handleTelegramCallback (server.go) recognizes the activation's OIDC
//     state, verifies the login-CSRF cookie, and calls finishActivation,
//     which makes ZERO store.* calls: it only proves identity and, if it
//     matches the claim, advances to awaiting_consent and renders a consent
//     page. Signing in is never itself authorization.
//  4. POST /local-bridge/activate/consent — Approve, with a valid
//     consentToken, is the ONLY path that writes to the database:
//     EnsureUserByTelegramID + ProvisionLocalAccount + RegisterDevice.
//  5. POST /api/local-bridge/activate/poll — the CLI polls device_code and
//     receives exactly one of pending/denied/done; every internal in-progress
//     state (awaiting_consent, resolving) reports as pending.
//
// See platform-gitops/agents-state/mctl-telegram/proposals/
// issue-482-feat-local-bridge-self-service-device-ac/design.md for the full
// rationale, in particular "Risk: activation phishing", which is the reason
// the consent step and the (non-URL-embedded) user_code both exist.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/telegramoidc"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Activation status values. Always mutated under s.mu. The state machine
// moves forward only:
//
//	pending -> awaiting_consent -> resolving -> done
//
// with denied reachable from any non-terminal state. done and denied are
// terminal. Every transition is guarded on the SPECIFIC state it advances
// from (see the per-transition functions below), never on a blanket "still
// unresolved" test -- see design.md's transition table for why a blanket
// guard deadlocks the happy path.
const (
	statusPending         = "pending"
	statusAwaitingConsent = "awaiting_consent"
	statusResolving       = "resolving"
	statusDenied          = "denied"
	statusDone            = "done"
)

// activationPollIntervalSeconds is the poll interval handleActivateStart
// advertises to the CLI. A constant, not derived from ActivationTTL: RFC
// 8628 treats it as a server-chosen politeness hint, independent of the
// code's lifetime.
const activationPollIntervalSeconds = 5

// localBridgeActivation is the transient server-side state of one
// self-service activation attempt. Every field is read and written only
// under Server.mu -- the same mutex that already guards pending/enables --
// because poll, the browser leg, and the sweeper all reach the same
// *localBridgeActivation concurrently.
type localBridgeActivation struct {
	deviceCode string // keys Server.activations
	createdAt  time.Time

	// startIP is the rate-limiter key (see Server.clientIP) of whoever
	// called /activate/start. It exists only so the capacity policy in
	// handleActivateStart can tell one client's activations from another's;
	// nothing else reads it, and it is never surfaced to a browser.
	startIP string

	claimedTGID int64
	// deviceRegKey is the CLI-supplied device_registration_key. It is ONLY
	// ever used as RegisterDevice's idempotency key -- never confused with
	// the server-generated registry device_id, which lives in
	// resultDeviceID below.
	deviceRegKey string
	deviceLabel  string

	// userCode is the short, human-typable code; the ONLY way a browser
	// binds to this activation. It must never appear in any URL. Keys
	// Server.activationsByUserCode.
	userCode string

	// Set once the browser starts the Telegram leg. oidcState keys
	// Server.activationsByState while the leg is in flight.
	oidcState, oidcNonce, oidcVerifier string

	// consentToken is set once Telegram OIDC has proven the identity and
	// cleared on resolution (or replaced with a fresh value on a resumed
	// awaiting_consent leg, or a retried store call). Its presence means
	// "identity proven, approval still outstanding" and it is what makes the
	// consent POST authorised.
	consentToken string
	// verifiedIdentity carries the WHOLE OIDC-verified identity, not merely
	// the Telegram id: the consent POST is a separate HTTP request, so
	// Username/display name would otherwise be lost between the callback and
	// the account provisioning that needs them.
	verifiedIdentity *telegramoidc.Identity

	status         string
	denialReason   string
	resultDeviceID string
}

// activationFailWindow is one client IP's failed-submission budget for the
// user_code form and the consent endpoint (shared limiter — see
// design.md's "Deriving the client IP").
type activationFailWindow struct {
	count     int
	startedAt time.Time
}

// unindexActivation removes act from the two browser-reachable secondary
// indexes (activationsByState, activationsByUserCode) but leaves it in
// s.activations, keyed by device_code. Called on RESOLUTION (done/denied):
// the browser must not be able to reach a finished activation again, but the
// CLI still has to poll device_code to learn the outcome and, for done,
// collect device_id. Must be called with s.mu held.
func (s *Server) unindexActivation(act *localBridgeActivation) {
	if act.userCode != "" && s.activationsByUserCode[act.userCode] == act {
		delete(s.activationsByUserCode, act.userCode)
	}
	if act.oidcState != "" && s.activationsByState[act.oidcState] == act {
		delete(s.activationsByState, act.oidcState)
	}
}

// dropActivation removes act from ALL THREE indexes, including
// s.activations. Called only by eviction (MaxPendingActivations) and by the
// TTL sweep -- i.e. when the activation is genuinely gone rather than merely
// finished. Must be called with s.mu held.
func (s *Server) dropActivation(act *localBridgeActivation) {
	s.unindexActivation(act)
	delete(s.activations, act.deviceCode)
}

// denyActivationFrom transitions act to "denied" if and only if its current
// status equals from, recording reason and clearing sensitive fields. It
// backs every "-> denied" row in design.md's transition table; callers pass
// the specific precondition their call site requires, so a stale or
// replayed request that finds the wrong precondition is a silent no-op
// instead of clobbering a state some other request already advanced.
// Returns whether the transition was applied.
func (s *Server) denyActivationFrom(act *localBridgeActivation, from, reason string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if act.status != from {
		return false
	}
	act.status = statusDenied
	act.denialReason = reason
	act.oidcVerifier = ""
	act.oidcNonce = ""
	act.consentToken = ""
	act.verifiedIdentity = nil
	s.unindexActivation(act)
	return true
}

// denyActivation marks act denied from the "pending" precondition -- every
// browser-leg-originated denial (login-CSRF mismatch, OIDC error, exchange
// failure, claimed/verified id mismatch) transitions from pending per
// design.md's table.
func (s *Server) denyActivation(act *localBridgeActivation, reason string) {
	s.denyActivationFrom(act, statusPending, reason)
}

// ----- user_code generation -----

// crockfordAlphabet excludes I, L, O, U to avoid visual confusion with
// 1, 1, 0, V when a user copies the code by hand from their terminal.
const crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// generateUserCode mints an 8-character Crockford-base32 code in the RFC
// 8628 "XXXX-XXXX" shape from 8 random bytes (~40 bits — 256 = 32*8 divides
// evenly, so the modulo below introduces no bias).
func generateUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate user_code: %w", err)
	}
	out := make([]byte, 8)
	for i, v := range b {
		out[i] = crockfordAlphabet[int(v)%len(crockfordAlphabet)]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

// generateUserCodeFn is a package var so tests can inject a generator that
// returns a controlled sequence (e.g. a duplicate first) to deterministically
// exercise the collision-regeneration path (T24). Production value is
// generateUserCode.
var generateUserCodeFn = generateUserCode

// maxUserCodeMintAttempts bounds the regenerate-on-collision loop. 40 bits of
// entropy makes a true collision vanishingly unlikely; this only exists so a
// pathological/broken generator fails loudly (503) instead of looping
// forever under the lock.
const maxUserCodeMintAttempts = 20

// mintUserCodeLocked returns a fresh user_code guaranteed not to collide with
// a live entry in s.activationsByUserCode. Must be called with s.mu held.
func (s *Server) mintUserCodeLocked() (string, error) {
	for i := 0; i < maxUserCodeMintAttempts; i++ {
		code, err := generateUserCodeFn()
		if err != nil {
			return "", err
		}
		if _, exists := s.activationsByUserCode[code]; !exists {
			return code, nil
		}
	}
	return "", errors.New("exhausted attempts generating a unique user_code")
}

// ----- client IP derivation (trusted-proxy-aware) -----

// clientIP derives the rate-limiter key for r using the trust boundary in
// s.cfg.TrustedProxyCIDRs. Evaluated from the outside in, and in this order:
// the immediate transport peer (r.RemoteAddr) is checked FIRST; a
// X-Forwarded-For header is consulted ONLY when that peer is itself inside
// the trusted set, and then only the first entry (scanning right to left)
// that is itself outside the trusted set is used. Checking the header before
// the peer would let a directly-connected attacker choose their own limiter
// key by rotating the header value per request.
func (s *Server) clientIP(r *http.Request) string {
	peer := hostPart(r.RemoteAddr)
	peerAddr, err := netip.ParseAddr(peer)
	if err != nil {
		// Unparseable RemoteAddr (not expected outside contrived tests) --
		// fall back to the raw string as the key rather than granting a
		// free, unlimited pass.
		return peer
	}
	if !s.peerIsTrustedProxy(peerAddr) {
		return peerAddr.String()
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return peerAddr.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		cand := strings.TrimSpace(parts[i])
		candAddr, cerr := netip.ParseAddr(cand)
		if cerr != nil {
			continue
		}
		if !s.peerIsTrustedProxy(candAddr) {
			return candAddr.String()
		}
	}
	// The whole forwarded chain is inside the trusted set -- fall back to
	// the immediate peer.
	return peerAddr.String()
}

func (s *Server) peerIsTrustedProxy(addr netip.Addr) bool {
	for _, p := range s.cfg.TrustedProxyCIDRs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// hostPart strips the port from a host:port address as found in
// http.Request.RemoteAddr, falling back to the raw string when there is no
// port to split (a bare IP, as httptest.NewRequest sometimes leaves it).
func hostPart(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// activationsForIPLocked reports how many live activations were started from
// ip, and which of them is the oldest. Both answers come from one pass; the
// capacity policy in handleActivateStart needs them together. Must be called
// with s.mu held.
func (s *Server) activationsForIPLocked(ip string) (int, *localBridgeActivation) {
	var count int
	var oldest *localBridgeActivation
	for _, a := range s.activations {
		if a.startIP != ip {
			continue
		}
		count++
		if oldest == nil || a.createdAt.Before(oldest.createdAt) {
			oldest = a
		}
	}
	return count, oldest
}

// ----- failed-submission rate limiter -----

// activationFailBudgetSpent reports whether ip's failed-submission budget is
// exhausted for the current window, WITHOUT recording anything -- callers
// check this before performing any lookup, so an exhausted key short-circuits
// before the (O(1), but still real) map access.
func (s *Server) activationFailBudgetSpent(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.activationFails[ip]
	if !ok {
		return false
	}
	if s.clock().Sub(w.startedAt) > s.cfg.ActivationFailWindow {
		return false
	}
	return w.count >= s.cfg.ActivationFailBudget
}

// recordActivationFailure increments ip's failure count, starting a fresh
// window if none is live. Shared by the user_code form and the consent
// endpoint per design.md.
func (s *Server) recordActivationFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	w, ok := s.activationFails[ip]
	if !ok || now.Sub(w.startedAt) > s.cfg.ActivationFailWindow {
		// New key: bound the limiter map before adding to it. Every sibling
		// map on Server carries an explicit cap because it is written from an
		// unauthenticated path, and this one is no different -- a failure is
		// recorded for whatever key clientIP derives, so a spread-out source
		// grows it without ever tripping the per-key budget. The sweeper
		// prunes expired windows on its own schedule; this is the bound that
		// holds between sweeps. Evicting the oldest window can only ever
		// forgive past failures, never manufacture them.
		if s.cfg.MaxActivationFailKeys > 0 && !ok &&
			len(s.activationFails) >= s.cfg.MaxActivationFailKeys {
			var oldestKey string
			var oldest *activationFailWindow
			for k, fw := range s.activationFails {
				if oldest == nil || fw.startedAt.Before(oldest.startedAt) {
					oldestKey, oldest = k, fw
				}
			}
			if oldest != nil {
				delete(s.activationFails, oldestKey)
			}
		}
		w = &activationFailWindow{startedAt: now}
		s.activationFails[ip] = w
	}
	w.count++
}

// ----- login-CSRF state-binding cookie (lb_act_state) -----

// activationStateCookieName carries a hash of the Telegram-leg OIDC state,
// binding the redirect to the browser that submitted the user_code. See
// design.md's "Login-CSRF binding": without it, an attacker can type their
// own user_code in their own browser, capture the resulting AuthCodeURL, and
// forward it to a victim, whose sign-in would otherwise land on the
// attacker's activation having never seen the code entry form.
const activationStateCookieName = "lb_act_state"

// setActivationStateCookie sets the login-CSRF binding cookie. Path=/ is
// required, not optional: this cookie is set while responding to
// POST /local-bridge/activate but read back at the unrelated,
// non-overlapping path /oauth/telegram/callback -- s.tgoidc's single
// baked-in RedirectURL. A default (request-path)-scoped cookie would simply
// never be sent there, silently rejecting every legitimate activation.
func setActivationStateCookie(w http.ResponseWriter, oidcState string) {
	http.SetCookie(w, &http.Cookie{
		Name:     activationStateCookieName,
		Value:    hashActivationState(oidcState),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

// clearActivationStateCookie deletes the login-CSRF binding cookie. Called
// as soon as handleTelegramCallback has consumed it (single use), so a stale
// cookie cannot be replayed against a later activation.
func clearActivationStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     activationStateCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// hashActivationState derives the cookie value from the OIDC state so the
// cookie does not simply echo a value that is also visible in the redirect
// URL/browser history. Not a secret -- a binding check, so SHA-256 is
// sufficient. Compared with hmac.Equal (not ==) at the callback.
func hashActivationState(oidcState string) string {
	sum := sha256.Sum256([]byte(oidcState))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ----- code-form double-submit CSRF cookie -----

// activationCSRFCookieName is the double-submit CSRF token for
// POST /local-bridge/activate itself. Without it, an attacker's page can
// auto-submit a hidden cross-site form carrying THE ATTACKER'S OWN
// user_code; the victim's browser would post it, receive the state cookie,
// and land on the attacker's device's consent page without the victim ever
// having typed anything -- see design.md's "The form POST must be
// CSRF-protected" for why SameSite=Lax alone is not treated as sufficient
// here.
const activationCSRFCookieName = "lb_act_csrf"

func setActivationCSRFCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     activationCSRFCookieName,
		Value:    tok,
		Path:     "/local-bridge/activate",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

// activationCSRFTokenFor returns the CSRF token to embed in a freshly
// rendered user_code form: the existing cookie's value when the request
// already carries one (a resubmission after a rejection reuses it), or a
// freshly minted token (setting the cookie) otherwise.
func activationCSRFTokenFor(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(activationCSRFCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	tok := randomToken(32)
	setActivationCSRFCookie(w, tok)
	return tok
}

// constantTimeStringEqual compares consent tokens without a timing oracle.
func constantTimeStringEqual(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ----- POST /api/local-bridge/activate/start -----

type activateStartRequest struct {
	TelegramID            int64  `json:"telegram_id"`
	DeviceRegistrationKey string `json:"device_registration_key"`
	DeviceLabel           string `json:"device_label"`
}

// handleActivateStart is unauthenticated by design (that is the point of the
// issue): it accepts a CLIENT-CLAIMED telegram_id and device_registration_key
// and mints a pending activation. No database row is touched here or at any
// point before the signed-in browser's explicit consent -- see
// design.md's "Risk: unauthenticated write-adjacent endpoint".
func (s *Server) handleActivateStart(w http.ResponseWriter, r *http.Request) {
	var req activateStartRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		s.writeActivateError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.TelegramID <= 0 {
		s.writeActivateError(w, http.StatusBadRequest, "telegram_id must be a positive integer")
		return
	}
	key := strings.TrimSpace(req.DeviceRegistrationKey)
	if key == "" {
		s.writeActivateError(w, http.StatusBadRequest, "device_registration_key is required")
		return
	}
	if len(key) > 512 {
		s.writeActivateError(w, http.StatusBadRequest, "device_registration_key exceeds 512 bytes")
		return
	}
	if len(req.DeviceLabel) > 256 {
		s.writeActivateError(w, http.StatusBadRequest, "device_label exceeds 256 bytes")
		return
	}

	ip := s.clientIP(r)
	act := &localBridgeActivation{
		deviceCode:   randomToken(32),
		claimedTGID:  req.TelegramID,
		deviceRegKey: key,
		deviceLabel:  req.DeviceLabel,
		createdAt:    s.clock(),
		startIP:      ip,
		status:       statusPending,
	}

	s.mu.Lock()
	// Bound the activation map. /activate/start is unauthenticated; without
	// a cap an attacker could grow process memory by calling it repeatedly.
	//
	// A plain oldest-evict is not enough, and the difference is not a memory
	// concern but a denial of service against legitimate users: an
	// unauthenticated flood from one address would push OTHER users'
	// in-flight activations out of the map, and their correctly typed
	// verification codes would start coming back as unknown in the middle of
	// signing in. So capacity is only ever reclaimed from the requesting
	// client. Two rules, in order:
	//
	//  1. A single client may hold at most MaxActivationsPerIP live
	//     activations; asking for one more recycles that client's own oldest.
	//     A CLI that retries never trips this -- it is dozens, not one.
	//  2. When the map is globally full, evict the requester's own oldest if
	//     it has one, and otherwise refuse the request. Refusing the flood is
	//     correct; evicting a stranger mid-sign-in is not.
	count, oldestOwn := s.activationsForIPLocked(ip)
	freed := false
	if s.cfg.MaxActivationsPerIP > 0 && count >= s.cfg.MaxActivationsPerIP && oldestOwn != nil {
		s.dropActivation(oldestOwn)
		freed = true
	}
	// Only when rule 1 has not already made room -- otherwise a request that
	// trips both rules would recycle two of the client's activations for the
	// one slot it needs.
	if !freed && s.cfg.MaxPendingActivations > 0 && len(s.activations) >= s.cfg.MaxPendingActivations {
		if oldestOwn == nil {
			s.mu.Unlock()
			w.Header().Set("Retry-After", "30")
			s.writeActivateError(w, http.StatusServiceUnavailable,
				"too many activations in progress, try again shortly")
			return
		}
		s.dropActivation(oldestOwn)
	}
	userCode, err := s.mintUserCodeLocked()
	if err != nil {
		s.mu.Unlock()
		slog.Error("local bridge activation: could not mint a unique user_code", "err", err)
		s.writeActivateError(w, http.StatusServiceUnavailable, "could not allocate a verification code, try again")
		return
	}
	act.userCode = userCode
	s.activations[act.deviceCode] = act
	s.activationsByUserCode[userCode] = act
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// No verification_uri_complete, ever: the verification_uri below is a
	// constant path carrying no activation-identifying parameter. See
	// requirements.md's resolved "Short human-typable code" open question --
	// this absence is a security property, not a style choice.
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code":      act.deviceCode,
		"user_code":        userCode,
		"verification_uri": strings.TrimRight(s.cfg.Issuer, "/") + "/local-bridge/activate",
		"expires_in":       int(s.cfg.ActivationTTL.Seconds()),
		"interval":         activationPollIntervalSeconds,
	})
}

func (s *Server) writeActivateError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// ----- GET /local-bridge/activate -----

// handleActivateForm renders the user_code entry form. It takes NO query
// parameters, and performs no lookup, no OIDC round trip, and no store call
// -- the browser binds to an activation only by the user typing the
// user_code their own CLI printed.
func (s *Server) handleActivateForm(w http.ResponseWriter, r *http.Request) {
	renderActivationForm(w, activationFormPage{CSRFToken: activationCSRFTokenFor(w, r)})
}

// ----- POST /local-bridge/activate -----

// activationGenericRejection is the single, byte-identical message shown for
// every rejection of a user_code submission: unknown, expired,
// already-resolved, or budget-exhausted. Not an oracle -- see T11.
const activationGenericRejection = "That code is not valid. It may be incorrect, expired, or already used. If you still need to activate a device, run the activation command again and enter the new code it prints."

// renderActivationRejected re-renders the user_code form with the generic
// rejection message, reusing whatever CSRF cookie the request already
// carries so a resubmission is not itself blocked by CSRF.
func renderActivationRejected(w http.ResponseWriter, r *http.Request) {
	renderActivationForm(w, activationFormPage{
		CSRFToken: activationCSRFTokenFor(w, r),
		Error:     activationGenericRejection,
	})
}

// handleActivateVerify resolves a submitted user_code and, on a live pending
// match, starts the Telegram OIDC leg. CSRF is checked FIRST, before any
// lookup and without setting the state cookie (T20); the failed-submission
// budget is checked next, ALSO before any lookup (T11); the user_code lookup
// itself is a single activationsByUserCode map access, never a scan of
// s.activations.
func (s *Server) handleActivateVerify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderActivationRejected(w, r)
		return
	}

	// Double-submit CSRF check. A missing or mismatched token means this POST
	// was not issued by a page this server rendered -- refuse before any
	// lookup and without setting the login-CSRF state cookie.
	csrfCookie, cerr := r.Cookie(activationCSRFCookieName)
	formTok := r.FormValue("csrf_token")
	if cerr != nil || formTok == "" || !constantTimeStringEqual(csrfCookie.Value, formTok) {
		renderActivationRejected(w, r)
		return
	}

	ip := s.clientIP(r)
	if s.activationFailBudgetSpent(ip) {
		renderActivationRejected(w, r)
		return
	}

	userCode := strings.TrimSpace(r.FormValue("user_code"))

	s.mu.Lock()
	act, ok := s.activationsByUserCode[userCode]
	if ok && s.clock().Sub(act.createdAt) > s.cfg.ActivationTTL {
		ok = false
	}
	if !ok {
		s.mu.Unlock()
		s.recordActivationFailure(ip)
		renderActivationRejected(w, r)
		return
	}

	if act.status == statusAwaitingConsent {
		// Resuming, not restarting: the identity was already proven by a
		// prior pass through Telegram OIDC. finishActivation requires
		// `pending`, so starting a second OIDC leg here would fail that
		// precondition on the eventual callback and strand the user on a
		// blank page while the CLI polls until TTL (T26). Mint a fresh
		// consentToken and re-render the consent page directly.
		act.consentToken = randomToken(32)
		page := activationConsentPage{
			UserCode:     act.userCode,
			ConsentToken: act.consentToken,
			DeviceLabel:  act.deviceLabel,
		}
		if act.verifiedIdentity != nil {
			page.Username = act.verifiedIdentity.Username
			page.DisplayName = strings.TrimSpace(act.verifiedIdentity.FirstName + " " + act.verifiedIdentity.LastName)
		}
		s.mu.Unlock()
		renderActivationConsent(w, page)
		return
	}

	if act.status != statusPending {
		// resolving / done / denied: no longer reachable from the browser.
		s.mu.Unlock()
		s.recordActivationFailure(ip)
		renderActivationRejected(w, r)
		return
	}

	// Mint a fresh nonce/PKCE verifier/state exactly like handleAuthorize.
	nonce := randomToken(16)
	tgVerifier, tgChallenge := pkceChallenge()
	oidcState := randomToken(32)
	if act.oidcState != "" {
		// A browser leg is already in flight for this activation (e.g. the
		// user reopened the form before finishing sign-in). Delete the
		// superseded entry so no orphan key survives to be cleaned up only
		// by TTL.
		delete(s.activationsByState, act.oidcState)
	}
	act.oidcState = oidcState
	act.oidcNonce = nonce
	act.oidcVerifier = tgVerifier
	s.activationsByState[oidcState] = act
	s.mu.Unlock()

	setActivationStateCookie(w, oidcState)
	http.Redirect(w, r, s.tgoidc.AuthCodeURL(oidcState, nonce, tgChallenge), http.StatusFound)
}

// ----- finishActivation (called from handleTelegramCallback) -----

// finishActivation implements design.md's steps 1-4 of the OIDC callback
// leg. It makes ZERO store.* calls -- signing in must never by itself write
// anything; only the later, separate consent POST does that. verifier and
// nonce are the values the CALLER copied from act under s.mu before calling
// Exchange; this function must never read act.oidcVerifier/act.oidcNonce
// again -- a concurrent form submission for the same activation can rewrite
// those fields while the exchange is in flight, which in Go is a genuine
// data race, not merely a stale read (T15, T23).
func (s *Server) finishActivation(w http.ResponseWriter, r *http.Request, act *localBridgeActivation, q url.Values, verifier, nonce string) {
	if oidcErr := q.Get("error"); oidcErr != "" {
		s.denyActivation(act, "telegram sign-in was not completed")
		renderActivationDenied(w, "Telegram sign-in was not completed. Return to your terminal and run the activation command again.")
		return
	}
	code := q.Get("code")
	if code == "" {
		s.denyActivation(act, "telegram sign-in did not return an authorization code")
		renderActivationDenied(w, "Telegram did not return an authorization code. Return to your terminal and run the activation command again.")
		return
	}

	identity, err := s.tgoidc.Exchange(r.Context(), code, verifier, nonce)
	if err != nil {
		slog.Error("local bridge activation: telegram OIDC exchange failed", "err", err)
		s.denyActivation(act, "telegram verification failed")
		renderActivationDenied(w, "Telegram sign-in could not be verified. Return to your terminal and run the activation command again.")
		return
	}
	if identity.TelegramID <= 0 {
		s.denyActivation(act, "telegram sign-in did not resolve a usable telegram id")
		renderActivationDenied(w, "Telegram sign-in did not resolve a usable Telegram id. Return to your terminal and run the activation command again.")
		return
	}

	// T2: identity is proven, but does not match what the CLI claimed at
	// start. No store call has been made anywhere above this line.
	if identity.TelegramID != act.claimedTGID {
		s.denyActivation(act, "telegram account mismatch")
		renderActivationDenied(w, "The Telegram account you signed in with does not match the account this device requested. Nothing was changed. If you did not start this activation yourself, you can safely ignore this page.")
		return
	}

	// Identity is proven AND matches the claim -- but that is NOT yet
	// authorisation. Advance to awaiting_consent and render the consent
	// page; the database write happens only if the signed-in browser
	// explicitly approves it at /local-bridge/activate/consent. See
	// design.md's "Risk: activation phishing": without this separate step,
	// an attacker who opened the activation naming a victim's telegram_id
	// would get their own device registered on the victim's account merely
	// by the victim signing in -- there is no mismatch for the guard above
	// to catch, because the claimed and verified ids are the same.
	s.mu.Lock()
	ok := act.status == statusPending
	var page activationConsentPage
	if ok {
		act.verifiedIdentity = identity
		act.consentToken = randomToken(32)
		act.status = statusAwaitingConsent
		page = activationConsentPage{
			UserCode:     act.userCode,
			ConsentToken: act.consentToken,
			DeviceLabel:  act.deviceLabel,
			Username:     identity.Username,
			DisplayName:  strings.TrimSpace(identity.FirstName + " " + identity.LastName),
		}
	}
	s.mu.Unlock()
	if !ok {
		// Already resolved, or superseded by a concurrent leg for the same
		// activation -- refused without touching the database, which falls
		// straight out of the transition table (finishActivation only ever
		// advances from pending).
		renderActivationError(w, "This activation has already been used or has expired. Return to your terminal and run the activation command again if you need a new one.")
		return
	}
	renderActivationConsent(w, page)
}

// ----- POST /local-bridge/activate/consent -----

// handleActivateConsent is the ONLY handler in this feature that writes to
// the database, and only on an explicit Approve carrying a valid
// consentToken. It resolves the activation by ONE activationsByUserCode
// lookup (never a scan for a matching consentToken, which would be an O(N)
// walk under the global lock reachable by anyone POSTing random tokens).
func (s *Server) handleActivateConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderActivationError(w, activationGenericRejection)
		return
	}
	userCode := strings.TrimSpace(r.FormValue("user_code"))
	consentTok := r.FormValue("consent_token")
	approve := r.FormValue("action") == "approve"

	ip := s.clientIP(r)
	if s.activationFailBudgetSpent(ip) {
		renderActivationError(w, activationGenericRejection)
		return
	}

	s.mu.Lock()
	act, ok := s.activationsByUserCode[userCode]
	if ok && s.clock().Sub(act.createdAt) > s.cfg.ActivationTTL {
		ok = false
	}
	if !ok || act.status != statusAwaitingConsent || !constantTimeStringEqual(act.consentToken, consentTok) {
		s.mu.Unlock()
		s.recordActivationFailure(ip)
		renderActivationError(w, activationGenericRejection)
		return
	}

	if !approve {
		// Deny: no store call, ever.
		act.status = statusDenied
		act.denialReason = "declined by user"
		act.oidcVerifier = ""
		act.oidcNonce = ""
		act.consentToken = ""
		act.verifiedIdentity = nil
		s.unindexActivation(act)
		s.mu.Unlock()
		renderActivationDenied(w, "You declined the device request. Nothing was changed on your account.")
		return
	}

	// Claim the activation NOW, while STILL holding the lock, before any
	// database call. This is what makes a double-clicked Approve, or two
	// concurrent POSTs replaying the same token, a no-op for the second one
	// instead of two racing provisioning runs (T12, T22).
	act.status = statusResolving
	act.consentToken = ""
	identity := act.verifiedIdentity
	deviceLabel := act.deviceLabel
	deviceRegKey := act.deviceRegKey
	s.mu.Unlock()

	s.approveActivation(w, r, act, identity, deviceLabel, deviceRegKey)
}

// approveActivation runs design.md's steps 5-8 of the approve path: resolve
// the internal user, provision (or confirm) the local account, register the
// device, and mark the activation done -- all fed from act.verifiedIdentity
// (the OIDC-proven identity), never the CLI-claimed one.
func (s *Server) approveActivation(w http.ResponseWriter, r *http.Request, act *localBridgeActivation, identity *telegramoidc.Identity, deviceLabel, deviceRegKey string) {
	ctx := r.Context()
	displayName := strings.TrimSpace(identity.FirstName + " " + identity.LastName)
	uid, err := s.store.EnsureUserByTelegramID(ctx, identity.TelegramID, identity.Username, displayName)
	if err != nil {
		slog.Error("local bridge activation: ensure user failed", "err", err)
		s.retryActivationAfterStoreFailure(w, act, "We hit a temporary problem resolving your account. Approve again to retry.")
		return
	}

	provErr := s.store.ProvisionLocalAccount(ctx, uid, identity.TelegramID, displayName, identity.Username)
	if provErr != nil {
		if !errors.Is(provErr, db.ErrAccountAlreadyActive) {
			slog.Error("local bridge activation: provision local account failed", "err", provErr)
			s.retryActivationAfterStoreFailure(w, act, "We hit a temporary problem provisioning your account. Approve again to retry.")
			return
		}
		// An active row already exists. Idempotent-if-local (T1); refused if
		// hosted (T3) -- no local_bridge_devices row follows either way in
		// the hosted case.
		mode, modeErr := s.store.GetAccountMode(ctx, uid)
		if modeErr != nil {
			slog.Error("local bridge activation: get account mode failed", "err", modeErr)
			s.retryActivationAfterStoreFailure(w, act, "We hit a temporary problem checking your account. Approve again to retry.")
			return
		}
		if mode != db.ModeLocal {
			s.denyActivationFrom(act, statusResolving, "hosted account")
			renderActivationDenied(w, "This Telegram account already has an active hosted connection and cannot also be activated for Local Bridge here. Contact an operator if you believe this is wrong.")
			return
		}
	}

	deviceID, regErr := s.store.RegisterDevice(ctx, uid, deviceLabel, deviceRegKey)
	if regErr != nil {
		slog.Error("local bridge activation: register device failed", "err", regErr)
		s.retryActivationAfterStoreFailure(w, act, "We hit a temporary problem registering the device. Approve again to retry.")
		return
	}

	s.mu.Lock()
	if act.status == statusResolving {
		act.status = statusDone
		act.resultDeviceID = deviceID
		act.verifiedIdentity = nil
		s.unindexActivation(act)
	}
	s.mu.Unlock()
	s.store.LogToolCall(ctx, uid, "local_bridge_activate", "", "ok", "", "")
	renderActivationDone(w)
}

// retryActivationAfterStoreFailure restores act to awaiting_consent with a
// FRESH consentToken and re-renders the consent page with an error banner --
// never a bare 500. Minting a new token into a response the browser never
// shows would leave the user submitting the stale one, failing the CSRF
// check forever: the activation would sit in awaiting_consent until TTL
// while the CLI polls pending and nobody could make progress (T25).
func (s *Server) retryActivationAfterStoreFailure(w http.ResponseWriter, act *localBridgeActivation, banner string) {
	s.mu.Lock()
	var page activationConsentPage
	ok := act.status == statusResolving
	if ok {
		act.status = statusAwaitingConsent
		act.consentToken = randomToken(32)
		page = activationConsentPage{
			UserCode:     act.userCode,
			ConsentToken: act.consentToken,
			DeviceLabel:  act.deviceLabel,
			Error:        banner,
		}
		if act.verifiedIdentity != nil {
			page.Username = act.verifiedIdentity.Username
			page.DisplayName = strings.TrimSpace(act.verifiedIdentity.FirstName + " " + act.verifiedIdentity.LastName)
		}
	}
	s.mu.Unlock()
	if !ok {
		renderActivationError(w, activationGenericRejection)
		return
	}
	renderActivationConsent(w, page)
}

// ----- POST /api/local-bridge/activate/poll -----

type activatePollRequest struct {
	DeviceCode string `json:"device_code"`
}

// handleActivatePoll maps the activation's internal status down to EXACTLY
// the three values the CLI's contract defines: awaiting_consent and
// resolving are internal in-progress states and MUST be reported as pending
// (T21) -- the client must never receive a status its own acceptance
// criteria do not name.
func (s *Server) handleActivatePoll(w http.ResponseWriter, r *http.Request) {
	var req activatePollRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4*1024)).Decode(&req); err != nil || req.DeviceCode == "" {
		s.writeActivateError(w, http.StatusBadRequest, "device_code is required")
		return
	}

	s.mu.Lock()
	act, ok := s.activations[req.DeviceCode]
	var status, reason, resultDeviceID string
	if ok {
		if s.clock().Sub(act.createdAt) > s.cfg.ActivationTTL {
			ok = false
		} else {
			status, reason, resultDeviceID = act.status, act.denialReason, act.resultDeviceID
		}
	}
	s.mu.Unlock()

	if !ok {
		// A resolved (done/denied) activation stays in s.activations until
		// its TTL sweep -- see unindexActivation vs dropActivation -- so
		// "unknown" here means genuinely unknown or expired, distinct from
		// "not finished yet".
		s.writeActivateError(w, http.StatusBadRequest, "unknown or expired device_code")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch status {
	case statusDone:
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "done", "device_id": resultDeviceID})
	case statusDenied:
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "denied", "reason": reason})
	default: // pending, awaiting_consent, resolving
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	}
}
