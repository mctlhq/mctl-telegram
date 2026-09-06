package oauth

// enable_access.go implements the in-browser "enable message access" flow.
//
// After Telegram OIDC proves identity, an admin who has no MTProto session is
// walked through phone -> SMS code -> optional 2FA, all over HTTP.
// The gotd auth flow cannot be split across requests (the MTProto connection
// lives only inside one client.Run callback), so telegram.Login runs in a
// background goroutine and the per-step HTTP handlers feed it the code and
// password through channels.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// enableStep tracks where an enable_access flow is. Guarded by enableSession.lock.
type enableStep int

const (
	stepPermissions enableStep = iota // awaiting permissions choice (wizard mode only)
	stepPhone                         // awaiting the phone number (initial screen)
	stepCode                          // awaiting the SMS code
	stepPassword                      // awaiting the 2FA cloud password
	stepDone                          // session provisioned, authorization code issued
)

// Per-step waits. SendCode/SignIn are network round-trips against Telegram;
// the channel sends are near-instant because the login goroutine is already
// parked in askCode/askPassword by the time a handler writes to them.
const (
	enableSendCodeWait = 90 * time.Second
	enableSignInWait   = 60 * time.Second
	enableChanSendWait = 10 * time.Second
)

// enableLockWait bounds how long a concurrent/duplicate step submit waits for
// the per-session lock before giving up. The mutating steps hold the lock only
// for microseconds; only handleEnableStart holds it longer (during the MTProto
// SendCode round-trip). Waiting briefly lets a duplicate submit — common from
// in-app browsers and MCP clients that re-issue a POST — resolve and continue
// the flow instead of dead-ending the user on an error page. A var so tests can
// shrink it — tests that override it must run sequentially (no t.Parallel), as
// it is read without synchronisation.
var enableLockWait = 2 * time.Second

// enableSession is the server-side state of one in-browser enable_access flow,
// keyed by an unguessable "es" token minted at the Telegram callback. It carries
// the OAuth context so the flow can resume the authorization-code dance once
// the MTProto session exists.
type enableSession struct {
	oc        oauthCtx
	uid       int64 // internal users.id (EnsureUserByTelegramID)
	tgID      int64 // Telegram user id, == oc.TelegramID
	createdAt time.Time

	// lock serialises handlers for this session: each handler holds it for
	// the duration of one step (acquired via acquireStepLock, which waits
	// briefly so a concurrent double-submit resolves instead of dead-ending),
	// so step/flow below need no further synchronisation between handlers.
	lock      sync.Mutex
	step      enableStep
	phone     string
	sendOptIn bool
	flow      *loginFlow

	// terminalMsg is non-empty once the session has been refused for a reason
	// restarting cannot clear (today: an active Local Bridge account). The
	// step fallbacks in handleEnableCode/handleEnablePassword re-render it, so
	// a browser-back re-POST of the last step lands back on the dead-end
	// screen instead of the phone step's "Please start again." — which is a
	// retry invitation for a condition that will not clear.
	//
	// /start deliberately does NOT read it: a resubmit there re-runs the
	// pre-flight mode gate, which re-derives the refusal from live account
	// state rather than replaying a cached message. If the operator has since
	// switched the account back to hosted, that path lets the user through.
	terminalMsg string
}

// loginFlow couples an HTTP handler to the background goroutine running
// telegram.Login. The goroutine blocks in askCode/askPassword reading codeCh
// and pwCh; needCode/needPw signal which input the goroutine is waiting for;
// done is closed when telegram.Login and session finalisation have returned.
type loginFlow struct {
	codeCh   chan string
	pwCh     chan string
	needCode chan struct{}
	needPw   chan struct{}
	done     chan struct{}
	cancel   context.CancelFunc

	// Result fields — written by the goroutine before it closes done, and
	// read by handlers only after a receive from done. The channel close
	// provides the happens-before edge, so no mutex is needed.
	tgUserID int64
	err      error
}

// startLoginFlow launches telegram.Login in a background goroutine driven by
// channels. The goroutine owns a context with a CodeTTL deadline so it always
// terminates even if the user abandons the browser; cancel releases it sooner
// when a /start re-submission supersedes it. wantTgID is the OIDC-proven
// Telegram id — the goroutine rejects the flow if the phone login resolves to
// a different account.
func (s *Server) startLoginFlow(uid, wantTgID int64, phone string, sendOptIn bool) *loginFlow {
	lf := &loginFlow{
		codeCh:   make(chan string),
		pwCh:     make(chan string),
		needCode: make(chan struct{}, 1),
		needPw:   make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	bgCtx, cancel := context.WithTimeout(context.Background(), s.cfg.CodeTTL)
	lf.cancel = cancel

	askCode := func(ctx context.Context) (string, error) {
		select {
		case lf.needCode <- struct{}{}:
		default:
		}
		select {
		case c := <-lf.codeCh:
			return c, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	askPassword := func(ctx context.Context) (string, error) {
		select {
		case lf.needPw <- struct{}{}:
		default:
		}
		select {
		case p := <-lf.pwCh:
			return p, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	go func() {
		defer cancel()
		defer close(lf.done)
		// The per-step HTTP handler abandons its wait after enableSendCodeWait/
		// enableSignInWait and logs only a coarse "timeout" to the audit, while
		// this goroutine keeps running on bgCtx (CodeTTL). Without this it is the
		// only place that sees the real telegram.Login error (FLOOD_WAIT, DC
		// dial failure, RPC hang surfacing as the bgCtx deadline), so log the
		// final outcome here regardless of whether a handler is still waiting.
		started := time.Now()
		defer func() {
			if lf.err != nil {
				slog.Error("enable: telegram login failed",
					"uid", uid, "want_tg_id", wantTgID,
					"elapsed", time.Since(started).String(), "err", lf.err)
			} else {
				slog.Info("enable: telegram login succeeded",
					"uid", uid, "tg_id", lf.tgUserID,
					"elapsed", time.Since(started).String())
			}
		}()
		// Serialise login work for this uid. A /start re-submission cancels
		// the prior flow and starts a new one; without this lock the cancelled
		// predecessor — if its login RPC had already returned — could still
		// run its revoke/SaveSession and clobber the newer flow's session.
		ul := s.uidLoginMutex(uid)
		// Test seam (nil in production): announce that this goroutine is about
		// to park on the mutex, so a test holding it can provision a local
		// account into the window the re-check below exists for.
		if s.loginFlowParked != nil {
			s.loginFlowParked()
		}
		ul.Lock()
		defer ul.Unlock()
		// Re-check under the uid lock, after handleEnableStart's pre-flight
		// check: a local account could have been provisioned between the two.
		// This is the last point at which we can refuse and still be sure no
		// Telegram session bytes have been written — s.loginFn persists them
		// through the gotd SessionStore the moment auth succeeds, overwriting
		// the local row's blob before SaveSession is ever reached.
		if local, cErr := s.hasActiveLocalAccount(bgCtx, uid); cErr != nil {
			// Wrapped in errModeCheckFailed so handleEnableStart can give this
			// the same treatment as the identical failure at the pre-flight
			// gate: the mode_check_error label and the "could not verify"
			// wording. Without the sentinel it surfaces through the generic
			// arm as result="error" inside "Telegram rejected the request",
			// and Telegram was not contacted on this path either.
			lf.err = fmt.Errorf("%w: %w", errModeCheckFailed, cErr)
			return
		} else if local {
			lf.err = db.ErrAccountModeConflict
			return
		}
		tgID, displayName, username, err := s.loginFn(bgCtx, s.cfg.TGAPIID, s.cfg.TGAPIHash, s.store, uid, phone, askCode, askPassword, s.loginCfg)
		if err != nil {
			lf.err = err
			return
		}
		// From here on the login has already persisted its session bytes
		// through the gotd SessionStore, and with no loaded row id that write
		// lands on EVERY active row of this uid -- including a bridge-only one
		// provisioned since the re-check above. So every exit between here and
		// a successful SaveSession has to run the repair, not just the
		// SaveSession refusal: a LoadSession failure, "no session bytes were
		// persisted" and the identity-mismatch bail-out all leave the same
		// stray bytes behind, and a hosted worker holding a live session for
		// an account the operator believes is local is the exact outcome this
		// PR exists to prevent. A defer is the only form that cannot be
		// forgotten by a future exit added in between.
		//
		// Detached and bounded, not merely detached: bgCtx carries the flow's
		// CodeTTL deadline, so the repair must not die on an expiry that is
		// itself a likely cause of getting here -- while WithoutCancel alone
		// would strip the deadline too, and this runs under the uid login
		// mutex, where an unresponsive database would park the goroutine
		// forever and lock the user out of every later attempt.
		//
		// The identity-mismatch local half now clears inline (and surfaces a
		// failure), and the unknown half revokes, so this defer is a no-op on
		// that branch. It remains the backstop for a LoadSession failure, "no
		// session bytes were persisted", and SaveSession itself.
		saved := false
		defer func() {
			if saved {
				return
			}
			repairCtx, repairCancel := strayRepairContext(bgCtx)
			defer repairCancel()
			if cErr := s.clearStraySessionIfLocal(repairCtx, uid); cErr != nil {
				slog.Error("enable: clear stray session blob failed", "uid", uid, "err", cErr)
			}
		}()
		// Identity binding. The Telegram account that just completed
		// phone/SMS/2FA MUST be the same one Telegram OIDC proved. Otherwise an
		// admin authenticated as account A could enter account B's phone and
		// end up operating B's messages through A's token. telegram.Login has
		// already persisted B's session bytes via the gotd SessionStore, so
		// revoke that row before bailing out.
		if tgID != wantTgID {
			// telegram.Login already persisted the wrong account's session
			// bytes under uid, and they must not stay usable: a later callback
			// would otherwise issue a token backed by them.
			//
			// Revoking is the right tool only when no bridge-only row is
			// active. RevokeActiveSession is `WHERE user_id AND revoked_at IS
			// NULL` -- every active row -- so on the race this whole block
			// assumes it would revoke the local row too, which is the exact
			// destruction this change exists to prevent, and it would also
			// make the deferred repair above a no-op: both that repair's
			// EXISTS and LoadSession filter on revoked_at IS NULL, so once
			// the rows are revoked there is nothing left for it to match.
			//
			// With a local row present the repair is the better instrument
			// anyway: it drops the wrong account's bytes from every active row
			// while leaving the rows themselves alone, so the bridge keeps
			// working and the stray session is gone. Called inline, not left
			// to the defer: a failed ClearStraySessionIfLocal must surface
			// the same way a failed revoke does, otherwise the wrong
			// account's session stays on a row whose contract says NULL and
			// lf.err carries only the identity-mismatch message. The defer
			// then becomes a no-op (already-NULL blobs) or a second try.
			//
			// Both the check and the revoke/repair use a detached, bounded
			// context rather than bgCtx. bgCtx carries the flow's CodeTTL
			// deadline -- the very expiry the deferred repair was made
			// detached to survive. On expiry the check fails, local becomes
			// false, the revoke on the same dead context fails too, and
			// lf.err becomes the revoke error, so friendlyErr renders "the
			// login attempt expired." instead of the identity mismatch. The
			// decision has to depend on account state, not on where the
			// deadline happened to land.
			decisionCtx, decisionCancel := strayRepairContext(bgCtx)
			defer decisionCancel()
			local, cErr := s.hasActiveLocalAccount(decisionCtx, uid)
			if cErr != nil {
				// Unknown, and the two failure modes are not symmetric: an
				// unrevoked wrong-account session is exploitable, whereas a
				// wrongly revoked local row degrades rather than breaks -- the
				// daemon keeps being admitted, because GetAccountMode does not
				// filter on revoked_at, and what is lost is this PR's own
				// protection until the user reconnects. So revoke, and say why
				// rather than leaving it to be re-derived.
				slog.Warn("enable: account-mode check failed on the identity-mismatch path; revoking",
					"uid", uid, "err", cErr)
				local = false
			}
			if !local {
				// A failed revoke must surface — otherwise the wrong session
				// stays active. wrapIdentityCleanupErr, not %w of rErr
				// directly: decisionCtx's own 5s budget can expire here,
				// and a raw DeadlineExceeded would render as login CodeTTL
				// expiry.
				if _, rErr := s.store.RevokeActiveSession(decisionCtx, uid, "disconnect"); rErr != nil {
					lf.err = wrapIdentityCleanupErr("revoke wrong-account session", rErr)
					return
				}
			} else if clearErr := s.clearStraySessionIfLocal(decisionCtx, uid); clearErr != nil {
				// Symmetric with the revoke arm: a cleanup we could not
				// complete has to reach the caller. slog.Error on the defer
				// is not enough -- the surviving row is mode='local', so
				// nothing is served from those bytes, but they are still
				// sitting on a row whose contract says NULL.
				lf.err = wrapIdentityCleanupErr("clear wrong-account session", clearErr)
				return
			}
			lf.err = errors.New("the phone number belongs to a different Telegram account than the one you signed in with — log in with the same account")
			return
		}
		// Replicate cmd/login/main.go: telegram.Login persists the raw
		// session bytes via the gotd SessionStore, but the telegram_accounts
		// metadata (telegram_user_id, display name, expires_at, send_enabled
		// default) is finalised by an explicit SaveSession.
		pt, lerr := s.store.LoadSession(bgCtx, uid)
		if lerr != nil {
			lf.err = fmt.Errorf("reload session: %w", lerr)
			return
		}
		if pt == nil {
			lf.err = errors.New("login completed but no session bytes were persisted")
			return
		}
		if serr := s.store.SaveSession(bgCtx, uid, pt, tgID, displayName, username); serr != nil {
			// The deferred repair above covers this: SaveSession's own guard
			// is gated on account state rather than on ErrAccountModeConflict
			// precisely because it can fail with the CodeTTL deadline instead
			// of the sentinel while a local row is present.
			lf.err = fmt.Errorf("save session: %w", serr)
			return
		}
		// Past the point of no return for the repair: the session is now
		// legitimately the user's, and clearing it would undo a good login.
		saved = true
		if sendOptIn {
			if _, serr := s.store.SetSendEnabled(bgCtx, uid, true); serr != nil {
				lf.err = fmt.Errorf("enable sending: %w", serr)
				return
			}
		}
		lf.tgUserID = tgID
	}()
	return lf
}

// hasActiveLocalAccount is the account-mode query both the pre-flight gate and
// startLoginFlow's re-check run. It exists as a method so tests can drive the
// failure half of that guard: the store is a real *db.Store everywhere, so
// without a seam the two errModeCheckFailed branches -- which deliberately do
// something different to the session than their mode-conflict siblings -- have
// nothing red to stop a later refactor from flattening them together.
func (s *Server) hasActiveLocalAccount(ctx context.Context, uid int64) (bool, error) {
	if s.modeCheckFn != nil {
		return s.modeCheckFn(ctx, uid)
	}
	return s.store.HasActiveLocalAccount(ctx, uid)
}

// clearStraySessionIfLocal is the repair both the deferred backstop and the
// identity-mismatch local half run. The seam exists so tests can drive the
// failure half of that cleanup: without it a later edit can drop the inline
// surface and leave only slog.Error, and every current test stays green.
func (s *Server) clearStraySessionIfLocal(ctx context.Context, uid int64) error {
	if s.clearStrayFn != nil {
		return s.clearStrayFn(ctx, uid)
	}
	return s.store.ClearStraySessionIfLocal(ctx, uid)
}

// strayRepairContext outlives parent (so a CodeTTL expiry cannot take the
// repair down with it) and is bounded by StraySessionRepairTimeout (so an
// unresponsive database cannot hold the uid login mutex forever). Shared by
// the deferred stray-session repair and the identity-mismatch branch, which
// has to make the same kind of decision after the login has already
// persisted bytes.
func strayRepairContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(parent), db.StraySessionRepairTimeout)
}

// errIdentityCleanupTimeout is a stray-repair budget expiry on the
// identity-mismatch revoke/clear path. It replaces context.DeadlineExceeded
// so friendlyErr/shortReason cannot treat a failed cleanup as login CodeTTL
// expiry ("the login attempt expired." / audit "timeout").
var errIdentityCleanupTimeout = errors.New("repair timed out")

// wrapIdentityCleanupErr records a failed identity-mismatch revoke/clear.
// decisionCtx is bounded by StraySessionRepairTimeout; if that budget
// expires, the store returns DeadlineExceeded — the same sentinel as a
// login CodeTTL expiry. Wrapping that with %w would make
// errors.Is(..., DeadlineExceeded) true and hide the cleanup failure
// this path exists to surface.
func wrapIdentityCleanupErr(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", op, errIdentityCleanupTimeout)
	}
	return fmt.Errorf("%s: %w", op, err)
}

// errModeCheckFailed marks a failure of the account-mode query itself, as
// opposed to a mode conflict. Both the pre-flight gate and startLoginFlow's
// re-check run the same HasActiveLocalAccount call; this is what lets the
// handler label and word them identically no matter which one failed.
var errModeCheckFailed = errors.New("could not verify the account mode")

// uidLoginMutex returns the per-user mutex that serialises enable_access login
// goroutines for one users.id. See Server.loginMu.
func (s *Server) uidLoginMutex(uid int64) *sync.Mutex {
	m, _ := s.loginMu.LoadOrStore(uid, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// isWizardMode reports whether this enable_access flow was initiated via the
// built-in self-connect client (i.e. the /telegram/connect landing page).
func (es *enableSession) isWizardMode() bool {
	return es.oc.ClientID == ConnectClientID
}

// acquireStepLock waits up to enableLockWait for the session lock, polling so a
// duplicate or concurrent step submit does not dead-end the user. The
// permissions step releases the lock in microseconds; handleEnableStart/Code/
// Password hold it across their MTProto round-trip. On acquiring, the handler
// runs normally and its es.step guard re-renders the correct screen for the
// current step (without resetting it). It returns false only when the lock is
// held for the whole window — e.g. a step still awaiting Telegram — in which
// case the caller shows a non-terminal "still finishing" page; it also returns
// false if the request is cancelled. The caller owns the unlock on success.
func (es *enableSession) acquireStepLock(ctx context.Context) bool {
	deadline := time.Now().Add(enableLockWait)
	for {
		if es.lock.TryLock() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// handleEnablePermissions receives the permissions choice (read-only vs
// read+send), records the opt-in, and advances to the phone screen.
func (s *Server) handleEnablePermissions(w http.ResponseWriter, r *http.Request) {
	es, esTok, ok := s.lookupEnable(r)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}
	if !es.acquireStepLock(r.Context()) {
		renderEnableError(w, "The previous step is still finishing — it can take a moment while Telegram responds. Wait, then resubmit.")
		return
	}
	defer es.lock.Unlock()

	if es.step != stepPermissions {
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       es.phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
		return
	}

	sendOptin := r.FormValue("send_optin")
	es.sendOptIn = sendOptin == "send"
	es.step = stepPhone
	renderEnablePhone(w, enablePhonePage{
		Issuer:      s.cfg.Issuer,
		EnableToken: esTok,
		SendOptIn:   es.sendOptIn,
		WizardMode:  true,
		WizardStep:  3,
	})
}

// renderEnablePhoneStep resets the flow to stepPhone and renders the phone
// screen. Every handler path that bounces the user back to the start uses it,
// so es.step never lags behind the screen actually shown (a stale stepCode /
// stepPassword would otherwise let a direct POST skip the UI order).
// It also propagates wizard context from the session so error fallbacks from
// later steps keep showing the 4-step indicator (callers that already set
// WizardMode are not overridden).
func renderEnablePhoneStep(w http.ResponseWriter, es *enableSession, p enablePhonePage) {
	if es.isWizardMode() && !p.WizardMode {
		p.WizardMode = true
		p.WizardStep = 3
	}
	es.step = stepPhone
	renderEnablePhone(w, p)
}

// abandonFlow returns the session to stepPhone and lets go of its login flow,
// cancelling it first if it is still running.
//
// The step reset is the same invariant renderEnablePhoneStep maintains: es.step
// must never lag the screen actually shown. A refusal that left es.step ==
// stepCode with es.flow non-nil would satisfy handleEnableStart's duplicate-
// /start guard, so a resubmitted /start would be handed a code screen for an
// SMS Telegram was never asked to send, and would return from that guard before
// ever reaching the pre-flight mode gate that produced the refusal.
//
// The cancel matters on one path that is easy to miss: the enableSendCodeWait
// arm renders the phone step while its goroutine keeps running on bgCtx until
// CodeTTL (by design — see startLoginFlow). A refusal on the next /start would
// otherwise drop the reference to that live goroutine without ending it. Every
// other caller reaches here from a <-lf.done arm, where the cancel is a no-op.
func (es *enableSession) abandonFlow() {
	es.step = stepPhone
	if es.flow != nil && es.flow.cancel != nil {
		es.flow.cancel()
	}
	es.flow = nil
}

// renderModeCheckRetry renders the account-mode query having failed. The
// retryable counterpart to renderEnableTerminalError, and the pair is the
// distinction that matters here: a mode CONFLICT is terminal and gets the
// dead-end screen, a mode CHECK failure is not and gets the phone form back.
//
// The phone step rather than renderEnableError specifically because this is
// retryable: the recovery is "resubmit the phone form", and renderEnableError
// writes a page with nothing to resubmit -- which would also make the two
// outcomes visually identical, differing only in wording. Every other
// retryable outcome in handleEnableStart already leaves this way.
//
// One function for both call sites (the pre-flight gate and startLoginFlow's
// re-check) so the wording and the prefilled fields cannot drift apart.
func (s *Server) renderModeCheckRetry(w http.ResponseWriter, es *enableSession, esTok, phone string, sendOptIn bool) {
	// Owned here, like renderEnableTerminalError owns its own abandonFlow, so
	// a third mode-check exit cannot forget it. Forgetting would look fine --
	// renderEnablePhoneStep resets es.step on its own, so the duplicate-/start
	// guard stays satisfied -- while es.flow kept pointing at an uncancelled
	// goroutine, which is the enableSendCodeWait orphan abandonFlow exists to
	// close.
	es.abandonFlow()
	renderEnablePhoneStep(w, es, enablePhonePage{
		Issuer:      s.cfg.Issuer,
		EnableToken: esTok,
		Phone:       phone,
		SendOptIn:   sendOptIn,
		WizardMode:  es.isWizardMode(),
		WizardStep:  3,
		Error:       "Could not verify this account's mode. Try again, or contact the operator if it persists.",
	})
}

// renderEnableTerminalError abandons the flow, records the refusal as terminal
// and renders the dead-end screen. The terminal counterpart to
// renderEnablePhoneStep: it is for refusals a restart cannot clear, so unlike
// that one it must not leave any route back that offers a retry.
func renderEnableTerminalError(w http.ResponseWriter, es *enableSession, msg string) {
	es.abandonFlow()
	es.terminalMsg = msg
	renderEnableError(w, msg)
}

// lookupEnable parses the form, resolves the "es" token to a live (un-expired)
// enableSession, and returns it. ok is false when the token is missing,
// unknown, or past CodeTTL.
func (s *Server) lookupEnable(r *http.Request) (es *enableSession, esTok string, ok bool) {
	if err := r.ParseForm(); err != nil {
		return nil, "", false
	}
	tok := r.FormValue("es")
	if tok == "" {
		return nil, "", false
	}
	s.mu.Lock()
	e, found := s.enables[tok]
	s.mu.Unlock()
	if !found || s.clock().Sub(e.createdAt) > s.cfg.CodeTTL {
		return nil, "", false
	}
	return e, tok, true
}

// handleEnableStart receives the phone number, launches the MTProto login
// goroutine, and renders either the SMS-code screen or (on early failure) the
// phone screen with an error. Re-submitting /start cancels any prior attempt.
func (s *Server) handleEnableStart(w http.ResponseWriter, r *http.Request) {
	es, esTok, ok := s.lookupEnable(r)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}
	if !es.acquireStepLock(r.Context()) {
		renderEnableError(w, "The previous step is still finishing — it can take a moment while Telegram responds. Wait, then resubmit.")
		return
	}
	defer es.lock.Unlock()

	if s.cfg.TGAPIID == 0 || s.cfg.TGAPIHash == "" {
		renderEnableError(w, "This server is not configured for in-browser Telegram login. Contact the operator.")
		return
	}

	// A duplicate /start that acquired the lock after the original already
	// advanced to the code screen must NOT cancel and relaunch the live flow
	// (that would invalidate the SMS code the user is entering and send a
	// second one). Re-render the code screen instead. A legitimate restart
	// after an error arrives with es.step == stepPhone -- every error branch
	// resets it, via renderEnablePhoneStep when the user can retry and via
	// renderEnableTerminalError when the refusal is terminal -- so this only
	// catches duplicates.
	if es.step == stepCode && es.flow != nil {
		renderEnableCode(w, enableCodePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       es.phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
		return
	}

	rawPhone := r.FormValue("phone")
	// In wizard mode the send permission was already captured by
	// handleEnablePermissions; in non-wizard mode read it from the form.
	sendOptIn := es.sendOptIn
	if !es.isWizardMode() {
		sendOptIn = r.FormValue("send_optin") != ""
	}
	phone := normalizePhone(rawPhone)
	if !validPhone(phone) {
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       rawPhone,
			SendOptIn:   sendOptIn,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       "Enter a phone number in international format, e.g. +14155551234.",
		})
		return
	}

	// phoneStart bounds the connect + SendCode round-trip that the select
	// below waits on. Declared before the mode gate so the gate's own outcomes
	// are recorded too: a pre-flight refusal returns without ever reaching
	// startLoginFlow, so leaving the declaration below it made every ordinary
	// mode conflict invisible to mctl_login_phone_step and left only the
	// narrow race window on the dashboard.
	phoneStart := time.Now()
	observePhoneStep := func(result string) {
		if s.metrics != nil {
			s.metrics.ObserveLoginPhoneStep(result, time.Since(phoneStart).Seconds())
		}
	}

	// Refuse a hosted connect while a Local Bridge account is active, BEFORE
	// any MTProto login starts. telegram.Login persists the new session bytes
	// through the gotd SessionStore as soon as auth succeeds, so by the time
	// SaveSession's guard fires the local row's blob is already gone; the only
	// way to leave the bridge untouched is to never start the login.
	if local, cErr := s.hasActiveLocalAccount(r.Context(), es.uid); cErr != nil {
		// Not "error": that label is reserved for Telegram RPC failures (see
		// the select below). This is our own store refusing to answer, and it
		// must not read as Telegram flakiness on the dashboard.
		observePhoneStep("mode_check_error")
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:mode_check", "", "error", cErr.Error(), "")
		// Any refusal already on file has to go. This arm cannot
		// re-derive the account state — that is what just failed — so all it
		// knows is "unknown", and "unknown" must not outrank the retry it is
		// about to offer. Leaving a cached message here would let a step
		// fallback replay a Local Bridge refusal to an account that has since
		// been switched back to hosted, which is the same staleness the clear
		// at the pass-through below exists to prevent, reached through the arm
		// that cannot check instead of the one that can.
		//
		// This is a choice between two wrong messages, not a strict
		// improvement: when the account IS still local the clear discards a
		// refusal that was true, and the next step fallback offers a retry for
		// a condition retrying cannot clear. That is the accepted cost --
		// resubmitting the phone form re-enters the gate and re-derives the
		// refusal in one round-trip, whereas a stale refusal has no such exit,
		// and the user has just been shown a retryable screen either way.
		es.terminalMsg = ""
		s.renderModeCheckRetry(w, es, esTok, rawPhone, sendOptIn)
		return
	} else if local {
		observePhoneStep("mode_conflict")
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(db.ErrAccountModeConflict), "", "error", db.ErrAccountModeConflict.Error(), "")
		renderEnableTerminalError(w, es, friendlyErr(db.ErrAccountModeConflict))
		return
	}

	// Supersede any prior in-flight attempt (the user restarted after an error).
	if es.flow != nil && es.flow.cancel != nil {
		es.flow.cancel()
	}
	es.phone = phone
	es.sendOptIn = sendOptIn
	// Reaching this statement means the pre-flight gate re-derived the account
	// state and let the user through, which is exactly the condition under
	// which a cached terminal message is stale: the operator may have switched
	// the account back to hosted since it was set. Leaving it would let the
	// step fallbacks tell a user whose reconnect is now working that it cannot.
	es.terminalMsg = ""
	es.flow = s.startLoginFlow(es.uid, es.tgID, phone, sendOptIn)
	es.step = stepCode
	lf := es.flow

	select {
	case <-lf.needCode:
		observePhoneStep("ok")
		s.store.LogToolCall(r.Context(), es.uid, "connect:phone_submitted", "", "ok", "", "")
		renderEnableCode(w, enableCodePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
	case <-lf.done:
		if lf.err != nil {
			// Mirror shortReason: a per-RPC deadline (the 25s loginRPCTimeout) or
			// a superseded flow surfaces here as context.DeadlineExceeded/Canceled
			// — that is the SendCode-stall the timeout alert watches, so record it
			// as "timeout", not "error" (which is reserved for Telegram RPC errors
			// like PHONE_NUMBER_INVALID / FLOOD_WAIT).
			// A mode conflict is terminal and Telegram was never contacted, so
			// it gets neither the "Telegram rejected the request ... Try
			// again." framing nor the result="error" label reserved for real
			// RPC failures -- booking it there makes a config condition read
			// as Telegram flakiness on the dashboard. This is also the branch
			// startLoginFlow's own re-check reliably lands in: that check sets
			// lf.err and returns before lf.needCode is ever signalled, so
			// lf.done closes first and the code/password handlers' terminal
			// screens (which got this treatment) are never reached.
			if errors.Is(lf.err, db.ErrAccountModeConflict) {
				observePhoneStep("mode_conflict")
				s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(lf.err), "", "error", lf.err.Error(), "")
				renderEnableTerminalError(w, es, friendlyErr(lf.err))
				return
			}
			// The re-check's other half. Same query, same non-Telegram cause
			// as the pre-flight gate above, so the same label and wording —
			// retryable, hence abandonFlow rather than the terminal renderer.
			// No terminalMsg clear here, unlike the gate arm this mirrors:
			// handleEnableStart empties the field unconditionally before
			// launching the flow, so any request reaching this select has
			// already had it cleared in the same request. Adding the
			// symmetric clear would be dead code, not extra safety.
			if errors.Is(lf.err, errModeCheckFailed) {
				observePhoneStep("mode_check_error")
				s.store.LogToolCall(r.Context(), es.uid, "connect:failed:mode_check", "", "error", lf.err.Error(), "")
				s.renderModeCheckRetry(w, es, esTok, rawPhone, sendOptIn)
				return
			}
			result := "error"
			if errors.Is(lf.err, context.DeadlineExceeded) || errors.Is(lf.err, context.Canceled) {
				result = "timeout"
			}
			observePhoneStep(result)
			s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(lf.err), "", "error", lf.err.Error(), "")
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: rawPhone, SendOptIn: sendOptIn,
				Error: "Telegram rejected the request: " + friendlyErr(lf.err) + " Try again.",
			})
			return
		}
		// Login completed without ever asking for a code (a pre-existing
		// auth on the session storage). Nothing more to collect.
		observePhoneStep("ok")
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSendCodeWait):
		observePhoneStep("timeout")
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:timeout", "", "error", "send code timeout", "")
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: rawPhone, SendOptIn: sendOptIn,
			Error: "Timed out contacting Telegram. Please try again.",
		})
	}
}

// handleEnableCode feeds the SMS code to the login goroutine and renders the
// 2FA screen, the success redirect, or the phone screen on rejection.
func (s *Server) handleEnableCode(w http.ResponseWriter, r *http.Request) {
	es, esTok, ok := s.lookupEnable(r)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}
	if !es.acquireStepLock(r.Context()) {
		renderEnableError(w, "The previous step is still finishing — it can take a moment while Telegram responds. Wait, then resubmit.")
		return
	}
	defer es.lock.Unlock()

	if es.step != stepCode || es.flow == nil {
		// A duplicate submit that acquired the lock after the original advanced
		// to stepPassword must re-render the password screen — NOT call
		// renderEnablePhoneStep, which writes es.step = stepPhone and would
		// bounce the real user back to the phone screen on their next submit.
		if es.step == stepPassword {
			renderEnablePassword(w, enablePasswordPage{
				Issuer:      s.cfg.Issuer,
				EnableToken: esTok,
				WizardMode:  es.isWizardMode(),
				WizardStep:  3,
			})
			return
		}
		// A re-POST of this step after a terminal refusal (browser back, or a
		// client that reissues its last request) must land back on the dead-end
		// screen. "Please start again." below is a retry invitation, and this
		// is the one condition restarting cannot clear.
		if es.terminalMsg != "" {
			renderEnableError(w, es.terminalMsg)
			return
		}
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Please start again.",
		})
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		renderEnableCode(w, enableCodePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       es.phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       "Enter the code Telegram sent you.",
		})
		return
	}
	lf := es.flow

	select {
	case lf.codeCh <- code:
	case <-lf.done:
		// Goroutine already exited — fall through to result handling below.
	case <-time.After(enableChanSendWait):
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "The login flow stopped responding. Please start again.",
		})
		return
	}

	select {
	case <-lf.needPw:
		s.store.LogToolCall(r.Context(), es.uid, "connect:code_submitted", "", "ok", "", "")
		es.step = stepPassword
		renderEnablePassword(w, enablePasswordPage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
	case <-lf.done:
		if lf.err != nil {
			s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(lf.err), "", "error", lf.err.Error(), "")
			// A mode conflict is terminal, not a bad code: retrying the flow
			// re-hits the same guard. Render the dead-end screen rather than
			// the phone step's "start again to get a fresh code" framing.
			if errors.Is(lf.err, db.ErrAccountModeConflict) {
				renderEnableTerminalError(w, es, friendlyErr(lf.err))
				return
			}
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: "The code was not accepted: " + friendlyErr(lf.err) + " Start again to get a fresh code.",
			})
			return
		}
		s.store.LogToolCall(r.Context(), es.uid, "connect:code_submitted", "", "ok", "", "")
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:timeout", "", "error", "verify code timeout", "")
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
			Error: "Timed out verifying the code. Please start again.",
		})
	}
}

// handleEnablePassword feeds the 2FA cloud password to the login goroutine and
// renders the success redirect, or the phone screen on rejection.
func (s *Server) handleEnablePassword(w http.ResponseWriter, r *http.Request) {
	es, esTok, ok := s.lookupEnable(r)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}
	if !es.acquireStepLock(r.Context()) {
		renderEnableError(w, "The previous step is still finishing — it can take a moment while Telegram responds. Wait, then resubmit.")
		return
	}
	defer es.lock.Unlock()

	if es.step != stepPassword || es.flow == nil {
		// If the original request already finished the sign-in (stepDone), a
		// late duplicate must not reset es.step; the session is done. The real
		// user already has their authorization code.
		if es.step == stepDone {
			renderEnableError(w, "This sign-in already completed. Return to your MCP client.")
			return
		}
		// Same as handleEnableCode: a terminal refusal outranks the retry
		// framing below.
		if es.terminalMsg != "" {
			renderEnableError(w, es.terminalMsg)
			return
		}
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Please start again.",
		})
		return
	}
	password := r.FormValue("password")
	if password == "" {
		renderEnablePassword(w, enablePasswordPage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       "Enter your Telegram two-step verification password.",
		})
		return
	}
	lf := es.flow

	select {
	case lf.pwCh <- password:
	case <-lf.done:
		// Goroutine already exited — fall through to result handling below.
	case <-time.After(enableChanSendWait):
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "The login flow stopped responding. Please start again.",
		})
		return
	}

	select {
	case <-lf.done:
		if lf.err != nil {
			s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(lf.err), "", "error", lf.err.Error(), "")
			// Terminal, same as in handleEnableCode: a mode conflict is not a
			// wrong password and restarting cannot clear it.
			if errors.Is(lf.err, db.ErrAccountModeConflict) {
				renderEnableTerminalError(w, es, friendlyErr(lf.err))
				return
			}
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: "The password was not accepted: " + friendlyErr(lf.err) + " Start again.",
			})
			return
		}
		s.store.LogToolCall(r.Context(), es.uid, "connect:2fa_submitted", "", "ok", "", "")
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:timeout", "", "error", "verify password timeout", "")
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
			Error: "Timed out verifying the password. Please start again.",
		})
	}
}

// finishEnable consumes the enable session and hands control back to the
// standard authorization-code redirect.
func (s *Server) finishEnable(w http.ResponseWriter, r *http.Request, es *enableSession, esTok string) {
	es.step = stepDone
	s.mu.Lock()
	delete(s.enables, esTok)
	s.mu.Unlock()
	s.store.LogToolCall(r.Context(), es.uid, "connect:success", "", "ok", "", "")
	// Completing MTProto login is the registration event: persist the
	// client tier so an auto-approved user keeps access after
	// AUTO_APPROVE_CLIENTS is flipped off. Only write when open
	// registration is on and the row is still unset. Neither this path
	// nor the OIDC auto-grant excludes ClientTelegramIDs: when
	// AutoApproveClients is on, an env-listed identity gets the same
	// persisted 'client' row as any other first-time user. While
	// AutoApproveClients is off the write does not run, so an
	// env-listed TG_LOGIN_CLIENTS identity stays unset and removal
	// from the allowlist still revokes. An explicit none set by an
	// admin is never overwritten. Admins and lookup-only identities
	// keep their env-allowlist tiers — writing 'client' for a lookup
	// admin is the same trap that path already refuses (removal
	// would promote them).
	if s.cfg.AutoApproveClients && !s.cfg.AdminTelegramIDs[es.tgID] && !s.cfg.LookupAdminTelegramIDs[es.tgID] {
		dbTier, err := s.store.GetAccessTier(r.Context(), es.tgID)
		if err != nil {
			slog.Error("finishEnable: read access tier", "uid", es.uid, "err", err)
		} else if dbTier == "" {
			if terr := s.store.SetAccessTier(r.Context(), es.tgID, db.TierClient); terr != nil {
				slog.Error("finishEnable: set client tier", "uid", es.uid, "err", terr)
			} else {
				slog.Info("auto-granted client tier on enable", "telegram_id", es.tgID)
			}
		}
	}
	s.issueAuthCode(w, r, es.oc)
}

// normalizePhone strips the spacing characters humans type into phone fields
// so "+1 (415) 555-1234" validates the same as "+14155551234".
func normalizePhone(s string) string {
	var b strings.Builder
	for _, c := range strings.TrimSpace(s) {
		switch c {
		case ' ', '-', '(', ')', '.', '\t':
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}

// validPhone enforces a loose E.164 shape: a leading '+', a non-zero country
// digit, and 7-15 digits total. Telegram does the authoritative check.
func validPhone(s string) bool {
	if len(s) < 8 || len(s) > 16 || s[0] != '+' || s[1] == '0' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// localModeConnectMsg is the terminal wording for a hosted connect refused
// because Local Bridge owns the account. It deliberately does not tell the
// signed-in user to "switch the account back to hosted mode": mode changes go
// through set_account_mode, which is admin-only, so that instruction is a dead
// end for the person reading the screen. Point them at the two things they can
// actually do instead.
const localModeConnectMsg = "This account runs Local Bridge — its Telegram session lives on your own machine, and connecting here would replace it. Stop the bridge on that machine, or ask the operator to move the account back to hosted mode, then reconnect."

// friendlyErr renders a login error for display. Telegram RPC errors are
// short codes (PHONE_NUMBER_INVALID, FLOOD_WAIT) and carry no secrets; the
// phone/code/password never appear in telegram.Login's error strings.
func friendlyErr(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "the login attempt expired."
	}
	if errors.Is(err, db.ErrAccountModeConflict) {
		return localModeConnectMsg
	}
	// Map well-known MTProto error codes to human-readable messages.
	var rpcErr *tgerr.Error
	if errors.As(err, &rpcErr) {
		switch {
		case rpcErr.Message == "PHONE_NUMBER_INVALID":
			return "The phone number is not valid. Use international format, e.g. +14155551234."
		case rpcErr.Message == "PHONE_CODE_INVALID":
			return "The login code is incorrect."
		case rpcErr.Message == "PHONE_CODE_EXPIRED":
			return "The login code has expired. Start again to receive a fresh code."
		case strings.HasPrefix(rpcErr.Message, "FLOOD_WAIT_"):
			return "Telegram rate limit reached. Wait a moment before trying again."
		}
	}
	m := err.Error()
	if len(m) > 200 {
		m = m[:200]
	}
	if !strings.HasSuffix(m, ".") {
		m += "."
	}
	return m
}

// shortReason maps a login error to a short token suitable for use in an audit
// tool_name suffix (e.g. "connect:failed:phone_invalid").
func shortReason(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, errIdentityCleanupTimeout) {
		return "identity_cleanup_timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if errors.Is(err, db.ErrAccountModeConflict) {
		return "local_mode_active"
	}
	var rpcErr *tgerr.Error
	if errors.As(err, &rpcErr) {
		switch {
		case rpcErr.Message == "PHONE_NUMBER_INVALID":
			return "phone_invalid"
		case rpcErr.Message == "PHONE_CODE_INVALID":
			return "code_invalid"
		case rpcErr.Message == "PHONE_CODE_EXPIRED":
			return "code_expired"
		case strings.HasPrefix(rpcErr.Message, "FLOOD_WAIT_"):
			return "flood_wait"
		}
	}
	if strings.Contains(err.Error(), "different Telegram account") {
		return "identity_mismatch"
	}
	return "unknown"
}
