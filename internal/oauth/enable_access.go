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
	"sync/atomic"
	"time"

	tdauth "github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// enableStep tracks where an enable_access flow is. Guarded by enableSession.lock.
type enableStep int

const (
	stepPermissions enableStep = iota // awaiting permissions choice (wizard mode only)
	stepPhone                         // awaiting the phone number (initial screen)
	stepCode                          // awaiting the SMS code
	stepPassword                      // awaiting the 2FA cloud password
	stepDone                          // session provisioned, authorization code issued
	stepQR                            // showing a QR code, waiting for a scan (#901)
)

// Per-step waits. SendCode/SignIn are network round-trips against Telegram;
// the channel sends are near-instant because the login goroutine is already
// parked in askCode/askPassword by the time a handler writes to them.
const (
	enableSignInWait   = 60 * time.Second
	enableChanSendWait = 10 * time.Second
)

// enableSendCodeWait is a var, not a const, only so tests can shorten it to
// drive handleEnableStart's timeout arm; production never writes it.
var enableSendCodeWait = 90 * time.Second

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
	// terminalDesc is the error_description that goes with terminalMsg on
	// the access_denied return to the client.
	terminalDesc string

	// qrOffered is whether the phone step shows "Use a QR code instead"
	// (#901): the QR flag is on and the browser that reached the callback is
	// a desktop one, where the code is scanned with the phone. Fixed at the
	// callback. It only decides the button; the QR routes check the flag.
	qrOffered bool
	// qrWait is how long the current QR flow waits for a scan, fixed when
	// it starts; the status page states it.
	qrWait time.Duration
}

// loginFlow couples an HTTP handler to the background goroutine running
// telegram.Login. The goroutine blocks in askCode/askPassword reading codeCh
// and pwCh; needCode/needPw signal which input the goroutine is waiting for;
// done is closed when telegram.Login and session finalisation have returned.
//
// needCode/needPw carry the prompt's telegram.Reprompt: the zero value for the
// first prompt, and the reason and attempts left when telegram.Login asks
// again within the same flow (a mistyped code or password, or a new code after
// AUTH_RESTART). Passing it through the channel, rather than a field, keeps it
// ordered with the signal itself.
type loginFlow struct {
	codeCh   chan string
	pwCh     chan string
	needCode chan telegram.Reprompt
	needPw   chan telegram.Reprompt
	done     chan struct{}
	cancel   context.CancelFunc

	// Result fields — written by the goroutine before it closes done, and
	// read by handlers only after a receive from done. The channel close
	// provides the happens-before edge, so no mutex is needed.
	tgUserID int64
	err      error

	// step is the last onboarding stage this flow reached. Written around
	// the loginFn call below on the login goroutine, and inside askCode/
	// askPassword -- which in production run on a goroutine gotd's
	// client.Run spawns for its callback (telegram.Login ->
	// client.Run(ctx, fn)), NOT on the login goroutine. It is still read
	// unsynchronised by the deferred logger, and that is safe because
	// client.Run joins its callback goroutine before it returns: loginFn
	// returning is the happens-before edge between the last write and the
	// read. Do not add a mutex; do not read step anywhere else.
	step string
	// superseded is set by a /start re-submission before it calls cancel(),
	// so the deferred logger can tell "user started over" from "user walked
	// away". Both surface as context.Canceled/DeadlineExceeded and are
	// otherwise indistinguishable (see the comment on abandonFlow and its
	// sibling call site). atomic.Bool because its writers are HTTP handler
	// goroutines, not this flow's own login goroutine.
	superseded atomic.Bool

	// method is the loginMethod name ("code" or "qr"). Set before the
	// goroutine starts and never written again.
	method string
	// qrURL is the newest QR login URL telegram.LoginQR exported, for the
	// status page to draw. It is a login token: it is never logged, written
	// to the audit or put in a URL, and lives only as long as the flow.
	qrURL atomic.Pointer[string]
	// qrScanned is set once a scanned QR login asks for the 2FA password,
	// after the needPw signal is buffered. The status page reads it, never
	// step, which is not safe to read from a handler.
	qrScanned atomic.Bool
	// heldSession is the session the login hands over through
	// LoginConfig.HoldSession instead of writing it (#919, #913).
	// Written and read only by the flow's own goroutine.
	heldSession []byte
}

// Login method names, the method label on mctl_login_flow_total and the
// audit Reason on QR rows.
const (
	methodCode = "code"
	methodQR   = "qr"
)

// loginMethod is how an enable_access flow signs in to Telegram (#901):
// phone number and login code through telegram.Login, or a QR code through
// telegram.LoginQR.
type loginMethod struct {
	name string
	// firstStep is lf.step while the login runs, before it asks for input.
	firstStep string
	// qrWait is LoginConfig.QRWait for this flow; zero for the phone method.
	qrWait time.Duration
	run    func(ctx context.Context, uid int64, lf *loginFlow, askCode, askPassword func(context.Context) (string, error), cfg telegram.LoginConfig) (int64, string, string, error)
}

// phoneLogin is the phone-number-and-code method for phone.
func (s *Server) phoneLogin(phone string) loginMethod {
	return loginMethod{
		name:      methodCode,
		firstStep: "phone_submitted",
		run: func(ctx context.Context, uid int64, _ *loginFlow, askCode, askPassword func(context.Context) (string, error), cfg telegram.LoginConfig) (int64, string, string, error) {
			return s.loginFn(ctx, s.cfg.TGAPIID, s.cfg.TGAPIHash, s.store, uid, phone, askCode, askPassword, cfg)
		},
	}
}

// isAbandonment reports whether err is the shape a walked-away user leaves
// behind: the flow's own CodeTTL deadline, or its context being cancelled
// with no explicit supersession recorded. errors.Is, never a string match on
// "context canceled" -- see design.md's Alternatives section for why a
// string match cannot distinguish this from any other error that happens to
// wrap a cancelled context.
func isAbandonment(err error) bool {
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

// isUserWaitStep reports whether a flow at step is parked on the user: a
// code or password prompt, or a QR code on screen. A context error there is
// a user who walked away, not a stall on our side or Telegram's.
func isUserWaitStep(step string) bool {
	switch step {
	case "code_requested", "password_requested", "qr_shown":
		return true
	}
	return false
}

// enableQRWait is the longest a QR code stays on screen before the flow stops
// waiting for a scan (#901); enableQRWaitFor shortens it to what is left of
// the enable session. The 2FA password asked after a scan is not part of it.
// A var only so tests can shorten it.
var enableQRWait = 5 * time.Minute

// loginFlowResult is the result label mctl_login_flow_total records for a
// finished flow, classified the same way as the final log line.
func loginFlowResult(lf *loginFlow) string {
	switch {
	case lf.err == nil:
		return "ok"
	case lf.superseded.Load() && isAbandonment(lf.err):
		return "superseded"
	case errors.Is(lf.err, telegram.ErrQRLoginExpired):
		return "expired"
	case isAbandonment(lf.err) && (isUserWaitStep(lf.step) || lf.step == "queued"):
		return "abandoned"
	case shortReason(lf.err) == "identity_mismatch":
		return "mismatch"
	}
	return "error"
}

// startLoginFlow launches the login method m in a background goroutine driven
// by channels. The goroutine owns a context with a CodeTTL deadline so it
// always terminates even if the user abandons the browser; cancel releases it
// sooner when a /start re-submission supersedes it. wantTgID is the
// OIDC-proven Telegram id — the goroutine rejects the flow if the login
// resolves to a different account.
func (s *Server) startLoginFlow(uid, wantTgID int64, m loginMethod, sendOptIn bool, signInStartedAt time.Time) *loginFlow {
	lf := &loginFlow{
		codeCh:   make(chan string),
		pwCh:     make(chan string),
		needCode: make(chan telegram.Reprompt, 1),
		needPw:   make(chan telegram.Reprompt, 1),
		done:     make(chan struct{}),
		method:   m.name,
	}
	bgCtx, cancel := context.WithTimeout(context.Background(), s.cfg.CodeTTL)
	lf.cancel = cancel
	// Supersede the uid's previous flow whatever enable session it belongs
	// to. handleEnableStart only cancels es.flow, the attempt made from the
	// same wizard token; an attempt from a fresh tab has a fresh token and
	// would otherwise queue on the uid mutex behind a predecessor parked in
	// askCode until that one's CodeTTL expires -- 30 minutes in production,
	// during which every /start for this account times out and each timed-out
	// goroutine still sends a login code once it finally gets the mutex
	// (mctl-telegram#859). Cancelling the predecessor makes its askCode/
	// askPassword return at once, so it releases the mutex before this
	// goroutine asks for it. Same superseded-then-cancel order as the
	// in-session path, so the predecessor logs the INFO supersession line.
	if prev, loaded := s.loginFlows.Swap(uid, lf); loaded {
		if p, ok := prev.(*loginFlow); ok && p != nil && p != lf {
			p.superseded.Store(true)
			p.cancel()
		}
	}

	askCode := func(ctx context.Context) (string, error) {
		lf.step = "code_requested"
		rp, _ := telegram.RepromptFrom(ctx)
		select {
		case lf.needCode <- rp:
		default:
		}
		select {
		case c := <-lf.codeCh:
			lf.step = "code_submitted"
			return c, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	askPassword := func(ctx context.Context) (string, error) {
		lf.step = "password_requested"
		rp, _ := telegram.RepromptFrom(ctx)
		select {
		case lf.needPw <- rp:
		default:
		}
		// After the signal, so the status page that sees it can take the
		// buffered needPw before it moves the user to the password step.
		lf.qrScanned.Store(true)
		select {
		case p := <-lf.pwCh:
			lf.step = "password_submitted"
			return p, nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}

	go func() {
		defer cancel()
		defer close(lf.done)
		// Only drop the registry entry if it is still ours: a successor has
		// already swapped itself in when it superseded this flow, and
		// deleting unconditionally would unregister that live successor.
		defer s.loginFlows.CompareAndDelete(uid, lf)
		// The per-step HTTP handler abandons its wait after enableSendCodeWait/
		// enableSignInWait and logs only a coarse "timeout" to the audit, while
		// this goroutine keeps running on bgCtx (CodeTTL). Without this it is the
		// only place that sees the real telegram.Login error (FLOOD_WAIT, DC
		// dial failure, RPC hang surfacing as the bgCtx deadline), so log the
		// final outcome here regardless of whether a handler is still waiting.
		started := time.Now()
		defer func() {
			if s.metrics != nil {
				s.metrics.ObserveLoginFlow(m.name, loginFlowResult(lf), time.Since(started).Seconds())
			}
		}()
		defer func() {
			elapsed := time.Since(started).String()
			switch {
			case lf.err == nil:
				slog.Info("enable: telegram login succeeded",
					"uid", uid, "tg_id", lf.tgUserID,
					"elapsed", elapsed)
			case lf.superseded.Load() && isAbandonment(lf.err):
				// A later /start re-submission cancelled this flow — the user
				// started over, not walked away. INFO, not an error: this is
				// an ordinary UI interaction, and logging it at WARN/ERROR
				// would make the abandonment reclassification below noisy for
				// no reason. The error must actually be the cancellation:
				// superseded is stored by handler goroutines and can land
				// while this goroutine already holds a real failure
				// (FLOOD_WAIT, identity mismatch, errModeCheckFailed), which
				// must keep falling through to the ERROR arm with its err.
				slog.Info("enable: login flow superseded",
					"uid", uid, "step", lf.step, "elapsed", elapsed)
			case errors.Is(lf.err, telegram.ErrQRLoginExpired):
				// Nobody scanned the QR code in time: the user walked away
				// from it, the QR counterpart of the arm below.
				slog.Warn("enable: onboarding abandoned",
					"uid", uid, "step", lf.step, "method", m.name, "elapsed", elapsed)
			case isAbandonment(lf.err) && isUserWaitStep(lf.step):
				// The CodeTTL deadline expired while parked in askCode/
				// askPassword: a user who walked away from the browser. WARN,
				// not ERROR -- see design.md's rationale. No err attribute:
				// "context canceled"/"context deadline exceeded" is the
				// deadline restated, and dropping it is what keeps a
				// log-scraper from alerting on the word "canceled" itself.
				//
				// Gated on the step: bgCtx's deadline covers the whole loginFn
				// call, so the same context error also surfaces when SendCode
				// or the sign-in RPC hangs (step phone_submitted /
				// code_submitted / password_submitted) or when the
				// hasActiveLocalAccount query above times out. Those are
				// Telegram- or DB-side stalls, not a user walking away, and
				// they keep the ERROR arm with the underlying err.
				slog.Warn("enable: onboarding abandoned",
					"uid", uid, "step", lf.step, "elapsed", elapsed)
			case isAbandonment(lf.err) && lf.step == "queued":
				// The flow's own CodeTTL ran out while it was still waiting
				// for the uid mutex, with no supersession recorded: it never
				// contacted the database or Telegram, so there is no failure
				// to report, only a slot that was never reached. WARN like the
				// walked-away case, not ERROR.
				slog.Warn("enable: login flow expired before it started",
					"uid", uid, "elapsed", elapsed)
			default:
				slog.Error("enable: telegram login failed",
					"uid", uid, "want_tg_id", wantTgID,
					"elapsed", elapsed, "err", lf.err)
			}
		}()
		// Serialise login work for this uid. A /start re-submission cancels
		// the prior flow and starts a new one; without this lock the cancelled
		// predecessor — if its login RPC had already returned — could still
		// run its SaveSession and clobber the newer flow's session.
		ul := s.uidLoginMutex(uid)
		// Test seam (nil in production): announce that this goroutine is about
		// to park on the mutex, so a test holding it can provision a local
		// account into the window the re-check below exists for.
		if s.loginFlowParked != nil {
			s.loginFlowParked()
		}
		ul.Lock()
		defer ul.Unlock()
		// The wait for the mutex is not context-aware, so a flow cancelled
		// while queued (superseded by a newer attempt, or dropped by its
		// handler's enableSendCodeWait) still gets here once the holder
		// releases. Leave before touching the database or Telegram: this is
		// exactly the goroutine that would otherwise send the stray login
		// code the user never asked for.
		if cErr := bgCtx.Err(); cErr != nil {
			lf.step = "queued"
			lf.err = cErr
			return
		}
		// Re-check under the uid lock, after handleEnableStart's pre-flight
		// check: a local account could have been provisioned between the two.
		// This is the last point at which we can refuse before the user is
		// sent a login code (or shown a QR code) for a connect that
		// SaveSessionForSignIn would refuse anyway. The login itself writes
		// nothing (#913), so a local row provisioned after this point is
		// still caught there, before any bytes reach it.
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
		lf.step = m.firstStep
		// WantTelegramID makes the login itself log out an account other than
		// the OIDC-proven one, so the refusal below does not leave that
		// account with a live device (#899).
		loginCfg := s.loginCfg
		loginCfg.WantTelegramID = wantTgID
		loginCfg.QRWait = m.qrWait
		// Both methods hand their session over here instead of writing it
		// (#919, #913). A held session is an authorization only this
		// goroutine knows about: it was never written, so nothing else will
		// ever find it. Every exit that does not commit it -- the cancel
		// guard, a failed or refused SaveSessionForSignIn, a cancel that
		// lands after the guard -- has to log it out, or the user keeps a
		// device nobody holds in Active Sessions. A defer, so a future exit
		// cannot forget it. Registered before the login, so it runs before
		// the flow reports done.
		loginCfg.HoldSession = func(b []byte) { lf.heldSession = b }
		defer func() {
			if lf.heldSession != nil {
				s.logOutHeldSession(bgCtx, uid, lf.heldSession)
				lf.heldSession = nil
			}
		}()
		tgID, displayName, username, err := m.run(bgCtx, uid, lf, askCode, askPassword, loginCfg)
		if err != nil {
			lf.err = err
			return
		}
		// Identity binding. The Telegram account that just signed in MUST be
		// the same one Telegram OIDC proved. Otherwise an admin authenticated
		// as account A could enter account B's phone (or scan with B) and end
		// up operating B's messages through A's token. The login has already
		// logged B's new authorization out and written nothing, so there is
		// nothing of it to revoke here -- and revoking anyway would end the
		// session the user already had (#913).
		if tgID != wantTgID {
			if m.name == methodQR {
				lf.err = errors.New("the QR code was scanned with a different Telegram account than the one you signed in with — scan it with the same account")
			} else {
				lf.err = errors.New("the phone number belongs to a different Telegram account than the one you signed in with — log in with the same account")
			}
			return
		}
		// The user cancelled this attempt, or another one superseded it,
		// while the login was finishing (#919): the scan or code landed just
		// after. It must not complete the sign-in. superseded is set before
		// the cancel, so it also covers the moment before bgCtx sees it. The
		// held session is logged out by the defer above; it was never
		// written. After the identity binding, so a mismatch on a flow that
		// expired meanwhile still reports the mismatch.
		if bgCtx.Err() != nil || lf.superseded.Load() {
			lf.err = fmt.Errorf("sign-in finished after the attempt was cancelled: %w", context.Canceled)
			return
		}
		// The login held its session instead of writing it: it reaches the
		// database only here, in the same transaction as the telegram_accounts
		// metadata (telegram_user_id, display name, expires_at, send_enabled
		// default), so a cancel or a failure can never leave a written blob
		// without SaveSessionForSignIn.
		pt := lf.heldSession
		if pt == nil {
			lf.err = errors.New("login completed but no session bytes were persisted")
			return
		}
		// SaveSessionForSignIn, not SaveSession: a delete that committed
		// while this sign-in was in progress must not leave the new session
		// behind (#821).
		if s.beforeSignInSave != nil {
			s.beforeSignInSave()
		}
		if serr := s.store.SaveSessionForSignIn(bgCtx, uid, pt, tgID, displayName, username, signInStartedAt); serr != nil {
			lf.err = fmt.Errorf("save session: %w", serr)
			return
		}
		// The session is now legitimately the user's: the defer must not
		// log it out.
		lf.heldSession = nil
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

// logOutHeldSession ends the authorization a held session carries, best
// effort, on telegram.DetachedLogOutContext: it usually runs because bgCtx
// was cancelled.
func (s *Server) logOutHeldSession(bgCtx context.Context, uid int64, data []byte) {
	ctx, cancel := telegram.DetachedLogOutContext(bgCtx)
	defer cancel()
	var err error
	if s.logOutSessionFn != nil {
		err = s.logOutSessionFn(ctx, data)
	} else {
		err = telegram.LogOutSession(ctx, s.cfg.TGAPIID, s.cfg.TGAPIHash, data, s.loginCfg)
	}
	if err != nil {
		slog.Warn("enable: logout of an unsaved sign-in failed", "uid", uid, "err", err)
		return
	}
	slog.Info("enable: logged out an unsaved sign-in", "uid", uid)
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
		QROffered:   es.qrOffered,
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
	p.QROffered = es.qrOffered
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
		es.flow.superseded.Store(true)
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
func (s *Server) renderEnableTerminalError(w http.ResponseWriter, es *enableSession, err error) {
	es.abandonFlow()
	es.terminalMsg = friendlyErr(err)
	es.terminalDesc = deniedDescription(err)
	s.renderEnableTerminal(w, es)
}

// renderEnableTerminal renders the dead-end screen recorded on es, with the
// access_denied return to the client.
func (s *Server) renderEnableTerminal(w http.ResponseWriter, es *enableSession) {
	s.renderEnableDenied(w, es.oc, es.terminalMsg, es.terminalDesc)
}

// isTerminalLoginErr reports whether a login error is a refusal restarting
// the flow cannot clear: an active Local Bridge account, or a delete that
// committed after this sign-in started (signInStartedAt is fixed for the
// session, so every retry is refused again).
func isTerminalLoginErr(err error) bool {
	return errors.Is(err, db.ErrAccountModeConflict) || errors.Is(err, db.ErrAccountDeletedSinceGrant)
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

	// Any refusal already on file goes here, once, for every way the gate can
	// end. Reaching the live account-state check is itself the proof that a
	// cached answer is superseded: whatever the check returns -- pass,
	// conflict, or "cannot tell" -- is derived from the account as it is now,
	// and the cached message is by construction older. The conflict arm
	// re-sets the field through renderEnableTerminalError two lines below, so
	// the only paths that keep an empty field are the two that should.
	//
	// Placed before the gate rather than on each of its exits deliberately.
	// The rule is one sentence -- a cached terminal refusal must not outlive
	// the state that justified it -- but as a per-exit clear it took three
	// commits to establish, one exit at a time, and the next exit added
	// between here and startLoginFlow would have reintroduced it again. Here
	// it covers exits that do not exist yet.
	//
	// The cost is real and accepted: when the account IS still local, the
	// mode_check_error arm now discards a refusal that was true and offers a
	// retry for a condition retrying cannot clear. Resubmitting the phone form
	// re-enters this gate and re-derives the refusal in one round-trip,
	// whereas a stale refusal has no such exit, and that arm has just shown
	// the user a retryable screen either way.
	es.terminalMsg, es.terminalDesc = "", ""

	// Refuse a hosted connect while a Local Bridge account is active, BEFORE
	// any MTProto login starts: the user would otherwise go through a login
	// code and 2FA only for SaveSessionForSignIn to refuse the session at
	// the end. The login writes nothing before that (#913), so the bridge
	// row itself is safe either way.
	if local, cErr := s.hasActiveLocalAccount(r.Context(), es.uid); cErr != nil {
		// Not "error": that label is reserved for Telegram RPC failures (see
		// the select below). This is our own store refusing to answer, and it
		// must not read as Telegram flakiness on the dashboard.
		observePhoneStep("mode_check_error")
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:mode_check", Status: "error", ErrMsg: cErr.Error()})
		// The clear above already ran: this arm cannot re-derive the account
		// state -- that is what just failed -- so all it knows is "unknown",
		// and "unknown" must not outrank the retry it is about to offer.
		s.renderModeCheckRetry(w, es, esTok, rawPhone, sendOptIn)
		return
	} else if local {
		observePhoneStep("mode_conflict")
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + shortReason(db.ErrAccountModeConflict), Status: "error", ErrMsg: db.ErrAccountModeConflict.Error()})
		s.renderEnableTerminalError(w, es, db.ErrAccountModeConflict)
		return
	}

	// Supersede any prior in-flight attempt (the user restarted after an error).
	if es.flow != nil && es.flow.cancel != nil {
		es.flow.superseded.Store(true)
		es.flow.cancel()
	}
	es.phone = phone
	es.sendOptIn = sendOptIn
	es.flow = s.startLoginFlow(es.uid, es.tgID, s.phoneLogin(phone), sendOptIn, es.oc.SignInStartedAt)
	es.step = stepCode
	lf := es.flow

	select {
	case <-lf.needCode:
		observePhoneStep("ok")
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:phone_submitted", Status: "ok"})
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
				s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + shortReason(lf.err), Status: "error", ErrMsg: lf.err.Error()})
				s.renderEnableTerminalError(w, es, lf.err)
				return
			}
			// The re-check's other half. Same query, same non-Telegram cause
			// as the pre-flight gate above, so the same label and wording —
			// retryable, hence abandonFlow rather than the terminal renderer.
			// No terminalMsg clear here, and none is needed: the single
			// clear ahead of the pre-flight gate ran in this same request,
			// before the flow it is now reporting on was ever launched. A
			// symmetric clear would be dead code, not extra safety.
			if errors.Is(lf.err, errModeCheckFailed) {
				observePhoneStep("mode_check_error")
				s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:mode_check", Status: "error", ErrMsg: lf.err.Error()})
				s.renderModeCheckRetry(w, es, esTok, rawPhone, sendOptIn)
				return
			}
			result := "error"
			if errors.Is(lf.err, context.DeadlineExceeded) || errors.Is(lf.err, context.Canceled) {
				result = "timeout"
			}
			observePhoneStep(result)
			reason := shortReason(lf.err)
			s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + reason, Status: "error", ErrMsg: lf.err.Error()})
			msg := phoneStepErrMsg(lf.err)
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: rawPhone, SendOptIn: sendOptIn,
				Error: msg,
			})
			return
		}
		// Login completed without ever asking for a code (a pre-existing
		// auth on the session storage). Nothing more to collect.
		observePhoneStep("ok")
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSendCodeWait):
		observePhoneStep("timeout")
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:timeout", Status: "error", ErrMsg: "send code timeout"})
		// The user is sent back to the phone form, so the flow this request
		// launched must not keep running behind their back: left alive it
		// would deliver a login code minutes later, after they have already
		// resubmitted or walked away (mctl-telegram#859). Cancelling here is
		// safe because SendCode itself is bounded by loginRPCTimeout, far
		// below enableSendCodeWait -- a flow still not at askCode by now is
		// queued on the uid mutex or stalled, never mid-delivery.
		es.abandonFlow()
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: rawPhone, SendOptIn: sendOptIn,
			Error: "Timed out contacting Telegram. Please try again.",
		})
	}
}

// handleEnableCode feeds the login code to the login goroutine and renders the
// 2FA screen, the success redirect, the code screen again when the code did
// not match and attempts are left, or the phone screen when the flow ended.
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
			s.renderEnableTerminal(w, es)
			return
		}
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Please start again.",
		})
		return
	}
	// Only the digits reach Telegram, so "12 345" or a pasted "Login code:
	// 12345" is the code the user meant rather than a rejected one (#900).
	code := telegram.LoginCodeDigits(r.FormValue("code"))
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
	case rp := <-lf.needCode:
		// telegram.Login asked for the code again within the same flow: the
		// code did not match (or Telegram restarted the sign-in and sent a new
		// one). Stay on this step. The audit row is connect:retry:*, not
		// connect:failed:*, because the flow is still alive.
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:retry:" + rp.Reason, Status: "error", ErrMsg: rp.Reason})
		renderEnableCode(w, enableCodePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       es.phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       codeRepromptMsg(rp),
		})
	case <-lf.needPw:
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:code_submitted", Status: "ok"})
		es.step = stepPassword
		renderEnablePassword(w, enablePasswordPage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
	case <-lf.done:
		if lf.err != nil {
			s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + shortReason(lf.err), Status: "error", ErrMsg: lf.err.Error()})
			// A mode conflict or a delete since the sign-in started is
			// terminal, not a bad code: retrying the flow re-hits the same
			// guard. Render the dead-end screen rather than
			// the phone step's "start again to get a fresh code" framing.
			if isTerminalLoginErr(lf.err) {
				s.renderEnableTerminalError(w, es, lf.err)
				return
			}
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: codeStepErrMsg(lf.err),
			})
			return
		}
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:code_submitted", Status: "ok"})
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:timeout", Status: "error", ErrMsg: "verify code timeout"})
		renderEnablePhoneStep(w, es, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
			Error: "Timed out verifying the code. Please start again.",
		})
	}
}

// handleEnablePassword feeds the 2FA cloud password to the login goroutine and
// renders the success redirect, the password screen again after a wrong
// password with attempts left, the code screen when an AUTH_RESTART during the
// password check made Telegram send a new code, or the phone screen when the
// flow ended. (The reverse cannot strand the user: handleEnableCode already
// follows the flow onto the password step through lf.needPw.)
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
			s.renderEnableTerminal(w, es)
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
	case rp := <-lf.needCode:
		// The password check hit AUTH_RESTART: telegram.Login restarted the
		// sign-in, Telegram sent a new code, and the goroutine is parked in
		// askCode for it. Move the user back to the code step so they can
		// enter it, instead of waiting out enableSignInWait here while the
		// flow waits for a code nobody can submit.
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:retry:" + rp.Reason, Status: "error", ErrMsg: rp.Reason})
		es.step = stepCode
		renderEnableCode(w, enableCodePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       es.phone,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       codeRepromptMsg(rp),
		})
	case rp := <-lf.needPw:
		// A wrong password with attempts left: telegram.Login is asking again
		// on the same connection, so the user stays on this step.
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:retry:" + rp.Reason, Status: "error", ErrMsg: rp.Reason})
		renderEnablePassword(w, enablePasswordPage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
			Error:       passwordRepromptMsg(rp),
		})
	case <-lf.done:
		if lf.err != nil {
			reason := shortReason(lf.err)
			s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + reason, Status: "error", ErrMsg: lf.err.Error(), Reason: es.qrAuditReason()})
			// Terminal, same as in handleEnableCode: neither refusal is a
			// wrong password and restarting cannot clear it.
			if isTerminalLoginErr(lf.err) {
				s.renderEnableTerminalError(w, es, lf.err)
				return
			}
			// A scanned QR login asked for this password. Its restart is a
			// new QR code, not a phone number and a fresh code.
			if lf.method == methodQR {
				s.renderQRFailed(w, es, esTok, lf.err)
				return
			}
			if reason == "bad_password" {
				// Only the last of telegram.LoginPasswordAttempts wrong
				// passwords lands here; earlier ones come back through
				// lf.needPw above and keep the user on the password step.
				// By now the login goroutine has exited and es.flow cannot
				// accept another password, so the way forward is a fresh
				// phone + code round.
				// The copy must match the page it lands on: this is the phone
				// step, so it tells the user to restart rather than echoing
				// friendlyErr's "check it and try again", which only makes
				// sense on a live password step.
				renderEnablePhoneStep(w, es, enablePhonePage{
					Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
					Error: badPasswordRestartMsg,
				})
				return
			}
			// Every wrong password took the bad_password arm above, so
			// whatever ended the flow here was not the password (#909).
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: framedLoginErr(signInDidNotFinishPrefix, lf.err, " Start again."),
			})
			return
		}
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:2fa_submitted", Status: "ok", Reason: es.qrAuditReason()})
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:timeout", Status: "error", ErrMsg: "verify password timeout"})
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
	s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:success", Status: "ok", Reason: es.qrAuditReason()})
	// Completing MTProto login is the registration event: persist the
	// client tier so an auto-approved user keeps access after
	// AUTO_APPROVE_CLIENTS is flipped off. Only write when open
	// registration is on; the SQL predicate (GrantClientTierIfUnset)
	// is what keeps an already-set tier — including a concurrent
	// admin none — from being overwritten. Neither this path nor the
	// OIDC auto-grant excludes ClientTelegramIDs: when
	// AutoApproveClients is on, an env-listed identity gets the same
	// persisted 'client' row as any other first-time user. While
	// AutoApproveClients is off the write does not run, so an
	// env-listed TG_LOGIN_CLIENTS identity stays unset and removal
	// from the allowlist still revokes. Admins and lookup-only
	// identities keep their env-allowlist tiers — writing 'client'
	// for a lookup admin is the same trap that path already refuses
	// (removal would promote them).
	if s.cfg.AutoApproveClients && !s.cfg.AdminTelegramIDs[es.tgID] && !s.cfg.LookupAdminTelegramIDs[es.tgID] {
		granted, terr := s.store.GrantClientTierIfUnset(r.Context(), es.tgID)
		if terr != nil {
			slog.Error("finishEnable: grant client tier", "uid", es.uid, "err", terr)
		} else if granted {
			slog.Info("auto-granted client tier on enable", "telegram_id", es.tgID)
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
	if errors.Is(err, db.ErrAccountDeletedSinceGrant) {
		return accountDeletedDuringSignInMsg
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
		case rpcErr.Message == "AUTH_RESTART":
			return "Telegram ended the sign-in session. Submit your phone number again to get a fresh code."
		}
	}
	// Live 2FA rejections never reach this arm: handleEnablePassword renders
	// badPasswordRestartMsg instead, because the login goroutine has already
	// exited. Kept for friendlyErr's own contract and pinned by
	// enable_access_friendly_test.go.
	if isBadPasswordErr(err) {
		return "That two-step verification password was not accepted. Check it and try again."
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

// framedLoginErr renders a login failure for a step page, wrapping
// friendlyErr in prefix/suffix except for AUTH_RESTART, which friendlyErr
// already renders as a complete instruction ("Telegram ended the sign-in
// session. Submit your phone number again to get a fresh code."). Wrapping
// that both misattributes the failure to the step the user just completed and
// repeats the instruction. Telegram raises AUTH_RESTART from auth.signIn, so
// the code step is the step that actually sees it.
func framedLoginErr(prefix string, err error, suffix string) string {
	if shortReason(err) == "auth_restart" {
		return friendlyErr(err)
	}
	return prefix + friendlyErr(err) + suffix
}

// signInDidNotFinishPrefix frames a failure that the input on the current step
// did not cause (#909): a FLOOD_WAIT on the SendCode an AUTH_RESTART retry
// made, the flow's CodeTTL running out, a database error while finalising the
// session, the identity mismatch. Prefixing those with the step's own verdict
// ("The password was not accepted: ") tells the user their input was wrong
// when it was not, and sends them to retype something that was fine.
const signInDidNotFinishPrefix = "The sign-in did not finish: "

// phoneStepErrMsg frames a failure that ended the flow before a code was
// asked for. "Telegram rejected the request" is said only for an actual
// Telegram RPC error; an expired flow or a local failure is not a rejection.
func phoneStepErrMsg(err error) string {
	var rpcErr *tgerr.Error
	if errors.As(err, &rpcErr) {
		return framedLoginErr("Telegram rejected the request: ", err, " Try again.")
	}
	return framedLoginErr(signInDidNotFinishPrefix, err, " Try again.")
}

// codeStepErrMsg frames a failure that ended the flow after a code was
// submitted. "The code was not accepted" is said only when Telegram rejected
// the code itself; anything else gets the neutral prefix.
func codeStepErrMsg(err error) string {
	switch shortReason(err) {
	case "code_invalid", "code_expired":
		return framedLoginErr("The code was not accepted: ", err, " Start again to get a fresh code.")
	}
	return framedLoginErr(signInDidNotFinishPrefix, err, " Start again.")
}

// shortReason maps a login error to a short token suitable for use in an audit
// tool_name suffix (e.g. "connect:failed:phone_invalid").
func shortReason(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if errors.Is(err, db.ErrAccountModeConflict) {
		return "local_mode_active"
	}
	if errors.Is(err, db.ErrAccountDeletedSinceGrant) {
		return "account_deleted"
	}
	if errors.Is(err, telegram.ErrQRLoginExpired) {
		return "qr_expired"
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
		case rpcErr.Message == "AUTH_RESTART":
			return "auth_restart"
		}
	}
	if strings.Contains(err.Error(), "different Telegram account") {
		return "identity_mismatch"
	}
	if isBadPasswordErr(err) {
		return "bad_password"
	}
	return "unknown"
}

// codeRepromptMsg is the code step's notice when telegram.Login asks for the
// code again within the same flow.
func codeRepromptMsg(rp telegram.Reprompt) string {
	if rp.Reason == telegram.RepromptAuthRestart {
		return "Telegram restarted the sign-in and sent you a new code. Enter the new code."
	}
	return fmt.Sprintf("That code did not match, try again (%s left).", attemptsLeft(rp.AttemptsLeft))
}

// passwordRepromptMsg is the password step's notice after a wrong two-step
// verification password with attempts left.
func passwordRepromptMsg(rp telegram.Reprompt) string {
	return fmt.Sprintf("That password did not match, try again (%s left).", attemptsLeft(rp.AttemptsLeft))
}

func attemptsLeft(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}

// badPasswordRestartMsg is shown on the phone step after a rejected two-step
// verification password. The login flow has already ended by then, so the
// only way forward is a fresh phone + code round.
const badPasswordRestartMsg = "That two-step verification password was not accepted. Submit your phone number again to get a fresh code, then enter the correct password."

// isBadPasswordErr reports whether err is gotd/td's rejected-2FA-password
// error. The observed error string is "sign in with password: invalid
// password" — telegram/auth.Flow.password wraps gotd/td's exported
// auth.ErrPasswordInvalid sentinel (github.com/gotd/td/telegram/auth), which
// errors.Is reaches through the wrapping (go-faster/errors.Wrap implements
// the standard Unwrap() error interface, same as fmt.Errorf("%w")). The
// case-insensitive substring fallback on "invalid password" /
// "PASSWORD_HASH_INVALID" covers a future gotd/td release that changes the
// sentinel's identity but keeps recognisable wording or the underlying
// tgerr message — see requirements.md's Open questions.
func isBadPasswordErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, tdauth.ErrPasswordInvalid) {
		return true
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "invalid password") || strings.Contains(m, "password_hash_invalid")
}
