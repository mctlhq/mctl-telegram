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
		if local, cErr := s.store.HasActiveLocalAccount(bgCtx, uid); cErr != nil {
			lf.err = fmt.Errorf("check account mode: %w", cErr)
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
		// Identity binding. The Telegram account that just completed
		// phone/SMS/2FA MUST be the same one Telegram OIDC proved. Otherwise an
		// admin authenticated as account A could enter account B's phone and
		// end up operating B's messages through A's token. telegram.Login has
		// already persisted B's session bytes via the gotd SessionStore, so
		// revoke that row before bailing out.
		if tgID != wantTgID {
			// telegram.Login already persisted the wrong account's session
			// bytes under uid; revoke them. The uid mutex guarantees no
			// concurrent flow for uid, so this only targets this flow's own
			// row. A failed revoke must surface — otherwise the wrong session
			// stays active and a later callback would issue a token backed by
			// it.
			if _, rErr := s.store.RevokeActiveSession(bgCtx, uid, "disconnect"); rErr != nil {
				lf.err = fmt.Errorf("revoke wrong-account session: %w", rErr)
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
			// Backstop: a local account won the race against both checks
			// above. The login already wrote its session bytes through the
			// gotd SessionStore, which with no loaded row id targets EVERY
			// active row, so drop them from all of them — otherwise the hosted
			// worker could act as the user through a row the operator believes
			// is bridge-only. The rows themselves stay active; the bridge
			// re-uploads its own session on next connect.
			if errors.Is(serr, db.ErrAccountModeConflict) {
				if cErr := s.store.ClearActiveSessionBlobs(bgCtx, uid); cErr != nil {
					slog.Error("enable: clear stray session blob failed", "uid", uid, "err", cErr)
				}
			}
			lf.err = fmt.Errorf("save session: %w", serr)
			return
		}
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
	// after an error arrives with es.step == stepPhone (every error branch
	// resets it via renderEnablePhoneStep), so this only catches duplicates.
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

	// Refuse a hosted connect while a Local Bridge account is active, BEFORE
	// any MTProto login starts. telegram.Login persists the new session bytes
	// through the gotd SessionStore as soon as auth succeeds, so by the time
	// SaveSession's guard fires the local row's blob is already gone; the only
	// way to leave the bridge untouched is to never start the login.
	if local, cErr := s.store.HasActiveLocalAccount(r.Context(), es.uid); cErr != nil {
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:mode_check", "", "error", cErr.Error(), "")
		renderEnableError(w, "Could not verify this account's mode. Try again, or contact the operator if it persists.")
		return
	} else if local {
		s.store.LogToolCall(r.Context(), es.uid, "connect:failed:"+shortReason(db.ErrAccountModeConflict), "", "error", db.ErrAccountModeConflict.Error(), "")
		renderEnableError(w, friendlyErr(db.ErrAccountModeConflict))
		return
	}

	// Supersede any prior in-flight attempt (the user restarted after an error).
	if es.flow != nil && es.flow.cancel != nil {
		es.flow.cancel()
	}
	es.phone = phone
	es.sendOptIn = sendOptIn
	es.flow = s.startLoginFlow(es.uid, es.tgID, phone, sendOptIn)
	es.step = stepCode
	lf := es.flow

	// phoneStart bounds the connect + SendCode round-trip that this select waits
	// on. observePhoneStep records its duration and outcome so the
	// SendCode-stall failure mode (the "send code timeout" below) is queryable
	// and alertable, not just visible as a coarse audit row.
	phoneStart := time.Now()
	observePhoneStep := func(result string) {
		if s.metrics != nil {
			s.metrics.ObserveLoginPhoneStep(result, time.Since(phoneStart).Seconds())
		}
	}

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
				renderEnableError(w, friendlyErr(lf.err))
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
				renderEnableError(w, friendlyErr(lf.err))
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
				renderEnableError(w, friendlyErr(lf.err))
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
