package oauth

// enable_access.go implements the in-browser "enable message access" flow.
//
// After the Telegram Login Widget proves identity, an admin who has no MTProto
// session is walked through phone -> SMS code -> optional 2FA, all over HTTP.
// The gotd auth flow cannot be split across requests (the MTProto connection
// lives only inside one client.Run callback), so telegram.Login runs in a
// background goroutine and the per-step HTTP handlers feed it the code and
// password through channels.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// enableStep tracks where an enable_access flow is. Guarded by enableSession.lock.
type enableStep int

const (
	stepPhone    enableStep = iota // awaiting the phone number (initial screen)
	stepCode                       // awaiting the SMS code
	stepPassword                   // awaiting the 2FA cloud password
	stepDone                       // session provisioned, authorization code issued
)

// Per-step waits. SendCode/SignIn are network round-trips against Telegram;
// the channel sends are near-instant because the login goroutine is already
// parked in askCode/askPassword by the time a handler writes to them.
const (
	enableSendCodeWait = 45 * time.Second
	enableSignInWait   = 60 * time.Second
	enableChanSendWait = 10 * time.Second
)

// enableSession is the server-side state of one in-browser enable_access flow,
// keyed by an unguessable "es" token minted at the widget callback. It carries
// the OAuth context so the flow can resume the authorization-code dance once
// the MTProto session exists.
type enableSession struct {
	oc        oauthCtx
	uid       int64 // internal users.id (EnsureUserByTelegramID)
	tgID      int64 // Telegram user id, == oc.TelegramID
	createdAt time.Time

	// lock serialises handlers for this session: each handler TryLocks it
	// for the duration of one step. A concurrent double-submit fails the
	// TryLock and is told to wait, so step/flow below need no further
	// synchronisation between handlers.
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
// when a /start re-submission supersedes it. wantTgID is the widget-proven
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
		tgID, displayName, username, err := s.loginFn(bgCtx, s.cfg.TGAPIID, s.cfg.TGAPIHash, s.store, uid, phone, askCode, askPassword)
		if err != nil {
			lf.err = err
			return
		}
		// Identity binding. The Telegram account that just completed
		// phone/SMS/2FA MUST be the same one the widget proved. Otherwise an
		// admin authenticated as account A could enter account B's phone and
		// end up operating B's messages through A's token. telegram.Login has
		// already persisted B's session bytes via the gotd SessionStore, so
		// revoke that row before bailing out.
		if tgID != wantTgID {
			_, _ = s.store.RevokeActiveSession(bgCtx, uid)
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
			lf.err = fmt.Errorf("save session: %w", serr)
			return
		}
		if sendOptIn {
			if serr := s.store.SetSendEnabled(bgCtx, uid, true); serr != nil {
				lf.err = fmt.Errorf("enable sending: %w", serr)
				return
			}
		}
		lf.tgUserID = tgID
	}()
	return lf
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
	if !es.lock.TryLock() {
		renderEnableError(w, "Another step of this sign-in is still in progress. Wait a moment, then retry.")
		return
	}
	defer es.lock.Unlock()

	if s.cfg.TGAPIID == 0 || s.cfg.TGAPIHash == "" {
		renderEnableError(w, "This server is not configured for in-browser Telegram login. Contact the operator.")
		return
	}

	rawPhone := r.FormValue("phone")
	sendOptIn := r.FormValue("send_optin") != ""
	phone := normalizePhone(rawPhone)
	if !validPhone(phone) {
		renderEnablePhone(w, enablePhonePage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			Phone:       rawPhone,
			SendOptIn:   sendOptIn,
			Error:       "Enter a phone number in international format, e.g. +14155551234.",
		})
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

	select {
	case <-lf.needCode:
		renderEnableCode(w, enableCodePage{Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: phone})
	case <-lf.done:
		if lf.err != nil {
			renderEnablePhone(w, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: rawPhone, SendOptIn: sendOptIn,
				Error: "Telegram rejected the request: " + friendlyErr(lf.err) + " Try again.",
			})
			return
		}
		// Login completed without ever asking for a code (a pre-existing
		// auth on the session storage). Nothing more to collect.
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSendCodeWait):
		renderEnablePhone(w, enablePhonePage{
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
	if !es.lock.TryLock() {
		renderEnableError(w, "Another step of this sign-in is still in progress. Wait a moment, then retry.")
		return
	}
	defer es.lock.Unlock()

	if es.step != stepCode || es.flow == nil {
		renderEnablePhone(w, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Please start again.",
		})
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))
	if code == "" {
		renderEnableCode(w, enableCodePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Enter the code Telegram sent you.",
		})
		return
	}
	lf := es.flow

	select {
	case lf.codeCh <- code:
	case <-lf.done:
		// Goroutine already exited — fall through to result handling below.
	case <-time.After(enableChanSendWait):
		renderEnablePhone(w, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "The login flow stopped responding. Please start again.",
		})
		return
	}

	select {
	case <-lf.needPw:
		es.step = stepPassword
		renderEnablePassword(w, enablePasswordPage{Issuer: s.cfg.Issuer, EnableToken: esTok})
	case <-lf.done:
		if lf.err != nil {
			renderEnablePhone(w, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: "The code was not accepted: " + friendlyErr(lf.err) + " Start again to get a fresh code.",
			})
			return
		}
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		renderEnablePhone(w, enablePhonePage{
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
	if !es.lock.TryLock() {
		renderEnableError(w, "Another step of this sign-in is still in progress. Wait a moment, then retry.")
		return
	}
	defer es.lock.Unlock()

	if es.step != stepPassword || es.flow == nil {
		renderEnablePhone(w, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "Please start again.",
		})
		return
	}
	password := r.FormValue("password")
	if password == "" {
		renderEnablePassword(w, enablePasswordPage{
			Issuer: s.cfg.Issuer, EnableToken: esTok,
			Error: "Enter your Telegram two-step verification password.",
		})
		return
	}
	lf := es.flow

	select {
	case lf.pwCh <- password:
	case <-lf.done:
		// Goroutine already exited — fall through to result handling below.
	case <-time.After(enableChanSendWait):
		renderEnablePhone(w, enablePhonePage{
			Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone,
			Error: "The login flow stopped responding. Please start again.",
		})
		return
	}

	select {
	case <-lf.done:
		if lf.err != nil {
			renderEnablePhone(w, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: "The password was not accepted: " + friendlyErr(lf.err) + " Start again.",
			})
			return
		}
		s.finishEnable(w, r, es, esTok)
	case <-time.After(enableSignInWait):
		renderEnablePhone(w, enablePhonePage{
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
	m := err.Error()
	if len(m) > 200 {
		m = m[:200]
	}
	if !strings.HasSuffix(m, ".") {
		m += "."
	}
	return m
}
