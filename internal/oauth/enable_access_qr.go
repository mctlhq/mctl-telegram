package oauth

// enable_access_qr.go is the web QR login of enable_access (#901, slice 1):
// instead of a phone number and a login code, the user scans a QR code with
// Telegram on their phone. It runs telegram.LoginQR in the same login
// goroutine as the phone method (startLoginFlow), and reuses the password step
// for an account with two-step verification.
//
// The QR code is a login token. It is drawn as inline SVG on a status page
// that refreshes itself with <meta http-equiv="refresh">, so the page needs
// no JavaScript and no CSP change. The token is never logged, audited or put
// in a URL, and the status page finds its flow through a path-scoped cookie
// rather than a query parameter.
//
// Everything here is behind Config.EnableAccessQREnabled: with it off every
// QR route answers 404.

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"rsc.io/qr"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const (
	enableQRStatusPath = "/oauth/telegram/enable_access/qr/status"
	// enableQRCookie carries the "es" token to the status page. Its path
	// keeps it off every other request, and SameSite=Strict, HttpOnly and
	// Secure keep it out of cross-site requests, scripts and plain HTTP.
	enableQRCookie     = "mctl_enable_qr"
	enableQRCookiePath = "/oauth/telegram/enable_access/qr"
	// enableQRRefresh is the status page's meta refresh while a QR code is
	// on screen. Telegram exports a new token about every 30 seconds.
	enableQRRefresh = 4
	// enableQRBusyRefresh is the refresh of the placeholder page shown while
	// the flow is being prepared or a step holds the session lock.
	enableQRBusyRefresh = 1
)

// qrLogin is the QR method: telegram.LoginQR, with the newest exported URL
// kept on the flow for the status page.
func (s *Server) qrLogin() loginMethod {
	return loginMethod{
		name:      methodQR,
		firstStep: "qr_requested",
		run: func(ctx context.Context, uid int64, lf *loginFlow, _, askPassword func(context.Context) (string, error), cfg telegram.LoginConfig) (int64, string, string, error) {
			show := func(_ context.Context, url, _ string) error {
				lf.qrURL.Store(&url)
				lf.step = "qr_shown"
				return nil
			}
			return s.qrLoginFn(ctx, s.cfg.TGAPIID, s.cfg.TGAPIHash, s.store, uid, show, askPassword, cfg)
		},
	}
}

// qrAuditReason is the audit Reason of a connect:* row: "qr" for the QR
// method, empty for the phone method, whose rows predate the field.
func (es *enableSession) qrAuditReason() string {
	if es.flow != nil && es.flow.method == methodQR {
		return methodQR
	}
	return ""
}

// isDesktopBrowser reports whether ua looks like a desktop browser. The QR
// login asks the user to scan the screen with their phone, which a phone
// cannot do with its own screen, so the button is offered only on desktops.
// A wrong guess costs only the button: the phone method is always there.
func isDesktopBrowser(ua string) bool {
	if ua == "" {
		return false
	}
	for _, mobile := range []string{"Mobi", "Android", "iPhone", "iPad", "iPod"} {
		if strings.Contains(ua, mobile) {
			return false
		}
	}
	return true
}

// handleEnableQRStart launches the QR login from the phone step and sends the
// browser to the status page.
func (s *Server) handleEnableQRStart(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableAccessQREnabled {
		http.NotFound(w, r)
		return
	}
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
	switch {
	case es.step == stepQR && es.flow != nil:
		// A duplicate submit: the QR flow is already running.
		s.redirectToQRStatus(w, r, esTok)
		return
	case es.step == stepDone:
		renderEnableError(w, "This sign-in already completed. Return to your MCP client.")
		return
	case es.step != stepPhone:
		// The QR login starts only from the phone step. In particular there
		// is no route into it from the code step in this slice.
		renderEnableError(w, "A QR code can be requested only from the phone number step. Go back to it and try again.")
		return
	}

	sendOptIn := es.sendOptIn
	if !es.isWizardMode() {
		sendOptIn = r.FormValue("send_optin") != ""
	}
	// The same pre-flight mode gate as handleEnableStart, for the same
	// reason: with an active Local Bridge account a hosted connect must not
	// start at all.
	es.terminalMsg, es.terminalDesc = "", ""
	if local, cErr := s.hasActiveLocalAccount(r.Context(), es.uid); cErr != nil {
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:mode_check", Status: "error", ErrMsg: cErr.Error(), Reason: methodQR})
		s.renderModeCheckRetry(w, es, esTok, "", sendOptIn)
		return
	} else if local {
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + shortReason(db.ErrAccountModeConflict), Status: "error", ErrMsg: db.ErrAccountModeConflict.Error(), Reason: methodQR})
		s.renderEnableTerminalError(w, es, db.ErrAccountModeConflict)
		return
	}

	if es.flow != nil && es.flow.cancel != nil {
		es.flow.superseded.Store(true)
		es.flow.cancel()
	}
	es.sendOptIn = sendOptIn
	es.flow = s.startLoginFlow(es.uid, es.tgID, s.qrLogin(), sendOptIn, es.oc.SignInStartedAt)
	es.step = stepQR
	s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:qr_started", Status: "ok", Reason: methodQR})
	s.redirectToQRStatus(w, r, esTok)
}

// redirectToQRStatus hands the "es" token to the status page in its cookie
// and redirects there, so the token never appears in a URL.
func (s *Server) redirectToQRStatus(w http.ResponseWriter, r *http.Request, esTok string) {
	http.SetCookie(w, &http.Cookie{
		Name:     enableQRCookie,
		Value:    esTok,
		Path:     enableQRCookiePath,
		MaxAge:   int(s.cfg.CodeTTL / time.Second),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, enableQRStatusPath, http.StatusSeeOther)
}

// handleEnableQRStatus is the page the browser sits on while the QR login
// runs. Each refresh shows the current QR code, the password step once a
// scanned account asks for its two-step verification password, the success
// redirect, or the failure with a way to start over.
//
// It never waits for the session lock: a refresh that finds a step handler
// holding it shows a placeholder that refreshes again. Under the lock the
// first refresh to find the flow finished is the one that finishes the
// session; any later one sees stepDone, so only one authorization code is
// ever issued.
func (s *Server) handleEnableQRStatus(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableAccessQREnabled {
		http.NotFound(w, r)
		return
	}
	var esTok string
	if c, err := r.Cookie(enableQRCookie); err == nil {
		esTok = c.Value
	}
	es, ok := s.lookupEnableToken(esTok)
	if !ok {
		renderEnableError(w, "This sign-in session has expired. Close this page and reconnect from your MCP client.")
		return
	}
	if !es.lock.TryLock() {
		renderEnableQRBusy(w)
		return
	}
	defer es.lock.Unlock()

	if es.step != stepQR || es.flow == nil {
		switch {
		case es.step == stepDone:
			renderEnableError(w, "This sign-in already completed. Return to your MCP client.")
		case es.step == stepPassword:
			// A refresh of the status page after the scan moved the user on.
			renderEnablePassword(w, enablePasswordPage{
				Issuer:      s.cfg.Issuer,
				EnableToken: esTok,
				WizardMode:  es.isWizardMode(),
				WizardStep:  3,
			})
		case es.terminalMsg != "":
			s.renderEnableTerminal(w, es)
		default:
			renderEnablePhoneStep(w, es, enablePhonePage{
				Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
				Error: "Please start again.",
			})
		}
		return
	}
	lf := es.flow

	select {
	case <-lf.done:
		s.finishQRFlow(w, r, es, esTok, lf)
		return
	default:
	}
	if lf.qrScanned.Load() {
		// Take the signal askPassword buffered for this first prompt, so
		// handleEnablePassword does not read it later as a re-prompt after
		// a wrong password.
		select {
		case <-lf.needPw:
		default:
		}
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:qr_scanned", Status: "ok", Reason: methodQR})
		es.step = stepPassword
		renderEnablePassword(w, enablePasswordPage{
			Issuer:      s.cfg.Issuer,
			EnableToken: esTok,
			WizardMode:  es.isWizardMode(),
			WizardStep:  3,
		})
		return
	}
	url := lf.qrURL.Load()
	if url == nil {
		renderEnableQRBusy(w)
		return
	}
	renderEnableQR(w, enableQRPage{
		EnableToken: esTok,
		QR:          renderQRSVG(*url),
		Host:        issuerHost(s.cfg.Issuer),
		Username:    es.oc.Username,
		AppName:     s.cfg.TelegramAppName,
		Minutes:     int(enableQRWait / time.Minute),
		WizardMode:  es.isWizardMode(),
	})
}

// finishQRFlow renders the end of a QR flow whose goroutine has exited.
func (s *Server) finishQRFlow(w http.ResponseWriter, r *http.Request, es *enableSession, esTok string, lf *loginFlow) {
	if lf.err == nil {
		s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:qr_scanned", Status: "ok", Reason: methodQR})
		s.finishEnable(w, r, es, esTok)
		return
	}
	s.store.LogToolCall(r.Context(), db.ToolCall{UserID: es.uid, Tool: "connect:failed:" + shortReason(lf.err), Status: "error", ErrMsg: lf.err.Error(), Reason: methodQR})
	switch {
	case isTerminalLoginErr(lf.err):
		s.renderEnableTerminalError(w, es, lf.err)
	case errors.Is(lf.err, errModeCheckFailed):
		s.renderModeCheckRetry(w, es, esTok, "", es.sendOptIn)
	default:
		s.renderQRFailed(w, es, esTok, lf.err)
	}
}

// renderQRFailed ends a QR flow that can be retried: the phone step, with the
// reason and both ways forward, a new QR code or the phone number.
func (s *Server) renderQRFailed(w http.ResponseWriter, es *enableSession, esTok string, err error) {
	es.abandonFlow()
	renderEnablePhoneStep(w, es, enablePhonePage{
		Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
		Error: qrStepErrMsg(err),
	})
}

// handleEnableQRCancel is "Use your phone number instead" on the QR page: it
// stops the QR flow and shows the phone step.
func (s *Server) handleEnableQRCancel(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.EnableAccessQREnabled {
		http.NotFound(w, r)
		return
	}
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

	switch {
	case es.step == stepDone:
		renderEnableError(w, "This sign-in already completed. Return to your MCP client.")
		return
	case es.step == stepQR:
		es.abandonFlow()
	}
	renderEnablePhoneStep(w, es, enablePhonePage{
		Issuer: s.cfg.Issuer, EnableToken: esTok, Phone: es.phone, SendOptIn: es.sendOptIn,
	})
}

// qrStepErrMsg words a QR flow that ended without a session. The way forward
// is on the page it lands on: a new QR code or the phone number.
func qrStepErrMsg(err error) string {
	switch shortReason(err) {
	case "qr_expired":
		return "The QR code was not scanned in time. Show a new one, or use your phone number instead."
	case "auth_restart":
		return "Telegram ended the sign-in session. Show a new QR code, or use your phone number instead."
	case "identity_mismatch":
		return friendlyErr(err)
	case "bad_password":
		return "That two-step verification password was not accepted. Show a new QR code to try again."
	}
	return framedLoginErr(signInDidNotFinishPrefix, err, " Show a new QR code, or use your phone number instead.")
}

// issuerHost is the host of the issuer URL, the site name the QR page tells
// the user to trust.
func issuerHost(issuer string) string {
	if u, err := neturl.Parse(issuer); err == nil && u.Host != "" {
		return u.Host
	}
	return issuer
}

// lookupEnableToken resolves an "es" token to a live enableSession, like
// lookupEnable without reading it from a form.
func (s *Server) lookupEnableToken(tok string) (*enableSession, bool) {
	if tok == "" {
		return nil, false
	}
	s.mu.Lock()
	e, found := s.enables[tok]
	s.mu.Unlock()
	if !found || s.clock().Sub(e.createdAt) > s.cfg.CodeTTL {
		return nil, false
	}
	return e, true
}

// renderQRSVG draws url as a QR code in inline SVG: one path of dark modules
// on a white square with a four-module quiet zone, which phone cameras need
// to find the code. The URL itself is not in the output, only its modules.
func renderQRSVG(url string) template.HTML {
	code, err := qr.Encode(url, qr.M)
	if err != nil {
		return ""
	}
	const quiet = 4
	size := code.Size + 2*quiet
	var path strings.Builder
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				path.WriteString("M" + strconv.Itoa(x+quiet) + " " + strconv.Itoa(y+quiet) + "h1v1h-1z")
			}
		}
	}
	n := strconv.Itoa(size)
	return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ` + n + ` ` + n +
		`" width="240" height="240" shape-rendering="crispEdges" role="img" aria-label="Telegram login QR code">` +
		`<rect width="` + n + `" height="` + n + `" fill="#fff"/><path fill="#000" d="` + path.String() + `"/></svg>`)
}
