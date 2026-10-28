package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gotd/contrib/middleware/floodwait"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// LoginConfig carries optional wiring for the interactive login client. The
// zero value is valid (no global limiter), so callers that do not need
// api_id-wide throttling — e.g. cmd/login — can omit it entirely.
type LoginConfig struct {
	// GlobalMiddleware, when non-nil, is inserted into the login client's
	// MTProto invoker chain. main.go passes the same instance it gives the
	// ClientPool so the login client and the message-serving pool share one
	// api_id-wide rate budget. A first-time login (auth.sendCode) is the most
	// flood-sensitive call against the shared TG_API_ID, so it must be subject
	// to the same ceiling as steady-state traffic.
	GlobalMiddleware telegram.Middleware
	// TestDC points the login client at Telegram's test datacenters
	// (TG_TEST_DC, issue #854). It must match the ClientPool's setting, or
	// the pool would load a session its DCs do not know.
	TestDC bool
	// WantTelegramID, when non-zero, is the Telegram account the caller
	// expects to log in (enable_access passes the OIDC-proven id). If a
	// different account completes authorization, the login logs that
	// authorization out with auth.logOut before returning, so the other
	// account is not left with a live device it never meant to add (#899).
	// The caller still sees the real id and makes the refusal itself.
	WantTelegramID int64
	// QRWait, when positive, bounds how long LoginQR waits for a scan
	// before it gives up with ErrQRLoginExpired. A 2FA password asked after
	// the scan is not part of that wait. Login ignores it.
	QRWait time.Duration
}

// loginClientOptions is the gotd configuration shared by the phone and QR
// login clients.
func loginClientOptions(sess session.Storage, cfg LoginConfig) telegram.Options {
	return telegram.Options{
		SessionStorage: sess,
		DCList:         dcList(cfg.TestDC),
		Device:         deviceConfig,
		Middlewares:    loginMiddlewares(cfg),
	}
}

// loginFloodWaitMaxWait bounds a single FLOOD_WAIT sleep on the login client.
// A genuine flood-wait from Telegram is honoured up to this ceiling; a longer
// demanded wait surfaces as an error rather than parking the login goroutine
// (which holds uidLoginMutex) for minutes. Kept at the per-RPC timeout so a
// waiter sleep cannot outlive the rpcTimeoutMiddleware budget.
const loginFloodWaitMaxWait = loginRPCTimeout

// loginFloodWaitMaxRetries caps flood-wait retries during login. Two retries
// absorb a transient FLOOD_WAIT without letting a persistently throttled
// api_id stall the interactive flow indefinitely.
const loginFloodWaitMaxRetries = 2

// loginRPCTimeout bounds every individual MTProto RPC issued during an
// interactive login (SendCode, SignIn, the SRP password exchange, Self).
// Without it these inherit the caller's CodeTTL context (~30m): a stuck
// SendCode then hangs for the whole TTL, holding uidLoginMutex and surfacing
// only as the handler's coarse "send code timeout". With a per-RPC deadline a
// stall returns context.DeadlineExceeded promptly, which propagates as a
// classified login error and frees the mutex. Sized well above a healthy
// round-trip but below the enableSendCodeWait (90s) handler ceiling.
const loginRPCTimeout = 25 * time.Second

// rpcTimeoutMiddleware wraps each tg.Invoker call with a bounded context so a
// single hung MTProto RPC cannot stall the whole login flow. It is attached
// only to the short-lived login client, never the message-serving pool.
func rpcTimeoutMiddleware(d time.Duration) telegram.Middleware {
	return telegram.MiddlewareFunc(func(next tg.Invoker) telegram.InvokeFunc {
		return func(ctx context.Context, input bin.Encoder, output bin.Decoder) error {
			ctx, cancel := context.WithTimeout(ctx, d)
			defer cancel()
			return next.Invoke(ctx, input, output)
		}
	})
}

// loginMiddlewares builds the MTProto invoker chain for the interactive login
// client, outermost first (gotd applies index 0 first):
//
//	floodwait -> [globalRateLimit] -> rpcTimeout -> invoke
//
// floodwait sits outermost so its sleep+retry re-acquires a global rate token
// and gets a fresh per-RPC deadline on each attempt; rpcTimeout is innermost so
// it bounds only the actual RPC, never the waiter's sleep. The optional global
// limiter (shared with the pool) is omitted when nil so the chain stays
// allocation-minimal and behaviour is unchanged when the limiter is disabled.
func loginMiddlewares(cfg LoginConfig) []telegram.Middleware {
	mws := []telegram.Middleware{
		floodwait.NewSimpleWaiter().
			WithMaxRetries(loginFloodWaitMaxRetries).
			WithMaxWait(loginFloodWaitMaxWait),
	}
	if cfg.GlobalMiddleware != nil {
		mws = append(mws, cfg.GlobalMiddleware)
	}
	mws = append(mws, rpcTimeoutMiddleware(loginRPCTimeout))
	return mws
}

// Login runs the interactive phone -> code -> 2FA-password flow for a single
// user. Session bytes are persisted into the DB via the SessionStore. Returns
// the resolved Telegram user metadata for storage in telegram_accounts.
func Login(
	ctx context.Context,
	apiID int,
	apiHash string,
	store *db.Store,
	userID int64,
	phone string,
	askCode func(ctx context.Context) (string, error),
	askPassword func(ctx context.Context) (string, error),
	cfgs ...LoginConfig,
) (telegramUserID int64, displayName, username string, err error) {
	if apiID == 0 || apiHash == "" {
		return 0, "", "", errors.New("TG_API_ID / TG_API_HASH must be set before login")
	}
	if phone == "" {
		return 0, "", "", errors.New("phone required")
	}
	var cfg LoginConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	sessStore := &SessionStore{UserID: userID, Store: store}
	client := telegram.NewClient(apiID, apiHash, loginClientOptions(sessStore, cfg))

	authenticator := &interactiveAuthenticator{
		phone:    phone,
		code:     askCode,
		password: askPassword,
	}

	// Breadcrumbs to localise where a stuck login hangs: the enable_access
	// handler only records a coarse "send code timeout" in the audit, so these
	// distinguish a dial/handshake hang (never reach "connection established")
	// from a SendCode hang (established, but the auth flow never returns).
	slog.InfoContext(ctx, "telegram login: connecting to telegram", "user_id", userID)
	runErr := client.Run(ctx, func(ctx context.Context) error {
		slog.InfoContext(ctx, "telegram login: connection established, running auth flow", "user_id", userID)
		_, authErr := client.Auth().Status(ctx)
		if authErr != nil {
			// Fresh session — proceed with flow.
		}
		if err := runPhoneFlow(ctx, client.Auth(), authenticator); err != nil {
			return fmt.Errorf("auth flow: %w", err)
		}
		me, err := client.Self(ctx)
		if err != nil {
			return fmt.Errorf("self: %w", err)
		}
		telegramUserID = me.ID
		displayName = strings.TrimSpace(me.FirstName + " " + me.LastName)
		if displayName == "" {
			displayName = me.Username
		}
		username = me.Username
		if logOutIfMismatch(ctx, client.API(), userID, cfg.WantTelegramID, me.ID) {
			return nil
		}
		// Force a session flush so the SessionStorage sees the post-auth bytes.
		// gotd already calls StoreSession on every change, but we trigger one
		// trivial call to be safe.
		_, _ = client.API().HelpGetConfig(ctx)
		return nil
	})
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return 0, "", "", runErr
	}

	// Sanity check session persisted.
	if _, err := sessStore.LoadSession(ctx); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return 0, "", "", errors.New("login completed but no session bytes were persisted")
		}
		return 0, "", "", err
	}
	return telegramUserID, displayName, username, nil
}

// Attempt budgets for the interactive login (#900). A mistyped login code or
// 2FA password used to end the whole flow, and every new flow costs the user a
// fresh code. Three tries absorb a typo without turning the prompt into a
// guessing loop; Telegram enforces its own limits on top of these.
const (
	LoginCodeAttempts     = 3
	LoginPasswordAttempts = 3
)

// Reprompt reasons. They are the same tokens enable_access's shortReason
// gives the matching Telegram errors, so an audit row reads the same whether
// the flow went on or ended.
const (
	RepromptCodeInvalid = "code_invalid"
	RepromptBadPassword = "bad_password"
	RepromptAuthRestart = "auth_restart"
)

// Reprompt tells a code or password prompt that it is being called again
// within the same login flow, and why. AttemptsLeft counts the attempt the
// prompt is about to collect.
type Reprompt struct {
	Reason       string
	AttemptsLeft int
}

type repromptKey struct{}

// WithReprompt returns ctx carrying r. The login flows pass it to the prompt
// they call again; it is exported so a prompt can be tested on its own.
func WithReprompt(ctx context.Context, r Reprompt) context.Context {
	return context.WithValue(ctx, repromptKey{}, r)
}

// RepromptFrom reports whether a prompt was called again after a rejection.
// A first prompt has no Reprompt.
func RepromptFrom(ctx context.Context) (Reprompt, bool) {
	r, ok := ctx.Value(repromptKey{}).(Reprompt)
	return r, ok
}

// LoginCodeDigits keeps only the ASCII digits of an entered login code, so
// "12 345" or a pasted "Login code: 12345." reach Telegram as "12345". An
// input with no digits comes back empty and is treated as no code at all.
func LoginCodeDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// runPhoneFlow is gotd's auth.Flow.Run reworked so that a mistake does not end
// the flow (#900). auth.Flow returns on the first SignIn or password error;
// here:
//
//   - PHONE_CODE_INVALID asks for the code again and signs in with the same
//     phone_code_hash, up to LoginCodeAttempts codes in total. No new code is
//     sent: the one the user has stays valid.
//   - a rejected 2FA password is asked for again, up to LoginPasswordAttempts.
//   - AUTH_RESTART, from auth.sendCode or anything after it, restarts at
//     auth.sendCode once per flow. A second one surfaces as before.
//
// PHONE_CODE_EXPIRED and every other error still end the flow.
func runPhoneFlow(ctx context.Context, client auth.FlowClient, a *interactiveAuthenticator) error {
	restarted := false
	restartOnce := func(err error) bool {
		if restarted || !tgerr.Is(err, "AUTH_RESTART") {
			return false
		}
		restarted = true
		slog.InfoContext(ctx, "telegram login: AUTH_RESTART, restarting the sign-in once")
		return true
	}
	var first *Reprompt
	for {
		sentClass, err := client.SendCode(ctx, a.phone, auth.SendCodeOptions{})
		if err != nil {
			if restartOnce(err) {
				continue
			}
			return fmt.Errorf("send code: %w", err)
		}
		var sent *tg.AuthSentCode
		switch s := sentClass.(type) {
		case *tg.AuthSentCode:
			sent = s
		case *tg.AuthSentCodeSuccess:
			switch az := s.Authorization.(type) {
			case *tg.AuthAuthorization:
				// Already authorized; nothing to collect.
				return nil
			case *tg.AuthAuthorizationSignUpRequired:
				return a.signUp(ctx, client, "", az.TermsOfService)
			default:
				return fmt.Errorf("unexpected authorization type: %T", az)
			}
		default:
			return fmt.Errorf("unexpected sent code type: %T", sentClass)
		}
		err = a.signIn(ctx, client, sent, first)
		if err != nil && restartOnce(err) {
			// The restart sent a new code, so the user has to be told the
			// one they typed is gone, not merely that it did not match.
			first = &Reprompt{Reason: RepromptAuthRestart, AttemptsLeft: LoginCodeAttempts}
			continue
		}
		return err
	}
}

// signIn collects the code for sent and signs in with its phone_code_hash,
// asking again after PHONE_CODE_INVALID, then collects the 2FA password if the
// account has one. first, when non-nil, is passed to the first code prompt.
func (a *interactiveAuthenticator) signIn(ctx context.Context, client auth.FlowClient, sent *tg.AuthSentCode, first *Reprompt) error {
	hash := sent.PhoneCodeHash
	rp := first
	for attempt := 1; ; attempt++ {
		promptCtx := ctx
		if rp != nil {
			promptCtx = WithReprompt(ctx, *rp)
		}
		var code string
		var err error
		if attempt == 1 {
			// Code logs where Telegram delivered this code; a re-ask is for
			// the same code and has nothing new to record.
			code, err = a.Code(promptCtx, sent)
		} else {
			code, err = a.code(promptCtx)
		}
		if err != nil {
			return fmt.Errorf("get code: %w", err)
		}
		_, err = client.SignIn(ctx, a.phone, code, hash)
		var signUpRequired *auth.SignUpRequired
		switch {
		case err == nil:
			return nil
		case errors.Is(err, auth.ErrPasswordAuthNeeded):
			_, err := askPasswordChecked(ctx, a.Password, client.Password)
			return err
		case errors.As(err, &signUpRequired):
			return a.signUp(ctx, client, hash, signUpRequired.TermsOfService)
		case tgerr.Is(err, "PHONE_CODE_INVALID") && attempt < LoginCodeAttempts:
			left := LoginCodeAttempts - attempt
			slog.InfoContext(ctx, "telegram login: code rejected, asking again", "attempts_left", left)
			rp = &Reprompt{Reason: RepromptCodeInvalid, AttemptsLeft: left}
		default:
			return fmt.Errorf("sign in: %w", err)
		}
	}
}

// signUp mirrors auth.Flow's sign-up branch. SignUp always refuses, so a
// number with no Telegram account ends here with that refusal.
func (a *interactiveAuthenticator) signUp(ctx context.Context, client auth.FlowClient, hash string, tos tg.HelpTermsOfService) error {
	if err := a.AcceptTermsOfService(ctx, tos); err != nil {
		return fmt.Errorf("confirm TOS: %w", err)
	}
	info, err := a.SignUp(ctx)
	if err != nil {
		return fmt.Errorf("sign up info not provided: %w", err)
	}
	if _, err := client.SignUp(ctx, auth.SignUp{
		PhoneNumber:   a.phone,
		PhoneCodeHash: hash,
		FirstName:     info.FirstName,
		LastName:      info.LastName,
	}); err != nil {
		return fmt.Errorf("sign up: %w", err)
	}
	return nil
}

// askPasswordChecked asks for the 2FA cloud password and checks it, asking
// again after a rejected password up to LoginPasswordAttempts times in total.
// Login and LoginQR share it. The last rejection is returned wrapped, so it
// still classifies as auth.ErrPasswordInvalid.
func askPasswordChecked(
	ctx context.Context,
	ask func(ctx context.Context) (string, error),
	check func(ctx context.Context, password string) (*tg.AuthAuthorization, error),
) (*tg.AuthAuthorization, error) {
	promptCtx := ctx
	for attempt := 1; ; attempt++ {
		pw, err := ask(promptCtx)
		if err != nil {
			return nil, fmt.Errorf("read 2FA password: %w", err)
		}
		authz, err := check(ctx, pw)
		if err == nil {
			return authz, nil
		}
		if !isPasswordRejected(err) || attempt >= LoginPasswordAttempts {
			return nil, fmt.Errorf("check 2FA password: %w", err)
		}
		left := LoginPasswordAttempts - attempt
		slog.InfoContext(ctx, "telegram login: 2FA password rejected, asking again", "attempts_left", left)
		promptCtx = WithReprompt(ctx, Reprompt{Reason: RepromptBadPassword, AttemptsLeft: left})
	}
}

// isPasswordRejected reports a wrong 2FA password. gotd maps
// PASSWORD_HASH_INVALID to auth.ErrPasswordInvalid; the raw RPC error is
// accepted too in case a caller checks the password without that mapping.
func isPasswordRejected(err error) bool {
	return errors.Is(err, auth.ErrPasswordInvalid) || tgerr.Is(err, "PASSWORD_HASH_INVALID")
}

// retryAuthRestartOnce calls fn and, if it fails with AUTH_RESTART, calls it
// once more. A second AUTH_RESTART is returned to the caller. LoginQR wraps
// qr.Auth (auth.exportLoginToken) in it; the phone flow has its own restart
// in runPhoneFlow because it also has to re-ask for the code.
func retryAuthRestartOnce[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	v, err := fn()
	if err == nil || !tgerr.Is(err, "AUTH_RESTART") {
		return v, err
	}
	slog.InfoContext(ctx, "telegram login: AUTH_RESTART, restarting the sign-in once")
	return fn()
}

type interactiveAuthenticator struct {
	phone    string
	code     func(ctx context.Context) (string, error)
	password func(ctx context.Context) (string, error)
}

func (a *interactiveAuthenticator) Phone(ctx context.Context) (string, error) {
	return a.phone, nil
}

func (a *interactiveAuthenticator) Code(ctx context.Context, sent *tg.AuthSentCode) (string, error) {
	// The code screen cannot tell where Telegram delivered the code (app,
	// SMS, email, Fragment), so record it: "no code arrived" is otherwise
	// undiagnosable. Never the code, hash or phone.
	delivery, next, timeout := codeDelivery(sent)
	slog.InfoContext(ctx, "telegram login: code sent",
		"delivery", delivery, "next_delivery", next, "timeout_s", timeout)
	return a.code(ctx)
}

// codeDelivery names how Telegram sent the login code, how it would send it
// on auth.resendCode, and the resend timeout in seconds. Names are the TL
// constructor names (auth.sentCodeTypeApp, auth.codeTypeSms, ...); next is
// "" and timeout 0 when Telegram did not set them.
func codeDelivery(sent *tg.AuthSentCode) (delivery, next string, timeout int) {
	if sent == nil || sent.Type == nil {
		return "unknown", "", 0
	}
	delivery = sent.Type.TypeName()
	if nt, ok := sent.GetNextType(); ok && nt != nil {
		next = nt.TypeName()
	}
	if t, ok := sent.GetTimeout(); ok {
		timeout = t
	}
	return delivery, next, timeout
}

func (a *interactiveAuthenticator) Password(ctx context.Context) (string, error) {
	if a.password == nil {
		return "", errors.New("2FA password required but no prompt configured")
	}
	return a.password(ctx)
}

func (a *interactiveAuthenticator) AcceptTermsOfService(_ context.Context, _ tg.HelpTermsOfService) error {
	return nil
}

func (a *interactiveAuthenticator) SignUp(_ context.Context) (auth.UserInfo, error) {
	return auth.UserInfo{}, errors.New("account does not exist; sign-up via tg-mcp is not supported")
}
