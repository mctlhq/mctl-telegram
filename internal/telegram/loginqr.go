package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"rsc.io/qr"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// LoginQR runs the Telegram QR-code login flow. It is an alternative to Login
// for operators who already have Telegram open on another device and can scan
// a QR without entering a phone number or SMS code.
//
// show is called each time a fresh QR token is exported (tokens expire after
// ~30 s and are refreshed automatically). It receives the deep-link URL and an
// ASCII-art rendering of the same URL for terminal display.
//
// password is asked for the account's 2FA cloud password when Telegram accepts
// the scan but answers SESSION_PASSWORD_NEEDED; nil makes such an account fail
// the login.
//
// The session is held in memory until the signed-in account has passed the
// LoginConfig.WantTelegramID check, and only then written to the database
// (deferredSession, #901). On a mismatch the new authorization is logged out
// and nothing is written; the caller still sees the real id and refuses.
// Otherwise the resolved Telegram user metadata is returned, identical to
// Login.
//
// LoginConfig.QRWait, when set, bounds the wait for a scan; running out of it
// returns ErrQRLoginExpired.
func LoginQR(
	ctx context.Context,
	apiID int,
	apiHash string,
	store *db.Store,
	userID int64,
	show func(ctx context.Context, url, asciiArt string) error,
	password func(ctx context.Context) (string, error),
	cfgs ...LoginConfig,
) (telegramUserID int64, displayName, username string, err error) {
	if apiID == 0 || apiHash == "" {
		return 0, "", "", errors.New("TG_API_ID / TG_API_HASH must be set before login")
	}
	var cfg LoginConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	sess := &deferredSession{target: &SessionStore{UserID: userID, Store: store}}
	dispatcher := tg.NewUpdateDispatcher()
	var scanned atomic.Bool
	loggedIn, onLoginToken := loginTokenSignal(&scanned)
	dispatcher.OnLoginToken(onLoginToken)

	opts := loginClientOptions(sess, cfg)
	opts.UpdateHandler = dispatcher
	client := gotdtelegram.NewClient(apiID, apiHash, opts)
	// signedIn is set only once the callback got through sign-in and the
	// account check; mismatch tells which way that check went.
	signedIn, mismatch := false, false

	runErr := client.Run(ctx, func(ctx context.Context) error {
		qr := qrlogin.NewQR(client.API(), apiID, apiHash, qrlogin.Options{
			// Migrate wires the DC-migration callback so QR auth succeeds for
			// accounts whose home DC differs from the client's current DC.
			// Without this, auth.loginTokenMigrateTo returns an error instead
			// of transparently importing the accepted token.
			Migrate: client.MigrateTo,
		})
		// AUTH_RESTART from auth.exportLoginToken is retried once (#900): a
		// fresh export starts the QR sign-in over without the user noticing.
		authz, err := withQRWait(ctx, cfg.QRWait, func(ctx context.Context) (*tg.AuthAuthorization, error) {
			return retryAuthRestartOnce(ctx, func() (*tg.AuthAuthorization, error) {
				return qr.Auth(ctx, loggedIn, func(ctx context.Context, token qrlogin.Token) error {
					url := token.URL()
					return show(ctx, url, renderQR(url))
				})
			})
		})
		if err != nil {
			authz, err = passwordAfterQR(ctx, err, password, client.Auth().Password)
			if err != nil {
				return fmt.Errorf("qr auth: %w", err)
			}
		}
		scanned.Store(true)
		user, mm, err := acceptQRAuth(ctx, client.API(), cfg, userID, authz)
		if err != nil {
			return err
		}
		telegramUserID = user.ID
		displayName = strings.TrimSpace(user.FirstName + " " + user.LastName)
		if displayName == "" {
			displayName = user.Username
		}
		username = user.Username
		if mm {
			signedIn, mismatch = true, true
			return nil
		}
		// Trigger a session flush so SessionStorage sees the post-auth bytes.
		_, _ = client.API().HelpGetConfig(ctx)
		signedIn = true
		return nil
	})
	if err := finishLogin(ctx, "qr login", apiID, apiHash, cfg, userID, sess, runErr, scanned.Load(), signedIn, mismatch); err != nil {
		return 0, "", "", err
	}
	return telegramUserID, displayName, username, nil
}

// finishLogin settles a Login or LoginQR run (settleLogin) and, when the run
// failed after the auth key may have been signed in (authorized: the QR code
// was scanned, or a login code was submitted), logs out the authorization the
// key may now carry. That happens when the flow is cancelled or superseded
// just as the sign-in lands, or when the session cannot be written: nothing
// is stored, but without the logout the user is left with a device nobody
// holds in Active Sessions (#919, #913). A mismatched account was already
// logged out by the account check. label prefixes the errors ("qr login").
func finishLogin(ctx context.Context, label string, apiID int, apiHash string, cfg LoginConfig, userID int64, sess *deferredSession, runErr error, authorized, signedIn, mismatch bool) error {
	err := settleLogin(ctx, label, sess, runErr, signedIn, mismatch, cfg.HoldSession)
	if err == nil || !authorized {
		return err
	}
	if data := sess.take(); data != nil {
		logOutCtx, cancel := DetachedLogOutContext(ctx)
		defer cancel()
		if lErr := logOutSessionFn(logOutCtx, apiID, apiHash, data, cfg); lErr != nil {
			slog.WarnContext(ctx, "telegram "+label+": logout of an unfinished authorization failed",
				"user_id", userID, "err", lErr)
		} else {
			slog.InfoContext(ctx, "telegram "+label+": logged out an unfinished authorization", "user_id", userID)
		}
	}
	return err
}

// loginTokenSignal is qrlogin.OnLoginToken with two changes. It records that
// the code was scanned: from then on the auth key may carry an authorization,
// which a run that does not finish must log out (#919). And the signal is
// buffered: qr.Auth reads it only while parked in its select, so an
// unbuffered non-blocking send is lost whenever the update lands during a
// token export or the show callback, and the accepted scan goes unnoticed.
// One buffered slot is enough, because further updates only coalesce.
func loginTokenSignal(scanned *atomic.Bool) (qrlogin.LoggedIn, tg.LoginTokenHandler) {
	loginToken := make(chan struct{}, 1)
	return loginToken, func(context.Context, tg.Entities, *tg.UpdateLoginToken) error {
		scanned.Store(true)
		select {
		case loginToken <- struct{}{}:
		default:
		}
		return nil
	}
}

// logOutTimeout bounds a logout that runs after the caller's context has
// ended.
const logOutTimeout = 15 * time.Second

// DetachedLogOutContext is ctx without its cancellation, bounded by
// logOutTimeout. A logout of an authorization nobody will use runs precisely
// because ctx was cancelled, so it cannot run on ctx itself.
func DetachedLogOutContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), logOutTimeout)
}

// logOutSessionFn is LogOutSession; a var only so tests can record it.
var logOutSessionFn = LogOutSession

// LogOutSession ends the authorization held by the session bytes data with
// auth.logOut, on a client of its own. It is for an authorization whose
// login client is already gone, so the bytes are all that is left of it.
func LogOutSession(ctx context.Context, apiID int, apiHash string, data []byte, cfg LoginConfig) error {
	client := gotdtelegram.NewClient(apiID, apiHash, loginClientOptions(&deferredSession{data: data}, cfg))
	return client.Run(ctx, func(ctx context.Context) error {
		if _, err := client.API().AuthLogOut(ctx); err != nil {
			return fmt.Errorf("auth.logOut: %w", err)
		}
		return nil
	})
}

// acceptQRAuth is the part of LoginQR's callback right after Telegram has
// accepted the scan (and the 2FA password, if any). It reports that through
// cfg.OnQRAccepted first, before any further network call, then runs the
// account check, which logs a mismatched account out.
func acceptQRAuth(ctx context.Context, api authLogOuter, cfg LoginConfig, userID int64, authz *tg.AuthAuthorization) (*tg.User, bool, error) {
	if cfg.OnQRAccepted != nil {
		cfg.OnQRAccepted()
	}
	user, ok := authz.User.(*tg.User)
	if !ok {
		return nil, false, fmt.Errorf("unexpected auth user type %T", authz.User)
	}
	return user, logOutIfMismatch(ctx, api, userID, cfg.WantTelegramID, user.ID), nil
}

// settleLogin decides what a Login or LoginQR run leaves in the database. Only a
// run whose callback signed in and passed the account check may write, and
// it writes the buffered session once (none on a mismatch). Any other run
// drops the buffer: by then gotd has already buffered the fresh auth key of
// the initial key exchange, which is signed in to nothing, and writing it
// would replace the user's working session with a dead one. That includes
// a context.Canceled from inside client.Run while ctx is still live, which
// gotd returns when a connection fails under the callback.
//
// A context.Canceled after sign-in completed is client shutdown noise and
// does not fail the login. Neither does any run error after a mismatch: the account check
// already logged the new authorization out, so the buffer is dropped and the
// caller still learns it was the wrong account, not a generic failure.
func settleLogin(ctx context.Context, label string, sess *deferredSession, runErr error, signedIn, mismatch bool, hold func([]byte)) error {
	if !signedIn {
		if runErr == nil {
			runErr = errors.New(label + " ended before sign-in completed")
		}
		return runErr
	}
	if runErr != nil && !mismatch && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	if hold != nil && !mismatch {
		// The caller writes the bytes itself, with the account metadata.
		data := sess.take()
		if data == nil {
			return errors.New(label + ": login completed but no session bytes were persisted")
		}
		hold(data)
		return nil
	}
	// The only write of this login's session to the database, and only for
	// the expected account.
	if err := sess.settle(ctx, mismatch); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

// ErrQRLoginExpired is returned by LoginQR when LoginConfig.QRWait ran out
// before any device scanned the code.
var ErrQRLoginExpired = errors.New("the QR code was not scanned in time")

// withQRWait runs auth, the wait for a scan, under its own deadline d (none
// when d <= 0). Only that wait is bounded: the 2FA password asked after a
// scan runs on the caller's ctx. A context error caused by d itself, rather
// than by the caller's ctx, becomes ErrQRLoginExpired.
func withQRWait(ctx context.Context, d time.Duration, auth func(context.Context) (*tg.AuthAuthorization, error)) (*tg.AuthAuthorization, error) {
	if d <= 0 {
		return auth(ctx)
	}
	waitCtx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	authz, err := auth(waitCtx)
	if err != nil && ctx.Err() == nil && waitCtx.Err() != nil && errors.Is(err, context.DeadlineExceeded) {
		return nil, ErrQRLoginExpired
	}
	return authz, err
}

// passwordAfterQR finishes a QR login that Telegram accepted but answered with
// SESSION_PASSWORD_NEEDED: the account has a 2FA cloud password, which is
// asked for and checked on the same connection, again after a wrong one up to
// LoginPasswordAttempts times. Any other error is returned unchanged.
func passwordAfterQR(
	ctx context.Context,
	qrErr error,
	password func(ctx context.Context) (string, error),
	check func(ctx context.Context, password string) (*tg.AuthAuthorization, error),
) (*tg.AuthAuthorization, error) {
	if !tgerr.Is(qrErr, "SESSION_PASSWORD_NEEDED") {
		return nil, qrErr
	}
	if password == nil {
		return nil, fmt.Errorf("2FA password required but no prompt configured: %w", qrErr)
	}
	return askPasswordChecked(ctx, password, check)
}

// renderQR encodes url as a QR code and returns an ASCII-art string suitable
// for terminal display. Each module is rendered as two characters wide so it
// appears square in fixed-width fonts. A quiet zone of 2 modules is added.
func renderQR(url string) string {
	code, err := qr.Encode(url, qr.M)
	if err != nil {
		return "[QR encode error — open the URL directly]\n" + url
	}

	border := 2
	var sb strings.Builder
	for y := -border; y < code.Size+border; y++ {
		for x := -border; x < code.Size+border; x++ {
			if x >= 0 && y >= 0 && x < code.Size && y < code.Size && code.Black(x, y) {
				sb.WriteString("██")
			} else {
				sb.WriteString("  ")
			}
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
