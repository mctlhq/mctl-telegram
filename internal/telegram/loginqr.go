package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	loggedIn := qrlogin.OnLoginToken(dispatcher)

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
	if err := settleQRLogin(ctx, sess, runErr, signedIn, mismatch); err != nil {
		return 0, "", "", err
	}
	return telegramUserID, displayName, username, nil
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

// settleQRLogin decides what LoginQR's run leaves in the database. Only a
// run whose callback signed in and passed the account check may write, and
// it writes the buffered session once (none on a mismatch). Any other run
// drops the buffer: by then gotd has already buffered the fresh auth key of
// the initial key exchange, which is signed in to nothing, and writing it
// would replace the user's working session with a dead one. That includes
// a context.Canceled from inside client.Run while ctx is still live, which
// gotd returns when a connection fails under the callback.
//
// A context.Canceled after sign-in completed is client shutdown noise and
// does not fail the login.
func settleQRLogin(ctx context.Context, sess *deferredSession, runErr error, signedIn, mismatch bool) error {
	if !signedIn {
		if runErr == nil {
			runErr = errors.New("qr login ended before sign-in completed")
		}
		return runErr
	}
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	// The only write of this login's session to the database, and only for
	// the expected account.
	if err := sess.settle(ctx, mismatch); err != nil {
		return fmt.Errorf("qr login: %w", err)
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
