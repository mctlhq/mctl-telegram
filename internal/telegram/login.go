package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gotd/td/bin"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

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
) (telegramUserID int64, displayName, username string, err error) {
	if apiID == 0 || apiHash == "" {
		return 0, "", "", errors.New("TG_API_ID / TG_API_HASH must be set before login")
	}
	if phone == "" {
		return 0, "", "", errors.New("phone required")
	}

	sessStore := &SessionStore{UserID: userID, Store: store}
	client := telegram.NewClient(apiID, apiHash, telegram.Options{
		SessionStorage: sessStore,
		Device: telegram.DeviceConfig{
			DeviceModel:    "mctl Telegram Assistant",
			SystemVersion:  "Linux",
			AppVersion:     "1.0",
			SystemLangCode: "en",
			LangCode:       "en",
		},
		Middlewares: []telegram.Middleware{
			rpcTimeoutMiddleware(loginRPCTimeout),
		},
	})

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
		flow := auth.NewFlow(authenticator, auth.SendCodeOptions{})
		if err := flow.Run(ctx, client.Auth()); err != nil {
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

type interactiveAuthenticator struct {
	phone    string
	code     func(ctx context.Context) (string, error)
	password func(ctx context.Context) (string, error)
}

func (a *interactiveAuthenticator) Phone(ctx context.Context) (string, error) {
	return a.phone, nil
}

func (a *interactiveAuthenticator) Code(ctx context.Context, _ *tg.AuthSentCode) (string, error) {
	return a.code(ctx)
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
