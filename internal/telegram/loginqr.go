package telegram

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/gotd/td/session"
	gotdtelegram "github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/tg"
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
// On success the session is persisted to the database and the resolved Telegram
// user metadata is returned, identical to Login.
func LoginQR(
	ctx context.Context,
	apiID int,
	apiHash string,
	store *db.Store,
	userID int64,
	show func(ctx context.Context, url, asciiArt string) error,
	cfgs ...LoginConfig,
) (telegramUserID int64, displayName, username string, err error) {
	if apiID == 0 || apiHash == "" {
		return 0, "", "", errors.New("TG_API_ID / TG_API_HASH must be set before login")
	}
	var cfg LoginConfig
	if len(cfgs) > 0 {
		cfg = cfgs[0]
	}

	sessStore := &SessionStore{UserID: userID, Store: store}
	dispatcher := tg.NewUpdateDispatcher()
	loggedIn := qrlogin.OnLoginToken(dispatcher)

	client := gotdtelegram.NewClient(apiID, apiHash, gotdtelegram.Options{
		SessionStorage: sessStore,
		UpdateHandler:  dispatcher,
		Device: gotdtelegram.DeviceConfig{
			DeviceModel:    "mctl Telegram Assistant",
			SystemVersion:  "Linux",
			AppVersion:     "1.0",
			SystemLangCode: "en",
			LangCode:       "en",
		},
		Middlewares: loginMiddlewares(cfg),
	})

	runErr := client.Run(ctx, func(ctx context.Context) error {
		qr := qrlogin.NewQR(client.API(), apiID, apiHash, qrlogin.Options{})
		auth, err := qr.Auth(ctx, loggedIn, func(ctx context.Context, token qrlogin.Token) error {
			url := token.URL()
			return show(ctx, url, renderQR(url))
		})
		if err != nil {
			return fmt.Errorf("qr auth: %w", err)
		}
		user, ok := auth.User.(*tg.User)
		if !ok {
			return fmt.Errorf("unexpected auth user type %T", auth.User)
		}
		telegramUserID = user.ID
		displayName = strings.TrimSpace(user.FirstName + " " + user.LastName)
		if displayName == "" {
			displayName = user.Username
		}
		username = user.Username
		// Trigger a session flush so SessionStorage sees the post-auth bytes.
		_, _ = client.API().HelpGetConfig(ctx)
		return nil
	})
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return 0, "", "", runErr
	}

	if _, err := sessStore.LoadSession(ctx); err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return 0, "", "", errors.New("qr login completed but no session bytes were persisted")
		}
		return 0, "", "", err
	}
	return telegramUserID, displayName, username, nil
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
