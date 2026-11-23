package linking

// messenger.go is the production Messenger (#1318 slice C1): the confirm
// card and the /connect web_app button, both sent through the PA output
// Sender (internal/pa/output), the only Bot API call site allowed under
// internal/pa (TestS1O1_SenderIsTheOnlyBotAPICallSite). It builds no Bot
// API request of its own.

import (
	"context"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// BotSender is the part of *output.Sender the messenger uses.
type BotSender interface {
	Send(ctx context.Context, chatID int64, text safetext.Text, kb output.Keyboard) error
	SendWebApp(ctx context.Context, chatID int64, text safetext.Text, label safetext.Template, appURL string) error
}

var _ BotSender = (*output.Sender)(nil)

// BotMessenger implements Messenger on the output Sender.
type BotMessenger struct {
	Sender BotSender
}

var _ Messenger = BotMessenger{}

// cardLabels maps the labels ConfirmCard writes to their registry
// templates. A label outside it is refused: a button label is server text,
// never data.
var cardLabels = map[string]safetext.Template{
	safetext.LabelConfirm.String(): safetext.LabelConfirm,
	safetext.LabelCancel.String():  safetext.LabelCancel,
}

// SendCard implements Messenger. The card text names the server's stable
// account id, which comes from the server, so it is rendered as untrusted
// text: anything Telegram could turn into a link is neutralised (T14). The
// buttons go in one row.
func (m BotMessenger) SendCard(ctx context.Context, chatID int64, card Card) error {
	if m.Sender == nil {
		return fmt.Errorf("%w: no sender", ErrConfig)
	}
	text, err := safetext.Render(card.Text, safetext.UserText{})
	if err != nil {
		return fmt.Errorf("pa linking: card text: %w", err)
	}
	if card.TextRU != "" {
		ru, err := safetext.Render(card.TextRU, safetext.UserText{})
		if err != nil {
			return fmt.Errorf("pa linking: card text: %w", err)
		}
		text = safetext.WithRussian(text, ru)
	}
	row := make([]output.Button, 0, len(card.Buttons))
	for _, b := range card.Buttons {
		label, ok := cardLabels[b.Label]
		if !ok {
			return fmt.Errorf("%w: card button label is not a registry template", ErrConfig)
		}
		row = append(row, output.Button{Label: label, Data: b.Data})
	}
	var kb output.Keyboard
	if len(row) > 0 {
		kb = output.Keyboard{row}
	}
	return m.Sender.Send(ctx, chatID, text, kb)
}

// SendConnectButton sends the /connect reply: a fixed text and one web_app
// button opening appURL, the URL StartLink returned. The Sender accepts
// only the configured Mini App URL with a link token.
func (m BotMessenger) SendConnectButton(ctx context.Context, chatID int64, appURL string) error {
	if m.Sender == nil {
		return fmt.Errorf("%w: no sender", ErrConfig)
	}
	return m.Sender.SendWebApp(ctx, chatID, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, appURL)
}
