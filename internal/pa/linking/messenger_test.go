package linking

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Alice's synthetic chat id.
const messengerChat int64 = 100001

type sent struct {
	chat   int64
	text   string
	labels []string
	data   []string
	appURL string
}

type fakeBotSender struct{ calls []sent }

func (f *fakeBotSender) Send(_ context.Context, chatID int64, text safetext.Text, kb output.Keyboard) error {
	c := sent{chat: chatID, text: text.String()}
	for _, row := range kb {
		for _, b := range row {
			c.labels = append(c.labels, b.Label.String())
			c.data = append(c.data, b.Data)
		}
	}
	f.calls = append(f.calls, c)
	return nil
}

func (f *fakeBotSender) SendWebApp(_ context.Context, chatID int64, text safetext.Text, label safetext.Template, appURL string) error {
	f.calls = append(f.calls, sent{chat: chatID, text: text.String(), labels: []string{label.String()}, appURL: appURL})
	return nil
}

// The confirm card goes out through the Sender with its two callback
// buttons; an account id the server made link-shaped is neutralised.
func TestBotMessenger_ConfirmCard(t *testing.T) {
	f := &fakeBotSender{}
	m := BotMessenger{Sender: f}
	nonce := strings.Repeat("N", 43)
	if err := m.SendCard(context.Background(), messengerChat, ConfirmCard(connection.ServerTG, "telegram:100001", nonce)); err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if c.chat != messengerChat || c.text != "Connect tg account telegram:100001?" ||
		strings.Join(c.labels, ",") != "Confirm,Cancel" || c.data[0] != confirmPrefix+nonce || c.data[1] != cancelPrefix+nonce {
		t.Fatalf("card = %+v", c)
	}
	if err := m.SendCard(context.Background(), messengerChat, ConfirmCard(connection.ServerAlice, "evil.example/x", nonce)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.calls[1].text, "evil.example/x") {
		t.Errorf("link-shaped account id sent live: %q", f.calls[1].text)
	}
}

// A label that is not a registry template is refused and nothing is sent.
func TestBotMessenger_RefusesUnknownLabel(t *testing.T) {
	f := &fakeBotSender{}
	err := BotMessenger{Sender: f}.SendCard(context.Background(), messengerChat, Card{Text: "x", Buttons: []Button{{Label: "Open https://evil.example", Data: "d"}}})
	if !errors.Is(err, ErrConfig) || len(f.calls) != 0 {
		t.Fatalf("err = %v, calls = %d", err, len(f.calls))
	}
	if err := (BotMessenger{}).SendCard(context.Background(), messengerChat, Card{Text: "x"}); !errors.Is(err, ErrConfig) {
		t.Errorf("no sender: %v", err)
	}
}

func TestBotMessenger_ConnectButton(t *testing.T) {
	f := &fakeBotSender{}
	u := "https://pa.example/pa/link/app?link=" + strings.Repeat("A", 43)
	if err := (BotMessenger{Sender: f}).SendConnectButton(context.Background(), messengerChat, u); err != nil {
		t.Fatal(err)
	}
	c := f.calls[0]
	if c.appURL != u || c.labels[0] != safetext.LabelConnect.String() || c.text != safetext.TextConnectOpen.String() {
		t.Fatalf("connect = %+v", c)
	}
}
