package output

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const (
	testAppURL = "https://pa.example/pa/link/app"
	// A well-formed link token: 43 characters of base64url.
	testLinkToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func webAppSender(t *testing.T) (*fakeBotAPI, *Sender) {
	t.Helper()
	f, s := newFake(t)
	u, err := parseWebAppBase(testAppURL)
	if err != nil {
		t.Fatal(err)
	}
	s.webApp = u
	return f, s
}

// S1-O3: the web_app button opens exactly PA_APP_URL with a link token. It
// carries nothing but text and web_app.url, previews are disabled (S1-O1),
// and there is no parse mode.
func TestS1O3_WebAppButtonOnlyForAppURL(t *testing.T) {
	f, s := webAppSender(t)
	ctx := context.Background()
	good := testAppURL + "?link=" + testLinkToken
	if err := s.SendWebApp(ctx, aliceChat, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, good); err != nil {
		t.Fatalf("SendWebApp: %v", err)
	}
	if len(f.calls) != 1 || !strings.HasSuffix(f.calls[0].path, "/sendMessage") {
		t.Fatalf("calls = %v", f.calls)
	}
	body := f.calls[0].body
	for k := range body {
		if k != "chat_id" && k != "text" && k != "link_preview_options" && k != "reply_markup" {
			t.Errorf("unexpected field %q", k)
		}
	}
	if lpo, ok := body["link_preview_options"].(map[string]any); !ok || lpo["is_disabled"] != true {
		t.Errorf("link previews not disabled: %v", body)
	}
	rows := body["reply_markup"].(map[string]any)["inline_keyboard"].([]any)
	if len(rows) != 1 || len(rows[0].([]any)) != 1 {
		t.Fatalf("keyboard = %v", rows)
	}
	btn := rows[0].([]any)[0].(map[string]any)
	wa, _ := btn["web_app"].(map[string]any)
	if len(btn) != 2 || btn["text"] != "Connect" || len(wa) != 1 || wa["url"] != good {
		t.Errorf("button = %v", btn)
	}

	bad := []string{
		"",
		testAppURL,
		testAppURL + "?link=",
		testAppURL + "?link=short",
		testAppURL + "?link=" + testLinkToken + "A",
		testAppURL + "?link=" + testLinkToken + "&x=1",
		testAppURL + "?x=1&link=" + testLinkToken,
		testAppURL + "?link=" + testLinkToken + "&link=" + testLinkToken,
		testAppURL + "?link=" + testLinkToken + "#frag",
		testAppURL + "?link=" + strings.Repeat("A", 42) + "%41",
		"http://pa.example/pa/link/app?link=" + testLinkToken,
		"https://attacker.example/pa/link/app?link=" + testLinkToken,
		"https://pa.example.attacker.example/pa/link/app?link=" + testLinkToken,
		"https://pa.example:8443/pa/link/app?link=" + testLinkToken,
		"https://user@pa.example/pa/link/app?link=" + testLinkToken,
		"https://pa.example/pa/link/app/?link=" + testLinkToken,
		"https://pa.example/pa/link/other?link=" + testLinkToken,
		"https://pa.example/pa/link/%61pp?link=" + testLinkToken,
		"https://PA.example/pa/link/app?link=" + testLinkToken,
		"tg://resolve?domain=EvilBot&link=" + testLinkToken,
		"javascript:alert(1)//?link=" + testLinkToken,
	}
	for _, u := range bad {
		if err := s.SendWebApp(ctx, aliceChat, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, u); !errors.Is(err, ErrInvalidKeyboard) {
			t.Errorf("URL %q: err = %v, want ErrInvalidKeyboard", u, err)
		}
	}
	if len(f.calls) != 1 {
		t.Fatalf("a refused URL reached the Bot API: %d calls", len(f.calls))
	}
}

// Without a configured Mini App URL, and for anything but one non-empty
// part to a private chat, SendWebApp sends nothing.
func TestSendWebAppRefusesBadInput(t *testing.T) {
	f, s := newFake(t)
	ctx := context.Background()
	good := testAppURL + "?link=" + testLinkToken
	if err := s.SendWebApp(ctx, aliceChat, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, good); !errors.Is(err, ErrInvalidKeyboard) {
		t.Errorf("unconfigured: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("unconfigured sender reached the Bot API")
	}
	f2, s := webAppSender(t)
	if err := s.SendWebApp(ctx, -100200, safetext.ServerText(safetext.TextConnectOpen), safetext.LabelConnect, good); !errors.Is(err, ErrInvalidChat) {
		t.Errorf("group chat: %v", err)
	}
	if err := s.SendWebApp(ctx, aliceChat, safetext.Text{}, safetext.LabelConnect, good); !errors.Is(err, ErrEmptyText) {
		t.Errorf("empty text: %v", err)
	}
	if err := s.SendWebApp(ctx, aliceChat, safetext.ServerText(safetext.TextConnectOpen), safetext.Template{}, good); !errors.Is(err, ErrInvalidKeyboard) {
		t.Errorf("empty label: %v", err)
	}
	long, err := safetext.Render(strings.Repeat("Bob wrote a long message. ", 400), safetext.UserText{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SendWebApp(ctx, aliceChat, long, safetext.LabelConnect, good); !errors.Is(err, ErrPartTooLong) {
		t.Errorf("multi-part text: %v", err)
	}
	if len(f2.calls) != 0 {
		t.Fatalf("refused input reached the Bot API")
	}
}

// The configured URL itself must be a bare https URL.
func TestNewSenderWebAppURL(t *testing.T) {
	if _, err := NewSender(Config{Token: testToken, WebAppURL: testAppURL}); err != nil {
		t.Fatalf("valid web app URL: %v", err)
	}
	for _, u := range []string{"http://pa.example/pa/link/app", "https://pa.example/pa/link/app?x=1", "https://pa.example/a#f", "https://u@pa.example/a", "/pa/link/app", "https://pa.example/pa/link/%61pp"} {
		if _, err := NewSender(Config{Token: testToken, WebAppURL: u}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("web app URL %q: %v", u, err)
		}
	}
}
