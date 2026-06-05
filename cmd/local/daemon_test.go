package main

import (
	"strings"
	"testing"

	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
)

func TestWrapMsgs_RedactsTelegramLoginSecrets(t *testing.T) {
	in := []tg.Message{
		{
			ID:   1,
			Peer: "user:42",
			Text: "Login code: 31535. Do not share.\nIP: 2001:db8::1",
		},
	}

	out := wrapMsgs(in)
	if strings.Contains(out[0].Text, "31535") {
		t.Fatalf("login code leaked: %q", out[0].Text)
	}
	if strings.Contains(out[0].Text, "2001:db8::1") {
		t.Fatalf("login IP leaked: %q", out[0].Text)
	}
	if !strings.Contains(out[0].Text, "Login code: [redacted]") {
		t.Fatalf("missing redacted login code marker: %q", out[0].Text)
	}
	if !strings.Contains(out[0].Text, "IP: [redacted]") {
		t.Fatalf("missing redacted IP marker: %q", out[0].Text)
	}
	if !strings.HasPrefix(out[0].Text, `<telegram-content origin="telegram"`) {
		t.Fatalf("message was not wrapped as untrusted Telegram content: %q", out[0].Text)
	}
}
