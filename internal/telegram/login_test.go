package telegram

import (
	"testing"

	"github.com/gotd/td/tg"
)

func TestCodeDelivery(t *testing.T) {
	withNext := &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeApp{Length: 5}}
	withNext.SetNextType(&tg.AuthCodeTypeSMS{})
	withNext.SetTimeout(60)

	for _, tc := range []struct {
		name          string
		sent          *tg.AuthSentCode
		delivery, nxt string
		timeout       int
	}{
		{"app with sms fallback", withNext, "auth.sentCodeTypeApp", "auth.codeTypeSms", 60},
		{"email only", &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeEmailCode{}}, "auth.sentCodeTypeEmailCode", "", 0},
		{"fragment", &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeFragmentSMS{}}, "auth.sentCodeTypeFragmentSms", "", 0},
		{"no type", &tg.AuthSentCode{}, "unknown", "", 0},
		{"nil", nil, "unknown", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, n, to := codeDelivery(tc.sent)
			if d != tc.delivery || n != tc.nxt || to != tc.timeout {
				t.Fatalf("codeDelivery = (%q, %q, %d), want (%q, %q, %d)", d, n, to, tc.delivery, tc.nxt, tc.timeout)
			}
		})
	}
}
