package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// T13: the bot-permission sentence appears only while the scope is requested
// and never claims the permission is optional.
func TestHandleConnect_BotAccessSentence(t *testing.T) {
	const sentence = "Telegram may also ask whether the MCTL login bot can message you."
	for _, on := range []bool{true, false} {
		srv := newTestConnectServer(t, func(c *ConnectConfig) { c.BotAccessRequested = on })
		rec := httptest.NewRecorder()
		srv.HandleConnect(rec, httptest.NewRequest("GET", "/telegram/connect", nil))
		body := rec.Body.String()
		if got := strings.Contains(body, sentence); got != on {
			t.Errorf("BotAccessRequested=%v: sentence rendered=%v", on, got)
		}
		for _, claim := range []string{"optional", "without it"} {
			if strings.Contains(strings.ToLower(body), claim) {
				t.Errorf("BotAccessRequested=%v: page claims %q", on, claim)
			}
		}
	}
}
