package web

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// T13: the "Allow messages" hint appears only while the scope is requested.
// Its claims were verified on preview (#922 task 8): Telegram shows a
// separate toggle, off by default, and sign-in works either way.
func TestHandleConnect_BotAccessSentence(t *testing.T) {
	const sentence = "turn on <strong>Allow messages</strong>"
	for _, on := range []bool{true, false} {
		srv := newTestConnectServer(t, func(c *ConnectConfig) { c.BotAccessRequested = on })
		rec := httptest.NewRecorder()
		srv.HandleConnect(rec, httptest.NewRequest("GET", "/telegram/connect", nil))
		body := rec.Body.String()
		if got := strings.Contains(body, sentence); got != on {
			t.Errorf("BotAccessRequested=%v: sentence rendered=%v", on, got)
		}
	}
}

// The docs carry the same hint under the same condition.
func TestDocs_BotAccessHint(t *testing.T) {
	const sentence = "turn on <strong>Allow messages</strong>"
	for _, on := range []bool{true, false} {
		rec := httptest.NewRecorder()
		Docs("https://tg.mctl.ai", "/mcp", "https://tg.mctl.ai", true, on).ServeHTTP(rec, httptest.NewRequest("GET", "/docs", nil))
		if got := strings.Contains(rec.Body.String(), sentence); got != on {
			t.Errorf("botAccessRequested=%v: hint rendered=%v", on, got)
		}
	}
}
