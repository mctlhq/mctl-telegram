package oauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestRedirectForLog(t *testing.T) {
	for in, want := range map[string]string{
		"": "",
		"https://claude.ai/api/mcp/auth_callback":    "https://claude.ai/api/mcp/auth_callback",
		"https://x.example/cb?code=SECRET&state=s#f": "https://x.example/cb",
		"http://127.0.0.1:33418/cb":                  "http://127.0.0.1:33418/cb",
		"not a url":                                  "invalid",
	} {
		if got := redirectForLog(in); got != want {
			t.Errorf("redirectForLog(%q) = %q, want %q", in, got, want)
		}
	}
}

// The grant lines carry the callback (host and path only), so a redirect_uri
// ceiling record can be written from the log.
func TestGrantLogsCarryRedirectPath(t *testing.T) {
	srv := newTestServer(t, withDanaInEveryAdminMembership)
	mux := newMockRouter()
	srv.Register(mux)
	logs := captureServerLogFor(t, srv)
	seedSession(t, srv, danaTelegramID)

	cb := "https://claude.ai/api/mcp/auth_callback"
	resp := tokenFor(t, srv, mux, danaTelegramID, "dana_tg", "claude.ai", cb, "telegram:dialogs:read")
	if status, body := refreshResp(t, mux, resp["refresh_token"].(string), "claude.ai"); status != http.StatusOK {
		t.Fatalf("refresh = %d %s", status, body)
	}
	want := "redirect_uri=" + cb
	for _, msg := range []string{"oauth: token authorization_code grant", refreshGrantLine} {
		var line string
		for _, l := range strings.Split(logs.String(), "\n") {
			if strings.Contains(l, msg) {
				line = l
			}
		}
		if !strings.Contains(line, want) {
			t.Fatalf("%q line lacks %s:\n%s", msg, want, line)
		}
	}
}
