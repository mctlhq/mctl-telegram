package pa

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const fakeToken = "7000000001:pa-test-token-not-real"

func infoServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+fakeToken+"/getWebhookInfo" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGetWebhookInfo(t *testing.T) {
	srv := infoServer(t, http.StatusOK, `{"ok":true,"result":{"url":"https://pa.example/pa/bot/webhook","pending_update_count":2,"allowed_updates":["message","callback_query"]}}`)
	info, err := GetWebhookInfo(context.Background(), srv.Client(), srv.URL, fakeToken)
	if err != nil {
		t.Fatal(err)
	}
	if info.URL != "https://pa.example/pa/bot/webhook" || info.PendingUpdateCount != 2 {
		t.Fatalf("info = %+v", info)
	}
	if p := CheckWebhook(info, "https://pa.example/pa/bot/webhook", time.Unix(0, 0)); len(p) != 0 {
		t.Fatalf("healthy webhook reported problems %v", p)
	}
}

// An unreadable getWebhookInfo is an error, never a zero info (I9).
func TestGetWebhookInfo_FailuresAreErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"http 500", http.StatusInternalServerError, `{"ok":false}`},
		{"ok false", http.StatusOK, `{"ok":false,"description":"Unauthorized"}`},
		{"no result", http.StatusOK, `{"ok":true}`},
		{"malformed", http.StatusOK, `<html>proxy</html>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := infoServer(t, tc.status, tc.body)
			_, err := GetWebhookInfo(context.Background(), srv.Client(), srv.URL, fakeToken)
			if err == nil {
				t.Fatal("want error")
			}
			if strings.Contains(err.Error(), fakeToken) {
				t.Fatalf("error leaks the token: %v", err)
			}
		})
	}
	t.Run("transport error does not leak the token", func(t *testing.T) {
		_, err := GetWebhookInfo(context.Background(), nil, "http://127.0.0.1:1", fakeToken)
		if err == nil || strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), "pa-test-token") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCheckWebhook(t *testing.T) {
	const want = "https://pa.example/pa/bot/webhook"
	since := time.Unix(1_000_000, 0)
	good := WebhookInfo{URL: want, AllowedUpdates: []string{"callback_query", "message"}}
	cases := []struct {
		name string
		info WebhookInfo
		want []string
	}{
		{"healthy, order-insensitive", good, nil},
		{"url changed", WebhookInfo{URL: "https://attacker.example/hook", AllowedUpdates: good.AllowedUpdates}, []string{ProblemURLChanged}},
		{"no webhook", WebhookInfo{AllowedUpdates: good.AllowedUpdates}, []string{ProblemURLChanged}},
		{"default allowed_updates", WebhookInfo{URL: want}, []string{ProblemAllowedUpdates}},
		{"wider allowed_updates", WebhookInfo{URL: want, AllowedUpdates: []string{"message", "callback_query", "business_message"}}, []string{ProblemAllowedUpdates}},
		{"old delivery error", WebhookInfo{URL: want, AllowedUpdates: good.AllowedUpdates, LastErrorDate: since.Unix() - 1}, nil},
		{"new delivery error", WebhookInfo{URL: want, AllowedUpdates: good.AllowedUpdates, LastErrorDate: since.Unix()}, []string{ProblemLastErrorRecent}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CheckWebhook(tc.info, want, since); !slices.Equal(got, tc.want) {
				t.Fatalf("problems = %v, want %v", got, tc.want)
			}
		})
	}
}
