package linking_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

type testServer struct{ r chi.Router }

func (h *harness) server(t *testing.T) *testServer {
	t.Helper()
	r := chi.NewRouter()
	h.svc.Mount(r)
	return &testServer{r: r}
}

func (s *testServer) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.r.ServeHTTP(w, req)
	resp := w.Result()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (s *testServer) post(t *testing.T, path, body string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := s.do(t, req)
	return resp.StatusCode
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

var externalRef = regexp.MustCompile(`(?i)(src|href)\s*=\s*"(https?:)?//`)

// checkPageHeaders: no caching, no referrer, a CSP that loads nothing from
// anywhere but this origin, and no third-party resource in the markup.
func checkPageHeaders(t *testing.T, resp *http.Response, body string, framed bool) {
	t.Helper()
	h := resp.Header
	if h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", h)
	}
	csp := h.Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "base-uri 'none'", "form-action 'self'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP %q lacks %q", csp, want)
		}
	}
	if !framed && !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP %q allows framing", csp)
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "*") {
		t.Fatalf("CSP %q is permissive", csp)
	}
	if externalRef.MatchString(body) && !strings.Contains(body, `href="https://t.me/`) {
		t.Fatalf("page references a third-party resource:\n%s", body)
	}
	if strings.Contains(body, "<script src") || strings.Contains(body, "<link") {
		t.Fatalf("page loads an external script or stylesheet")
	}
}

// TestLinking_HTTPPages runs the browser half over HTTP: the callback page
// names the masked target Telegram account and shows no completion link
// until "This is my Telegram account" is posted; every page carries the
// CSP and no third-party resource.
func TestLinking_HTTPPages(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, false)
		srv := h.server(t)

		resp, body := srv.do(t, httptest.NewRequest(http.MethodGet, linking.AppPath+"?link=x", nil))
		if resp.StatusCode != 200 || !strings.Contains(body, "tgWebAppData") {
			t.Fatalf("app page %d", resp.StatusCode)
		}
		checkPageHeaders(t, resp, body, true)

		link := h.start(connection.ServerTG)
		req := httptest.NewRequest(http.MethodPost, linking.BeginPath,
			strings.NewReader(`{"init_data":`+quote(h.initData(h.alice, ""))+`,"link":"`+link+`"}`))
		resp, body = srv.do(t, req)
		if resp.StatusCode != 200 {
			t.Fatalf("begin %d", resp.StatusCode)
		}
		var began struct{ URL string }
		if err := json.Unmarshal([]byte(body), &began); err != nil {
			t.Fatal(err)
		}
		cb := h.as[connection.ServerTG].authorize(t, began.URL, h.tgLogin(h.alice))

		resp, body = srv.do(t, httptest.NewRequest(http.MethodGet, "/pa/oauth/callback/tg?"+cb.Encode(), nil))
		if resp.StatusCode != 200 {
			t.Fatalf("callback %d", resp.StatusCode)
		}
		checkPageHeaders(t, resp, body, false)
		idStr := strconv.FormatInt(h.alice, 10)
		if !strings.Contains(body, "A*** (id ending "+idStr[len(idStr)-3:]+")") || strings.Contains(body, idStr) {
			t.Fatalf("callback page does not name the masked account, or leaks the full id:\n%s", body)
		}
		if strings.Contains(body, "t.me/") || strings.Contains(body, cb.Get("code")) {
			t.Fatalf("callback page shows the completion link or the code before confirmation")
		}
		m := regexp.MustCompile(`name="handoff" value="([^"]+)"`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no handoff form:\n%s", body)
		}

		// The handoff value is read from the form body only.
		resp, _ = srv.do(t, formReq(linking.HandoffPath+"?handoff="+url.QueryEscape(m[1]), ""))
		if resp.StatusCode == 200 {
			t.Fatal("handoff accepted from the URL")
		}
		resp, body = srv.do(t, formReq(linking.HandoffPath, "handoff="+url.QueryEscape(m[1])))
		if resp.StatusCode != 200 {
			t.Fatalf("handoff %d", resp.StatusCode)
		}
		checkPageHeaders(t, resp, body, false)
		dl := regexp.MustCompile(`href="(https://t\.me/fake_pa_bot/link\?startapp=[A-Za-z0-9_-]{43})"`).FindStringSubmatch(body)
		if dl == nil {
			t.Fatalf("no completion deep link:\n%s", body)
		}
		resp, _ = srv.do(t, formReq(linking.HandoffPath, "handoff="+url.QueryEscape(m[1])))
		if resp.StatusCode == 200 {
			t.Fatal("handoff reused")
		}

		// A refused callback renders the error page with the same headers.
		resp, body = srv.do(t, httptest.NewRequest(http.MethodGet, "/pa/oauth/callback/tg?"+cb.Encode(), nil))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("replayed callback %d", resp.StatusCode)
		}
		checkPageHeaders(t, resp, body, false)
	})
}

func formReq(path, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// disableUnreadable is the linking store with the disable read failing.
type disableUnreadable struct{ *db.Store }

func (disableUnreadable) PAPrincipalDisabledState(context.Context, int64) (bool, error) {
	return false, errors.New("injected: disable unreadable")
}

// Every step of the linking flow refuses, fail-closed, a principal the
// webhook would refuse (#1318 A1): one not on the allowlist, one an admin
// disabled, and one whose disable cannot be read. The HTTP routes answer
// 403. A step that already holds the principal's connection fails it and
// revokes any tokens; one that runs before consuming its secret changes
// nothing, and the linking sweep fails the pending row.
func TestLinking_RefusesUnadmittedPrincipal(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		refusals := map[string]func(h *harness){
			"not allowlisted": func(h *harness) { h.allow.deny(h.alice) },
			"disabled": func(h *harness) {
				if err := s.SetPAPrincipalDisabled(context.Background(), h.alice, 1, "test", h.clock.Now()); err != nil {
					h.t.Fatal(err)
				}
				h.t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM pa_principal_disables WHERE principal = $1`, h.alice) })
			},
			"disable unreadable": func(h *harness) {
				var err error
				h.svc, err = linking.New(linking.Config{
					BotToken: paBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
					AppURL: appURL, Servers: h.servers, Manager: h.m, Store: disableUnreadable{s}, Tokens: tokenClient{h.as},
					Accounts: h.accounts, Messenger: h.msgr, Allowed: h.allow, Now: h.clock.Now,
				})
				if err != nil {
					h.t.Fatal(err)
				}
			},
		}
		for mode, refuse := range refusals {
			t.Run(mode, func(t *testing.T) {
				ctx := context.Background()
				t.Run("start", func(t *testing.T) {
					h := newHarness(t, s, false)
					refuse(h)
					if _, err := h.svc.StartLink(ctx, principal(t, h.alice), connection.ServerTG); !errors.Is(err, linking.ErrPrincipalRefused) {
						t.Fatalf("StartLink: %v", err)
					}
					if cs, err := h.m.List(ctx, h.alice); err != nil || len(cs) != 0 {
						t.Fatalf("connections after a refused /connect: %d %v", len(cs), err)
					}
				})
				t.Run("begin", func(t *testing.T) {
					h := newHarness(t, s, false)
					link := h.start(connection.ServerTG)
					refuse(h)
					if code := h.server(t).post(t, linking.BeginPath, `{"init_data":`+quote(h.initData(h.alice, ""))+`,"link":"`+link+`"}`); code != http.StatusForbidden {
						t.Fatalf("begin %d", code)
					}
					if st := h.state(connection.ServerTG); st != connection.StatePendingLink {
						t.Fatalf("state %s after a refused begin", st)
					}
				})
				t.Run("callback", func(t *testing.T) {
					h := newHarness(t, s, false)
					cb := h.toCallback(connection.ServerTG, h.tgLogin(h.alice))
					refuse(h)
					resp, _ := h.server(t).do(t, httptest.NewRequest(http.MethodGet, "/pa/oauth/callback/tg?"+cb.Encode(), nil))
					if resp.StatusCode != http.StatusForbidden || h.state(connection.ServerTG) != connection.StateFailed {
						t.Fatalf("callback %d, state %s", resp.StatusCode, h.state(connection.ServerTG))
					}
				})
				t.Run("handoff", func(t *testing.T) {
					h := newHarness(t, s, false)
					res, err := h.svc.Callback(ctx, connection.ServerTG, h.toCallback(connection.ServerTG, h.tgLogin(h.alice)))
					if err != nil {
						t.Fatal(err)
					}
					refuse(h)
					resp, _ := h.server(t).do(t, formReq(linking.HandoffPath, "handoff="+url.QueryEscape(res.Handoff)))
					if resp.StatusCode != http.StatusForbidden || h.state(connection.ServerTG) != connection.StateFailed {
						t.Fatalf("handoff %d, state %s", resp.StatusCode, h.state(connection.ServerTG))
					}
				})
				t.Run("complete", func(t *testing.T) {
					h := newHarness(t, s, false)
					code := h.toCompletion(connection.ServerTG, h.tgLogin(h.alice))
					refuse(h)
					if st := h.server(t).post(t, linking.CompletePath, `{"init_data":`+quote(h.initData(h.alice, code))+`}`); st != http.StatusForbidden {
						t.Fatalf("complete %d", st)
					}
					if n := h.as[connection.ServerTG].exchangeCount(); n != 0 {
						t.Fatalf("%d code exchanges for a refused principal", n)
					}
				})
				t.Run("confirm", func(t *testing.T) {
					h := newHarness(t, s, false)
					confirm, _ := confirmData(h.toConfirm(connection.ServerTG, h.tgLogin(h.alice)))
					refuse(h)
					before := h.revoker.count()
					handled, err := h.svc.HandleCallback(ctx, callbackUpdate(t, h.alice, confirm))
					if !handled || !errors.Is(err, linking.ErrPrincipalRefused) {
						t.Fatalf("confirm: handled=%v err=%v", handled, err)
					}
					c := h.connection(connection.ServerTG)
					if c.State != connection.StateFailed || h.sealedTokens(c.ID) != 0 || h.revoker.count() <= before {
						t.Fatalf("state %s, sealed %d bytes, revoked %d->%d", c.State, h.sealedTokens(c.ID), before, h.revoker.count())
					}
				})
			})
		}
	})
}

// New refuses a configuration without the allowlist: there is no
// "allow everyone" default.
func TestLinking_NewNeedsAllowlist(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		h := newHarness(t, s, false)
		_, err := linking.New(linking.Config{
			BotToken: paBotToken, LoginBotToken: loginBotToken, BotUsername: "fake_pa_bot", MiniAppName: "link",
			AppURL: appURL, Servers: h.servers, Manager: h.m, Store: s, Tokens: tokenClient{h.as},
			Accounts: h.accounts, Messenger: h.msgr,
		})
		if !errors.Is(err, linking.ErrConfig) {
			t.Fatalf("New without an allowlist: %v, want ErrConfig", err)
		}
	})
}
