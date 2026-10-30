package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// rejectRecorder implements ConnectMetrics.
type rejectRecorder struct {
	mu  sync.Mutex
	got []string
}

func (r *rejectRecorder) CountLoginCallbackRejected(route, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, route+"/"+reason)
}

func (r *rejectRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.got...)
}

func seedConnectSession(srv *ConnectServer, state string, createdAt time.Time) {
	srv.mu.Lock()
	srv.sessions[state] = &connectSession{verifier: strings.Repeat("a", 43), createdAt: createdAt}
	srv.mu.Unlock()
}

// TestHandleConnectDone_CountsEveryRejection (#960 signal 2): every reject
// branch of /telegram/connect/done increments
// mctl_login_callback_rejected_total exactly once, under route connect_done
// and the reason its log line carries. A recovered redirect and a success
// count nothing.
func TestHandleConnectDone_CountsEveryRejection(t *testing.T) {
	cases := []struct {
		name      string
		exchanger *stubExchanger
		ident     ConnectIdentifier
		setup     func(srv *ConnectServer) *http.Request
		want      []string
	}{
		{name: "missing_state", setup: func(*ConnectServer) *http.Request {
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc", nil)
		}, want: []string{"connect_done/" + reasonMissingState}},
		{name: "missing_code", setup: func(*ConnectServer) *http.Request {
			return httptest.NewRequest("GET", "/telegram/connect/done?state=s", nil)
		}, want: []string{"connect_done/" + reasonMissingCode}},
		{name: "oidc_error", setup: func(*ConnectServer) *http.Request {
			return httptest.NewRequest("GET", "/telegram/connect/done?error=access_denied&state=s", nil)
		}, want: []string{"connect_done/" + reasonOIDCError}},
		{name: "unknown_state", setup: func(*ConnectServer) *http.Request {
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=never-issued", nil)
		}, want: []string{"connect_done/" + reasonUnknownState}},
		{name: "expired_state", setup: func(srv *ConnectServer) *http.Request {
			seedConnectSession(srv, "expired", time.Now().Add(-time.Hour))
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=expired", nil)
		}, want: []string{"connect_done/" + reasonExpiredState}},
		{name: "exchange_failed", exchanger: &stubExchanger{err: errors.New("invalid_grant")}, setup: func(srv *ConnectServer) *http.Request {
			seedConnectSession(srv, "live", time.Now())
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=live", nil)
		}, want: []string{"connect_done/" + reasonExchangeFailed}},
		{name: "prefetch_refused", setup: func(srv *ConnectServer) *http.Request {
			seedConnectSession(srv, "live", time.Now())
			req := httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=live", nil)
			req.Header.Set("Sec-Purpose", "prefetch")
			return req
		}, want: []string{"connect_done/" + reasonPrefetchRefused}},
		{name: "recovered_redirect", ident: &stubIdentifier{id: &auth.Identity{UserID: 1}}, setup: func(*ConnectServer) *http.Request {
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=never-issued", nil)
		}},
		{name: "success", setup: func(srv *ConnectServer) *http.Request {
			seedConnectSession(srv, "live", time.Now())
			return httptest.NewRequest("GET", "/telegram/connect/done?code=abc&state=live", nil)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captureConnectLog(t)
			rec := &rejectRecorder{}
			srv := newTestConnectServer(t, func(cfg *ConnectConfig) {
				cfg.Metrics = rec
				if tc.exchanger != nil {
					cfg.OAuthServer = tc.exchanger
				}
				if tc.ident != nil {
					cfg.Identifier = tc.ident
				}
			})
			srv.HandleConnectDone(httptest.NewRecorder(), tc.setup(srv))
			got := rec.snapshot()
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("rejections = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRootMCP_CountsMCPRequests (#960 signal 3): every request "/" serves as
// MCP is counted once with a bounded method and UA family; a landing-page
// load is not counted at all.
func TestRootMCP_CountsMCPRequests(t *testing.T) {
	var got []string
	h := RootMCP(namedHandler("landing"), namedHandler("mcp"), func(method, family string) {
		got = append(got, method+"/"+family)
	})
	cases := []struct {
		method, accept, ua, want string
	}{
		{http.MethodGet, "text/html", "Mozilla/5.0 Chrome/130", ""},
		{http.MethodPost, "application/json, text/event-stream", "openai-mcp/1.0.0", "POST/chatgpt"},
		{http.MethodPost, "", "Claude-User", "POST/claude"},
		{http.MethodGet, "text/event-stream", "Perplexity-User/1.0", "GET/perplexity"},
		{http.MethodDelete, "", "mctl-telegram-canary/0.108.0", "DELETE/canary"},
		{http.MethodPut, "", "", "other/other"},
	}
	for _, tc := range cases {
		got = nil
		req := httptest.NewRequest(tc.method, "/", nil)
		if tc.accept != "" {
			req.Header.Set("Accept", tc.accept)
		}
		req.Header.Set("User-Agent", tc.ua)
		h.ServeHTTP(httptest.NewRecorder(), req)
		want := []string{}
		if tc.want != "" {
			want = []string{tc.want}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s / UA %q: counted %v, want %v", tc.method, tc.ua, got, want)
		}
	}
}

// TestUAFamily pins the User-Agent to family mapping, including the
// precedence of the canary over the connector tokens and the fallback.
func TestUAFamily(t *testing.T) {
	cases := map[string]string{
		"Claude-User":                          UAFamilyClaude,
		"claude-ai/0.1":                        UAFamilyClaude,
		"Anthropic-MCP/1":                      UAFamilyClaude,
		"ChatGPT-User/1.0":                     UAFamilyChatGPT,
		"openai-mcp/1.0.0":                     UAFamilyChatGPT,
		"Perplexity-User/1.0":                  UAFamilyPerplexity,
		"mctl-telegram-canary/0.108.0":         UAFamilyCanary,
		"mctl-telegram-canary/0.1 Claude-User": UAFamilyCanary,
		"":                                     UAFamilyOther,
		"curl/8.7.1":                           UAFamilyOther,
	}
	for ua, want := range cases {
		if got := UAFamily(ua); got != want {
			t.Errorf("UAFamily(%q) = %q, want %q", ua, got, want)
		}
	}
}

// TestLoginSignalLabelsArePrimed holds this package's label values to the
// sets internal/metrics primes, so no value it can emit is created lazily
// (and missed by increase()) and the two lists cannot drift apart.
func TestLoginSignalLabelsArePrimed(t *testing.T) {
	reg := metrics.New()

	rejected := labelSet(t, reg.LoginCallbackRejectedTotal, "route", "reason")
	for _, reason := range []string{
		reasonMissingState, reasonMissingCode, reasonOIDCError, reasonUnknownState,
		reasonExpiredState, reasonExchangeFailed, reasonPrefetchRefused,
	} {
		if !rejected[connectDoneRoute+"/"+reason] {
			t.Errorf("mctl_login_callback_rejected_total{route=%q,reason=%q} is not primed", connectDoneRoute, reason)
		}
	}

	root := labelSet(t, reg.RootMCPRequestsTotal, "method", "ua_family")
	want := 0
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, "other"} {
		for _, f := range []string{UAFamilyClaude, UAFamilyChatGPT, UAFamilyPerplexity, UAFamilyCanary, UAFamilyOther} {
			want++
			if !root[m+"/"+f] {
				t.Errorf("mctl_root_mcp_requests_total{method=%q,ua_family=%q} is not primed", m, f)
			}
		}
	}
	if len(root) != want {
		t.Errorf("mctl_root_mcp_requests_total has %d primed series, want %d", len(root), want)
	}
}

// labelSet collects c's series as "a/b" keys of the two named labels.
func labelSet(t *testing.T, c prometheus.Collector, a, b string) map[string]bool {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	out := map[string]bool{}
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		lv := map[string]string{}
		for _, l := range pb.GetLabel() {
			lv[l.GetName()] = l.GetValue()
		}
		out[lv[a]+"/"+lv[b]] = true
	}
	return out
}
