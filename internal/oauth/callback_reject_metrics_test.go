package oauth

import (
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// TestHandleTelegramCallback_CountsEveryRejection (#960 signal 2): every
// reject branch of /oauth/telegram/callback increments
// mctl_login_callback_rejected_total exactly once, under route
// oauth_callback and the same reason its log line carries.
func TestHandleTelegramCallback_CountsEveryRejection(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		// do drives one request through mux and returns nothing; the
		// assertion is on the recorded counter.
		do func(t *testing.T, srv *Server, mux *mockRouter)
	}{
		{"missing_state", reasonMissingState, func(t *testing.T, _ *Server, mux *mockRouter) {
			req := httptest.NewRequest("GET", "/oauth/telegram/callback?code=abc", nil)
			mux.serve("GET", "/oauth/telegram/callback", httptest.NewRecorder(), req)
		}},
		{"unknown_state", reasonUnknownState, func(t *testing.T, _ *Server, mux *mockRouter) {
			callbackWithState(t, mux, "never-issued-state")
		}},
		{"expired_state", reasonExpiredState, func(t *testing.T, srv *Server, mux *mockRouter) {
			_, challenge := pkceVerifierAndChallenge()
			state := stateFromAuthorize(t, mux, challenge)
			srv.mu.Lock()
			srv.pending[state].CreatedAt = time.Now().Add(-time.Hour)
			srv.mu.Unlock()
			callbackWithState(t, mux, state)
		}},
		{"oidc_error", reasonOIDCError, func(t *testing.T, _ *Server, mux *mockRouter) {
			_, challenge := pkceVerifierAndChallenge()
			state := stateFromAuthorize(t, mux, challenge)
			q := url.Values{"state": {state}, "error": {"access_denied"}}
			req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
			mux.serve("GET", "/oauth/telegram/callback", httptest.NewRecorder(), req)
		}},
		{"missing_code", reasonMissingCode, func(t *testing.T, _ *Server, mux *mockRouter) {
			_, challenge := pkceVerifierAndChallenge()
			state := stateFromAuthorize(t, mux, challenge)
			q := url.Values{"state": {state}}
			req := httptest.NewRequest("GET", "/oauth/telegram/callback?"+q.Encode(), nil)
			mux.serve("GET", "/oauth/telegram/callback", httptest.NewRecorder(), req)
		}},
		{"exchange_failed", reasonExchangeFailed, func(t *testing.T, srv *Server, mux *mockRouter) {
			authFake(srv).exchangeErr = errors.New("token endpoint: boom")
			_, challenge := pkceVerifierAndChallenge()
			callbackWithState(t, mux, stateFromAuthorize(t, mux, challenge))
		}},
		{"prefetch_refused", reasonPrefetchRefused, func(t *testing.T, _ *Server, mux *mockRouter) {
			_, challenge := pkceVerifierAndChallenge()
			state := stateFromAuthorize(t, mux, challenge)
			callbackWithStateHeaders(t, mux, state, map[string]string{"Sec-Purpose": "prefetch"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captureServerLog(t)
			srv := newTestServer(t)
			m := &flowMetrics{}
			srv.WithMetrics(m)
			mux := newMockRouter()
			srv.Register(mux)

			tc.do(t, srv, mux)

			want := callbackRoute + "/" + tc.reason
			if got := m.rejectedSnapshot(); len(got) != 1 || got[0] != want {
				t.Errorf("rejections = %v, want [%s]", got, want)
			}
		})
	}

	// A callback that succeeds counts nothing: the counter measures
	// rejections, not traffic.
	t.Run("success", func(t *testing.T) {
		captureServerLog(t)
		srv := newTestServer(t)
		m := &flowMetrics{}
		srv.WithMetrics(m)
		mux := newMockRouter()
		srv.Register(mux)
		seedSession(t, srv, 500100101)
		_, challenge := pkceVerifierAndChallenge()
		rec := callbackWithState(t, mux, stateFromAuthorize(t, mux, challenge))
		if loc := authCodeRedirect(t, rec); loc.Query().Get("code") == "" {
			t.Fatalf("no authorization code in %s", loc)
		}
		if got := m.rejectedSnapshot(); len(got) != 0 {
			t.Errorf("rejections = %v, want none", got)
		}
	})
}

// TestLoginSignalLabelsArePrimed holds this package's login-signal label
// values to the sets internal/metrics primes (#960): every callback reason
// and both login methods exist at 0 before first use.
func TestLoginSignalLabelsArePrimed(t *testing.T) {
	reg := metrics.New()
	for _, reason := range []string{
		reasonMissingState, reasonMissingCode, reasonOIDCError, reasonUnknownState,
		reasonExpiredState, reasonExchangeFailed, reasonPrefetchRefused,
	} {
		if !hasSeries(t, reg.LoginCallbackRejectedTotal, map[string]string{"route": callbackRoute, "reason": reason}) {
			t.Errorf("mctl_login_callback_rejected_total{route=%q,reason=%q} is not primed", callbackRoute, reason)
		}
	}
	for _, method := range []string{methodCode, methodQR} {
		if !hasSeries(t, reg.LoginFlowStartedTotal, map[string]string{"method": method}) {
			t.Errorf("mctl_login_flow_started_total{method=%q} is not primed", method)
		}
		// Every value loginFlowResult can return, so the runbook's
		// started-minus-finished subtraction never loses a method.
		for _, result := range []string{"ok", "error", "mismatch", "expired", "stalled", "abandoned", "superseded"} {
			if !hasSeries(t, reg.LoginFlowTotal, map[string]string{"method": method, "result": result}) {
				t.Errorf("mctl_login_flow_total{method=%q,result=%q} is not primed", method, result)
			}
		}
	}
}

// hasSeries reports whether c already exports a series with exactly labels.
func hasSeries(t *testing.T, c prometheus.Collector, labels map[string]string) bool {
	t.Helper()
	ch := make(chan prometheus.Metric, 64)
	go func() { c.Collect(ch); close(ch) }()
	found := false
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err != nil {
			t.Fatalf("write metric: %v", err)
		}
		match := len(pb.GetLabel()) == len(labels)
		for _, l := range pb.GetLabel() {
			if labels[l.GetName()] != l.GetValue() {
				match = false
			}
		}
		found = found || match
	}
	return found
}
