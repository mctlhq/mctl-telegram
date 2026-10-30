package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// loginPathFake models the public login path of a healthy deployment, as
// observed on tg.mctl.ai on 2026-10-30. Each mutation flag breaks exactly one
// hop the way it broke, or could break, in production.
type loginPathFake struct {
	rootMCP405      bool // MCP refused on "/" (the pre-#957 behaviour)
	edgeBlockUA     string
	edge401NoBearer bool // something other than the app answers 401
	proxyRealm      bool // an auth proxy answers with its own Bearer challenge
	mcpUnauthOK     bool // auth bypassed: 200 to an unauthenticated initialize
	prmWrongRes     bool
	noConnectLink   bool
	authorizeNo302  bool
	authorizeHost   string
	callback500     bool
	callbackBlank   bool // 200 with an empty page
	prmNoAS         bool
	prmMCPStale     bool
	connectOtherCID bool
	rootWrongMeta   bool // "/" answers with the /mcp metadata document
	authorize200Loc bool // a Location header on a non-redirect status
}

func (f *loginPathFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	var base string
	challenge := func(w http.ResponseWriter, metadataPath string) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram", resource_metadata="`+base+metadataPath+`"`)
		w.WriteHeader(http.StatusUnauthorized)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, r *http.Request) {
		res := base
		if f.prmWrongRes {
			res = base + "/mcp"
		}
		as := []string{base}
		if f.prmNoAS {
			as = nil
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource": res, "authorization_servers": as})
	})
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		if f.prmMCPStale {
			// An error status in front of a body that still parses, as a
			// cache serving a stale document on a 503 would.
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
	})
	mux.HandleFunc("GET /telegram/connect", func(w http.ResponseWriter, r *http.Request) {
		if f.noConnectLink {
			_, _ = w.Write([]byte("<html><body>maintenance</body></html>"))
			return
		}
		cid := connectClientID
		if f.connectOtherCID {
			cid = "someone_else"
		}
		_, _ = w.Write([]byte(`<a href="` + base + `/oauth/authorize?client_id=` + cid + `&amp;code_challenge=abc&amp;code_challenge_method=S256&amp;response_type=code&amp;state=s">Connect</a>`))
	})
	mux.HandleFunc("GET /oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != connectClientID || q.Get("code_challenge_method") != "S256" || q.Get("redirect_uri") != base+"/telegram/connect/done" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		if f.authorizeNo302 {
			_, _ = w.Write([]byte("<html>chooser</html>"))
			return
		}
		host := "oauth.telegram.org"
		if f.authorizeHost != "" {
			host = f.authorizeHost
		}
		tq := url.Values{
			"client_id":             {"1000001"},
			"redirect_uri":          {base + "/oauth/telegram/callback"},
			"response_type":         {"code"},
			"code_challenge":        {"xyz"},
			"code_challenge_method": {"S256"},
			"state":                 {"server-state"},
		}
		if f.authorize200Loc {
			w.Header().Set("Location", "https://"+host+"/auth?"+tq.Encode())
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, "https://"+host+"/auth?"+tq.Encode(), http.StatusFound)
	})
	mux.HandleFunc("GET /oauth/telegram/callback", func(w http.ResponseWriter, r *http.Request) {
		if f.callback500 {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if f.callbackBlank {
			return
		}
		_, _ = w.Write([]byte("<p>That sign-in link was already used or has expired.</p>"))
	})
	mux.HandleFunc("POST /{$}", func(w http.ResponseWriter, r *http.Request) {
		if f.rootMCP405 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if f.rootWrongMeta {
			challenge(w, "/.well-known/oauth-protected-resource/mcp")
			return
		}
		challenge(w, "/.well-known/oauth-protected-resource")
	})
	mux.HandleFunc("POST /mcp", func(w http.ResponseWriter, r *http.Request) {
		if f.edgeBlockUA != "" && r.Header.Get("User-Agent") == f.edgeBlockUA {
			w.Header().Set("Server", "cloudflare")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("<html>Attention Required!</html>"))
			return
		}
		if f.proxyRealm {
			w.Header().Set("WWW-Authenticate", `Bearer realm="proxy", resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.mcpUnauthOK {
			w.Header().Set("WWW-Authenticate", `Bearer realm="mctl-telegram", resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
			writeJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
			return
		}
		if f.edge401NoBearer {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		challenge(w, "/.well-known/oauth-protected-resource/mcp")
	})
	srv := httptest.NewServer(mux)
	base = srv.URL
	return srv
}

func loginPathConfig(baseURL string) *config {
	return &config{
		baseURL:   baseURL,
		timeout:   5 * time.Second,
		mcpPath:   "/mcp",
		loginPath: true,
		oidcHost:  "oauth.telegram.org",
	}
}

// TestRunLoginPathGreen is the converged case: every step passes and the
// login-path gauge reads 1 without touching the tool-path gauge.
func TestRunLoginPathGreen(t *testing.T) {
	srv := (&loginPathFake{}).server(t)
	defer srv.Close()

	met := newCanaryMetrics()
	met.registry.MustRegister(met.loginPathSuccess)
	if !runLoginPath(t.Context(), loginPathConfig(srv.URL), met) {
		t.Fatal("expected the login path to pass against a healthy server")
	}
	if got := testutil.ToFloat64(met.loginPathSuccess); got != 1 {
		t.Errorf("login_path_success = %v, want 1", got)
	}
	for _, step := range loginPathSteps {
		if got := testutil.ToFloat64(met.stepFailures.WithLabelValues(step)); got != 0 {
			t.Errorf("step %s failure = %v, want 0", step, got)
		}
	}
	if got := testutil.ToFloat64(met.success); got != 0 {
		t.Errorf("tool-path success gauge changed to %v by the login path", got)
	}
}

// TestRunLoginPathMutations proves each step red: every mutation turns its
// own step, and only its own step, red.
func TestRunLoginPathMutations(t *testing.T) {
	cases := []struct {
		name string
		fake loginPathFake
		step string
	}{
		{"protected resource names the wrong resource", loginPathFake{prmWrongRes: true}, "prm_root"},
		{"protected resource lists no authorization server", loginPathFake{prmNoAS: true}, "prm_root"},
		{"bare origin points at the /mcp metadata", loginPathFake{rootWrongMeta: true}, "mcp_root"},
		{"authorize sets Location without redirecting", loginPathFake{authorize200Loc: true}, "authorize_redirect"},
		{"callback renders an empty page", loginPathFake{callbackBlank: true}, "callback_unknown_state"},
		{"protected resource for /mcp served with an error status", loginPathFake{prmMCPStale: true}, "prm_mcp"},
		{"connect link names another client", loginPathFake{connectOtherCID: true}, "connect_page"},
		{"connect page lost its authorize link", loginPathFake{noConnectLink: true}, "connect_page"},
		{"authorize renders instead of redirecting", loginPathFake{authorizeNo302: true}, "authorize_redirect"},
		{"authorize redirects somewhere other than Telegram", loginPathFake{authorizeHost: "evil.example"}, "authorize_redirect"},
		{"callback 5xx on an unknown state", loginPathFake{callback500: true}, "callback_unknown_state"},
		{"MCP refused on the bare origin (pre-#957)", loginPathFake{rootMCP405: true}, "mcp_root"},
		{"edge blocks Claude-User", loginPathFake{edgeBlockUA: "Claude-User"}, "edge_connector_ua"},
		{"edge blocks Perplexity-User", loginPathFake{edgeBlockUA: "Perplexity-User"}, "edge_connector_ua"},
		{"401 without the app's Bearer challenge", loginPathFake{edge401NoBearer: true}, "edge_connector_ua"},
		{"401 from an auth proxy with its own realm", loginPathFake{proxyRealm: true}, "edge_connector_ua"},
		{"unauthenticated initialize accepted", loginPathFake{mcpUnauthOK: true}, "edge_connector_ua"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := tc.fake.server(t)
			defer srv.Close()

			met := newCanaryMetrics()
			met.registry.MustRegister(met.loginPathSuccess)
			if runLoginPath(t.Context(), loginPathConfig(srv.URL), met) {
				t.Fatal("expected the login path to fail")
			}
			if got := testutil.ToFloat64(met.loginPathSuccess); got != 0 {
				t.Errorf("login_path_success = %v, want 0", got)
			}
			for _, step := range loginPathSteps {
				want := 0.0
				if step == tc.step {
					want = 1
				}
				if got := testutil.ToFloat64(met.stepFailures.WithLabelValues(step)); got != want {
					t.Errorf("step %s failure = %v, want %v", step, got, want)
				}
			}
		})
	}
}

// TestRunLoginPathUnreachable: a server that cannot be reached is a failure
// of every step, never a pass.
func TestRunLoginPathUnreachable(t *testing.T) {
	srv := (&loginPathFake{}).server(t)
	base := srv.URL
	srv.Close()

	met := newCanaryMetrics()
	met.registry.MustRegister(met.loginPathSuccess)
	if runLoginPath(t.Context(), loginPathConfig(base), met) {
		t.Fatal("expected an unreachable server to fail the login path")
	}
	for _, step := range loginPathSteps {
		if got := testutil.ToFloat64(met.stepFailures.WithLabelValues(step)); got != 1 {
			t.Errorf("step %s failure = %v, want 1", step, got)
		}
	}
}

// TestLoginPathGaugeAbsentWhenDisabled: a deployment that does not probe the
// login path must not publish a login_path_success series at all; a
// registered-but-unset gauge would push 0 and read as an outage.
func TestLoginPathGaugeAbsentWhenDisabled(t *testing.T) {
	met := newCanaryMetrics()
	mfs, err := met.registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if strings.Contains(mf.GetName(), "login_path") {
			t.Fatalf("metric %s is registered while the login path is disabled", mf.GetName())
		}
	}
}
