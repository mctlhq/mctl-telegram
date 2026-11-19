package pa

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

const monitorURL = "https://pa.example/pa/bot/webhook"

type gaugeRecorder struct {
	mu  sync.Mutex
	obs []WebhookObservation
}

func (g *gaugeRecorder) ObservePAWebhookInfo(readable bool, problems []string, pending int, lastErr int64, at time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.obs = append(g.obs, WebhookObservation{At: at, Readable: readable, Problems: problems,
		Info: WebhookInfo{PendingUpdateCount: pending, LastErrorDate: lastErr}})
}

func (g *gaugeRecorder) last() WebhookObservation {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.obs[len(g.obs)-1]
}

// switchableInfo serves getWebhookInfo with a body that a test can change.
type switchableInfo struct {
	mu     sync.Mutex
	status int
	body   string
}

func (s *switchableInfo) set(status int, body string) {
	s.mu.Lock()
	s.status, s.body = status, body
	s.mu.Unlock()
}

func newSwitchableInfo(t *testing.T) (*switchableInfo, *httptest.Server) {
	s := &switchableInfo{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bot"+fakeToken+"/getWebhookInfo" {
			http.NotFound(w, r)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		w.WriteHeader(s.status)
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

func infoJSON(u string, pending int, lastErr int64, msg string) string {
	return `{"ok":true,"result":{"url":` + strconv.Quote(u) + `,"pending_update_count":` + strconv.Itoa(pending) +
		`,"last_error_date":` + strconv.FormatInt(lastErr, 10) + `,"last_error_message":` + strconv.Quote(msg) +
		`,"allowed_updates":["message","callback_query"]}}`
}

// TestWebhookMonitor is the monitor part of T4: a healthy webhook, a
// changed URL, a new delivery error, a rejected secret and an unreadable
// getWebhookInfo, in turn.
func TestWebhookMonitor(t *testing.T) {
	info, srv := newSwitchableInfo(t)
	g := &gaugeRecorder{}
	now := time.Unix(1_800_000_000, 0)
	m, err := NewWebhookMonitor(WebhookMonitorConfig{
		HTTP: srv.Client(), BaseURL: srv.URL, Token: fakeToken, ExpectedURL: monitorURL, Gauges: g,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// An error from before the monitor started is history, not news.
	info.set(http.StatusOK, infoJSON(monitorURL, 1, now.Add(-time.Hour).Unix(), "Connection timed out"))
	if o := m.Check(context.Background()); !o.Readable || len(o.Problems) != 0 || g.last().Info.PendingUpdateCount != 1 {
		t.Fatalf("healthy: %+v", o)
	}

	now = now.Add(5 * time.Minute)
	info.set(http.StatusOK, infoJSON("https://attacker.example/hook", 0, 0, ""))
	if o := m.Check(context.Background()); !slices.Equal(o.Problems, []string{ProblemURLChanged}) {
		t.Fatalf("url changed: %+v", o)
	}

	now = now.Add(5 * time.Minute)
	info.set(http.StatusOK, infoJSON(monitorURL, 40, now.Add(-time.Minute).Unix(), "Wrong response from the webhook: 502 Bad Gateway"))
	if o := m.Check(context.Background()); !slices.Equal(o.Problems, []string{ProblemLastErrorRecent}) {
		t.Fatalf("delivery error: %+v", o)
	}

	now = now.Add(5 * time.Minute)
	info.set(http.StatusOK, infoJSON(monitorURL, 40, now.Add(-time.Minute).Unix(), "Wrong response from the webhook: 401 Unauthorized"))
	if o := m.Check(context.Background()); !slices.Equal(o.Problems, []string{ProblemLastErrorRecent, ProblemSecretRejected}) {
		t.Fatalf("secret rejected: %+v", o)
	}

	for _, bad := range []struct {
		status int
		body   string
	}{{http.StatusInternalServerError, `{"ok":false}`}, {http.StatusOK, `{"ok":true}`}, {http.StatusOK, `not json`}} {
		now = now.Add(5 * time.Minute)
		info.set(bad.status, bad.body)
		o := m.Check(context.Background())
		if o.Readable || len(o.Problems) != 0 || g.last().Readable {
			t.Fatalf("unreadable %d %q exported as readable: %+v", bad.status, bad.body, o)
		}
	}
	// The 401 seen at the last readable check (21 minutes back now), still
	// the latest error, is not new; one during the unreadable checks is.
	now = now.Add(5 * time.Minute)
	info.set(http.StatusOK, infoJSON(monitorURL, 0, now.Add(-21*time.Minute).Unix(), "Wrong response from the webhook: 401 Unauthorized"))
	if o := m.Check(context.Background()); len(o.Problems) != 0 {
		t.Fatalf("old error re-reported: %+v", o)
	}
	now = now.Add(5 * time.Minute)
	info.set(http.StatusOK, infoJSON(monitorURL, 0, now.Add(-4*time.Minute).Unix(), "Wrong response from the webhook: 401 Unauthorized"))
	if o := m.Check(context.Background()); !slices.Contains(o.Problems, ProblemSecretRejected) {
		t.Fatalf("new 401 missed: %+v", o)
	}
}

// TestWebhookMonitor_UnreadableThroughRegistry runs the monitor into the
// real metrics registry: unreadable is up 0, ok 0, never healthy.
func TestWebhookMonitor_UnreadableThroughRegistry(t *testing.T) {
	info, srv := newSwitchableInfo(t)
	reg := metrics.New()
	reg.StartPAWebhookMonitor()
	m, err := NewWebhookMonitor(WebhookMonitorConfig{HTTP: srv.Client(), BaseURL: srv.URL, Token: fakeToken, ExpectedURL: monitorURL, Gauges: reg})
	if err != nil {
		t.Fatal(err)
	}
	info.set(http.StatusOK, infoJSON(monitorURL, 0, 0, ""))
	m.Check(context.Background())
	info.set(http.StatusBadGateway, `bad gateway`)
	m.Check(context.Background())
	mfs, err := reg.Prometheus.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "mctl_pa_webhook_info_") && len(mf.GetMetric()) == 1 && mf.GetMetric()[0].GetGauge() != nil {
			got[mf.GetName()] = mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	if got["mctl_pa_webhook_info_up"] != 0 || got["mctl_pa_webhook_info_ok"] != 0 {
		t.Fatalf("unreadable exported as %v", got)
	}
}

func TestNewWebhookMonitor_RequiresEverything(t *testing.T) {
	g := &gaugeRecorder{}
	for _, cfg := range []WebhookMonitorConfig{
		{ExpectedURL: monitorURL, Gauges: g},
		{Token: fakeToken, Gauges: g},
		{Token: fakeToken, ExpectedURL: monitorURL},
	} {
		if _, err := NewWebhookMonitor(cfg); err == nil {
			t.Fatalf("%+v accepted", cfg)
		}
	}
}

// TestPAMetricLabels: the label sets the metrics registry pre-creates are
// exactly the outcomes and problems this package can report. The webhook
// and ingress outcomes are read from the source, so a new constant
// without a metric label fails here.
func TestPAMetricLabels(t *testing.T) {
	sorted := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }
	if !slices.Equal(sorted(WebhookProblems()), sorted(metrics.PAWebhookProblems)) {
		t.Fatalf("problems %v vs metrics %v", WebhookProblems(), metrics.PAWebhookProblems)
	}
	outbox := []string{OutboxOutcomeSent, OutboxOutcomeRetry, OutboxOutcomeFailed, OutboxOutcomeDropped,
		OutboxOutcomeUnknown, OutboxOutcomeStale, OutboxOutcomeClaimError}
	if !slices.Equal(sorted(outbox), sorted(metrics.PAOutboxOutcomes)) {
		t.Fatalf("outbox outcomes %v vs metrics %v", outbox, metrics.PAOutboxOutcomes)
	}
	var updates []string
	fset := token.NewFileSet()
	for _, file := range []string{"ingress.go", "webhook.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if (strings.HasPrefix(n.Name, "Outcome") || strings.HasPrefix(n.Name, "Drop")) && i < len(vs.Values) {
						if lit, ok := vs.Values[i].(*ast.BasicLit); ok {
							s, _ := strconv.Unquote(lit.Value)
							updates = append(updates, s)
						}
					}
				}
			}
		}
	}
	if !slices.Equal(sorted(updates), sorted(metrics.PAUpdateOutcomes)) {
		t.Fatalf("update outcomes %v vs metrics %v", sorted(updates), sorted(metrics.PAUpdateOutcomes))
	}
}

// TestSetWebhook registers url, secret_token and exactly AllowedUpdates.
func TestSetWebhook(t *testing.T) {
	const secret = "pa_webhook_secret_for_tests_only_0123456789"
	var got url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/bot"+fakeToken+"/setWebhook" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		got = r.PostForm
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	t.Cleanup(srv.Close)
	if err := SetWebhook(context.Background(), srv.Client(), srv.URL, fakeToken, SetWebhookRequest{URL: monitorURL, Secret: secret}); err != nil {
		t.Fatal(err)
	}
	if got.Get("url") != monitorURL || got.Get("secret_token") != secret || got.Get("allowed_updates") != `["message","callback_query"]` {
		t.Fatalf("form = %v", got)
	}
}

func TestSetWebhook_Refusals(t *testing.T) {
	const secret = "pa_webhook_secret_for_tests_only_0123456789"
	// Local refusals go to a server that would accept anything: each must
	// be refused before any request is made.
	var hits atomic.Int32
	accepting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"ok":true,"result":true}`))
	}))
	t.Cleanup(accepting.Close)
	for _, tc := range []struct {
		name string
		req  SetWebhookRequest
	}{
		{"http url", SetWebhookRequest{URL: "http://pa.example/pa/bot/webhook", Secret: secret}},
		{"query", SetWebhookRequest{URL: monitorURL + "?a=1", Secret: secret}},
		{"userinfo", SetWebhookRequest{URL: "https://u:p@pa.example/pa/bot/webhook", Secret: secret}},
		{"other path", SetWebhookRequest{URL: "https://pa.example/hook", Secret: secret}},
		{"short secret", SetWebhookRequest{URL: monitorURL, Secret: "short"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			err := SetWebhook(context.Background(), accepting.Client(), accepting.URL, fakeToken, tc.req)
			if err == nil || hits.Load() != 0 {
				t.Fatalf("err = %v, requests sent %d", err, hits.Load())
			}
			if strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), secret) {
				t.Fatalf("error leaks a credential: %v", err)
			}
		})
	}
	t.Run("valid request reaches the accepting server", func(t *testing.T) {
		hits.Store(0)
		if err := SetWebhook(context.Background(), accepting.Client(), accepting.URL, fakeToken, SetWebhookRequest{URL: monitorURL, Secret: secret}); err != nil || hits.Load() != 1 {
			t.Fatalf("err = %v, requests %d", err, hits.Load())
		}
	})
	t.Run("refused by telegram", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
		}))
		defer srv.Close()
		err := SetWebhook(context.Background(), srv.Client(), srv.URL, fakeToken, SetWebhookRequest{URL: monitorURL, Secret: secret})
		if err == nil || strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), secret) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("transport error does not leak", func(t *testing.T) {
		err := SetWebhook(context.Background(), nil, "http://127.0.0.1:1", fakeToken, SetWebhookRequest{URL: monitorURL, Secret: secret})
		if err == nil || strings.Contains(err.Error(), fakeToken) || strings.Contains(err.Error(), secret) {
			t.Fatalf("err = %v", err)
		}
	})
}

// TestSetWebhookNotCalledByServer: registering the webhook is an operator
// action (#1318). No non-test code outside internal/pa calls SetWebhook,
// and inside internal/pa only its own file names it.
func TestSetWebhookNotCalledByServer(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var calls []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules", ".worktrees":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if filepath.ToSlash(path) == "../../internal/pa/setwebhook.go" {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		// Comments may name setWebhook; code may not: no identifier
		// SetWebhook and no string that builds the method's URL.
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if x.Name == "SetWebhook" {
					calls = append(calls, fset.Position(x.Pos()).String())
				}
			case *ast.BasicLit:
				if x.Kind == token.STRING && strings.Contains(strings.ToLower(x.Value), "setwebhook") {
					calls = append(calls, fset.Position(x.Pos()).String())
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 0 {
		t.Fatalf("setWebhook referenced outside its helper: %v", calls)
	}
}
