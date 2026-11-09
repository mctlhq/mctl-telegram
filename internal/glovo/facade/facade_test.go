package facade_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/glovo/config"
	"github.com/mctlhq/mctl-telegram/internal/glovo/facade"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi/fakeapi"
)

func canon(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v) // map keys are sorted
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func canonRaw(t *testing.T, raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return canon(t, v)
}

func TestToolsListEqualsContract(t *testing.T) {
	r := newRig(t)
	tok := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	status, m := r.rpc(tok, "tools/list", "")
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	listed := m["result"].(map[string]any)["tools"].([]any)
	if len(listed) != 7 {
		t.Fatalf("listed %d tools", len(listed))
	}
	for _, x := range listed {
		tool := x.(map[string]any)
		ct := r.c.Tool(tool["name"].(string))
		if ct == nil {
			t.Fatalf("tool %v not in contract", tool["name"])
		}
		if canon(t, tool["inputSchema"]) != canonRaw(t, ct.InputRaw) {
			t.Errorf("%s: input schema differs from contract", ct.Name)
		}
		if canon(t, tool["outputSchema"]) != canonRaw(t, ct.OutputRaw) {
			t.Errorf("%s: output schema differs from contract", ct.Name)
		}
	}
	for _, method := range []string{"resources/list", "prompts/list", "resources/read", "prompts/get", "sampling/createMessage", "completion/complete"} {
		if _, m := r.rpc(tok, method, ""); m["result"] != nil && method != "completion/complete" {
			t.Errorf("%s answered with a result: %v", method, m["result"])
		}
	}
	if len(r.fake.Calls()) != 0 {
		t.Fatal("tools/list contacted mctl-api")
	}
}

func TestInitializePinned(t *testing.T) {
	r := newRig(t)
	tok := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	for _, asked := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "1999-01-01"} {
		status, m := r.rpc(tok, "initialize", fmt.Sprintf(`{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":"t","version":"1"}}`, asked))
		if status != 200 {
			t.Fatalf("%s: status %d", asked, status)
		}
		res := m["result"].(map[string]any)
		if n := res["serverInfo"].(map[string]any)["name"]; n != "mctl-glovo-mcp" {
			t.Errorf("server name %v", n)
		}
		if v := res["serverInfo"].(map[string]any)["version"]; v != "test" {
			t.Errorf("server version %v", v)
		}
		pv := res["protocolVersion"].(string)
		ok := false
		for _, s := range facade.SupportedProtocolVersions {
			ok = ok || s == pv
		}
		if !ok {
			t.Errorf("asked %s: negotiated %s outside the pinned list", asked, pv)
		}
		caps := res["capabilities"].(map[string]any)
		if caps["resources"] != nil || caps["prompts"] != nil {
			t.Errorf("capabilities advertise more than tools: %v", caps)
		}
	}
	status, _ := r.post(tok, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{"MCP-Protocol-Version": "2026-07-28"})
	if status != 400 {
		t.Errorf("unsupported protocol header: %d", status)
	}
	status, _ = r.rpc(tok, "server/discover", "")
	if status != 400 {
		t.Errorf("server/discover: %d", status)
	}
}

func TestDiscoveryAndUnauthenticated(t *testing.T) {
	r := newRig(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		code, body := r.get(p)
		var m map[string]any
		_ = json.Unmarshal([]byte(body), &m)
		if code != 200 || m["resource"] != resource || canon(t, m["scopes_supported"]) != `["glovo:read","glovo:basket:prepare"]` ||
			canon(t, m["bearer_methods_supported"]) != `["header"]` || canon(t, m["authorization_servers"]) != `["`+issuer+`"]` {
			t.Errorf("%s: %d %s", p, code, body)
		}
	}
	resp, err := http.Post(r.srv.URL+"/mcp", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="https://glovo.mctl.ai/.well-known/oauth-protected-resource/mcp"` {
		t.Fatalf("%d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	if len(r.fake.Calls()) != 0 {
		t.Fatal("unauthenticated request contacted mctl-api")
	}
	for _, p := range []string{"/", "/mcp/x", "/tg", "/.well-known/oauth-authorization-server", "/api/v1/anything"} {
		if code, _ := r.get(p); code != 404 {
			t.Errorf("%s: %d, want 404", p, code)
		}
	}
}

func TestScopeEnforcement(t *testing.T) {
	r := newRig(t)
	ro := r.tokenScoped(fakeapi.Alice, fakeapi.TeamAlpha, "glovo:read")
	if got := r.refusal(ro, "glovo_connect_account", `{"idempotency_key":"k"}`); got != "not_authorized" {
		t.Fatal(got)
	}
	if got := r.refusal(ro, "glovo_prepare_order", `{"preview_id":"x","idempotency_key":"k"}`); got != "not_authorized" {
		t.Fatal(got)
	}
	if len(r.fake.Calls()) != 0 {
		t.Fatal("scope refusal contacted mctl-api")
	}
	r.ok(ro, "glovo_get_basket", `{}`)
}

func TestCrossTenantAndOwner(t *testing.T) {
	r := newRig(t)
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	bob := r.token(fakeapi.Bob, fakeapi.TeamAlpha)
	carol := r.token(fakeapi.Carol, fakeapi.TeamBeta)

	pv := r.ok(alice, "glovo_preview_reorder", `{"order_ref":"ref_alice_1"}`)
	prep := r.ok(alice, "glovo_prepare_order", fmt.Sprintf(`{"preview_id":%q,"idempotency_key":"k1"}`, pv["preview_id"]))
	orderID := prep["order_id"].(string)
	r.fake.ResetCalls()

	for name, who := range map[string]string{"carol": carol, "bob": bob} {
		attempts := map[string][2]string{
			"order_status": {"glovo_order_status", fmt.Sprintf(`{"order_id":%q}`, orderID)},
			"order_ref":    {"glovo_preview_reorder", `{"order_ref":"ref_alice_1"}`},
			"preview_id":   {"glovo_prepare_order", fmt.Sprintf(`{"preview_id":%q,"idempotency_key":"z"}`, pv["preview_id"])},
		}
		for k, a := range attempts {
			if got := r.refusal(who, a[0], a[1]); got != "not_found" {
				t.Errorf("%s/%s: %q, want not_found", name, k, got)
			}
		}
		// A random id gets the identical result.
		if got := r.refusal(who, "glovo_order_status", `{"order_id":"ord_0000000000000000"}`); got != "not_found" {
			t.Errorf("%s random id: %q", name, got)
		}
	}
	if eff := r.fake.EffectCalls(); len(eff) != 0 {
		t.Fatalf("foreign ids caused effects: %v", eff)
	}

	// Same tenant, other user: distinct connections, isolated views.
	a := r.ok(alice, "glovo_connect_account", `{"idempotency_key":"c1"}`)
	b := r.ok(bob, "glovo_connect_account", `{"idempotency_key":"c1"}`)
	if a["connection_id"] == b["connection_id"] || !strings.HasPrefix(a["connection_id"].(string), "gcn_") {
		t.Fatalf("connections not distinct: %v %v", a["connection_id"], b["connection_id"])
	}
	if st := r.ok(bob, "glovo_auth_status", `{}`); st["connection_id"] != b["connection_id"] {
		t.Fatalf("bob sees %v", st)
	}
	if hist := r.ok(bob, "glovo_get_order_history", `{}`); strings.Contains(canon(t, hist), "alice") {
		t.Fatal("bob sees alice's history")
	}
}

func TestTenantResolution(t *testing.T) {
	r := newRig(t)
	r.fake.SetAmbiguous(fakeapi.Bob)
	cases := []struct{ sub, tenant, want string }{
		{fakeapi.Alice, "", "no_tenant"},
		{fakeapi.Bob, fakeapi.TeamAlpha, "ambiguous_tenant"},
		{fakeapi.Alice, "personal:alice", "scope_unsupported"},
		{fakeapi.Dana, fakeapi.TeamAlpha, "not_in_pilot"},
		{fakeapi.Carol, fakeapi.TeamAlpha, "not_authorized"},
		{fakeapi.Alice, "labs", "not_authorized"},
		{fakeapi.Alice, "mctl", "not_authorized"},
	}
	for _, c := range cases {
		r.fake.ResetCalls()
		if got := r.refusal(r.token(c.sub, c.tenant), "glovo_get_basket", `{}`); got != c.want {
			t.Errorf("%s/%q: %q want %s", c.sub, c.tenant, got, c.want)
		}
		if calls := r.fake.Calls(); len(calls) != 1 || calls[0].Path != "/resolve" {
			t.Errorf("%s/%q: calls %v, want only resolve", c.sub, c.tenant, calls)
		}
	}
	// Membership revoked between two calls.
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	r.ok(alice, "glovo_get_basket", `{}`)
	r.fake.SetMember(fakeapi.TeamAlpha, fakeapi.Alice, false)
	if got := r.refusal(alice, "glovo_get_basket", `{}`); got != "not_authorized" {
		t.Fatalf("after revoke: %q", got)
	}
}

func TestConfusedDeputyArguments(t *testing.T) {
	r := newRig(t)
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	bad := []struct{ tool, args string }{
		{"glovo_get_basket", `{"tenant":"team-beta"}`},
		{"glovo_get_basket", `{"tenant_id":"team-beta"}`},
		{"glovo_auth_status", `{"principal_id":"usr_bob"}`},
		{"glovo_auth_status", `{"owner_id":"usr_bob"}`},
		{"glovo_connect_account", `{"idempotency_key":"k","url":"https://evil.test"}`},
		{"glovo_connect_account", `{"idempotency_key":"k","extra":1}`},
		{"glovo_connect_account", `{"idempotency_key":"k","idempotency_key":"j"}`},
		{"glovo_connect_account", `{"idempotency_key":"` + strings.Repeat("a", 129) + `"}`},
		{"glovo_connect_account", `{}`},
		{"glovo_get_order_history", `{"limit":0}`},
		{"glovo_get_order_history", `{"limit":21}`},
		{"glovo_get_order_history", `{"limit":"5"}`},
		{"glovo_order_status", `{"order_id":5}`},
		{"glovo_order_status", `{"order_id":"a","hir_id":"hir_1"}`},
	}
	for _, b := range bad {
		if got := r.refusal(alice, b.tool, b.args); got != "invalid_arguments" {
			t.Errorf("%s %s: %q", b.tool, b.args, got)
		}
	}
	if n := len(r.fake.Calls()); n != 0 {
		t.Fatalf("invalid arguments reached mctl-api (%d calls)", n)
	}
}

func TestApprovalFlowAndReadOnly(t *testing.T) {
	r := newRig(t, func(c *config.Config) { c.Burst = 100 })
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)

	before := canon(t, r.ok(alice, "glovo_get_basket", `{}`))
	pv := r.ok(alice, "glovo_preview_reorder", `{"order_ref":"ref_alice_1"}`)
	args := fmt.Sprintf(`{"preview_id":%q,"idempotency_key":"k1"}`, pv["preview_id"])
	p1 := r.ok(alice, "glovo_prepare_order", args)
	p2 := r.ok(alice, "glovo_prepare_order", args)
	if p1["order_id"] != p2["order_id"] || p1["consent_request_id"] != p2["consent_request_id"] {
		t.Fatal("idempotency key replay produced a different order")
	}
	if !strings.HasPrefix(p1["consent_request_id"].(string), "aar_") {
		t.Fatalf("consent id %v", p1["consent_request_id"])
	}
	st := r.ok(alice, "glovo_order_status", fmt.Sprintf(`{"order_id":%q}`, p1["order_id"]))
	if st["state"] != "awaiting_consent" || st["outcome"] != "OUTCOME_UNKNOWN" {
		t.Fatalf("status %v", st)
	}
	if after := canon(t, r.ok(alice, "glovo_get_basket", `{}`)); after != before || r.fake.BasketWrites != 0 {
		t.Fatal("prepare changed the basket")
	}

	// A hir_ record never changes order state; only the separate human
	// endpoint approves, and nothing reachable through /mcp does.
	req, _ := http.NewRequest(http.MethodPost, r.apiSrv.URL+"/_fake/hir/"+p1["order_id"].(string), nil)
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
	}
	if st := r.ok(alice, "glovo_order_status", fmt.Sprintf(`{"order_id":%q}`, p1["order_id"])); st["state"] != "awaiting_consent" {
		t.Fatalf("hir_ changed state: %v", st)
	}
	for _, name := range []string{"glovo_approve_order", "glovo_place_order", "glovo_confirm_basket"} {
		if _, m := r.rpc(alice, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":{}}`, name)); m["error"] == nil {
			t.Errorf("%s: unknown tool was not refused", name)
		}
	}
	if !r.fake.Approve(p1["consent_request_id"].(string)) {
		t.Fatal("harness approval failed")
	}
	if st := r.ok(alice, "glovo_order_status", fmt.Sprintf(`{"order_id":%q}`, p1["order_id"])); st["state"] != "approved" {
		t.Fatalf("after human approval: %v", st)
	}

	// Read tools call no effect endpoint.
	r.fake.ResetCalls()
	for _, c := range [][2]string{{"glovo_auth_status", `{}`}, {"glovo_get_order_history", `{"limit":5}`},
		{"glovo_preview_reorder", `{"order_ref":"ref_alice_2"}`}, {"glovo_get_basket", `{}`},
		{"glovo_order_status", fmt.Sprintf(`{"order_id":%q}`, p1["order_id"])}} {
		r.ok(alice, c[0], c[1])
	}
	if eff := r.fake.EffectCalls(); len(eff) != 0 {
		t.Fatalf("read tools had effects: %v", eff)
	}
	for _, c := range r.fake.Calls() {
		if c.Path == "/connections" || c.Path == "/orders:prepare" {
			t.Fatalf("read tool called write endpoint %s", c.Path)
		}
	}
}

func TestUpstreamFailures(t *testing.T) {
	r := newRig(t)
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	cases := []struct {
		name string
		o    fakeapi.Override
		want string
	}{
		{"schema violation", fakeapi.Override{Status: 200, Body: `{"items":"x","totals_label":"a","fingerprint":"f"}`}, "upstream_invalid"},
		{"extra field", fakeapi.Override{Status: 200, Body: `{"items":[],"totals_label":"a","fingerprint":"f","debug":"secret-detail"}`}, "upstream_invalid"},
		{"not json", fakeapi.Override{Status: 200, Body: `<html>secret-detail</html>`}, "upstream_invalid"},
		{"oversize", fakeapi.Override{Status: 200, Body: strings.Repeat("x", 300<<10)}, "upstream_invalid"},
		{"500", fakeapi.Override{Status: 500, Body: "secret-detail"}, "upstream_unavailable"},
		{"unknown error code", fakeapi.Override{Status: 403, Body: `{"error":"secret-detail"}`}, "upstream_invalid"},
	}
	for _, c := range cases {
		r.fake.SetOverride("/basket", c.o)
		sc, isErr := r.call(alice, "glovo_get_basket", `{}`)
		if !isErr || sc["error"] != c.want {
			t.Errorf("%s: %v want %s", c.name, sc, c.want)
		}
		if strings.Contains(canon(t, sc), "secret-detail") {
			t.Errorf("%s: upstream text leaked", c.name)
		}
	}
	// Timeout.
	r2 := newRig(t)
	r2.api = mctlapi.NewHTTPClient(r2.apiSrv.URL, func() (string, error) { return cred, nil }, &http.Client{Timeout: 150 * time.Millisecond})
	r2.build()
	r2.fake.SetOverride("/basket", fakeapi.Override{Delay: time.Second})
	if got := r2.refusal(r2.token(fakeapi.Alice, fakeapi.TeamAlpha), "glovo_get_basket", `{}`); got != "upstream_unavailable" {
		t.Fatalf("timeout: %q", got)
	}
}

func TestLimits(t *testing.T) {
	r := newRig(t)
	alice, bob := r.token(fakeapi.Alice, fakeapi.TeamAlpha), r.token(fakeapi.Bob, fakeapi.TeamAlpha)
	for i := 0; i < 10; i++ {
		r.ok(alice, "glovo_auth_status", `{}`)
	}
	if got := r.refusal(alice, "glovo_auth_status", `{}`); got != "rate_limited" {
		t.Fatalf("11th call: %q", got)
	}
	r.ok(bob, "glovo_auth_status", `{}`)

	// Body cap.
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("a", facade.MaxRequestBytes) + `"}}`
	if status, _ := r.post(bob, big, nil); status != 413 {
		t.Fatalf("oversize body: %d", status)
	}

	// Global concurrency cap.
	r2 := newRig(t, func(c *config.Config) { c.MaxInflight = 2 })
	r2.fake.SetOverride("/resolve", fakeapi.Override{Delay: 400 * time.Millisecond})
	tok := r2.token(fakeapi.Carol, fakeapi.TeamBeta)
	var wg sync.WaitGroup
	codes := make(chan int, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, _ := r2.rpc(tok, "tools/call", `{"name":"glovo_get_basket","arguments":{}}`)
			codes <- s
		}()
	}
	wg.Wait()
	close(codes)
	n429 := 0
	for c := range codes {
		if c == 429 {
			n429++
		}
	}
	if n429 == 0 {
		t.Fatal("no request was refused by the concurrency cap")
	}
}

func TestHealthAndDisabled(t *testing.T) {
	r := newRig(t)
	if code, _ := r.get("/healthz"); code != 200 {
		t.Fatalf("healthz %d", code)
	}
	if code, _ := r.get("/readyz"); code != 503 {
		t.Fatalf("readyz before JWKS load: %d", code)
	}
	if err := r.ver.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if code, _ := r.get("/readyz"); code != 200 {
		t.Fatalf("readyz ready: %d", code)
	}
	r.fake.SetHealthy(false)
	if code, _ := r.get("/readyz"); code != 503 {
		t.Fatalf("readyz with mctl-api down: %d", code)
	}
	r.fake.SetHealthy(true)
	r.f.SetDraining()
	if code, _ := r.get("/readyz"); code != 503 {
		t.Fatalf("readyz draining: %d", code)
	}

	d := newRig(t, func(c *config.Config) { c.Enabled = false })
	for _, tok := range []string{"", d.fake.Mint(fakeapi.MintOpts{Sub: fakeapi.Alice, Tenant: fakeapi.TeamAlpha})} {
		if status, _ := d.post(tok, `{}`, nil); status != 503 {
			t.Errorf("disabled /mcp: %d", status)
		}
	}
	if code, _ := d.get("/readyz"); code != 503 {
		t.Errorf("disabled readyz: %d", code)
	}
	if code, _ := d.get("/healthz"); code != 200 {
		t.Errorf("disabled healthz: %d", code)
	}
	if len(d.fake.Calls()) != 0 {
		t.Fatal("disabled facade contacted mctl-api")
	}
}

func TestDrainOnShutdown(t *testing.T) {
	r := newRig(t)
	r.fake.SetOverride("/basket", fakeapi.Override{Delay: 400 * time.Millisecond})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.f.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- facade.Serve(ctx, srv, ln, r.f, 5*time.Second) }()

	tok := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	res := make(chan int, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/mcp",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"glovo_get_basket","arguments":{}}}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			res <- -1
			return
		}
		resp.Body.Close()
		res <- resp.StatusCode
	}()
	time.Sleep(150 * time.Millisecond) // the call is in flight
	cancel()
	if code := <-res; code != 200 {
		t.Fatalf("in-flight call during drain: %d", code)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if code, _ := r.get("/readyz"); code != 503 {
		t.Fatalf("readyz after drain: %d", code)
	}
}

func TestMetricsAuditAndNoLeak(t *testing.T) {
	r := newRig(t)
	alice := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	conn := r.ok(alice, "glovo_connect_account", `{"idempotency_key":"k"}`)
	r.ok(alice, "glovo_get_basket", `{}`)
	r.refusal(alice, "glovo_get_order_history", `{"limit":0}`)
	http.Post(r.srv.URL+"/mcp?access_token=abc", "application/json", strings.NewReader(`{}`)) //nolint:errcheck
	if err := r.ver.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.get("/readyz")

	code, metrics := r.get("/metrics")
	if code != 200 {
		t.Fatalf("metrics %d", code)
	}
	for _, want := range []string{
		`glovo_mcp_http_requests_total{code="200",route="mcp"}`,
		`glovo_mcp_tool_calls_total{outcome="ok",tool="glovo_get_basket"}`,
		`glovo_mcp_tool_calls_total{outcome="invalid_arguments",tool="glovo_get_order_history"}`,
		`glovo_mcp_tool_duration_seconds_count{tool="glovo_get_basket"}`,
		`glovo_mcp_authn_failures_total{reason="query_token"}`,
		`glovo_mcp_upstream_requests_total{code="200",op="resolve"}`,
		`glovo_mcp_ratelimited_total`,
	} {
		if !strings.Contains(metrics, want) {
			t.Errorf("metrics lack %s", want)
		}
	}
	logs := r.logs.String()
	if n := strings.Count(logs, `"msg":"glovo tool call"`); n != 3 {
		t.Errorf("audit records = %d, want 3", n)
	}
	for _, field := range []string{`"tool"`, `"outcome"`, `"latency_ms"`, `"principal_hash"`, `"tenant_hash"`, `"request_id"`} {
		if !strings.Contains(logs, field) {
			t.Errorf("audit lacks %s", field)
		}
	}
	secrets := append([]string{cred, conn["handoff_url"].(string), "gsc_", "/handoff/", fakeapi.Alice, fakeapi.TeamAlpha, "?"}, r.tokens...)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(logs, s) || strings.Contains(metrics, s) {
			t.Errorf("logs or metrics contain %q", s[:min(len(s), 12)])
		}
	}
	// A metrics scrape from outside the allowed CIDR is refused.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.RemoteAddr = "10.1.2.3:4444"
	r.f.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("metrics from outside CIDR: %d", rec.Code)
	}
}

func TestNoTelegramSurface(t *testing.T) {
	r := newRig(t)
	tok := r.token(fakeapi.Alice, fakeapi.TeamAlpha)
	_, m := r.rpc(tok, "tools/list", "")
	for _, x := range m["result"].(map[string]any)["tools"].([]any) {
		if n := x.(map[string]any)["name"].(string); !strings.HasPrefix(n, "glovo_") {
			t.Errorf("non-glovo tool %s", n)
		}
	}
	if _, err := os.Stat("../../../docs/tool-descriptors.json"); err != nil {
		t.Fatal(err)
	}
}

func TestHostGuardNormalizesDefaultPort(t *testing.T) {
	// An authenticated public client must not be blocked just because a proxy
	// preserves the explicit HTTPS port. Foreign or ambiguous Host authorities
	// must be rejected before any authentication or mctl-api work.
	for _, dev := range []bool{false, true} {
		mode := "production"
		if dev {
			mode = "development"
		}
		t.Run(mode, func(t *testing.T) {
			r := newRig(t, func(c *config.Config) { c.Dev = dev })
			cases := []struct {
				name, host string
				want       int
			}{
				{"public", "glovo.mctl.ai", http.StatusUnauthorized},
				{"public_default_port", "glovo.mctl.ai:443", http.StatusUnauthorized},
				{"public_case", "GLOVO.MCTL.AI:443", http.StatusUnauthorized},
				{"foreign", "evil.example", http.StatusForbidden},
				{"foreign_suffix", "glovo.mctl.ai.evil.example", http.StatusForbidden},
				{"wrong_port", "glovo.mctl.ai:8443", http.StatusForbidden},
				{"http_port", "glovo.mctl.ai:80", http.StatusForbidden},
				{"non_numeric_port", "glovo.mctl.ai:bad", http.StatusForbidden},
				{"zero_port", "glovo.mctl.ai:0", http.StatusForbidden},
				{"empty_port", "glovo.mctl.ai:", http.StatusForbidden},
				{"userinfo", "glovo.mctl.ai@evil.example", http.StatusForbidden},
				{"path_in_host", "glovo.mctl.ai/mcp", http.StatusForbidden},
				{"loopback_hostname", "localhost:8080", http.StatusForbidden},
				{"loopback_ipv4", "127.0.0.1:8080", http.StatusForbidden},
				{"loopback_ipv6", "[::1]:8080", http.StatusForbidden},
				{"unbracketed_ipv6", "::1", http.StatusForbidden},
			}
			if dev {
				for i := range cases {
					if strings.HasPrefix(cases[i].name, "loopback_") {
						cases[i].want = http.StatusUnauthorized
					}
				}
			}
			for _, tc := range cases {
				for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
					t.Run(tc.name+"/"+method, func(t *testing.T) {
						req := httptest.NewRequest(method, "https://glovo.mctl.ai/mcp", nil)
						req.Host = tc.host
						rr := httptest.NewRecorder()
						r.f.Handler().ServeHTTP(rr, req)
						if rr.Code != tc.want {
							t.Fatalf("Host=%q %s: status=%d, want=%d (body=%q)", tc.host, method, rr.Code, tc.want, rr.Body.String())
						}
					})
				}
			}
			if len(r.fake.Calls()) != 0 {
				t.Fatalf("Host/authentication checks contacted mctl-api")
			}
		})
	}
}
