package facade_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/config"
	"github.com/mctlhq/mctl-telegram/internal/glovo/contract"
	"github.com/mctlhq/mctl-telegram/internal/glovo/facade"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi/fakeapi"
)

const (
	issuer   = "https://api.mctl.test"
	resource = "https://glovo.mctl.ai/mcp"
	cred     = "workload-credential-for-tests"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rig struct {
	t       *testing.T
	fake    *fakeapi.Fake
	apiSrv  *httptest.Server
	ver     *authn.Verifier
	f       *facade.Facade
	srv     *httptest.Server
	logs    *syncBuf
	c       *contract.Contract
	cfg     config.Config
	api     *mctlapi.HTTPClient
	tokens  []string
	enabled bool
}

type rigOpt func(*config.Config)

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	c, err := contract.Load()
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, c: c, logs: &syncBuf{}}
	r.fake = fakeapi.New(fakeapi.Options{Issuer: issuer, Resource: resource, Credential: cred})
	r.apiSrv = httptest.NewServer(r.fake.Handler())
	t.Cleanup(r.apiSrv.Close)
	r.cfg = config.Config{
		Enabled: true, Dev: true, Addr: ":0", PublicBaseURL: "https://glovo.mctl.ai", Resource: resource,
		Issuer: issuer, JWKSURL: r.apiSrv.URL + "/.well-known/jwks.json", AuthorizationServer: issuer,
		APIBaseURL: r.apiSrv.URL, RatePerMin: 30, Burst: 10, MaxInflight: 64, MetricsAllowCIDR: "127.0.0.1/32",
	}
	for _, o := range opts {
		o(&r.cfg)
	}
	r.ver = authn.New(authn.Config{Issuer: issuer, Resource: resource, JWKSURL: r.cfg.JWKSURL, GlovoScopes: c.Scopes})
	r.api = mctlapi.NewHTTPClient(r.apiSrv.URL, func() (string, error) { return cred, nil }, nil)
	r.build()
	return r
}

func (r *rig) build() {
	log := slog.New(audit.NewRedactingHandler(slog.NewJSONHandler(r.logs, nil)))
	f, err := facade.New(facade.Options{Config: r.cfg, Contract: r.c, Verifier: r.ver, API: r.api, Logger: log, Version: "test"})
	if err != nil {
		r.t.Fatal(err)
	}
	r.api.OnCall = f.ObserveUpstream
	r.f = f
	r.srv = httptest.NewServer(f.Handler())
	r.t.Cleanup(r.srv.Close)
}

func (r *rig) token(sub, tenant string) string {
	tok := r.fake.Mint(fakeapi.MintOpts{Sub: sub, Tenant: tenant})
	r.tokens = append(r.tokens, tok)
	return tok
}

func (r *rig) tokenScoped(sub, tenant, scope string) string {
	tok := r.fake.Mint(fakeapi.MintOpts{Sub: sub, Tenant: tenant, Scope: scope})
	r.tokens = append(r.tokens, tok)
	return tok
}

// post sends a raw JSON-RPC body and returns the status and decoded message.
func (r *rig) post(token string, body string, hdr map[string]string) (int, map[string]any) {
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			if d, ok := strings.CutPrefix(sc.Text(), "data: "); ok {
				raw = []byte(d)
			}
		}
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return resp.StatusCode, m
}

func (r *rig) rpc(token, method string, params string) (int, map[string]any) {
	if params == "" {
		params = "{}"
	}
	return r.post(token, fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, params), nil)
}

// call invokes a tool with raw argument JSON. It returns the structured
// result and whether the result was an error.
func (r *rig) call(token, tool, args string) (map[string]any, bool) {
	r.t.Helper()
	status, m := r.rpc(token, "tools/call", fmt.Sprintf(`{"name":%q,"arguments":%s}`, tool, args))
	if status != 200 {
		r.t.Fatalf("%s: HTTP %d", tool, status)
	}
	res, _ := m["result"].(map[string]any)
	if res == nil {
		return map[string]any{"jsonrpc_error": m["error"]}, true
	}
	sc, _ := res["structuredContent"].(map[string]any)
	isErr, _ := res["isError"].(bool)
	return sc, isErr
}

func (r *rig) refusal(token, tool, args string) string {
	r.t.Helper()
	sc, isErr := r.call(token, tool, args)
	if !isErr {
		r.t.Fatalf("%s: expected refusal, got %v", tool, sc)
	}
	s, _ := sc["error"].(string)
	return s
}

func (r *rig) ok(token, tool, args string) map[string]any {
	r.t.Helper()
	sc, isErr := r.call(token, tool, args)
	if isErr {
		r.t.Fatalf("%s: unexpected refusal %v", tool, sc)
	}
	return sc
}

func (r *rig) get(path string) (int, string) {
	resp, err := http.Get(r.srv.URL + path)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
