package mctlapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/trace"

	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi/fakeapi"
)

const (
	issuer   = "https://api.mctl.test"
	resource = "https://glovo.mctl.ai/mcp"
	cred     = "workload-credential-for-tests"
)

type seen struct {
	method, path, body string
	hdr                http.Header
}

type harness struct {
	fake *fakeapi.Fake
	srv  *httptest.Server
	cli  *mctlapi.HTTPClient
	mu   sync.Mutex
	reqs []seen
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{fake: fakeapi.New(fakeapi.Options{Issuer: issuer, Resource: resource, Credential: cred})}
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.reqs = append(h.reqs, seen{r.Method, strings.TrimPrefix(r.URL.Path, mctlapi.BasePath), string(b), r.Header.Clone()})
		h.mu.Unlock()
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		h.fake.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(h.srv.Close)
	h.cli = mctlapi.NewHTTPClient(h.srv.URL, func() (string, error) { return cred, nil }, nil)
	return h
}

func (h *harness) ctx(sub, tenant string) (context.Context, string) {
	tok := h.fake.Mint(fakeapi.MintOpts{Sub: sub, Tenant: tenant})
	p := &authn.Principal{Subject: sub, Tenant: tenant}
	ctx := authn.WithPrincipal(context.Background(), p, tok)
	return authn.WithRequestID(ctx, "req-1"), tok
}

func TestWireGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/wire.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		WireVersion string `json:"wire_version"`
		Operations  []struct {
			Op, Method, Path string
			Body             map[string]any
		} `json:"operations"`
	}
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.WireVersion != mctlapi.WireVersion {
		t.Fatalf("golden wire version %q", g.WireVersion)
	}
	h := newHarness(t)
	ctx, tok := h.ctx(fakeapi.Alice, fakeapi.TeamAlpha)
	sc, err := h.cli.Resolve(ctx)
	if err != nil || sc.Tenant != fakeapi.TeamAlpha || !strings.HasPrefix(sc.Ref, "gsc_") {
		t.Fatalf("resolve: %+v %v", sc, err)
	}
	vars := map[string]string{}
	for _, op := range g.Operations {
		body := map[string]any{}
		for k, v := range op.Body {
			if s, ok := v.(string); ok && strings.HasPrefix(s, "$") {
				v = vars[s[1:]]
			}
			body[k] = v
		}
		path := op.Path
		id := ""
		if i := strings.Index(path, "$order_id"); i >= 0 {
			id = vars["order_id"]
			path = strings.Replace(path, "$order_id", id, 1)
		}
		var in any
		if op.Method == http.MethodPost {
			in = body
		}
		before := len(h.reqs)
		out, err := h.cli.Do(ctx, sc, mctlapi.Op(op.Op), in, id)
		if err != nil {
			t.Fatalf("%s: %v", op.Op, err)
		}
		var m map[string]any
		if err := json.Unmarshal(out, &m); err != nil {
			t.Fatalf("%s: response not an object", op.Op)
		}
		for _, k := range []string{"preview_id", "order_id"} {
			if s, ok := m[k].(string); ok {
				vars[k] = s
			}
		}
		got := h.reqs[before]
		if got.method != op.Method || got.path != path {
			t.Errorf("%s: sent %s %s, want %s %s", op.Op, got.method, got.path, op.Method, path)
		}
		if strings.Contains(got.path, "?") {
			t.Errorf("%s: query string on the wire", op.Op)
		}
		if got.hdr.Get("Authorization") != "Bearer "+cred || got.hdr.Get(mctlapi.HeaderSubjectToken) != tok ||
			got.hdr.Get(mctlapi.HeaderScopeRef) != sc.Ref || got.hdr.Get(mctlapi.HeaderRequestID) != "req-1" ||
			got.hdr.Get(mctlapi.HeaderSelectedTenant) != fakeapi.TeamAlpha {
			t.Errorf("%s: header contract broken", op.Op)
		}
		if op.Method == http.MethodPost {
			var sent map[string]any
			_ = json.Unmarshal([]byte(got.body), &sent)
			if len(sent) != len(body) {
				t.Errorf("%s: body %s", op.Op, got.body)
			}
		}
	}
}

func TestRefusalMapping(t *testing.T) {
	cases := []struct {
		sub, tenant, want string
	}{
		{fakeapi.Alice, "", mctlapi.CodeNoTenant},
		{fakeapi.Alice, "personal:alice", mctlapi.CodeScopeUnsupported},
		{fakeapi.Dana, fakeapi.TeamAlpha, mctlapi.CodeNotInPilot},
		{fakeapi.Carol, fakeapi.TeamAlpha, mctlapi.CodeNotAuthorized},
	}
	for _, c := range cases {
		h := newHarness(t)
		ctx, _ := h.ctx(c.sub, c.tenant)
		_, err := h.cli.Resolve(ctx)
		var re *mctlapi.RefusalError
		if !asRefusal(err, &re) || re.Code != c.want {
			t.Errorf("%s/%s: got %v want %s", c.sub, c.tenant, err, c.want)
		}
	}
}

func asRefusal(err error, out **mctlapi.RefusalError) bool {
	re, ok := err.(*mctlapi.RefusalError)
	*out = re
	return ok
}

func TestUpstreamFailuresNeverLeakBody(t *testing.T) {
	h := newHarness(t)
	ctx, _ := h.ctx(fakeapi.Alice, fakeapi.TeamAlpha)
	sc, err := h.cli.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h.fake.SetOverride("/basket", fakeapi.Override{Status: 500, Body: "secret-upstream-detail"})
	_, err = h.cli.Do(ctx, sc, mctlapi.OpBasket, nil, "")
	if re, _ := err.(*mctlapi.RefusalError); re == nil || re.Code != mctlapi.CodeUpstreamUnavailable || strings.Contains(err.Error(), "secret") {
		t.Fatalf("500: %v", err)
	}
	h.fake.SetOverride("/basket", fakeapi.Override{Status: 403, Body: `{"error":"made_up_code"}`})
	_, err = h.cli.Do(ctx, sc, mctlapi.OpBasket, nil, "")
	if re, _ := err.(*mctlapi.RefusalError); re == nil || re.Code != mctlapi.CodeUpstreamInvalid {
		t.Fatalf("unknown code: %v", err)
	}
	h.fake.SetOverride("/basket", fakeapi.Override{Status: 200, Body: strings.Repeat("x", mctlapi.MaxResponseBytes+10)})
	_, err = h.cli.Do(ctx, sc, mctlapi.OpBasket, nil, "")
	if re, _ := err.(*mctlapi.RefusalError); re == nil || re.Code != mctlapi.CodeUpstreamInvalid {
		t.Fatalf("oversize: %v", err)
	}
}

func TestOrderIDMustBeOpaque(t *testing.T) {
	h := newHarness(t)
	ctx, _ := h.ctx(fakeapi.Alice, fakeapi.TeamAlpha)
	sc, _ := h.cli.Resolve(ctx)
	n := len(h.fake.Calls())
	for _, id := range []string{"", "../x", "a/b", "a?b=1", strings.Repeat("a", 129)} {
		_, err := h.cli.Do(ctx, sc, mctlapi.OpOrder, nil, id)
		if re, _ := err.(*mctlapi.RefusalError); re == nil || re.Code != mctlapi.CodeNotFound {
			t.Errorf("id %q: %v", id, err)
		}
	}
	if len(h.fake.Calls()) != n {
		t.Fatal("invalid ids reached mctl-api")
	}
}

func TestTraceparentPropagated(t *testing.T) {
	h := newHarness(t)
	ctx, _ := h.ctx(fakeapi.Alice, fakeapi.TeamAlpha)
	tid, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	sid, _ := trace.SpanIDFromHex("0102030405060708")
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled}))
	if _, err := h.cli.Resolve(ctx); err != nil {
		t.Fatal(err)
	}
	if tp := h.reqs[0].hdr.Get("Traceparent"); !strings.Contains(tp, tid.String()) {
		t.Fatalf("traceparent = %q", tp)
	}
}

// TestRealAPI is the activation precondition: the same client against a real
// mctl-api, skipped unless GLOVO_WIRE_REAL_URL, GLOVO_WIRE_REAL_TOKEN and
// GLOVO_WIRE_REAL_CREDENTIAL are set.
func TestRealAPI(t *testing.T) {
	base, tok, c := os.Getenv("GLOVO_WIRE_REAL_URL"), os.Getenv("GLOVO_WIRE_REAL_TOKEN"), os.Getenv("GLOVO_WIRE_REAL_CREDENTIAL")
	if base == "" || tok == "" || c == "" {
		t.Skip("GLOVO_WIRE_REAL_* not set; real mctl-api contract join pending (mctl-api#957)")
	}
	cli := mctlapi.NewHTTPClient(base, func() (string, error) { return c, nil }, nil)
	ctx := authn.WithPrincipal(context.Background(), &authn.Principal{Subject: "real"}, tok)
	if _, err := cli.Resolve(ctx); err != nil {
		t.Fatalf("resolve against real mctl-api: %v", err)
	}
}
