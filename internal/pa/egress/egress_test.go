// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egress

// Tests S1-E1..S1-E7 of threat model T9. No test does real network I/O: the
// resolver is a stub, and the socket dial seam connects every checked
// address to a local httptest TLS server, whose certificate covers
// example.com and *.example.com.

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	hostMCP  = "mcp.example.com"
	hostAuth = "auth.example.com"
	hostEvil = "evil.example.com"
	publicV4 = "93.184.216.34"
	publicV6 = "2606:4700::1111"
)

// stubResolver answers per host from a sequence; the last entry repeats.
type stubResolver struct {
	mu    sync.Mutex
	seq   map[string][][]netip.Addr
	calls map[string]int
}

func newResolver() *stubResolver {
	return &stubResolver{seq: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

func (s *stubResolver) set(host string, answers ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var list []netip.Addr
	for _, a := range answers {
		list = append(list, netip.MustParseAddr(a))
	}
	s.seq[host] = append(s.seq[host], list)
}

func (s *stubResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq, ok := s.seq[host]
	if !ok {
		return nil, fmt.Errorf("stub: no such host %q", host)
	}
	i := s.calls[host]
	s.calls[host]++
	if i >= len(seq) {
		i = len(seq) - 1
	}
	return seq[i], nil
}

func (s *stubResolver) count(host string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[host]
}

type harness struct {
	srv *httptest.Server
	res *stubResolver

	mu     sync.Mutex
	dialed []string
}

func newHarness(t *testing.T, h http.Handler) *harness {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	hs := &harness{srv: srv, res: newResolver()}
	hs.res.set(hostMCP, publicV4)
	hs.res.set(hostAuth, publicV6)
	hs.res.set(hostEvil, publicV4)
	return hs
}

// connect is the socket seam. It records the address the policy asked for
// and connects to the test server instead. If a host name ever reaches it,
// it resolves the name the way the OS would; that second lookup is where a
// DNS rebind would bite, and the recorded address shows it.
func (h *harness) connect(ctx context.Context, _, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if _, perr := netip.ParseAddr(host); perr != nil {
		addrs, rerr := h.res.LookupNetIP(ctx, "ip", host)
		if rerr != nil {
			return nil, rerr
		}
		address = net.JoinHostPort(addrs[0].String(), port)
	}
	h.mu.Lock()
	h.dialed = append(h.dialed, address)
	h.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, "tcp", h.srv.Listener.Addr().String())
}

func (h *harness) dials() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.dialed...)
}

func (h *harness) client(t *testing.T, cfg Config) *http.Client {
	t.Helper()
	if cfg.Purpose == 0 {
		cfg.Purpose = PurposeMCP
	}
	if cfg.AllowedHosts == nil {
		cfg.AllowedHosts = []string{hostMCP, hostAuth}
	}
	pool := x509.NewCertPool()
	pool.AddCert(h.srv.Certificate())
	c, err := newClient(cfg, hooks{resolver: h.res, connect: h.connect, rootCAs: pool})
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func do(t *testing.T, c *http.Client, url string) ([]byte, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return ReadBody(resp)
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok "+r.Host)
	})
}

func TestBaselineAllowedRequestSucceeds(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{})
	for _, u := range []string{"https://" + hostMCP + "/mcp", "https://MCP.Example.COM:443/mcp", "https://" + hostAuth + "/x"} {
		b, err := do(t, c, u)
		if err != nil || !strings.HasPrefix(string(b), "ok ") {
			t.Fatalf("%s: %q %v", u, b, err)
		}
	}
	for _, d := range h.dials() {
		if d != publicV4+":443" && d != "["+publicV6+"]:443" {
			t.Errorf("dialled %s, want a checked literal on 443", d)
		}
	}
}

// S1-E1: an HTTP URL is refused, before any resolution or dial.
func TestS1E1_HTTPRefused(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{})
	for _, u := range []string{"http://" + hostMCP + "/mcp", "ftp://" + hostMCP + "/", "ws://" + hostMCP + "/"} {
		if _, err := do(t, c, u); !errors.Is(err, ErrNotHTTPS) {
			t.Errorf("%s: want ErrNotHTTPS, got %v", u, err)
		}
	}
	if _, err := do(t, c, "https://"+hostMCP+":8443/mcp"); !errors.Is(err, ErrPort) {
		t.Errorf("port 8443: want ErrPort, got %v", err)
	}
	if n := len(h.dials()); n != 0 {
		t.Fatalf("refused URLs dialled %d times", n)
	}
	if h.res.count(hostMCP) != 0 {
		t.Fatal("refused URLs were resolved")
	}
}

// S1-E2: a host outside the allowlist is refused, before any resolution or dial.
func TestS1E2_HostOutsideAllowlistRefused(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{})
	for _, u := range []string{
		"https://" + hostEvil + "/",
		"https://x" + hostMCP + "/",
		"https://" + hostMCP + ".evil.test/",
		"https://example.com/",
		"https://" + publicV4 + "/",
		"https://[" + publicV6 + "]/",
	} {
		if _, err := do(t, c, u); !errors.Is(err, ErrHostNotAllowed) {
			t.Errorf("%s: want ErrHostNotAllowed, got %v", u, err)
		}
	}
	if _, err := do(t, c, "https://"+hostMCP+"@"+hostEvil+"/"); err == nil {
		t.Error("userinfo URL must be refused")
	}
	if n := len(h.dials()); n != 0 {
		t.Fatalf("refused hosts dialled %d times", n)
	}
	if h.res.count(hostEvil) != 0 {
		t.Fatal("refused host was resolved")
	}
}

// S1-E3: a private IPv4, an IPv6 unique-local or an IPv4-mapped address is
// refused after resolution, and so are the other T9 ranges.
func TestS1E3_ResolvedDeniedAddressRefused(t *testing.T) {
	denied := []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254",
		"100.64.0.1", "0.1.2.3", "0.0.0.0", "224.0.0.1", "255.255.255.255",
		"10.42.0.5", "10.43.0.1", // cluster pod and service ranges
		"fd00::1", "fc00::1", "fe80::1", "::1", "::", "ff02::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::a00:1", "64:ff9b::7f00:1",
	}
	for _, ip := range denied {
		h := newHarness(t, okHandler())
		h.res.seq[hostMCP] = nil
		h.res.set(hostMCP, ip)
		c := h.client(t, Config{})
		if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
			t.Errorf("%s: want ErrNonPublic, got %v", ip, err)
		}
		if n := len(h.dials()); n != 0 {
			t.Errorf("%s: dialled %d times", ip, n)
		}
	}
}

// S1-E3: one denied answer among public ones refuses the host.
func TestS1E3_MixedAnswerRefused(t *testing.T) {
	h := newHarness(t, okHandler())
	h.res.seq[hostMCP] = nil
	h.res.set(hostMCP, publicV4, "10.0.0.1")
	c := h.client(t, Config{})
	if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
		t.Fatalf("want ErrNonPublic, got %v", err)
	}
	if n := len(h.dials()); n != 0 {
		t.Fatalf("dialled %d times", n)
	}
}

// S1-E3: a DNS rebind between check and dial cannot reach the new address.
// The resolver answers public first and private on every later lookup. The
// dial must connect to the checked literal from the single lookup; if the
// name reached the socket layer, the seam would resolve again and record the
// private address. A fresh connection after the rebind is refused.
func TestS1E3_RebindBetweenCheckAndDialRefused(t *testing.T) {
	h := newHarness(t, okHandler())
	h.res.seq[hostMCP] = nil
	h.res.set(hostMCP, publicV4)
	h.res.set(hostMCP, "10.0.0.1")
	c := h.client(t, Config{})
	if _, err := do(t, c, "https://"+hostMCP+"/"); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if got := h.dials(); len(got) != 1 || got[0] != publicV4+":443" {
		t.Fatalf("dialled %v, want only the checked literal %s:443", got, publicV4)
	}
	if n := h.res.count(hostMCP); n != 1 {
		t.Fatalf("resolved %d times for one dial, want 1", n)
	}
	c.CloseIdleConnections()
	if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
		t.Fatalf("after rebind: want ErrNonPublic, got %v", err)
	}
	if n := len(h.dials()); n != 1 {
		t.Fatalf("rebound address was dialled (%d dials)", n)
	}
}

// S1-E3: caller-supplied denied prefixes apply, including to mapped forms.
func TestS1E3_DeniedPrefixes(t *testing.T) {
	for _, ip := range []string{publicV4, "::ffff:" + publicV4, "64:ff9b::5db8:d822"} {
		h := newHarness(t, okHandler())
		h.res.seq[hostMCP] = nil
		h.res.set(hostMCP, ip)
		c := h.client(t, Config{DeniedPrefixes: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}})
		if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
			t.Errorf("%s: want ErrNonPublic, got %v", ip, err)
		}
	}
}

// The Control hook refuses denied addresses when called. As the dialer is
// wired it is defence in depth (see policy.control).
func TestControlHook(t *testing.T) {
	p := &policy{denied: []netip.Prefix{netip.MustParsePrefix("93.184.216.0/24")}}
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "[fd00::1]:443", "[::ffff:10.0.0.1]:443", publicV4 + ":443", "garbage"} {
		if err := p.control("tcp", a, nil); !errors.Is(err, ErrNonPublic) {
			t.Errorf("%s: want ErrNonPublic, got %v", a, err)
		}
	}
	if err := p.control("tcp", "["+publicV6+"]:443", nil); err != nil {
		t.Errorf("public: %v", err)
	}
}

func redirectHandler(routes map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if to, ok := routes[r.Host+r.URL.Path]; ok {
			http.Redirect(w, r, to, http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok "+r.Host+r.URL.Path)
	})
}

// S1-E4: no purpose but discovery follows a redirect, not even to the same
// allowlisted host, and the target is never requested.
func TestS1E4_RedirectRefusedOutsideDiscovery(t *testing.T) {
	var hits atomic.Int32
	inner := redirectHandler(map[string]string{hostMCP + "/a": "https://" + hostMCP + "/b"})
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/b" {
			hits.Add(1)
		}
		inner.ServeHTTP(w, r)
	}))
	for _, p := range []Purpose{PurposeRegistration, PurposeToken, PurposeRevocation, PurposeMCP, PurposeBotAPI} {
		c := h.client(t, Config{Purpose: p})
		if _, err := do(t, c, "https://"+hostMCP+"/a"); !errors.Is(err, ErrRedirect) {
			t.Errorf("%v: want ErrRedirect, got %v", p, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect target requested %d times", hits.Load())
	}
}

// S1-E4: a 3xx without a Location header is not a response the caller can
// mistake for success: outside discovery it fails like any redirect.
func TestS1E4_RedirectWithoutLocationRefused(t *testing.T) {
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	}))
	for _, p := range []Purpose{PurposeRegistration, PurposeToken, PurposeRevocation, PurposeMCP, PurposeBotAPI} {
		c := h.client(t, Config{Purpose: p})
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+hostMCP+"/", nil)
		resp, err := c.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrRedirect) {
			t.Errorf("%v: want ErrRedirect, got %v", p, err)
		}
	}
}

// S1-E4: discovery follows at most two hops, each re-checked; a hop to a
// foreign host, an IP literal, plain HTTP or a host resolving to a private
// address is refused.
func TestS1E4_DiscoveryRedirects(t *testing.T) {
	h := newHarness(t, redirectHandler(map[string]string{
		hostMCP + "/one":     "https://" + hostAuth + "/done",
		hostMCP + "/two":     "https://" + hostAuth + "/hop",
		hostAuth + "/hop":    "https://" + hostMCP + "/done",
		hostMCP + "/three":   "https://" + hostAuth + "/h1",
		hostAuth + "/h1":     "https://" + hostMCP + "/h2",
		hostMCP + "/h2":      "https://" + hostAuth + "/done",
		hostMCP + "/foreign": "https://" + hostEvil + "/done",
		hostMCP + "/literal": "https://10.0.0.1/done",
		hostMCP + "/mapped":  "https://[::ffff:10.0.0.1]/done",
		hostMCP + "/http":    "http://" + hostAuth + "/done",
	}))
	c := h.client(t, Config{Purpose: PurposeDiscovery})
	for _, path := range []string{"/one", "/two"} {
		b, err := do(t, c, "https://"+hostMCP+path)
		if err != nil || !strings.HasSuffix(string(b), "/done") {
			t.Errorf("%s: %q %v", path, b, err)
		}
	}
	cases := map[string]error{
		"/three":   ErrTooManyRedirects,
		"/foreign": ErrHostNotAllowed,
		"/literal": ErrHostNotAllowed,
		"/mapped":  ErrHostNotAllowed,
		"/http":    ErrNotHTTPS,
	}
	for path, want := range cases {
		if _, err := do(t, c, "https://"+hostMCP+path); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", path, want, err)
		}
	}
	if h.res.count(hostEvil) != 0 {
		t.Error("foreign redirect target was resolved")
	}

	// An allowlisted hop whose host resolves to a private address.
	h2 := newHarness(t, redirectHandler(map[string]string{hostMCP + "/private": "https://" + hostAuth + "/done"}))
	h2.res.seq[hostAuth] = nil
	h2.res.set(hostAuth, "10.0.0.1")
	c2 := h2.client(t, Config{Purpose: PurposeDiscovery})
	if _, err := do(t, c2, "https://"+hostMCP+"/private"); !errors.Is(err, ErrNonPublic) {
		t.Errorf("private hop: want ErrNonPublic, got %v", err)
	}
}

// S1-E5: an oversized response is cut at the cap and the call fails, with
// or without a Content-Length.
func TestS1E5_OversizedResponseFails(t *testing.T) {
	const max = 1024
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := max
		if r.URL.Path != "/exact" {
			n = max + 1
		}
		body := strings.Repeat("a", n)
		if r.URL.Path == "/chunked" {
			for i := 0; i < len(body); i += 100 {
				end := min(i+100, len(body))
				_, _ = io.WriteString(w, body[i:end])
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(n))
		_, _ = io.WriteString(w, body)
	}))
	c := h.client(t, Config{MaxBodyBytes: max})
	if b, err := do(t, c, "https://"+hostMCP+"/exact"); err != nil || len(b) != max {
		t.Fatalf("exact cap: %d %v", len(b), err)
	}
	// A declared length over the cap fails at Do, before the body is read.
	lreq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+hostMCP+"/length", nil)
	lresp, err := c.Do(lreq)
	if lresp != nil {
		_ = lresp.Body.Close()
	}
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("content-length over cap: want ErrTooLarge from Do, got %v", err)
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+hostMCP+"/chunked", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("chunked: %v", err)
	}
	if resp.ContentLength != -1 {
		t.Fatalf("chunked response carried a length: %d", resp.ContentLength)
	}
	b, err := ReadBody(resp)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("chunked over cap: want ErrTooLarge, got %v", err)
	}
	if len(b) > max {
		t.Fatalf("read %d bytes past a %d cap", len(b), max)
	}
}

// S1-E6: a slow response times out, whether the headers or the body stall.
//
// The handler never ends a response cleanly. It holds until the client call
// under test has returned, then aborts the connection. It must not return on
// r.Context().Done(): when the client gives up, its TLS close_notify reaches
// the server before the socket closes, which cancels that context. A handler
// that then returns lets the server write the final chunk, and under load
// those bytes can reach the client's pending read before its own socket is
// torn down. The body then ends with io.EOF after the deadline, which
// http.Client passes through as success, and the test saw nil (#1336). The
// 10s cap only frees a wedged handler, and it aborts too, so no path can
// hand the client a complete response.
func TestS1E6_SlowResponseTimesOut(t *testing.T) {
	var mu sync.Mutex
	gates := map[string]chan struct{}{}
	// gate returns the channel closed when the client call for uri returns.
	gate := func(uri string) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		ch, ok := gates[uri]
		if !ok {
			ch = make(chan struct{})
			gates[uri] = ch
		}
		return ch
	}
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slowbody" {
			_, _ = io.WriteString(w, "partial")
			w.(http.Flusher).Flush()
		}
		select {
		case <-gate(r.URL.RequestURI()):
		case <-time.After(10 * time.Second):
		}
		panic(http.ErrAbortHandler)
	}))
	c := h.client(t, Config{Timeout: 150 * time.Millisecond})

	type result struct {
		phase string // "headers" if Do failed, "body" if reading the body did
		err   error
	}
	call := func(uri string) (result, bool) {
		clientReturned := gate(uri)
		done := make(chan result, 1)
		go func() {
			defer close(clientReturned)
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://"+hostMCP+uri, nil)
			if err != nil {
				done <- result{"request", err}
				return
			}
			resp, err := c.Do(req)
			if err != nil {
				done <- result{"headers", err}
				return
			}
			if resp.StatusCode != http.StatusOK {
				_ = resp.Body.Close()
				done <- result{"headers", fmt.Errorf("status %d", resp.StatusCode)}
				return
			}
			_, err = ReadBody(resp)
			done <- result{"body", err}
		}()
		select {
		case res := <-done:
			return res, true
		case <-time.After(3 * time.Second):
			return result{}, false
		}
	}

	// Each path must time out in its own phase, so the test tells the header
	// deadline apart from the one that covers the body. Reaching the body
	// phase is a precondition, not the property under test: on a loaded
	// runner the dial, handshake and headers alone can outlast 150ms, and
	// /slowbody then times out before its body. That attempt still had to
	// time out, and is retried; any other outcome fails at once.
	const attempts = 5
	for _, tc := range []struct{ path, phase string }{
		{"/slowheaders", "headers"},
		{"/slowbody", "body"},
	} {
		var last result
		for n := 0; n < attempts; n++ {
			res, ok := call(fmt.Sprintf("%s?n=%d", tc.path, n))
			if !ok {
				t.Fatalf("%s: no timeout after 3s against a 150ms limit", tc.path)
			}
			var ne net.Error
			if res.err == nil || !errors.As(res.err, &ne) || !ne.Timeout() {
				t.Fatalf("%s: want a timeout, got %v (%s)", tc.path, res.err, res.phase)
			}
			last = res
			if res.phase == tc.phase {
				break
			}
			t.Logf("%s: attempt %d timed out in the %s, before the %s; retrying", tc.path, n+1, res.phase, tc.phase)
		}
		if last.phase != tc.phase {
			t.Errorf("%s: timed out in the %s on all %d attempts, never in the %s", tc.path, last.phase, attempts, tc.phase)
		}
	}
}

// S1-E7: proxy environment variables are ignored: the request goes direct
// to the checked address and the proxy sees nothing.
func TestS1E7_ProxyEnvIgnored(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		http.Error(w, "proxy", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	h := newHarness(t, okHandler())
	c := h.client(t, Config{})
	if _, err := do(t, c, "https://"+hostMCP+"/"); err != nil {
		t.Fatalf("request: %v", err)
	}
	if proxied.Load() != 0 {
		t.Fatalf("proxy received %d requests", proxied.Load())
	}
	if got := h.dials(); len(got) != 1 || got[0] != publicV4+":443" {
		t.Fatalf("dialled %v, want direct %s:443", got, publicV4)
	}
	if tr := c.Transport.(*policyTransport).base; tr.Proxy != nil {
		t.Fatal("transport consults a proxy function")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	bad := []Config{
		{Purpose: PurposeMCP},
		{Purpose: 0, AllowedHosts: []string{hostMCP}},
		{Purpose: Purpose(99), AllowedHosts: []string{hostMCP}},
		{Purpose: PurposeMCP, AllowedHosts: []string{""}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"https://" + hostMCP}},
		{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP + ":443"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"*.example.com"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP + "/path"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"::1"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{publicV4}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"10.0.0.1"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"10.1"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"2130706433"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"0x7f000001"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"a.0x7F"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{"10.0x1"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP, "127.0.0.1"}},
		{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP}, DeniedPrefixes: []netip.Prefix{{}}},
	}
	for i, cfg := range bad {
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d: want ErrInvalidConfig, got %v", i, err)
		}
	}
	for p, lim := range defaultLimits {
		c, err := New(Config{Purpose: p, AllowedHosts: []string{hostMCP}})
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		if c.Timeout != lim.timeout || lim.maxBody <= 0 {
			t.Errorf("%v: timeout %v body %d", p, c.Timeout, lim.maxBody)
		}
	}
}

// S1-E1, S1-E2: the per-request URL check on its own. The dial repeats the
// port and host checks as a second layer, so the end-to-end tests cannot
// tell the two layers apart; these unit tests pin each layer separately.
func TestS1E1E2_CheckURLLayer(t *testing.T) {
	c, err := newClient(Config{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP}}, hooks{})
	if err != nil {
		t.Fatal(err)
	}
	p := c.Transport.(*policyTransport).p
	cases := map[string]error{
		"http://" + hostMCP + "/":             ErrNotHTTPS,
		"https://" + hostMCP + ":8443/":       ErrPort,
		"https://" + hostEvil + "/":           ErrHostNotAllowed,
		"https://user:pw@" + hostMCP + "/":    errUserinfoInRequest,
		"https://" + hostMCP + "@" + hostEvil: errUserinfoInRequest,
	}
	for raw, want := range cases {
		u, _ := url.Parse(raw)
		if err := p.checkURL(u); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", raw, want, err)
		}
	}
	for _, raw := range []string{"https://" + hostMCP + "/", "https://" + hostMCP + ":443/x", "https://MCP.example.com./"} {
		u, _ := url.Parse(raw)
		if err := p.checkURL(u); err != nil {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

// S1-E2, S1-E3: the dial layer on its own refuses a foreign host, a port
// other than 443 and a proxy-style literal, without resolving or connecting.
func TestS1E2E3_DialLayer(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{AllowedHosts: []string{hostMCP}})
	p := c.Transport.(*policyTransport).p
	cases := map[string]error{
		hostEvil + ":443": ErrHostNotAllowed,
		"127.0.0.1:443":   ErrHostNotAllowed,
		publicV4 + ":443": ErrHostNotAllowed,
		hostMCP + ":8443": ErrPort,
		"127.0.0.1:3128":  ErrPort,
	}
	for addr, want := range cases {
		if _, err := p.dial(context.Background(), "tcp", addr); !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", addr, want, err)
		}
	}
	if n := len(h.dials()); n != 0 {
		t.Fatalf("dialled %d times", n)
	}
	if h.res.count(hostEvil) != 0 {
		t.Fatal("foreign host resolved")
	}
}

// S1-E5: a compressed body is capped after decompression: a small gzip
// payload that inflates past the cap fails with ErrTooLarge.
func TestS1E5_GzipBombCapped(t *testing.T) {
	const max = 4096
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(bytes.Repeat([]byte("a"), 64*max))
	_ = zw.Close()
	if buf.Len() >= max {
		t.Fatalf("fixture not a bomb: %d compressed bytes", buf.Len())
	}
	h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprint(buf.Len()))
		_, _ = w.Write(buf.Bytes())
	}))
	c := h.client(t, Config{MaxBodyBytes: max})
	b, err := do(t, c, "https://"+hostMCP+"/")
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v (%d bytes)", err, len(b))
	}
	if len(b) > max {
		t.Fatalf("read %d bytes past a %d cap", len(b), max)
	}
}

// S1-E4: a 304, or any 3xx http.Client would not follow, fails for every
// purpose, discovery included.
func TestS1E4_NonRedirect3xxRefused(t *testing.T) {
	for _, code := range []int{http.StatusNotModified, http.StatusMultipleChoices, http.StatusUseProxy} {
		h := newHarness(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://"+hostMCP+"/x")
			w.WriteHeader(code)
		}))
		for _, p := range []Purpose{PurposeDiscovery, PurposeMCP} {
			c := h.client(t, Config{Purpose: p})
			if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrRedirect) {
				t.Errorf("%d %v: want ErrRedirect, got %v", code, p, err)
			}
		}
	}
}

// S1-E4: a discovery client, which follows redirects, carries no
// credentials and sends only bodiless GET or HEAD requests.
func TestS1E4_DiscoveryIsAnonymousGET(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{Purpose: PurposeDiscovery})
	mk := func(method string, body io.Reader, hdr, val string) *http.Request {
		req, _ := http.NewRequestWithContext(context.Background(), method, "https://"+hostMCP+"/.well-known/x", body)
		if hdr != "" {
			req.Header.Set(hdr, val)
		}
		return req
	}
	bad := map[string]*http.Request{
		"post":          mk(http.MethodPost, strings.NewReader("x"), "", ""),
		"put":           mk(http.MethodPut, nil, "", ""),
		"get with body": mk(http.MethodGet, strings.NewReader("x"), "", ""),
		"authorization": mk(http.MethodGet, nil, "Authorization", "Bearer t"),
		"cookie":        mk(http.MethodGet, nil, "Cookie", "a=b"),
		"api key":       mk(http.MethodGet, nil, "X-Api-Key", "k"),
		"dpop":          mk(http.MethodGet, nil, "DPoP", "proof"),
		"custom":        mk(http.MethodGet, nil, "X-Forwarded-For", "10.0.0.1"),
	}
	for name, req := range bad {
		resp, err := c.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrDiscoveryRequest) {
			t.Errorf("%s: want ErrDiscoveryRequest, got %v", name, err)
		}
	}
	if n := len(h.dials()); n != 0 {
		t.Fatalf("refused discovery requests dialled %d times", n)
	}
	if _, err := do(t, c, "https://"+hostMCP+"/.well-known/x"); err != nil {
		t.Fatalf("anonymous GET: %v", err)
	}
	ok := mk(http.MethodGet, nil, "Accept", "application/json")
	ok.Header.Set("User-Agent", "mctl-pa")
	ok.Header.Set("MCP-Protocol-Version", "2025-06-18")
	ok.Header.Set("Accept-Encoding", "gzip")
	resp0, err := c.Do(ok)
	if err != nil {
		t.Fatalf("allowlisted headers: %v", err)
	}
	_ = resp0.Body.Close()
	// The same headers are fine on a non-discovery client.
	m := h.client(t, Config{Purpose: PurposeToken})
	resp, err := m.Do(mk(http.MethodPost, strings.NewReader("x"), "Authorization", "Basic x"))
	if err != nil {
		t.Fatalf("token POST: %v", err)
	}
	_ = resp.Body.Close()
}

// S1-E3: a denied prefix given in IPv4-mapped form denies the native IPv4
// answers too; a mapped prefix shorter than /96 is refused at config time.
func TestS1E3_MappedDeniedPrefixNormalised(t *testing.T) {
	h := newHarness(t, okHandler())
	c := h.client(t, Config{DeniedPrefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:93.184.216.0/120")}})
	if _, err := do(t, c, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
		t.Fatalf("native answer under a mapped prefix: want ErrNonPublic, got %v", err)
	}
	_, err := New(Config{Purpose: PurposeMCP, AllowedHosts: []string{hostMCP}, DeniedPrefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:0:0/80")}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("short mapped prefix: want ErrInvalidConfig, got %v", err)
	}
	// The NAT64 form is normalised the same way: 64:ff9b::5db8:d800/120 is
	// 93.184.216.0/24, and must deny the native and mapped answers too.
	for _, ans := range []string{publicV4, "::ffff:" + publicV4} {
		h2 := newHarness(t, okHandler())
		h2.res.seq[hostMCP] = nil
		h2.res.set(hostMCP, ans)
		c2 := h2.client(t, Config{DeniedPrefixes: []netip.Prefix{netip.MustParsePrefix("64:ff9b::5db8:d800/120")}})
		if _, err := do(t, c2, "https://"+hostMCP+"/"); !errors.Is(err, ErrNonPublic) {
			t.Errorf("%s under a NAT64 prefix: want ErrNonPublic, got %v", ans, err)
		}
	}
}

func TestNewRejectsOverridesAboveCeiling(t *testing.T) {
	for p, ceil := range ceilingLimits {
		def := defaultLimits[p]
		if def.timeout > ceil.timeout || def.maxBody > ceil.maxBody {
			t.Errorf("%v: default above ceiling", p)
		}
		bad := []Config{
			{Timeout: ceil.timeout + time.Nanosecond},
			{Timeout: -time.Second},
			{MaxBodyBytes: ceil.maxBody + 1},
			{MaxBodyBytes: -1},
		}
		for i, cfg := range bad {
			cfg.Purpose, cfg.AllowedHosts = p, []string{hostMCP}
			if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("%v case %d: want ErrInvalidConfig, got %v", p, i, err)
			}
		}
		c, err := New(Config{Purpose: p, AllowedHosts: []string{hostMCP}, Timeout: ceil.timeout, MaxBodyBytes: ceil.maxBody})
		if err != nil || c.Timeout != ceil.timeout {
			t.Errorf("%v at ceiling: %v", p, err)
		}
	}
}
