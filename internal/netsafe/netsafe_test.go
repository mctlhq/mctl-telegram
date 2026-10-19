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

package netsafe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicAddr(t *testing.T) {
	refusedList := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"0.0.0.0", "224.0.0.1", "100.64.0.1", "198.18.0.1", "240.0.0.1",
		"255.255.255.255", "192.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
		"::1", "::", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "2001:db8::1",
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::a9fe:a9fe",
		"192.88.99.1", "::7f00:1", "::a9fe:a9fe", "2002:7f00:1::", "2002:808:808::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b:1::a00:1", "fec0::1",
		"2001:2::1", "2001:3::1", "2001:4:112::1", "2001:1ff:ffff::1", "3fff::1", "3fff:fff:ffff::1",
	}
	for _, s := range refusedList {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be refused", s)
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2001:200::1", "3fff:1000::1"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
	if PublicAddr(netip.Addr{}) {
		t.Error("invalid address must be refused")
	}
}

type stubResolver struct {
	calls atomic.Int32
	seq   [][]netip.Addr
}

func (s *stubResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	i := int(s.calls.Add(1)) - 1
	if i >= len(s.seq) {
		i = len(s.seq) - 1
	}
	return s.seq[i], nil
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := c.Do(req)
	if resp != nil {
		t.Cleanup(func() { _ = resp.Body.Close() })
	}
	return resp, err
}

func TestResolvedNonPublicRefused(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "169.254.169.254", "::ffff:127.0.0.1"} {
		c := Client(Options{Resolver: &stubResolver{seq: [][]netip.Addr{{netip.MustParseAddr(ip)}}}})
		if _, err := get(t, c, "https://example.test/x"); err == nil || !errors.Is(err, ErrNonPublic) { //nolint:bodyclose // closed via t.Cleanup in get
			t.Errorf("%s: want ErrNonPublic, got %v", ip, err)
		}
	}
}

func TestDirectIPAndPortRefused(t *testing.T) {
	c := Client(Options{})
	if _, err := get(t, c, "https://127.0.0.1/x"); !errors.Is(err, ErrNonPublic) { //nolint:bodyclose // closed via t.Cleanup in get
		t.Fatalf("direct loopback: %v", err)
	}
	if _, err := get(t, c, "https://[::1]/x"); !errors.Is(err, ErrNonPublic) { //nolint:bodyclose // closed via t.Cleanup in get
		t.Fatalf("direct v6 loopback: %v", err)
	}
	c = Client(Options{Resolver: &stubResolver{seq: [][]netip.Addr{{netip.MustParseAddr("8.8.8.8")}}}})
	if _, err := get(t, c, "https://example.test:8443/x"); err == nil || !strings.Contains(err.Error(), "port 8443") { //nolint:bodyclose // closed via t.Cleanup in get
		t.Fatalf("port: %v", err)
	}
}

// The Control hook refuses a non-public address when called. As the dialer is
// wired it is defence in depth only (see controlPublic): the PublicAddr filter
// in DialContext is what the end-to-end tests above pin.
func TestControlHookRefusesNonPublic(t *testing.T) {
	for _, a := range []string{"127.0.0.1:443", "[::1]:443", "10.0.0.1:443", "[::ffff:127.0.0.1]:443"} {
		if err := controlPublic("tcp", a, nil); !errors.Is(err, ErrNonPublic) {
			t.Errorf("%s: %v", a, err)
		}
	}
	if err := controlPublic("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("public: %v", err)
	}
	if err := controlPublic("tcp", "garbage", nil); !errors.Is(err, ErrNonPublic) {
		t.Errorf("garbage: %v", err)
	}
}

func TestRedirectRefusedAndLoopbackServerUnreachable(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()
	// The loopback server is not reachable through the safe client at all.
	c := Client(Options{AllowedPorts: []int{portOf(srv.URL)}})
	if _, err := get(t, c, srv.URL); !errors.Is(err, ErrNonPublic) { //nolint:bodyclose // closed via t.Cleanup in get
		t.Fatalf("loopback server: %v", err)
	}
}

func portOf(u string) int {
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(u, "https://"))
	n := 0
	for _, ch := range p {
		n = n*10 + int(ch-'0')
	}
	return n
}

func TestRedirectIsFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	}))
	defer srv.Close()
	c := Client(Options{})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	// Swap in a transport that can reach the loopback test server, keeping the
	// redirect policy under test.
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	resp, err := get(t, c, srv.URL)
	if err == nil || !errors.Is(err, ErrRedirect) {
		if resp != nil {
			_ = resp.Body.Close()
		}
		t.Fatalf("redirect must fail: %v", err)
	}
}

func TestProxyEnvIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	c := Client(Options{})
	if c.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("proxy must be disabled")
	}
}

func TestReadLimited(t *testing.T) {
	read := func(n int) ([]byte, error) {
		resp := &http.Response{Body: nopCloser{strings.NewReader(strings.Repeat("a", n))}}
		defer func() { _ = resp.Body.Close() }()
		return ReadLimited(resp, 10)
	}
	if b, err := read(10); err != nil || len(b) != 10 {
		t.Fatalf("exact: %v %d", err, len(b))
	}
	if _, err := read(11); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("over: %v", err)
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error { return nil }

func TestTimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()
	c := Client(Options{Timeout: 50 * time.Millisecond})
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}
	if resp, err := get(t, c, srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("slow response must fail")
	}
}
