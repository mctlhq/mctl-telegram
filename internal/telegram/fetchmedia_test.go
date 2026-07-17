package telegram

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// insecureTestTLSConfig skips certificate verification — only ever used to
// point the guarded fetcher at an httptest.NewTLSServer's self-signed cert
// for an arbitrary test hostname that never matches the cert's SAN. Never
// reachable from the exported FetchGuardedURL, which always uses the secure
// default (see fetchGuardedURL's nil-tlsConfig fallback).
var insecureTestTLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec

// allowedTestIP is a fake "public-looking" address the test resolver hands
// back for every httptest.Server host — it must pass isDisallowedIP so the
// guard's dial-time check does not itself become the reason a "should
// succeed" test fails. The fake dialer below ignores this IP and redirects
// the real TCP connection to the test server's actual loopback address, so
// isDisallowedIP is never weakened for production use — only the resolver
// and dialer are swapped out.
var allowedTestIP = net.ParseIP("93.184.216.1")

// fakeResolver returns allowedTestIP for every host — used by "should
// succeed" tests so the SSRF guard's IP check (unfaked, real logic) passes.
func fakeResolver(context.Context, string) ([]net.IP, error) {
	return []net.IP{allowedTestIP}, nil
}

// dialToAddr builds a dialFunc that ignores the requested address and always
// connects to target instead — lets a fake "public" hostname/IP actually
// reach an httptest.Server bound to 127.0.0.1.
func dialToAddr(target string) dialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
}

// tlsServerAddr strips the https:// scheme httptest.NewTLSServer's URL
// carries, leaving the bare host:port a dialFunc needs.
func tlsServerAddr(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "https://")
}

func TestIsDisallowedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.169.254", true}, // cloud metadata, covered by link-local
		{"10.0.0.5", true},
		{"172.16.0.5", true},
		{"192.168.1.5", true},
		{"0.0.0.0", true},
		{"224.0.0.1", true}, // multicast
		{"93.184.216.1", false},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", tc.ip)
		}
		if got := isDisallowedIP(ip); got != tc.want {
			t.Errorf("isDisallowedIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestFetchGuardedURL_BadScheme rejects non-https schemes before any
// connection is attempted.
func TestFetchGuardedURL_BadScheme(t *testing.T) {
	_, _, err := fetchGuardedURL(context.Background(), "http://example.com/f.jpg", 1024, time.Second, fakeResolver, dialToAddr("127.0.0.1:1"), nil)
	if !errors.Is(err, ErrFetchBadScheme) {
		t.Fatalf("err = %v, want ErrFetchBadScheme", err)
	}
}

// TestFetchGuardedURL_DisallowedIP_Direct rejects a URL whose host resolves
// directly to a loopback/private/link-local address.
func TestFetchGuardedURL_DisallowedIP_Direct(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/f.jpg",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/f.jpg",
	}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			_, _, err := fetchGuardedURL(context.Background(), u, 1024, time.Second, nil, nil, nil)
			if !errors.Is(err, ErrFetchDisallowedIP) {
				t.Fatalf("err = %v, want ErrFetchDisallowedIP", err)
			}
		})
	}
}

// TestFetchGuardedURL_DisallowedIP_ViaHostname rejects a hostname that
// resolves (via the injected lookup) only to disallowed addresses, without
// ever dialing anything — exercised with a fake resolver so no real DNS
// lookup happens in the test.
func TestFetchGuardedURL_DisallowedIP_ViaHostname(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}
	dialed := false
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("should never dial")
	}
	_, _, err := fetchGuardedURL(context.Background(), "https://evil.internal/f.jpg", 1024, time.Second, lookup, dial, nil)
	if !errors.Is(err, ErrFetchDisallowedIP) {
		t.Fatalf("err = %v, want ErrFetchDisallowedIP", err)
	}
	if dialed {
		t.Error("dial must not be attempted once the resolved address is disallowed")
	}
}

// TestFetchGuardedURL_Success exercises the happy path against an
// httptest.NewTLSServer through the fake resolver/dialer, proving the guard
// logic itself is not what's under test here — the response is small and
// fits under the cap.
func TestFetchGuardedURL_Success(t *testing.T) {
	const body = "hello media bytes"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	data, mime, err := fetchGuardedURL(context.Background(), "https://allowed.example/f.jpg", 1024, 5*time.Second, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != body {
		t.Errorf("data = %q, want %q", data, body)
	}
	if mime != "image/jpeg" {
		t.Errorf("mime = %q, want image/jpeg", mime)
	}
}

// TestFetchGuardedURL_RedirectToDisallowedIP: a redirect chain that starts at
// an allowed host but 302s to a private-IP-literal URL must be rejected
// before any bytes are read from the disallowed target.
func TestFetchGuardedURL_RedirectToDisallowedIP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/private-file", http.StatusFound)
	}))
	defer srv.Close()

	_, _, err := fetchGuardedURL(context.Background(), "https://allowed.example/f.jpg", 1024, 5*time.Second, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if !errors.Is(err, ErrFetchDisallowedIP) {
		t.Fatalf("err = %v, want ErrFetchDisallowedIP", err)
	}
}

// TestFetchGuardedURL_RedirectToHTTP: a redirect from https to a plain http
// URL must be rejected too (CheckRedirect's scheme check).
func TestFetchGuardedURL_RedirectToHTTP(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://allowed.example/plain", http.StatusFound)
	}))
	defer srv.Close()

	_, _, err := fetchGuardedURL(context.Background(), "https://allowed.example/f.jpg", 1024, 5*time.Second, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if !errors.Is(err, ErrFetchBadScheme) {
		t.Fatalf("err = %v, want ErrFetchBadScheme", err)
	}
}

// TestFetchGuardedURL_Oversized: a response larger than maxBytes is rejected
// with a clear error, not a raw timeout/500, and the stream is capped rather
// than read into memory unbounded.
func TestFetchGuardedURL_Oversized(t *testing.T) {
	const cap = 16
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, cap*4))
	}))
	defer srv.Close()

	_, _, err := fetchGuardedURL(context.Background(), "https://allowed.example/big.bin", cap, 5*time.Second, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if !errors.Is(err, ErrFetchOversized) {
		t.Fatalf("err = %v, want ErrFetchOversized", err)
	}
}

// TestFetchGuardedURL_OversizedContentLength: a declared Content-Length above
// the cap is rejected before the body is even read.
func TestFetchGuardedURL_OversizedContentLength(t *testing.T) {
	const cap = 16
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000000")
		w.WriteHeader(http.StatusOK)
		// Deliberately do not write 1MB of body — if the implementation reads
		// the body before checking Content-Length, this test would hang/time
		// out instead of failing fast on the declared-size check.
	}))
	defer srv.Close()

	_, _, err := fetchGuardedURL(context.Background(), "https://allowed.example/big.bin", cap, 2*time.Second, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if !errors.Is(err, ErrFetchOversized) {
		t.Fatalf("err = %v, want ErrFetchOversized", err)
	}
}

// TestFetchGuardedURL_Timeout: a response that never completes within the
// fetch timeout returns a clear timeout error.
func TestFetchGuardedURL_Timeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block
	}))
	// defer order matters: close(block) must run BEFORE srv.Close(), or
	// Close() deadlocks waiting for the still-blocked handler to return.
	defer srv.Close()
	defer close(block)

	_, _, err := fetchGuardedURL(context.Background(), "https://allowed.example/slow.bin", 1024, 50*time.Millisecond, fakeResolver, dialToAddr(tlsServerAddr(srv)), insecureTestTLSConfig)
	if !errors.Is(err, ErrFetchTimeout) {
		t.Fatalf("err = %v, want ErrFetchTimeout", err)
	}
}
