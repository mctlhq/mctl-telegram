package telegram

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// Sentinel errors returned by FetchGuardedURL. Wrapped with extra detail via
// fmt.Errorf("%w: ...", ...) so callers can still match with errors.Is while
// getting an actionable message for the end user.
var (
	// ErrFetchBadScheme is returned when file_url is not https://.
	ErrFetchBadScheme = errors.New("file_url must use https://")
	// ErrFetchDisallowedIP is returned when file_url resolves (directly or via
	// a redirect) to a loopback, link-local, private-use, or otherwise
	// non-public address. This is the SSRF guard.
	ErrFetchDisallowedIP = errors.New("file_url resolves to a disallowed address (loopback/link-local/private-range)")
	// ErrFetchOversized is returned when the response is, or becomes, larger
	// than the configured cap.
	ErrFetchOversized = errors.New("file_url response exceeds the configured upload size cap")
	// ErrFetchTimeout is returned when the fetch does not complete within the
	// configured timeout.
	ErrFetchTimeout = errors.New("file_url fetch timed out")
)

// maxFetchRedirects bounds redirect-chain length. http.Client's own default
// (10) is generous enough to be a footgun for a caller-supplied URL; keep it
// tight.
const maxFetchRedirects = 5

// lookupIPFunc resolves a hostname to its candidate addresses. Overridable in
// tests so redirect/oversize/timeout behavior can be exercised against an
// httptest.Server without weakening the production IP guard.
type lookupIPFunc func(ctx context.Context, host string) ([]net.IP, error)

// dialFunc performs the actual TCP dial. Overridable in tests for the same
// reason as lookupIPFunc.
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func defaultLookupIP(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, len(addrs))
	for i, a := range addrs {
		ips[i] = a.IP
	}
	return ips, nil
}

// isDisallowedIP reports whether ip must never be dialed by the guarded
// fetcher. This covers loopback, link-local unicast/multicast (which also
// covers the well-known 169.254.169.254 cloud-metadata address — called out
// explicitly here given its history as an SSRF target even though it is just
// another link-local address), RFC 1918 / ULA private-use ranges, the
// unspecified address, and multicast.
func isDisallowedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsPrivate() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

// resolveAllowedIP resolves host and returns the first address that is not
// disallowed, or ErrFetchDisallowedIP if host is a literal disallowed IP or
// every resolved address is disallowed.
func resolveAllowedIP(ctx context.Context, host string, lookup lookupIPFunc) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrFetchDisallowedIP, ip)
		}
		return ip, nil
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if !isDisallowedIP(ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("%w: %q resolves only to disallowed addresses", ErrFetchDisallowedIP, host)
}

// fetchGuardedURL is the injectable core of FetchGuardedURL. lookup and dial
// default to real DNS/TCP; tests substitute fakes so redirect/oversize/
// timeout behavior can be exercised against an httptest.Server (which listens
// on loopback) without weakening the production IP guard: a fake resolver
// returns an allowed-looking IP for the test host, and a fake dialer steers
// the actual TCP connection to the test server regardless of that IP. The
// disallowed-IP guard itself (isDisallowedIP/resolveAllowedIP) is exercised
// directly, unfaked, by its own unit tests.
func fetchGuardedURL(ctx context.Context, rawURL string, maxBytes int64, timeout time.Duration, lookup lookupIPFunc, dial dialFunc, tlsConfig *tls.Config) ([]byte, string, error) {
	if lookup == nil {
		lookup = defaultLookupIP
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse file_url: %w", err)
	}
	if u.Scheme != "https" {
		return nil, "", ErrFetchBadScheme
	}
	if u.Hostname() == "" {
		return nil, "", fmt.Errorf("file_url missing host")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				return nil, fmt.Errorf("split host/port %q: %w", addr, splitErr)
			}
			ip, resolveErr := resolveAllowedIP(ctx, host, lookup)
			if resolveErr != nil {
				return nil, resolveErr
			}
			// Dial the specific IP just validated, not the hostname again — a
			// second hostname lookup performed by net.Dial itself could return a
			// different (rebound) address than the one just checked. Every
			// connection this transport makes, including one triggered by a
			// redirect hop, passes through this same DialContext.
			return dial(ctx, network, net.JoinHostPort(ip.String(), port))
		},
		TLSClientConfig: tlsConfig,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxFetchRedirects {
				return fmt.Errorf("file_url: too many redirects (max %d)", maxFetchRedirects)
			}
			if req.URL.Scheme != "https" {
				return ErrFetchBadScheme
			}
			// The redirect target's address is re-validated by DialContext above
			// when this client follows it; nothing further to check here.
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		switch {
		case errors.Is(err, ErrFetchBadScheme):
			return nil, "", ErrFetchBadScheme
		case errors.Is(err, ErrFetchDisallowedIP):
			return nil, "", ErrFetchDisallowedIP
		case isTimeoutErr(err):
			return nil, "", ErrFetchTimeout
		default:
			return nil, "", fmt.Errorf("fetch file_url: %w", err)
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("file_url returned HTTP %d", resp.StatusCode)
	}

	if maxBytes > 0 && resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return nil, "", fmt.Errorf("%w: declared content-length %d bytes exceeds %d-byte cap", ErrFetchOversized, resp.ContentLength, maxBytes)
	}

	// Stream capped at maxBytes+1 so a response that lied about (or omitted)
	// its declared size is caught as "oversized" mid-stream instead of being
	// silently truncated at exactly maxBytes bytes.
	readLimit := maxBytes
	if readLimit <= 0 {
		readLimit = 1<<62 - 1 // no configured cap: effectively unbounded
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, readLimit+1))
	if err != nil {
		if isTimeoutErr(err) {
			return nil, "", ErrFetchTimeout
		}
		return nil, "", fmt.Errorf("read file_url body: %w", err)
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, "", fmt.Errorf("%w: response body exceeds %d-byte cap", ErrFetchOversized, maxBytes)
	}
	return data, resp.Header.Get("Content-Type"), nil
}

// FetchGuardedURL fetches rawURL through an SSRF-guarded HTTP client:
// HTTPS-only, DNS and every redirect hop's connect address checked against
// loopback/link-local/private ranges (with a dial-time re-check defending
// against DNS-rebinding between the check and the real connection), bounded
// by timeout, and capped at maxBytes (0 = uncapped). This is the only
// outbound-HTTP path in this server driven by caller-supplied input — treat
// any change here as security-sensitive.
func FetchGuardedURL(ctx context.Context, rawURL string, maxBytes int64, timeout time.Duration) ([]byte, string, error) {
	return fetchGuardedURL(ctx, rawURL, maxBytes, timeout, nil, nil, nil)
}

func isTimeoutErr(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
