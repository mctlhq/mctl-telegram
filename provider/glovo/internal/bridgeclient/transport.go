package bridgeclient

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Bounds on every exchange.
const (
	RequestTimeout = 10 * time.Second
	MaxBodyBytes   = 64 << 10
	routePrefix    = "/api/v1/bridge/commands/"
)

// ErrOrigin is returned before dialing when a request leaves the pinned origin.
var ErrOrigin = errors.New("bridgeclient: request outside the configured origin")

// ParseOrigin validates MCTL_API_BASE_URL: an origin only (scheme, host, optional
// port). The scheme is https; http is allowed only for loopback hosts.
func ParseOrigin(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("MCTL_API_BASE_URL must be an absolute origin")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("MCTL_API_BASE_URL must be an origin only (no path, query, fragment or userinfo)")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("MCTL_API_BASE_URL may use http for loopback hosts only")
		}
	default:
		return nil, errors.New("MCTL_API_BASE_URL scheme must be https")
	}
	return &url.URL{Scheme: u.Scheme, Host: u.Host}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// originGuard refuses any request whose scheme/host/port differs from the
// origin, or whose path is outside the bridge routes, before dialing.
type originGuard struct {
	origin *url.URL
	next   http.RoundTripper
}

func (g originGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	u := r.URL
	if u.Scheme != g.origin.Scheme || !strings.EqualFold(u.Host, g.origin.Host) || u.User != nil ||
		!strings.HasPrefix(u.Path, routePrefix) {
		return nil, ErrOrigin
	}
	return g.next.RoundTrip(r)
}

// NewHTTPClient builds the client: no proxy (the environment is ignored), no
// redirects, a per-request timeout, and the origin guard.
func NewHTTPClient(origin *url.URL) *http.Client {
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: RequestTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
	}
	return &http.Client{
		Transport: originGuard{origin: origin, next: tr},
		Timeout:   RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("bridgeclient: redirects are refused")
		},
	}
}
