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

// Package egress builds the HTTP clients the Personal Assistant uses for
// every outbound request it makes to a catalog MCP server: OAuth
// authorization-server metadata discovery, dynamic client registration, the
// token and revocation endpoints, and the MCP transport. It implements the
// egress policy of threat model T9
// (docs/agent-runtime/personal-assistant-threat-model.md):
//
//   - HTTPS on port 443 only.
//   - The request host must be on the per-server allowlist the caller takes
//     from the pinned catalog. The check runs on every request the client
//     sends, so it also covers each redirect hop.
//   - The host is resolved once at dial time. Every answer must be a public
//     unicast address (netsafe.PublicAddr) outside any extra denied prefix,
//     or the whole dial is refused. The connection is then opened to the
//     checked IP literal, never to the name, so a DNS rebind between the
//     check and the connect cannot swap the address.
//   - Proxy environment variables are ignored.
//   - Redirects are not followed. Discovery is the one exception: at most
//     MaxDiscoveryHops hops, each re-checked against the scheme, the
//     allowlist and the address rules.
//   - Each purpose has a total time limit and a response body cap. A body
//     over the cap is cut at the cap and the read fails with ErrTooLarge.
//
// Cluster ranges. The platform cluster runs k3s with its default pod CIDR
// 10.42.0.0/16 and service CIDR 10.43.0.0/16 (no override in mctl-gitops
// infrastructure/k3s-preview/kube.tf), and its nodes sit in 10.255.0.0/16.
// All of these are inside RFC 1918 10.0.0.0/8, which netsafe.PublicAddr
// already refuses, so no extra prefix is needed for them; the tests pin
// 10.42.x and 10.43.x explicitly. Config.DeniedPrefixes exists for a range
// that is not private.
//
// The package is library code: nothing in the runtime constructs these
// clients yet.
package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/netsafe"
)

// Errors. ErrNonPublic, ErrTooLarge and ErrRedirect are the netsafe values,
// so callers can match either package's sentinel.
var (
	ErrNotHTTPS          = errors.New("egress: only https URLs are allowed")
	ErrPort              = errors.New("egress: only port 443 is allowed")
	ErrHostNotAllowed    = errors.New("egress: host is not on the server allowlist")
	ErrNonPublic         = netsafe.ErrNonPublic
	ErrTooLarge          = netsafe.ErrTooLarge
	ErrRedirect          = netsafe.ErrRedirect
	ErrTooManyRedirects  = errors.New("egress: too many discovery redirects")
	ErrNoAddress         = errors.New("egress: host resolved to no address")
	ErrInvalidConfig     = errors.New("egress: invalid config")
	ErrDiscoveryRequest  = errors.New("egress: discovery is for unauthenticated GET requests only")
	errUserinfoInRequest = errors.New("egress: credentials in the URL are not allowed")
)

// MaxDiscoveryHops is the number of redirects a discovery request may follow.
const MaxDiscoveryHops = 2

// Purpose names the kind of request a client is for. It selects the default
// limits and whether redirects may be followed.
type Purpose int

// Purposes. Only PurposeDiscovery follows redirects.
//
// PurposeDiscovery is for unauthenticated GET (or HEAD) requests for public
// metadata documents only. Because it follows redirects, the transport
// refuses any other method, a request body, and an Authorization or Cookie
// header on a discovery client, on the first request and on every hop.
const (
	PurposeDiscovery Purpose = iota + 1
	PurposeRegistration
	PurposeToken
	PurposeRevocation
	PurposeMCP
)

func (p Purpose) String() string {
	switch p {
	case PurposeDiscovery:
		return "discovery"
	case PurposeRegistration:
		return "registration"
	case PurposeToken:
		return "token"
	case PurposeRevocation:
		return "revocation"
	case PurposeMCP:
		return "mcp"
	default:
		return fmt.Sprintf("purpose(%d)", int(p))
	}
}

type limits struct {
	timeout time.Duration
	maxBody int64
}

// defaultLimits are the per-purpose caps. OAuth documents are small; the MCP
// transport carries tools/list and tool results, which T10 caps further.
//
// The PurposeMCP total timeout bounds the whole exchange, body included, so
// a long streamable-HTTP/SSE response is cut at 30s. A caller that needs a
// longer stream raises Timeout up to the ceiling below.
var defaultLimits = map[Purpose]limits{
	PurposeDiscovery:    {timeout: 5 * time.Second, maxBody: 64 << 10},
	PurposeRegistration: {timeout: 10 * time.Second, maxBody: 64 << 10},
	PurposeToken:        {timeout: 10 * time.Second, maxBody: 64 << 10},
	PurposeRevocation:   {timeout: 10 * time.Second, maxBody: 16 << 10},
	PurposeMCP:          {timeout: 30 * time.Second, maxBody: 1 << 20},
}

// ceilingLimits bound the Config overrides: a value above the ceiling is
// refused with ErrInvalidConfig rather than silently clamped.
var ceilingLimits = map[Purpose]limits{
	PurposeDiscovery:    {timeout: 10 * time.Second, maxBody: 256 << 10},
	PurposeRegistration: {timeout: 30 * time.Second, maxBody: 256 << 10},
	PurposeToken:        {timeout: 30 * time.Second, maxBody: 256 << 10},
	PurposeRevocation:   {timeout: 30 * time.Second, maxBody: 64 << 10},
	PurposeMCP:          {timeout: 5 * time.Minute, maxBody: 8 << 20},
}

// Config configures one client.
type Config struct {
	// Purpose selects the default limits and the redirect rule. Required.
	Purpose Purpose
	// AllowedHosts is the server's host allowlist from the pinned catalog:
	// bare host names, no scheme, port, path or wildcard. Matching is exact
	// and case-insensitive. Required.
	AllowedHosts []string
	// DeniedPrefixes are refused on top of the netsafe rules, for example
	// cluster pod and service ranges that are not RFC 1918. They are matched
	// against the address and its IPv4-mapped or NAT64 unwrapped form.
	DeniedPrefixes []netip.Prefix
	// Timeout overrides the purpose's total request time limit when > 0.
	Timeout time.Duration
	// MaxBodyBytes overrides the purpose's response body cap when > 0.
	MaxBodyBytes int64
}

// resolver resolves a host name. *net.Resolver satisfies it.
type resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// hooks are test seams. They are unexported so production code cannot
// replace the resolver, the socket dial or the trust roots.
type hooks struct {
	resolver resolver
	connect  func(ctx context.Context, network, address string) (net.Conn, error)
	rootCAs  *x509.CertPool
}

// New returns an *http.Client that enforces the T9 egress policy for cfg.
func New(cfg Config) (*http.Client, error) {
	return newClient(cfg, hooks{})
}

type policy struct {
	purpose Purpose
	hosts   map[string]struct{}
	denied  []netip.Prefix
	maxBody int64
	res     resolver
	connect func(ctx context.Context, network, address string) (net.Conn, error)
}

func newClient(cfg Config, h hooks) (*http.Client, error) {
	lim, ok := defaultLimits[cfg.Purpose]
	if !ok {
		return nil, fmt.Errorf("%w: unknown purpose %v", ErrInvalidConfig, cfg.Purpose)
	}
	ceil := ceilingLimits[cfg.Purpose]
	if cfg.Timeout < 0 || cfg.Timeout > ceil.timeout {
		return nil, fmt.Errorf("%w: %s timeout %v outside (0, %v]", ErrInvalidConfig, cfg.Purpose, cfg.Timeout, ceil.timeout)
	}
	if cfg.MaxBodyBytes < 0 || cfg.MaxBodyBytes > ceil.maxBody {
		return nil, fmt.Errorf("%w: %s body cap %d outside (0, %d]", ErrInvalidConfig, cfg.Purpose, cfg.MaxBodyBytes, ceil.maxBody)
	}
	if cfg.Timeout > 0 {
		lim.timeout = cfg.Timeout
	}
	if cfg.MaxBodyBytes > 0 {
		lim.maxBody = cfg.MaxBodyBytes
	}
	if len(cfg.AllowedHosts) == 0 {
		return nil, fmt.Errorf("%w: empty host allowlist", ErrInvalidConfig)
	}
	p := &policy{
		purpose: cfg.Purpose,
		hosts:   make(map[string]struct{}, len(cfg.AllowedHosts)),
		maxBody: lim.maxBody,
		res:     h.resolver,
		connect: h.connect,
	}
	for _, raw := range cfg.AllowedHosts {
		host := normalizeHost(raw)
		if host == "" || strings.ContainsAny(host, "/:@*?#[] ") {
			return nil, fmt.Errorf("%w: bad allowlist entry %q", ErrInvalidConfig, raw)
		}
		// The catalog pins host names. An IP literal, or a name whose last
		// label is numeric or hex (which resolvers and the WHATWG URL parser
		// read as an IPv4 literal, such as "10.1" or "0x7f.1"), is refused.
		if _, err := netip.ParseAddr(host); err == nil || numericLastLabel(host) {
			return nil, fmt.Errorf("%w: allowlist entry %q is an IP literal", ErrInvalidConfig, raw)
		}
		p.hosts[host] = struct{}{}
	}
	for _, pfx := range cfg.DeniedPrefixes {
		if !pfx.IsValid() {
			return nil, fmt.Errorf("%w: bad denied prefix %v", ErrInvalidConfig, pfx)
		}
		// An IPv4-mapped prefix (::ffff:a.b.c.d/n) would never match the
		// native IPv4 answers a resolver returns, so it is stored as the
		// IPv4 prefix it denotes. One shorter than /96 does not denote an
		// IPv4 range and is refused rather than left to fail open.
		if pfx.Addr().Is4In6() {
			if pfx.Bits() < 96 {
				return nil, fmt.Errorf("%w: IPv4-mapped denied prefix %v is shorter than /96", ErrInvalidConfig, pfx)
			}
			pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
		}
		p.denied = append(p.denied, pfx.Masked())
	}
	if p.res == nil {
		p.res = net.DefaultResolver
	}
	if p.connect == nil {
		d := &net.Dialer{Timeout: lim.timeout, Control: p.control}
		p.connect = d.DialContext
	}

	base := &http.Transport{
		// Never consult HTTP_PROXY / HTTPS_PROXY / NO_PROXY.
		Proxy:                  nil,
		DialContext:            p.dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: h.rootCAs},
		ForceAttemptHTTP2:      true,
		TLSHandshakeTimeout:    lim.timeout,
		ResponseHeaderTimeout:  lim.timeout,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConnsPerHost:    4,
	}
	return &http.Client{
		Transport:     &policyTransport{p: p, base: base},
		Timeout:       lim.timeout,
		CheckRedirect: p.checkRedirect,
	}, nil
}

func numericLastLabel(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if last == "" {
		return false
	}
	if strings.HasPrefix(last, "0x") {
		last = last[2:]
		for _, r := range last {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return false
			}
		}
		return true
	}
	for _, r := range last {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

// checkURL enforces scheme, port and host allowlist for one request.
func (p *policy) checkURL(u *url.URL) error {
	if u == nil {
		return ErrNotHTTPS
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, u.Scheme)
	}
	if u.User != nil {
		return errUserinfoInRequest
	}
	if port := u.Port(); port != "" && port != "443" {
		return fmt.Errorf("%w: %s", ErrPort, port)
	}
	if !p.hostAllowed(u.Hostname()) {
		return fmt.Errorf("%w: %q", ErrHostNotAllowed, u.Hostname())
	}
	return nil
}

func (p *policy) hostAllowed(host string) bool {
	_, ok := p.hosts[normalizeHost(host)]
	return ok
}

// addrAllowed reports whether a resolved address may be dialled.
func (p *policy) addrAllowed(ip netip.Addr) bool {
	if !netsafe.PublicAddr(ip) {
		return false
	}
	ip = ip.WithZone("")
	un := netsafe.Unwrap(ip)
	for _, pfx := range p.denied {
		if pfx.Contains(ip) || pfx.Contains(un) {
			return false
		}
	}
	return true
}

// dial resolves the host once, refuses the dial if any answer is not
// allowed, and connects to a checked IP literal. Handing the name to the
// socket layer instead would let it resolve again and connect to whatever
// the second answer is.
func (p *policy) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("egress: dial %q: %w", addr, err)
	}
	if port != "443" {
		return nil, fmt.Errorf("%w: %s", ErrPort, port)
	}
	host = normalizeHost(host)
	if !p.hostAllowed(host) {
		return nil, fmt.Errorf("%w: dial %q", ErrHostNotAllowed, host)
	}
	var addrs []netip.Addr
	if ip, perr := netip.ParseAddr(host); perr == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = p.res.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("egress: resolve %q: %w", host, err)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%w: %q", ErrNoAddress, host)
	}
	// One denied answer refuses the host: a pinned server that resolves to
	// a mix of public and internal addresses is misconfigured or attacked.
	for _, a := range addrs {
		if !p.addrAllowed(a) {
			return nil, fmt.Errorf("%w: %q resolved to %s", ErrNonPublic, host, a)
		}
	}
	var lastErr error
	for _, a := range addrs {
		conn, derr := p.connect(ctx, network, net.JoinHostPort(a.WithZone("").String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	return nil, lastErr
}

// control is the net.Dialer Control hook: it sees the address of the socket
// about to connect. As the dialer is wired it is defence in depth: dial
// passes only an IP literal that addrAllowed has just accepted, so no test
// over the full client can tell it apart from its absence. It stays against
// a change that hands the dialer a host name.
func (p *policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonPublic, err)
	}
	if !p.addrAllowed(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNonPublic, ap.Addr())
	}
	return nil
}

// checkRedirect allows discovery to follow at most MaxDiscoveryHops hops.
// The target of each hop is checked by policyTransport like any request.
// For every other purpose policyTransport already fails a 3xx, so the
// refusal here is defence in depth.
func (p *policy) checkRedirect(_ *http.Request, via []*http.Request) error {
	if p.purpose != PurposeDiscovery {
		return ErrRedirect
	}
	if len(via) > MaxDiscoveryHops {
		return ErrTooManyRedirects
	}
	return nil
}

// policyTransport checks every request (including each redirect hop, which
// http.Client sends through the transport) and caps every response body.
type policyTransport struct {
	p    *policy
	base *http.Transport
}

func (t *policyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	err := t.p.checkURL(req.URL)
	if err == nil && t.p.purpose == PurposeDiscovery {
		err = checkDiscoveryRequest(req)
	}
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	// Every 3xx counts, 304 included: no client here sends a conditional
	// request, so a 304 is never a legitimate answer and must not reach the
	// caller as an empty success. Discovery may see only the redirect codes
	// http.Client follows; anything else in 3xx fails there too.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 &&
		(t.p.purpose != PurposeDiscovery || !followable(resp.StatusCode)) {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: %s answered %d", ErrRedirect, t.p.purpose, resp.StatusCode)
	}
	if resp.ContentLength > t.p.maxBody {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("%w: content length %d over %d", ErrTooLarge, resp.ContentLength, t.p.maxBody)
	}
	resp.Body = &capBody{rc: resp.Body, left: t.p.maxBody}
	return resp, nil
}

func followable(code int) bool {
	switch code {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// checkDiscoveryRequest keeps a redirect-following client to anonymous
// reads, so no credential can be carried to a hop.
func checkDiscoveryRequest(req *http.Request) error {
	if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != "" {
		return fmt.Errorf("%w: method %s", ErrDiscoveryRequest, req.Method)
	}
	if req.Body != nil && req.Body != http.NoBody {
		return fmt.Errorf("%w: request body", ErrDiscoveryRequest)
	}
	for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization"} {
		if req.Header.Get(h) != "" {
			return fmt.Errorf("%w: %s header", ErrDiscoveryRequest, h)
		}
	}
	return nil
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the base
// transport.
func (t *policyTransport) CloseIdleConnections() { t.base.CloseIdleConnections() }

// capBody returns at most left bytes. If the body has more, the read that
// crosses the cap returns the bytes up to it together with ErrTooLarge, and
// every later read returns ErrTooLarge: an oversized body is a failure,
// never a silent truncation.
type capBody struct {
	rc   io.ReadCloser
	left int64
	over bool
}

func (b *capBody) Read(buf []byte) (int, error) {
	if b.over {
		return 0, ErrTooLarge
	}
	if int64(len(buf)) > b.left+1 {
		buf = buf[:b.left+1]
	}
	n, err := b.rc.Read(buf)
	if int64(n) > b.left {
		n = int(b.left)
		b.left = 0
		b.over = true
		return n, ErrTooLarge
	}
	b.left -= int64(n)
	return n, err
}

func (b *capBody) Close() error { return b.rc.Close() }

// ReadBody reads and closes resp.Body. It fails with ErrTooLarge when the
// body exceeds the client's cap.
func ReadBody(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	return io.ReadAll(resp.Body)
}
