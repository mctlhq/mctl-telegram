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

// Package netsafe provides an HTTP client that can reach public addresses
// only, for fetching a URL a third party chose (a client metadata document).
// It refuses every non-public destination, ignores proxy environment
// variables and follows no redirect. DNS rebinding cannot reach a refused
// address because the dialer resolves the host once, filters the answers with
// PublicAddr and connects to the accepted IP literal itself: there is no
// second resolution between the check and the connect.
package netsafe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNonPublic is returned when a destination is not a public address.
var ErrNonPublic = errors.New("netsafe: destination is not a public address")

// ErrTooLarge is returned by ReadLimited when the body exceeds the cap.
var ErrTooLarge = errors.New("netsafe: response body too large")

// ErrRedirect is returned for any 3xx answer.
var ErrRedirect = errors.New("netsafe: redirects are not followed")

// Resolver resolves a host name to addresses. *net.Resolver satisfies it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures Client.
type Options struct {
	// Timeout is the total request timeout. Default 5s.
	Timeout time.Duration
	// AllowedPorts lists the destination ports. Default [443].
	AllowedPorts []int
	// Resolver defaults to net.DefaultResolver; tests inject a stub.
	Resolver Resolver
}

var refused = mustPrefixes(
	"0.0.0.0/8",
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24", // deprecated 6to4 relay anycast
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
	"fc00::/7",
	"fe80::/10",
	"2001:db8::/32",
	"100::/64",
	"::/96",          // IPv4-compatible IPv6 (Is4In6 matches only ::ffff:)
	"2002::/16",      // 6to4, which carries an IPv4 address
	"2001::/23",      // IETF protocol assignments (RFC 2928), including Teredo, which carries an IPv4 address, and benchmarking
	"3fff::/20",      // documentation (RFC 9637)
	"64:ff9b:1::/48", // local-use NAT64
	"fec0::/10",      // deprecated site-local
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, p := range s {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// PublicAddr reports whether ip is a public unicast address. IPv4-mapped
// IPv6 and NAT64 (64:ff9b::/96) forms are unwrapped and judged as the IPv4
// address they carry.
func PublicAddr(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.WithZone("")
	if ip.Is4In6() {
		ip = ip.Unmap()
	} else if ip.Is6() && nat64.Contains(ip) {
		b := ip.As16()
		ip = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range refused {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// controlPublic is the net.Dialer Control hook: it sees the address of the
// socket about to connect and refuses a non-public one. As the dialer is
// wired it is redundant: DialContext dials only an IP literal PublicAddr has
// just accepted, so no input reaches it that the loop has not judged, and no
// test can tell it apart from its absence. That PublicAddr filter is what
// holds the guarantee (pinned by TestResolvedNonPublicRefused and
// TestDirectIPAndPortRefused). The hook stays as defence in depth against a
// change that hands the dialer the host name instead of the literal.
func controlPublic(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNonPublic, err)
	}
	if !PublicAddr(ap.Addr()) {
		return ErrNonPublic
	}
	return nil
}

// Client returns an *http.Client that can reach public addresses only.
func Client(opts Options) *http.Client {
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	ports := opts.AllowedPorts
	if len(ports) == 0 {
		ports = []int{443}
	}
	res := opts.Resolver
	if res == nil {
		res = net.DefaultResolver
	}
	dialer := &net.Dialer{
		Timeout: opts.Timeout,
		// Defence in depth only; see controlPublic.
		Control: controlPublic,
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, err := net.LookupPort(network, portStr)
			if err != nil {
				return nil, err
			}
			okPort := false
			for _, p := range ports {
				if p == port {
					okPort = true
				}
			}
			if !okPort {
				return nil, fmt.Errorf("netsafe: port %d is not allowed", port)
			}
			var addrs []netip.Addr
			if ip, perr := netip.ParseAddr(host); perr == nil {
				addrs = []netip.Addr{ip}
			} else {
				addrs, err = res.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return nil, err
				}
			}
			lastErr := ErrNonPublic
			for _, a := range addrs {
				if !PublicAddr(a) {
					continue
				}
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), portStr))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			return nil, lastErr
		},
		TLSHandshakeTimeout:   opts.Timeout,
		ResponseHeaderTimeout: opts.Timeout,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   opts.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirect
		},
	}
}

// ReadLimited reads at most max bytes of the body and fails with ErrTooLarge
// if there is more: an oversized body is a failure, never a truncation.
func ReadLimited(resp *http.Response, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}
