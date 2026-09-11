package web

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/mctlhq/mctl-telegram/internal/netctx"
)

// HeaderProbe is a TEMPORARY measurement middleware for the Phase 3
// correlation work (mctlhq/mctl-telegram#617, Slice 1). It answers one
// question and no other: which request identifiers actually arrive at the
// tg.mctl.ai ingress, and are they stable across calls?
//
// It must be mounted on the real MCP path rather than on a side endpoint: a
// Cloudflare MCP Server Portal only proxies to the configured upstream MCP
// URL, so a dedicated /debug route would never be exercised by the path under
// measurement.
//
// Design constraints, all of which the tests pin:
//
//   - Off by default. The caller passes enabled explicitly; a disabled probe
//     logs nothing at all and is a pure pass-through.
//   - Header names are always logged in full, because the deliverable is the
//     complete observed set, not the subset someone guessed at.
//   - Values are sanitized (see sanitizeHeader). Secret-bearing headers are
//     reduced to a length plus a truncated SHA-256 fingerprint, which is what
//     makes "same value across three calls" provable without disclosing the
//     value. Address-bearing headers are masked the same way.
//   - The request body is never read, buffered or logged. Correlation
//     evidence must not cost message content.
//
// Remove this middleware together with its config flag once Slice 1 of #617
// has posted its header table; it is not part of the correlation contract.
func HeaderProbe(next http.Handler, enabled bool) http.Handler {
	if !enabled {
		return next
	}
	var seq atomic.Uint64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		names := make([]string, 0, len(r.Header))
		for name := range r.Header {
			names = append(names, strings.ToLower(name))
		}
		sort.Strings(names)

		attrs := make([]any, 0, len(names))
		for _, name := range names {
			attrs = append(attrs, slog.String(name, sanitizeHeader(name, r.Header.Values(name))))
		}

		slog.Info("header_probe",
			"probe_seq", seq.Add(1),
			"method", r.Method,
			"path", r.URL.Path,
			"proto", r.Proto,
			// The real TCP peer, not the RealIP-rewritten r.RemoteAddr: it is
			// what distinguishes a call arriving from the Cloudflare edge from
			// one arriving directly.
			"socket_peer", maskAddr(netctx.Peer(r.Context())),
			"header_names", strings.Join(names, ","),
			slog.Group("headers", attrs...),
		)
		next.ServeHTTP(w, r)
	})
}

// probeSecretHeaderParts are substrings that mark a header as secret-bearing.
// Matching is on the lowercased header name, so it also covers vendor headers
// nobody has seen yet -- the probe's whole point is that the header set is not
// known in advance, so the sanitizer fails closed on unknown names that look
// credential-like.
var probeSecretHeaderParts = []string{
	"authorization", "cookie", "token", "secret", "key", "password",
	"credential", "signature", "session", "auth",
}

// probeAddrHeaders carry a client address: useful as "does it arrive", not
// worth storing verbatim in logs.
var probeAddrHeaders = map[string]struct{}{
	"cf-connecting-ip": {},
	"true-client-ip":   {},
	"x-forwarded-for":  {},
	"x-real-ip":        {},
	"forwarded":        {},
	"x-client-ip":      {},
}

const probeValueMax = 256

// sanitizeHeader renders one header's values for the probe log. The returned
// string always tells the reader whether the header arrived, how long its
// value was, and -- via the fingerprint -- whether it was the same value as on
// another request, which is exactly the evidence Slice 1 needs.
func sanitizeHeader(lowerName string, values []string) string {
	joined := strings.Join(values, ", ")
	out := ""
	switch {
	case isProbeSecretHeader(lowerName):
		out = redactedWithFingerprint(joined)
	case isProbeAddrHeader(lowerName):
		out = maskAddrList(joined) + " " + fingerprint(joined)
	case len(joined) > probeValueMax:
		out = joined[:probeValueMax] + "...[truncated len=" + strconv.Itoa(len(joined)) + "]"
	default:
		out = joined
	}
	if len(values) > 1 {
		out += " [values=" + strconv.Itoa(len(values)) + "]"
	}
	return out
}

func isProbeSecretHeader(lowerName string) bool {
	for _, part := range probeSecretHeaderParts {
		if strings.Contains(lowerName, part) {
			return true
		}
	}
	return false
}

func isProbeAddrHeader(lowerName string) bool {
	_, ok := probeAddrHeaders[lowerName]
	return ok
}

func redactedWithFingerprint(v string) string {
	return "[redacted len=" + strconv.Itoa(len(v)) + " " + fingerprint(v) + "]"
}

// fingerprint is a truncated SHA-256 over the value. Eight hex characters are
// enough to compare two observations of the same header and far too few to
// reverse a bearer token.
func fingerprint(v string) string {
	if v == "" {
		return "fp=-"
	}
	sum := sha256.Sum256([]byte(v))
	return "fp=" + hex.EncodeToString(sum[:4])
}

func maskAddrList(v string) string {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = maskAddr(strings.TrimSpace(p))
	}
	return strings.Join(parts, ", ")
}

// maskAddr keeps the network-ish prefix of an address and drops the host part:
// 203.0.113.7:44310 becomes 203.0.x.x, 2001:db8::1 becomes 2001:db8:x. An
// input that is not an address is reduced to a fingerprint rather than passed
// through, so an unexpected shape cannot leak.
func maskAddr(v string) string {
	if v == "" {
		return ""
	}
	host := v
	if h, _, err := net.SplitHostPort(v); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fingerprint(v)
	}
	if v4 := ip.To4(); v4 != nil {
		return strconv.Itoa(int(v4[0])) + "." + strconv.Itoa(int(v4[1])) + ".x.x"
	}
	groups := strings.Split(ip.To16().String(), ":")
	if len(groups) > 2 {
		groups = groups[:2]
	}
	return strings.Join(groups, ":") + ":x"
}
