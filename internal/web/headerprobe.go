package web

import (
	"crypto/hmac"
	"crypto/rand"
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
		observed, reconstructed := probeHeaders(r)
		names := make([]string, 0, len(observed))
		for name := range observed {
			names = append(names, name)
		}
		sort.Strings(names)

		omitted := 0
		if len(names) > probeMaxHeaders {
			omitted = len(names) - probeMaxHeaders
			names = names[:probeMaxHeaders]
		}

		attrs := make([]any, 0, len(names))
		for _, name := range names {
			// The key is prefixed because audit.RedactingHandler recurses into
			// groups and rewrites any attribute whose key is exactly one of its
			// sensitive names -- `authorization`, `session`, `signature`,
			// `code`, `nonce`. That would replace this middleware's own output
			// wholesale, taking the fingerprint with it and leaving a `len=`
			// that is the length of the sanitized string rather than of the
			// value. Losing `fp=` on `authorization` would cost exactly the
			// same-value-across-calls evidence the probe exists to collect.
			// Sanitization is not weakened by the prefix: isProbeSecretHeader
			// matches by substring over a superset of those names, and the
			// probe never emits a raw secret for the outer handler to catch.
			attrs = append(attrs, slog.String(probeKeyPrefix+name, sanitizeHeader(name, observed[name])))
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
			// Which names were rebuilt from the request struct rather than read
			// from r.Header, so the table says where each fact came from.
			"reconstructed", strings.Join(reconstructed, ","),
			"headers_omitted", omitted,
			slog.Group("headers", attrs...),
		)
		next.ServeHTTP(w, r)
	})
}

// probeHeaders returns every header name the ingress saw, lowercased, together
// with the names that had to be rebuilt from the request struct.
//
// r.Header is NOT the arriving header set. net/http moves Host into r.Host and
// deletes it from the map, moves Transfer-Encoding into r.TransferEncoding, and
// readTransfer removes Content-Length on a chunked request. Reporting r.Header
// alone would publish a table with no Host on any line -- and on a measurement
// of which route a call arrived through, a missing Host is indistinguishable
// from "the Portal did not send one".
//
// HTTP/2 pseudo-headers (:authority, :scheme, :path) are a different case: the
// net/http server never exposes them, :authority is surfaced as r.Host, and no
// reconstruction can recover the rest. The proto field records which transport
// the line came from so the reader can account for that themselves.
func probeHeaders(r *http.Request) (map[string][]string, []string) {
	observed := make(map[string][]string, len(r.Header)+3)
	for name, values := range r.Header {
		observed[strings.ToLower(name)] = values
	}
	var reconstructed []string
	add := func(name string, values ...string) {
		if _, ok := observed[name]; ok {
			return
		}
		observed[name] = values
		reconstructed = append(reconstructed, name)
	}
	if r.Host != "" {
		add("host", r.Host)
	}
	if len(r.TransferEncoding) > 0 {
		add("transfer-encoding", strings.Join(r.TransferEncoding, ", "))
	}
	if r.ContentLength >= 0 {
		add("content-length", strconv.FormatInt(r.ContentLength, 10))
	}
	sort.Strings(reconstructed)
	return observed, reconstructed
}

// probeSecretHeaderParts are substrings that mark a header as secret-bearing.
// Matching is on the lowercased header name, so it also covers vendor headers
// nobody has seen yet -- the probe's whole point is that the header set is not
// known in advance, so the sanitizer fails closed on unknown names that look
// credential-like.
var probeSecretHeaderParts = []string{
	"authorization", "cookie", "token", "secret", "key", "password",
	"credential", "signature", "session", "auth",
	// Cloudflare Access asserts the end-user identity in
	// Cf-Access-Jwt-Assertion, which is a signed JWT and matches none of the
	// substrings above -- on the very route this probe is pointed at.
	"jwt", "assertion", "bearer",
}

// probeSecretValueParts catch a credential carried in the VALUE of a header
// whose name looks innocent. Referer is the realistic case: a URL with
// ?access_token=... in its query is otherwise copied into the log verbatim,
// because the name-based rule never looks at the value. A JWT is matched by
// its "eyJ" header prefix.
var probeSecretValueParts = []string{
	"token=", "secret=", "password=", "apikey=", "api_key=", "access_key=",
	"signature=", "bearer ", "eyJ",
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

const (
	probeValueMax = 256
	// probeMaxHeaders bounds one log line. The probe is deliberately outermost,
	// so it runs ahead of auth with no rate limiter on the root router and with
	// MaxHeaderBytes at its 1 MiB default: without a cap an anonymous caller who
	// knows MCP_PATH turns every request into a multi-thousand-attribute line.
	// That is a log-cost hazard on the production ingress and it buries the
	// Portal lines the measurement is there to collect. A real request carries
	// well under this many headers, so the cap costs the measurement nothing and
	// headers_omitted reports whenever it bit.
	probeMaxHeaders = 64
	// probeKeyPrefix keeps header keys out of audit.RedactingHandler's exact-key
	// match -- see the call site.
	probeKeyPrefix = "h:"
)

// sanitizeHeader renders one header's values for the probe log. The returned
// string always tells the reader whether the header arrived, how long its
// value was, and -- via the fingerprint -- whether it was the same value as on
// another request, which is exactly the evidence Slice 1 needs.
func sanitizeHeader(lowerName string, values []string) string {
	joined := strings.Join(values, ", ")
	out := ""
	switch {
	case isProbeSecretHeader(lowerName), hasProbeSecretValue(joined):
		out = redactedWithFingerprint(joined)
	case isProbeAddrHeader(lowerName):
		out = maskAddrList(joined) + " " + fingerprint(joined)
	case len(joined) > probeValueMax:
		// Truncation is on a rune boundary: a byte slice through a multi-byte
		// rune emits an invalid fragment that slog renders as U+FFFD.
		out = strings.ToValidUTF8(joined[:probeValueMax], "") + "...[truncated len=" + strconv.Itoa(len(joined)) + "]"
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

func hasProbeSecretValue(v string) bool {
	lower := strings.ToLower(v)
	for _, part := range probeSecretValueParts {
		if strings.Contains(lower, strings.ToLower(part)) {
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

// probeFPKey salts the fingerprint. It is random per process and never logged.
//
// An unsalted hash of a low-entropy secret -- a Basic password, a short session
// id -- is a verification oracle: a reader of the logs can confirm a guess
// offline against the 32 published bits. Keying the hash removes that without
// touching what the probe needs, because every comparison it makes is between
// two observations from the same process.
//
// The cost is deliberate and documented in the runbook: fingerprints are not
// comparable across a restart or between replicas, so a measurement window's
// repeated calls must land on one process.
var probeFPKey = newProbeFPKey()

func newProbeFPKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// crypto/rand failing is not recoverable here, and a probe that
		// silently falls back to an unsalted hash is the thing this guards
		// against. Degrade to a constant that makes every fingerprint useless
		// rather than to one that is attackable.
		return nil
	}
	return key
}

// fingerprint is a truncated HMAC-SHA-256 over the value. Eight hex characters
// are enough to tell two observations of the same header apart from a rotated
// one, which is the per-request-id-versus-constant question, and carry no
// usable information about the value itself.
func fingerprint(v string) string {
	if v == "" {
		return "fp=-"
	}
	if probeFPKey == nil {
		return "fp=unavailable"
	}
	mac := hmac.New(sha256.New, probeFPKey)
	mac.Write([]byte(v))
	return "fp=" + hex.EncodeToString(mac.Sum(nil)[:4])
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
