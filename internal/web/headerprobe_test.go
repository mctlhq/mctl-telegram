package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/audit"
)

// captureProbe runs one request through an enabled probe and returns the
// decoded log records plus what the wrapped handler saw.
func captureProbe(t *testing.T, reqs ...*http.Request) ([]map[string]any, []string) {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	var bodies []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		w.WriteHeader(http.StatusTeapot)
	})
	h := HeaderProbe(next, true)
	for _, req := range reqs {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	var recs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v (%q)", err, line)
		}
		recs = append(recs, rec)
	}
	return recs, bodies
}

func probeRequest(headers map[string]string, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// headersOf returns the headers group with the probeKeyPrefix stripped, so a
// test names a header the way the request did.
func headersOf(t *testing.T, rec map[string]any) map[string]any {
	t.Helper()
	group, ok := rec["headers"].(map[string]any)
	if !ok {
		t.Fatalf("record has no headers group: %v", rec)
	}
	out := make(map[string]any, len(group))
	for k, v := range group {
		if !strings.HasPrefix(k, "h:") {
			t.Errorf("header key %q is missing the probe prefix", k)
		}
		out[strings.TrimPrefix(k, "h:")] = v
	}
	return out
}

// The disabled probe must be inert, not merely quiet: a measurement tool left
// wired into the request path is a liability, so off means the same handler
// comes back untouched.
func TestHeaderProbe_DisabledIsAPassThrough(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	h := HeaderProbe(next, false)
	h.ServeHTTP(httptest.NewRecorder(), probeRequest(map[string]string{"Cf-Ray": "abc-DME"}, ""))

	if !called {
		t.Fatal("disabled probe did not call the wrapped handler")
	}
	if buf.Len() != 0 {
		t.Fatalf("disabled probe logged %q", buf.String())
	}
}

// Slice 1 of #617 needs the COMPLETE set of arriving header names, not the
// ones someone expected. Every name present on the request must appear.
func TestHeaderProbe_LogsEveryHeaderNameAndTheRouteFacts(t *testing.T) {
	recs, _ := captureProbe(t, probeRequest(map[string]string{
		"Cf-Ray":               "9c1f0b3ea0e1abcd-DME",
		"Cf-Connecting-Ip":     "203.0.113.7",
		"Traceparent":          "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		"Mcp-Protocol-Version": "2026-07-28",
		"X-Unexpected-Edge":    "portal-1",
	}, `{"jsonrpc":"2.0"}`))

	if len(recs) != 1 {
		t.Fatalf("want 1 probe record, got %d", len(recs))
	}
	rec := recs[0]
	if rec["msg"] != "header_probe" {
		t.Fatalf("unexpected log message %v", rec["msg"])
	}
	names, _ := rec["header_names"].(string)
	for _, want := range []string{"cf-ray", "cf-connecting-ip", "traceparent", "mcp-protocol-version", "x-unexpected-edge"} {
		if !strings.Contains(names, want) {
			t.Errorf("header_names %q is missing %q", names, want)
		}
	}
	if rec["path"] != "/mcp" || rec["method"] != http.MethodPost {
		t.Errorf("route facts missing: %v %v", rec["method"], rec["path"])
	}
	h := headersOf(t, rec)
	if h["cf-ray"] != "9c1f0b3ea0e1abcd-DME" {
		t.Errorf("a non-secret edge id must be logged verbatim, got %v", h["cf-ray"])
	}
	if h["x-unexpected-edge"] != "portal-1" {
		t.Errorf("an unknown header must still be recorded, got %v", h["x-unexpected-edge"])
	}
}

// The probe reads identifiers, never content. A bearer token must not survive
// into the log, and the request body must reach the handler untouched.
func TestHeaderProbe_RedactsSecretsAndNeverTouchesTheBody(t *testing.T) {
	const token = "Bearer eyJhbGciOiJIUzI1NiJ9.super-secret-payload.sig"
	recs, bodies := captureProbe(t, probeRequest(map[string]string{
		"Authorization":  token,
		"Cookie":         "sid=abc",
		"Mcp-Session-Id": "sess-123",
		"X-Api-Key":      "k-live-1",
	}, `{"method":"tools/call"}`))

	rec := recs[0]
	raw, _ := json.Marshal(rec)
	for _, secret := range []string{"super-secret-payload", "sid=abc", "sess-123", "k-live-1"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("probe log leaked %q: %s", secret, raw)
		}
	}
	h := headersOf(t, rec)
	for _, name := range []string{"authorization", "cookie", "mcp-session-id", "x-api-key"} {
		v, _ := h[name].(string)
		if !strings.HasPrefix(v, "[redacted len=") || !strings.Contains(v, "fp=") {
			t.Errorf("%s must be redacted with a fingerprint, got %q", name, v)
		}
	}
	if len(bodies) != 1 || bodies[0] != `{"method":"tools/call"}` {
		t.Fatalf("wrapped handler must see the untouched body, got %q", bodies)
	}
}

// "Is it a per-request id or a constant?" is the question Slice 1 exists to
// answer, so equal values must fingerprint equally and different ones must
// not -- for redacted headers too, where the value itself is unavailable.
func TestHeaderProbe_FingerprintDistinguishesRepeatsFromRotation(t *testing.T) {
	recs, _ := captureProbe(t,
		probeRequest(map[string]string{"Authorization": "Bearer same", "Cf-Connecting-Ip": "203.0.113.7"}, ""),
		probeRequest(map[string]string{"Authorization": "Bearer same", "Cf-Connecting-Ip": "203.0.113.7"}, ""),
		probeRequest(map[string]string{"Authorization": "Bearer diff", "Cf-Connecting-Ip": "198.51.100.9"}, ""),
	)
	if len(recs) != 3 {
		t.Fatalf("want 3 records, got %d", len(recs))
	}
	first := headersOf(t, recs[0])["authorization"]
	second := headersOf(t, recs[1])["authorization"]
	third := headersOf(t, recs[2])["authorization"]
	if first != second {
		t.Errorf("the same credential must fingerprint identically: %v vs %v", first, second)
	}
	// "Bearer diff" is the same byte length as "Bearer same": only the
	// fingerprint can separate them, so a constant fingerprint fails here.
	if first == third {
		t.Errorf("a different credential must fingerprint differently: %v", third)
	}
	for i, want := range []float64{1, 2, 3} {
		if recs[i]["probe_seq"] != want {
			t.Errorf("record %d has probe_seq %v, want %v", i, recs[i]["probe_seq"], want)
		}
	}
}

// A client address answers "did it arrive", and that is all it is kept for.
func TestHeaderProbe_MasksClientAddresses(t *testing.T) {
	recs, _ := captureProbe(t, probeRequest(map[string]string{
		"Cf-Connecting-Ip": "203.0.113.7",
		"X-Forwarded-For":  "203.0.113.7, 198.51.100.9",
	}, ""))

	h := headersOf(t, recs[0])
	cf, _ := h["cf-connecting-ip"].(string)
	if !strings.HasPrefix(cf, "203.0.x.x") || strings.Contains(cf, "113.7") {
		t.Errorf("cf-connecting-ip must be masked, got %q", cf)
	}
	xff, _ := h["x-forwarded-for"].(string)
	if strings.Contains(xff, "113.7") || strings.Contains(xff, "100.9") {
		t.Errorf("every hop in x-forwarded-for must be masked, got %q", xff)
	}
	if !strings.Contains(xff, "203.0.x.x") || !strings.Contains(xff, "198.51.x.x") {
		t.Errorf("x-forwarded-for must keep the hop structure, got %q", xff)
	}
}

// Repeated headers are one of the shapes a forwarded id can take; collapsing
// them silently would misreport the observed set.
func TestHeaderProbe_AnnotatesRepeatedHeaderValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Add("X-Edge-Hop", "one")
	req.Header.Add("X-Edge-Hop", "two")
	recs, _ := captureProbe(t, req)

	v, _ := headersOf(t, recs[0])["x-edge-hop"].(string)
	if !strings.Contains(v, "one") || !strings.Contains(v, "two") || !strings.Contains(v, "values=2") {
		t.Errorf("repeated values must be shown and counted, got %q", v)
	}
}

// Host is the finding that makes a header table wrong rather than incomplete:
// net/http deletes it from r.Header, so a probe that reports only r.Header
// publishes "no Host on this route", which on a route question is a false
// negative. httptest.NewRequest cannot show this -- it fills r.Host from the
// URL either way -- so this test drives a real server over a real socket.
func TestHeaderProbe_ReportsHostAndTransferFactsFromARealRequest(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	srv := httptest.NewServer(HeaderProbe(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Host"]; ok {
			t.Error("precondition changed: net/http now leaves Host in r.Header")
		}
		_, _ = io.ReadAll(r.Body)
	}), true))
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_ = resp.Body.Close()

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v (%q)", err, buf.String())
	}
	h := headersOf(t, rec)
	if h["host"] == nil || h["host"] == "" {
		t.Errorf("host must be reported even though net/http removed it from r.Header: %v", rec)
	}
	if names, _ := rec["header_names"].(string); !strings.Contains(names, "host") {
		t.Errorf("header_names must list host, got %q", names)
	}
	if rc, _ := rec["reconstructed"].(string); !strings.Contains(rc, "host") {
		t.Errorf("host came from the request struct and must be marked as reconstructed, got %q", rc)
	}
	if h["content-length"] == nil {
		t.Errorf("content-length must be reported, got %v", h)
	}
}

// The probe sits ahead of auth with no rate limiter, so one request must not
// be able to become an unbounded log line.
func TestHeaderProbe_CapsHeaderCountAndSaysHowManyItDropped(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	for i := 0; i < 200; i++ {
		req.Header.Set("X-Flood-"+strconv.Itoa(i), "x")
	}
	recs, _ := captureProbe(t, req)

	h := headersOf(t, recs[0])
	if len(h) > 64 {
		t.Errorf("logged %d headers, want at most 64", len(h))
	}
	omitted, _ := recs[0]["headers_omitted"].(float64)
	if omitted <= 0 {
		t.Errorf("headers_omitted must report the drop, got %v", recs[0]["headers_omitted"])
	}
	if names, _ := rec0Names(recs[0]); strings.Count(names, ",")+1 > 64 {
		t.Errorf("header_names must be capped too, got %d entries", strings.Count(names, ",")+1)
	}
}

func rec0Names(rec map[string]any) (string, bool) {
	s, ok := rec["header_names"].(string)
	return s, ok
}

// What the operator reads in production goes through audit.RedactingHandler,
// which rewrites any attribute whose key is exactly one of its sensitive names
// and recurses into groups to do it. The fingerprint must survive that, or the
// same-value-across-calls evidence is gone precisely for the credential-bearing
// headers.
func TestHeaderProbe_FingerprintSurvivesTheProductionRedactingHandler(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(audit.NewRedactingHandler(slog.NewJSONHandler(&buf, nil))))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := HeaderProbe(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), true)
	h.ServeHTTP(httptest.NewRecorder(), probeRequest(map[string]string{
		"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.secret-value.sig",
		"Cf-Ray":        "9c1f0b3ea0e1abcd-DME",
	}, ""))

	out := buf.String()
	if strings.Contains(out, "secret-value") {
		t.Fatalf("production handler chain leaked the credential: %s", out)
	}
	if !strings.Contains(out, "fp=") {
		t.Errorf("the fingerprint must survive the redacting handler: %s", out)
	}
	if !strings.Contains(out, "9c1f0b3ea0e1abcd-DME") {
		t.Errorf("a non-secret edge id must survive the redacting handler: %s", out)
	}
}

// A credential can ride in the value of a header whose name looks innocent.
// Referer with a token in the query is the case that actually happens.
func TestHeaderProbe_RedactsSecretsCarriedInValues(t *testing.T) {
	recs, _ := captureProbe(t, probeRequest(map[string]string{
		"Referer":                 "https://example.test/cb?access_token=abcdef123456&x=1",
		"Cf-Access-Jwt-Assertion": "eyJhbGciOiJSUzI1NiJ9.assertion-payload.sig",
		// Deliberately not JWT-shaped: only the NAME rule can catch this one,
		// so the test fails if "jwt" is dropped from probeSecretHeaderParts.
		"X-Acme-Jwt": "opaque-not-base64-value",
	}, ""))

	raw, _ := json.Marshal(recs[0])
	for _, secret := range []string{"abcdef123456", "assertion-payload", "opaque-not-base64-value"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("probe leaked %q: %s", secret, raw)
		}
	}
	h := headersOf(t, recs[0])
	for _, name := range []string{"referer", "cf-access-jwt-assertion", "x-acme-jwt"} {
		v, _ := h[name].(string)
		if !strings.HasPrefix(v, "[redacted len=") {
			t.Errorf("%s must be redacted, got %q", name, v)
		}
	}
}

// Truncation must not emit an invalid rune fragment.
func TestHeaderProbe_TruncatesOnARuneBoundary(t *testing.T) {
	recs, _ := captureProbe(t, probeRequest(map[string]string{
		// One ASCII byte shifts every rune boundary off the 256-byte cut, so a
		// byte slice lands mid-rune.
		"X-Long": "x" + strings.Repeat("й", 400),
	}, ""))

	v, _ := headersOf(t, recs[0])["x-long"].(string)
	if !strings.Contains(v, "truncated len=") {
		t.Fatalf("long value must be truncated, got %q", v)
	}
	if strings.ContainsRune(v, '�') {
		t.Errorf("truncation split a rune: %q", v)
	}
}

// The fingerprint is keyed, not a bare digest: an unsalted hash of a
// low-entropy secret is an offline verification oracle for anyone who can read
// the logs.
func TestHeaderProbe_FingerprintIsSaltedNotABareDigest(t *testing.T) {
	const value = "Bearer short"
	sum := sha256.Sum256([]byte(value))
	bare := "fp=" + hex.EncodeToString(sum[:4])
	if got := fingerprint(value); got == bare {
		t.Fatalf("fingerprint is an unsalted SHA-256 digest: %s", got)
	}
	if fingerprint(value) != fingerprint(value) {
		t.Error("fingerprint must be stable within a process")
	}
}
