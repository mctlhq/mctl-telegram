package bridge

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// unsignedJWT builds a three-segment token whose payload carries the given
// JSON. The signature is garbage: the handler must log the claims for the
// operator without trusting them.
func unsignedJWT(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".nope"
}

// A refused daemon is the one incident this endpoint has. The log line must
// say which daemon (the claims, read unverified) and the failure must be
// counted where the alert can see it, under the same reason labels the HTTP
// middleware uses. Before #612 the line said only `JWT expired` and no
// counter moved, and the loop ran for two days.
func TestBridgeHandler_AuthFailureIsCountedAndNamesTheClaimedDaemon(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	m := metrics.New()
	h := NewBridgeHandlerWithMetrics(NewHub(), failProvider{err: errors.New("JWT expired")}, nil, context.Background(), m)

	req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
	req.Header.Set("Authorization", "Bearer "+unsignedJWT(`{"sub":"tg:700000011","tg_id":700000011,"device_id":"","exp":1788866352,"iat":1788862752}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := testutil.ToFloat64(m.AuthFailuresTotal.WithLabelValues("jwt_expired", "bridge")); got != 1 {
		t.Fatalf("mctl_auth_failures_total{reason=jwt_expired,provider=bridge} = %v, want 1", got)
	}
	line := buf.String()
	for _, want := range []string{`claimed_sub=tg:700000011`, `claimed_tg_id=700000011`, `claimed_exp=2026-09-08T11:19:12Z`, `reason=jwt_expired`} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "nope") || strings.Contains(line, "eyJ") {
		t.Errorf("log line carries token material:\n%s", line)
	}
	// The generic body is unchanged: nothing about the claims reaches the client.
	if strings.Contains(rec.Body.String(), "700000011") {
		t.Errorf("401 body leaked claims: %q", rec.Body.String())
	}
}

// An unauthenticated caller must not be able to push a megabyte into the
// log through the claims: an oversized payload yields nothing, and a long
// sub is clipped.
func TestClaimedIdentity_IsBounded(t *testing.T) {
	big := unsignedJWT(`{"sub":"` + strings.Repeat("a", 8000) + `"}`)
	req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
	req.Header.Set("Authorization", "Bearer "+big)
	if got := claimedIdentity(req); got != (claimedIdentityFields{}) {
		t.Fatalf("oversized payload was decoded: %+v", got)
	}
	long := unsignedJWT(`{"sub":"` + strings.Repeat("b", 500) + `","tg_id":700000011}`)
	req = httptest.NewRequest(http.MethodGet, "/bridge", nil)
	req.Header.Set("Authorization", "Bearer "+long)
	got := claimedIdentity(req)
	if len(got.Subject) != maxClaimedFieldLen || got.TelegramID != 700000011 {
		t.Fatalf("long sub not clipped or sibling claim lost: len(sub)=%d tg_id=%d", len(got.Subject), got.TelegramID)
	}
}

// One claim of the wrong type must not drop the others: the helper decodes
// field by field, so a device_id sent as a number still leaves sub in place.
func TestClaimedIdentity_FieldsAreIndependent(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
	req.Header.Set("Authorization", "Bearer "+unsignedJWT(`{"sub":"tg:700000011","device_id":42,"tg_id":"not-a-number","exp":1788866352}`))
	got := claimedIdentity(req)
	if got.Subject != "tg:700000011" || got.DeviceID != "" || got.TelegramID != 0 || got.ExpiresAt != "2026-09-08T11:19:12Z" {
		t.Fatalf("got %+v", got)
	}
}

// Every refusal branch counts and names the daemon, not only the verifier's.
func TestBridgeHandler_EveryRefusalIsCounted(t *testing.T) {
	m := metrics.New()
	// nil identity, no error: the "no token" branch.
	h := NewBridgeHandlerWithMetrics(NewHub(), failProvider{err: nil}, nil, context.Background(), m)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bridge", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := testutil.ToFloat64(m.AuthFailuresTotal.WithLabelValues("no_token", "bridge")); got != 1 {
		t.Fatalf("no_token counter = %v, want 1", got)
	}
}

// exp and iat are NumericDate: a fractional value is still a timestamp, and
// the identifying claims next to it must survive it.
func TestClaimedIdentity_AcceptsFractionalNumericDate(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
	req.Header.Set("Authorization", "Bearer "+unsignedJWT(`{"sub":"tg:1","tg_id":1,"exp":1788866352.5,"iat":1788862752.0}`))
	got := claimedIdentity(req)
	if got.Subject != "tg:1" || got.TelegramID != 1 || got.ExpiresAt != "2026-09-08T11:19:12Z" || got.IssuedAt != "2026-09-08T10:19:12Z" {
		t.Fatalf("got %+v", got)
	}
}

// No bearer, a non-JWT bearer, and an undecodable payload all degrade to
// empty fields rather than a panic or a skipped log line.
func TestClaimedIdentity_ToleratesGarbage(t *testing.T) {
	for _, h := range []string{"", "Bearer", "Bearer not.a.jwt.at.all", "Bearer a.!!!.c", "Bearer " + base64.RawURLEncoding.EncodeToString([]byte("x")) + ".Zm9v.c"} {
		req := httptest.NewRequest(http.MethodGet, "/bridge", nil)
		if h != "" {
			req.Header.Set("Authorization", h)
		}
		if got := claimedIdentity(req); got != (claimedIdentityFields{}) {
			t.Errorf("Authorization %q: got %+v, want zero", h, got)
		}
	}
}
