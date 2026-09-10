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
	req.Header.Set("Authorization", "Bearer "+unsignedJWT(`{"sub":"tg:8745115872","tg_id":8745115872,"device_id":"","exp":1788866352,"iat":1788862752}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if got := testutil.ToFloat64(m.AuthFailuresTotal.WithLabelValues("jwt_expired", "bridge")); got != 1 {
		t.Fatalf("mctl_auth_failures_total{reason=jwt_expired,provider=bridge} = %v, want 1", got)
	}
	line := buf.String()
	for _, want := range []string{`claimed_sub=tg:8745115872`, `claimed_tg_id=8745115872`, `claimed_exp=2026-09-08T11:19:12Z`, `reason=jwt_expired`} {
		if !strings.Contains(line, want) {
			t.Errorf("log line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(line, "nope") || strings.Contains(line, "eyJ") {
		t.Errorf("log line carries token material:\n%s", line)
	}
	// The generic body is unchanged: nothing about the claims reaches the client.
	if strings.Contains(rec.Body.String(), "8745115872") {
		t.Errorf("401 body leaked claims: %q", rec.Body.String())
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
