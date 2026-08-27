package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// jwtWithExp builds an unsigned-but-well-formed JWT carrying only exp. The
// canary never verifies its own token, so a real signature is unnecessary and
// would only couple this test to the signing package.
func jwtWithExp(exp time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return "aGRy." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

func TestLoadRenewConfig_DisabledWithoutSecretName(t *testing.T) {
	t.Setenv("CANARY_TOKEN_SECRET_NAME", "")
	rc, err := loadRenewConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.enabled {
		t.Fatal("renewal must stay off until a Secret is named; enabling it by default would make the canary fail every run in a cluster with no RBAC")
	}
}

func TestLoadRenewConfig_DefaultsAndOverrides(t *testing.T) {
	t.Setenv("CANARY_TOKEN_SECRET_NAME", "mctl-telegram-canary")
	t.Setenv("CANARY_TOKEN_SECRET_NAMESPACE", "labs")

	rc, err := loadRenewConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rc.enabled || rc.secretName != "mctl-telegram-canary" || rc.namespace != "labs" {
		t.Fatalf("unexpected config: %+v", rc)
	}
	if rc.secretKey != "bearer_token" {
		t.Fatalf("secretKey = %q, want the key the CronJob actually reads", rc.secretKey)
	}
	if rc.threshold != defaultRenewThreshold {
		t.Fatalf("threshold = %v, want %v", rc.threshold, defaultRenewThreshold)
	}

	t.Setenv("CANARY_TOKEN_RENEW_THRESHOLD", "48h")
	t.Setenv("CANARY_TOKEN_SECRET_KEY", "other_key")
	rc, err = loadRenewConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.threshold != 48*time.Hour || rc.secretKey != "other_key" {
		t.Fatalf("overrides not applied: %+v", rc)
	}
}

func TestLoadRenewConfig_RejectsBadThreshold(t *testing.T) {
	t.Setenv("CANARY_TOKEN_SECRET_NAME", "s")
	t.Setenv("CANARY_TOKEN_SECRET_NAMESPACE", "labs")
	for _, v := range []string{"nonsense", "0s", "-1h"} {
		t.Setenv("CANARY_TOKEN_RENEW_THRESHOLD", v)
		if _, err := loadRenewConfig(); err == nil {
			t.Fatalf("threshold %q accepted, want error", v)
		}
	}
}

// Namespace resolution must not silently default to something plausible: a
// wrong namespace would send the PATCH at a Secret in the wrong place.
func TestLoadRenewConfig_FailsWhenNamespaceUnresolvable(t *testing.T) {
	t.Setenv("CANARY_TOKEN_SECRET_NAME", "s")
	t.Setenv("CANARY_TOKEN_SECRET_NAMESPACE", "")
	old := saNamespacePath
	saNamespacePath = filepath.Join(t.TempDir(), "absent")
	defer func() { saNamespacePath = old }()

	if _, err := loadRenewConfig(); err == nil {
		t.Fatal("expected an error when the namespace cannot be determined")
	}
}

func TestRequestRenewedToken_ReturnsFreshToken(t *testing.T) {
	want := jwtWithExp(time.Now().Add(30 * 24 * time.Hour))
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(renewResponse{WorkerToken: want, ExpiresAt: "later"})
	}))
	defer srv.Close()

	tok, exp, err := requestRenewedToken(context.Background(), srv.Client(), srv.URL, "current-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != want {
		t.Fatalf("token = %q, want %q", tok, want)
	}
	if gotPath != "/api/mcp/worker-token/renew" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer current-token" {
		t.Fatalf("authorization = %q — renewal must authenticate with the token being renewed", gotAuth)
	}
	if time.Until(exp) < 29*24*time.Hour {
		t.Fatalf("exp %v not taken from the returned token", exp)
	}
}

// The expiry must come from the token itself, not the response envelope: the
// gauge and the next renewal decision both key off the token.
func TestRequestRenewedToken_RejectsTokenWithoutExp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(renewResponse{WorkerToken: "not.a.jwt", ExpiresAt: "2030-01-01T00:00:00Z"})
	}))
	defer srv.Close()
	if _, _, err := requestRenewedToken(context.Background(), srv.Client(), srv.URL, "t"); err == nil {
		t.Fatal("expected an error when the renewed token carries no readable exp")
	}
}

func TestRequestRenewedToken_SurfacesServerReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":"renewal window exhausted; an administrator must mint a new worker token"}`)
	}))
	defer srv.Close()
	_, _, err := requestRenewedToken(context.Background(), srv.Client(), srv.URL, "t")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "renewal window exhausted") {
		t.Fatalf("the server's reason must reach the log, got: %v", err)
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("status code should be in the error, got: %v", err)
	}
}

// inClusterFixture stands up a TLS server that impersonates the API server and
// points the projected-volume paths and KUBERNETES_* env at it.
func inClusterFixture(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.crt")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	tokPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokPath, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}

	oldCA, oldTok := saCACertPath, saTokenPath
	saCACertPath, saTokenPath = caPath, tokPath
	t.Cleanup(func() { saCACertPath, saTokenPath = oldCA, oldTok })

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", host)
	t.Setenv("KUBERNETES_SERVICE_PORT", port)
}

func TestPersistToken_PatchesOnlyTheTokenKey(t *testing.T) {
	var gotPath, gotAuth, gotCT string
	var gotBody map[string]any
	inClusterFixture(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth, gotCT = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "{}")
	})

	rc := &renewConfig{enabled: true, namespace: "labs", secretName: "mctl-telegram-canary", secretKey: "bearer_token"}
	if err := persistToken(context.Background(), rc, 5*time.Second, "the-new-token"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotPath != "/api/v1/namespaces/labs/secrets/mctl-telegram-canary" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer sa-token" {
		t.Fatalf("authorization = %q — the trailing newline in the projected token must be trimmed", gotAuth)
	}
	if gotCT != "application/strategic-merge-patch+json" {
		t.Fatalf("content-type = %q — a full replace would drop tg_user_id", gotCT)
	}
	data, _ := gotBody["data"].(map[string]any)
	if len(data) != 1 {
		t.Fatalf("patch touched %d keys, want exactly 1: %v", len(data), data)
	}
	enc, _ := data["bearer_token"].(string)
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("value is not base64: %v", err)
	}
	if string(raw) != "the-new-token" {
		t.Fatalf("patched value = %q", raw)
	}
}

func TestPersistToken_ErrorsOnNonOKStatus(t *testing.T) {
	inClusterFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"secrets \"mctl-telegram-canary\" is forbidden"}`)
	})
	rc := &renewConfig{enabled: true, namespace: "labs", secretName: "mctl-telegram-canary", secretKey: "bearer_token"}
	err := persistToken(context.Background(), rc, 5*time.Second, "t")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "is forbidden") {
		t.Fatalf("the RBAC reason must reach the log, got: %v", err)
	}
}

// Refusing to fall back to an unverified connection is deliberate: a canary
// that cannot authenticate the API server must not write its credential to it.
func TestNewInClusterClient_FailsWithoutUsableCA(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := saCACertPath
	saCACertPath = bad
	defer func() { saCACertPath = old }()
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")

	if _, _, err := newInClusterClient(time.Second); err == nil {
		t.Fatal("expected an error for an unusable CA bundle")
	}
}

// newCanaryServerWithRenew wraps the shared fake server with a renew route so
// these tests exercise the same probe path every other run() test does.
func newCanaryServerWithRenew(t *testing.T, renewCalls *int, renewHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	inner := newFakeServer(t, validOAuthHandler, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, validMCPResponse())
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/api/mcp/worker-token/renew", func(w http.ResponseWriter, r *http.Request) {
		*renewCalls++
		renewHandler(w, r)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, inner.URL+r.URL.Path, http.StatusTemporaryRedirect)
	})
	outer := httptest.NewServer(mux)
	t.Cleanup(func() { outer.Close(); inner.Close() })
	return outer
}

// gaugeValue reads the current value of the expiry gauge out of the registry.
func gaugeValue(t *testing.T, met *canaryMetrics) (float64, bool) {
	t.Helper()
	families, err := met.registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != "mctl_telegram_canary_token_expires_in_seconds" {
			continue
		}
		for _, m := range f.GetMetric() {
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func stepFailureCount(t *testing.T, met *canaryMetrics, step string) float64 {
	t.Helper()
	m := &dto.Metric{}
	c, err := met.stepFailures.GetMetricWithLabelValues(step)
	if err != nil {
		t.Fatalf("get counter: %v", err)
	}
	if err := c.(prometheus.Metric).Write(m); err != nil {
		t.Fatalf("write: %v", err)
	}
	return m.GetCounter().GetValue()
}

// Renewal must not fire while the token still has plenty of life: a canary
// that renewed on every run would mint 144 credentials a day.
func TestRun_DoesNotRenewWhileTokenIsFresh(t *testing.T) {
	var renewCalls int
	srv := newCanaryServerWithRenew(t, &renewCalls, func(w http.ResponseWriter, r *http.Request) {
		t.Error("renew must not be called while the token is fresh")
	})

	met := newCanaryMetrics()
	cfg := &config{
		baseURL:     srv.URL,
		bearerToken: jwtWithExp(time.Now().Add(29 * 24 * time.Hour)),
		tgUserID:    "924671154",
		timeout:     5 * time.Second,
		mcpPath:     "/mcp",
		renew:       &renewConfig{enabled: true, threshold: defaultRenewThreshold},
	}
	if ok := run(context.Background(), cfg, met); !ok {
		t.Fatal("run should have succeeded")
	}
	if renewCalls != 0 {
		t.Fatalf("renew called %d times on a fresh token", renewCalls)
	}
}

// A failing renewal must leave the run green: the token is still valid, and a
// red canary here would be a false alarm about the service under test.
func TestRun_RenewalFailureDoesNotFailTheRun(t *testing.T) {
	var renewCalls int
	srv := newCanaryServerWithRenew(t, &renewCalls, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, renewResponse{
			WorkerToken: jwtWithExp(time.Now().Add(30 * 24 * time.Hour)),
			ExpiresAt:   "later",
		})
	})

	met := newCanaryMetrics()
	cfg := &config{
		baseURL:     srv.URL,
		bearerToken: jwtWithExp(time.Now().Add(2 * 24 * time.Hour)),
		tgUserID:    "924671154",
		timeout:     5 * time.Second,
		mcpPath:     "/mcp",
		// enabled, but no in-cluster environment exists in a unit test, so the
		// persist step cannot succeed.
		renew: &renewConfig{enabled: true, threshold: defaultRenewThreshold, namespace: "labs", secretName: "s", secretKey: "bearer_token"},
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	if ok := run(context.Background(), cfg, met); !ok {
		t.Fatal("a failed renewal must not turn a healthy probe run red")
	}
	if renewCalls == 0 {
		t.Fatal("renewal should have been attempted on a near-expiry token")
	}
	if got := stepFailureCount(t, met, "token_renew"); got != 1 {
		t.Fatalf("token_renew failure counter = %v, want 1 — a silent renewal failure is how the token lapses unnoticed", got)
	}
	if v, ok := gaugeValue(t, met); !ok || v > (3*24*time.Hour).Seconds() {
		t.Fatalf("expiry gauge = %v (present=%v); it must keep reporting the OLD deadline so the alert still fires", v, ok)
	}
}
