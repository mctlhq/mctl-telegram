package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Token self-renewal.
//
// Since mctl-telegram#412 a worker token is bounded (30 days by default), which
// turned expiry from a distant problem into a scheduled outage: on the expiry
// date the canary goes red and stays red until a human re-mints. The thing
// meant to warn about failures would have become a source of them.
//
// The canary therefore exchanges its own token for a fresh one shortly before
// expiry and writes the replacement back into the Secret it reads at startup.
// Two properties keep this from being a privilege grab:
//
//   - The server-side endpoint copies identity and scopes from the presented
//     token and cannot be asked for anything else, so the canary can extend its
//     own credential and nothing more. It is never given "admin:users", which
//     would have let a compromised probe mint a token for any account.
//   - Renewal is bounded in aggregate by the server (see workertoken's
//     maxRenewalChain), so the credential still dies on a schedule a human
//     controls — annually rather than monthly.
//
// Every failure here is non-fatal. The canary carries on with the token it
// already holds, which is by construction still valid: renewal only runs while
// there is life left. A broken renewal must never turn a healthy probe run into
// a red one, so it reports through its own metric label and the existing expiry
// gauge, both of which alert long before the token actually lapses.

const (
	// renewAtFraction is the share of a token's total lifetime that must
	// remain before renewal is attempted. A third leaves ~1400 further
	// CronJob ticks to notice and fix a broken renewal before the credential
	// actually expires, which is what makes fail-open the safe choice above.
	//
	// Deriving this from the token's OWN lifetime rather than hardcoding a
	// duration keeps the canary correct if the server's TTL ever changes.
	// cmd/canary has no imports from internal/ by design, so a constant
	// copied from workertoken.defaultWorkerTokenTTL could drift silently and
	// leave the probe renewing at the wrong point in its credential's life.
	renewAtFraction = 3

	// defaultRenewThreshold applies only when the token's lifetime cannot be
	// measured because it carries no iat claim. It matches a third of the
	// 30-day default TTL.
	defaultRenewThreshold = 10 * 24 * time.Hour
)

// Projected service-account paths. Variables rather than constants purely so
// tests can point them at a temporary directory; nothing at runtime rewrites
// them.
var (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // path, not a credential
	saCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// renewResponse is the JSON returned by POST /api/mcp/worker-token/renew. It
// matches the mint endpoint's response shape.
type renewResponse struct {
	WorkerToken string `json:"worker_token"`
	ExpiresAt   string `json:"expires_at"`
}

// renewConfig describes where the renewed token must be persisted. Renewal is
// enabled only when secretName is set: the binary must stay runnable outside
// Kubernetes (locally, in tests, from a laptop) without pretending it can
// write a Secret.
type renewConfig struct {
	enabled bool
	// threshold is meaningful only when thresholdExplicit is set; otherwise
	// renewThreshold derives it from the token itself.
	threshold         time.Duration
	thresholdExplicit bool
	secretName        string
	secretKey         string
	namespace         string
}

// loadRenewConfig reads the renewal settings. An unset CANARY_TOKEN_SECRET_NAME
// disables renewal entirely, which is the state every deployment starts in —
// enabling it is a deliberate act that must be paired with granting the pod
// RBAC on that one Secret.
func loadRenewConfig() (*renewConfig, error) {
	rc := &renewConfig{
		threshold: defaultRenewThreshold,
		secretKey: "bearer_token",
	}

	rc.secretName = strings.TrimSpace(os.Getenv("CANARY_TOKEN_SECRET_NAME"))
	if rc.secretName == "" {
		return rc, nil
	}
	rc.enabled = true

	if k := strings.TrimSpace(os.Getenv("CANARY_TOKEN_SECRET_KEY")); k != "" {
		rc.secretKey = k
	}

	// Namespace comes from the projected service-account volume by default so
	// the deployment cannot point the canary at another namespace by accident;
	// the override exists for tests.
	rc.namespace = strings.TrimSpace(os.Getenv("CANARY_TOKEN_SECRET_NAMESPACE"))
	if rc.namespace == "" {
		b, err := os.ReadFile(saNamespacePath)
		if err != nil {
			return nil, fmt.Errorf("CANARY_TOKEN_SECRET_NAME is set but the namespace could not be determined (%s): %w", saNamespacePath, err)
		}
		rc.namespace = strings.TrimSpace(string(b))
	}
	if rc.namespace == "" {
		return nil, errors.New("CANARY_TOKEN_SECRET_NAME is set but the resolved namespace is empty")
	}

	if s := strings.TrimSpace(os.Getenv("CANARY_TOKEN_RENEW_THRESHOLD")); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("CANARY_TOKEN_RENEW_THRESHOLD invalid duration %q: %w", s, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("CANARY_TOKEN_RENEW_THRESHOLD must be positive, got %q", s)
		}
		rc.threshold = d
		rc.thresholdExplicit = true
	}

	return rc, nil
}

// requestRenewedToken exchanges the current bearer for a fresh one.
func requestRenewedToken(ctx context.Context, client *http.Client, baseURL, token string) (string, time.Time, error) {
	url := baseURL + "/api/mcp/worker-token/renew"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, http.NoBody)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body may carry the server's reason (for example the renewal
		// chain being exhausted), which is the single most useful thing to
		// have in the log when this starts failing. It never contains a token.
		return "", time.Time{}, fmt.Errorf("POST %s returned HTTP %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out renewResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("parse JSON: %w", err)
	}
	if out.WorkerToken == "" {
		return "", time.Time{}, errors.New("response carried no worker_token")
	}
	// Trust the token's own exp over the response field: it is what every
	// later reader, including the expiry gauge, will act on.
	exp, ok := tokenExpiry(out.WorkerToken)
	if !ok {
		return "", time.Time{}, errors.New("renewed token carries no readable exp claim")
	}
	return out.WorkerToken, exp, nil
}

// newInClusterClient builds an HTTP client that trusts the cluster CA. It
// deliberately does not fall back to skipping verification: a canary that
// cannot verify the API server should fail its renewal, not paper over it.
func newInClusterClient(timeout time.Duration) (*http.Client, string, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, "", errors.New("KUBERNETES_SERVICE_HOST/PORT unset: not running in a cluster")
	}
	ca, err := os.ReadFile(saCACertPath)
	if err != nil {
		return nil, "", fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, "", errors.New("cluster CA bundle contained no usable certificate")
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return client, "https://" + net.JoinHostPort(host, port), nil
}

// persistToken writes the renewed token into the Secret the CronJob reads at
// startup. A strategic-merge patch touches only the one key, leaving
// tg_user_id and anything else in the Secret alone.
func persistToken(ctx context.Context, rc *renewConfig, timeout time.Duration, token string) error {
	client, apiBase, err := newInClusterClient(timeout)
	if err != nil {
		return err
	}
	saToken, err := os.ReadFile(saTokenPath)
	if err != nil {
		return fmt.Errorf("read service account token: %w", err)
	}

	payload, err := json.Marshal(map[string]any{
		"data": map[string]string{
			rc.secretKey: base64.StdEncoding.EncodeToString([]byte(token)),
		},
	})
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", apiBase, rc.namespace, rc.secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(saToken)))
	req.Header.Set("Content-Type", "application/strategic-merge-patch+json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("PATCH secret: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PATCH secret returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// renewToken performs the two-step renewal: ask the server for a fresh token,
// then persist it so the next CronJob run starts with it. The order matters —
// persisting first would risk writing a token this run never validated.
//
// The in-memory token is only adopted by the caller after BOTH steps succeed.
// A renewed-but-unpersisted token would work for this run and vanish, leaving
// the Secret holding a credential ever closer to expiry while every run
// reported success; that silent drift is worse than a loud, metric-visible
// failure.
func renewToken(ctx context.Context, cfg *config, log *slog.Logger) (string, time.Time, error) {
	client := &http.Client{Timeout: cfg.timeout}
	reqCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	tok, exp, err := requestRenewedToken(reqCtx, client, cfg.baseURL, cfg.bearerToken)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("request renewal: %w", err)
	}

	persistCtx, cancelPersist := context.WithTimeout(ctx, cfg.timeout)
	defer cancelPersist()
	if err := persistToken(persistCtx, cfg.renew, cfg.timeout, tok); err != nil {
		return "", time.Time{}, fmt.Errorf("persist renewed token to secret %s/%s: %w", cfg.renew.namespace, cfg.renew.secretName, err)
	}
	// The Secret's name is worth logging; the key name inside it is not. It
	// is a constant the CronJob already declares, adds nothing to an
	// operator reading this line, and CodeQL flags any value reached through
	// a field named secretKey as a clear-text-logging risk. Cheaper to drop
	// the field than to argue with the analyser about it.
	log.Info("renewed token persisted", "secret", cfg.renew.namespace+"/"+cfg.renew.secretName)
	return tok, exp, nil
}

// renewThreshold returns how much remaining life should trigger a renewal.
//
// An explicit CANARY_TOKEN_RENEW_THRESHOLD always wins. Otherwise the value is
// a fraction of this token's own lifetime, read from its iat and exp, so a
// change to the server's TTL is picked up without touching the canary. Tokens
// with no readable iat fall back to the fixed default.
func renewThreshold(rc *renewConfig, token string) time.Duration {
	if rc.thresholdExplicit {
		return rc.threshold
	}
	iat, ok := tokenIssuedAt(token)
	if !ok {
		return defaultRenewThreshold
	}
	exp, ok := tokenExpiry(token)
	if !ok {
		return defaultRenewThreshold
	}
	lifetime := exp.Sub(iat)
	if lifetime <= 0 {
		return defaultRenewThreshold
	}
	return lifetime / renewAtFraction
}

// tokenIssuedAt reads the iat claim without verifying the token, for the same
// reason tokenExpiry does: the canary holds no signing key, and the server
// checks the credential on every call.
func tokenIssuedAt(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Iat int64 `json:"iat"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Iat <= 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Iat, 0).UTC(), true
}

// renewThresholdFor returns the renewal threshold for cfg, or zero when
// renewal is switched off.
func renewThresholdFor(cfg *config) time.Duration {
	if cfg.renew == nil || !cfg.renew.enabled {
		return 0
	}
	return renewThreshold(cfg.renew, cfg.bearerToken)
}
