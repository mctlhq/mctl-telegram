package k8ssa

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	saTokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	jwksPath     = "/openid/v1/jwks"
	maxJWKSBytes = 256 << 10
	// cacheTTL keeps keys long enough that a probe every few minutes does not
	// fetch, and short enough that a rotated-out key stops verifying soon.
	cacheTTL = time.Hour
	// minRefresh rate-limits forced refreshes: a stream of tokens naming an
	// unknown kid must not turn into a stream of API server requests.
	minRefresh = 30 * time.Second
)

// ClusterKeys fetches the cluster's service-account signing keys from the API
// server's issuer-discovery endpoint, authenticating with this pod's own
// ServiceAccount token. Kubernetes grants that endpoint to every
// ServiceAccount (system:service-account-issuer-discovery).
type ClusterKeys struct {
	client    *http.Client
	url       string
	tokenPath string
	now       func() time.Time

	mu        sync.Mutex
	set       *jose.JSONWebKeySet
	fetchedAt time.Time
	// failedAt and lastErr back off after a failed fetch. Without them an
	// empty or stale cache plus an erroring API server would turn every
	// request carrying the cluster iss, which is read before verification,
	// into another API server request.
	failedAt time.Time
	lastErr  error
}

// NewClusterKeys builds a key source for the cluster this process runs in.
// It refuses to start without the cluster CA rather than skip verification.
func NewClusterKeys(timeout time.Duration) (*ClusterKeys, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("KUBERNETES_SERVICE_HOST/PORT unset: not running in a cluster")
	}
	ca, err := os.ReadFile(saCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("cluster CA bundle contained no usable certificate")
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	return newClusterKeys(client, "https://"+net.JoinHostPort(host, port)+jwksPath, saTokenPath, time.Now), nil
}

func newClusterKeys(client *http.Client, url, tokenPath string, now func() time.Time) *ClusterKeys {
	return &ClusterKeys{client: client, url: url, tokenPath: tokenPath, now: now}
}

// Keys implements KeySource. A failed fetch is an error, never an empty set:
// the provider then refuses the token instead of treating "could not read the
// keys" as "no keys match".
func (c *ClusterKeys) Keys(ctx context.Context, refresh bool) (*jose.JSONWebKeySet, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	fresh := c.set != nil && now.Sub(c.fetchedAt) < cacheTTL
	if fresh && (!refresh || now.Sub(c.fetchedAt) < minRefresh) {
		return c.set, nil
	}
	if c.lastErr != nil && now.Sub(c.failedAt) < minRefresh {
		if fresh {
			// A forced refresh failed recently; keep serving the good set.
			return c.set, nil
		}
		return nil, fmt.Errorf("jwks fetch failed %s ago, not retrying yet: %w", now.Sub(c.failedAt).Round(time.Second), c.lastErr)
	}
	set, err := c.fetch(ctx)
	if err != nil {
		// A caller that cancelled or timed out its own request says nothing
		// about the API server; letting it start the backoff would let any
		// client lock everyone else out for minRefresh.
		if ctx.Err() == nil {
			c.failedAt, c.lastErr = now, err
		}
		return nil, err
	}
	c.set, c.fetchedAt, c.lastErr = set, now, nil
	return set, nil
}

func (c *ClusterKeys) fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	tok, err := os.ReadFile(c.tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read own service account token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	// The API server serves keys as application/jwk-set+json and answers 406
	// to an Accept that excludes it, such as plain application/json
	// (observed in prod on 2026-11-13).
	req.Header.Set("Accept", "application/jwk-set+json, application/json;q=0.9")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read jwks: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return nil, errors.New("jwks larger than 256 KiB")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("jwks contains no keys")
	}
	return &set, nil
}
