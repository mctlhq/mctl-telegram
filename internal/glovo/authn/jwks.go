package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	jwksTTL          = 10 * time.Minute
	jwksMinRefetch   = 30 * time.Second
	jwksMaxBytes     = 64 << 10
	jwksFetchTimeout = 5 * time.Second
)

// jwksCache holds the mctl-api public keys. The facade never holds a signing
// or shared secret: verification is asymmetric only.
type jwksCache struct {
	url    string
	client *http.Client
	now    func() time.Time

	// flight serializes refreshes so concurrent callers share one fetch.
	flight sync.Mutex

	mu          sync.Mutex
	set         jose.JSONWebKeySet
	loaded      bool
	fetchedAt   time.Time
	lastAttempt time.Time
}

func newJWKSCache(url string, client *http.Client, now func() time.Time) *jwksCache {
	if client == nil {
		client = &http.Client{Timeout: jwksFetchTimeout}
	}
	return &jwksCache{url: url, client: client, now: now}
}

// Loaded reports whether a JWKS has been fetched successfully at least once.
func (c *jwksCache) Loaded() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loaded
}

// refresh fetches unconditionally.
func (c *jwksCache) refresh(ctx context.Context) error {
	c.mu.Lock()
	c.lastAttempt = c.now()
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("fetch jwks: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes+1))
	if err != nil {
		return fmt.Errorf("read jwks: %w", err)
	}
	if len(body) > jwksMaxBytes {
		return errors.New("jwks response too large")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return errors.New("jwks malformed")
	}
	c.mu.Lock()
	c.set = set
	c.loaded = true
	c.fetchedAt = c.now()
	c.mu.Unlock()
	return nil
}

// key returns the public key for kid. An unknown kid triggers at most one
// refetch per jwksMinRefetch; a stale cache is refreshed after jwksTTL.
func (c *jwksCache) key(ctx context.Context, kid string) (*jose.JSONWebKey, error) {
	c.mu.Lock()
	loaded, stale := c.loaded, c.now().Sub(c.fetchedAt) > jwksTTL
	c.mu.Unlock()
	if !loaded || stale {
		if err := c.refreshThrottled(ctx); err != nil && !loaded {
			return nil, err
		}
	}
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	if err := c.refreshThrottled(ctx); err == nil {
		if k := c.lookup(kid); k != nil {
			return k, nil
		}
	}
	return nil, nil
}

var errJWKSBackoff = errors.New("jwks refresh throttled")

// refreshThrottled collapses concurrent refreshes into one and allows at most
// one attempt per jwksMinRefetch, successful or not. A caller that waited on
// another refresh re-checks the cache and does not fetch again.
func (c *jwksCache) refreshThrottled(ctx context.Context) error {
	c.flight.Lock()
	defer c.flight.Unlock()
	c.mu.Lock()
	now := c.now()
	fresh := c.loaded && now.Sub(c.fetchedAt) <= jwksTTL
	recent := !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < jwksMinRefetch
	c.mu.Unlock()
	if recent {
		if fresh {
			return nil
		}
		return errJWKSBackoff
	}
	return c.refresh(ctx)
}

func (c *jwksCache) lookup(kid string) *jose.JSONWebKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	ks := c.set.Key(kid)
	if len(ks) == 0 {
		return nil
	}
	k := ks[0]
	if !k.IsPublic() {
		return nil
	}
	return &k
}
