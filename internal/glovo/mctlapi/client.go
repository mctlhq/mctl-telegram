package mctlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/propagation"

	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
)

const (
	// MaxResponseBytes caps every mctl-api response body.
	MaxResponseBytes = 256 << 10
	callTimeout      = 5 * time.Second
)

// Wire header names.
const (
	HeaderSubjectToken = "X-Mctl-Subject-Token"
	// HeaderSelectedTenant is untrusted and diagnostic only: mctl-api must
	// derive the selected team from the verified, server-owned grant.
	HeaderSelectedTenant = "X-Mctl-Selected-Tenant"
	HeaderScopeRef       = "X-Mctl-Scope-Ref"
	HeaderRequestID      = "X-Request-Id"
)

var opaqueID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

type opSpec struct {
	method string
	path   string
	retry  retryKind
}

type retryKind int

const (
	retryRead retryKind = iota
	retryReset
	retryNone
)

var ops = map[Op]opSpec{
	OpConnection: {http.MethodGet, "/connection", retryRead},
	OpConnect:    {http.MethodPost, "/connections", retryReset},
	OpOrders:     {http.MethodPost, "/orders:list", retryRead},
	OpPreview:    {http.MethodPost, "/previews", retryNone},
	OpBasket:     {http.MethodGet, "/basket", retryRead},
	OpPrepare:    {http.MethodPost, "/orders:prepare", retryReset},
	OpOrder:      {http.MethodGet, "/orders/", retryRead},
}

// HTTPClient is the HTTP implementation of Client.
type HTTPClient struct {
	base       string
	credential func() (string, error)
	http       *http.Client
	// OnCall observes one upstream request (op, status class); optional.
	OnCall func(op string, code int)
}

// NewHTTPClient builds a client. credential returns the facade workload
// credential on every call.
func NewHTTPClient(baseURL string, credential func() (string, error), hc *http.Client) *HTTPClient {
	if hc == nil {
		hc = &http.Client{Timeout: callTimeout}
	}
	return &HTTPClient{base: strings.TrimRight(baseURL, "/"), credential: credential, http: hc}
}

// FileCredential returns a credential func that re-reads path when its
// modification time changes (a mounted secret rotates in place).
func FileCredential(path string) func() (string, error) {
	var mu sync.Mutex
	var mod time.Time
	var cached string
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		fi, err := os.Stat(path)
		if err != nil {
			return "", errors.New("credential unreadable")
		}
		if cached == "" || !fi.ModTime().Equal(mod) {
			b, err := os.ReadFile(path)
			if err != nil {
				return "", errors.New("credential unreadable")
			}
			cached, mod = strings.TrimSpace(string(b)), fi.ModTime()
		}
		if cached == "" {
			return "", errors.New("credential empty")
		}
		return cached, nil
	}
}

// Resolve implements Client.
func (c *HTTPClient) Resolve(ctx context.Context) (Scope, error) {
	body, err := c.roundTrip(ctx, "resolve", http.MethodPost, "/resolve", []byte("{}"), "", retryNone)
	if err != nil {
		return Scope{}, err
	}
	var r struct {
		ScopeRef  string    `json:"scope_ref"`
		Tenant    string    `json:"tenant"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil || r.ScopeRef == "" || r.Tenant == "" {
		return Scope{}, Refuse(CodeUpstreamInvalid)
	}
	return Scope{Ref: r.ScopeRef, Tenant: r.Tenant, ExpiresAt: r.ExpiresAt}, nil
}

// Do implements Client.
func (c *HTTPClient) Do(ctx context.Context, scope Scope, op Op, body any, pathID string) (json.RawMessage, error) {
	spec, ok := ops[op]
	if !ok || scope.Ref == "" {
		return nil, Refuse(CodeUpstreamInvalid)
	}
	path := spec.path
	if op == OpOrder {
		if !opaqueID.MatchString(pathID) {
			// An id that cannot exist is indistinguishable from a foreign one.
			return nil, Refuse(CodeNotFound)
		}
		path += url.PathEscape(pathID)
	}
	var payload []byte
	if spec.method == http.MethodPost {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, Refuse(CodeUpstreamInvalid)
		}
	}
	return c.roundTrip(ctx, string(op), spec.method, path, payload, scope.Ref, spec.retry)
}

// Health implements Client. It uses the API base /healthz with a 2 s bound.
func (c *HTTPClient) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("mctl-api health: request failed")
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mctl-api health: status %d", resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) roundTrip(ctx context.Context, op, method, path string, payload []byte, scopeRef string, rk retryKind) (json.RawMessage, error) {
	attempts := 1
	if rk != retryNone {
		attempts = 2
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			select {
			case <-time.After(time.Duration(20+rand.IntN(60)) * time.Millisecond):
			case <-ctx.Done():
				return nil, Refuse(CodeUpstreamUnavailable)
			}
		}
		body, status, retriable, err := c.once(ctx, method, path, payload, scopeRef)
		if c.OnCall != nil {
			c.OnCall(op, status)
		}
		if err == nil {
			return body, nil
		}
		lastErr = err
		if !retriable {
			break
		}
		if rk == retryReset && status != 0 {
			break // only a connection reset is retried for idempotent writes
		}
	}
	return nil, lastErr
}

// once performs a single HTTP exchange. retriable is true for a transport
// failure or a 5xx; status is 0 for a transport failure.
func (c *HTTPClient) once(ctx context.Context, method, path string, payload []byte, scopeRef string) (json.RawMessage, int, bool, error) {
	cred, err := c.credential()
	if err != nil {
		return nil, 0, false, Refuse(CodeUpstreamUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	defer cancel()
	var rd io.Reader
	if payload != nil {
		rd = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+BasePath+path, rd)
	if err != nil {
		return nil, 0, false, Refuse(CodeUpstreamUnavailable)
	}
	req.Header.Set("Authorization", "Bearer "+cred)
	req.Header.Set(HeaderSubjectToken, authn.SubjectToken(ctx))
	if p := authn.FromContext(ctx); p != nil {
		req.Header.Set(HeaderSelectedTenant, p.Tenant)
	}
	if id := authn.RequestID(ctx); id != "" {
		req.Header.Set(HeaderRequestID, id)
	}
	if scopeRef != "" {
		req.Header.Set(HeaderScopeRef, scopeRef)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	propagation.TraceContext{}.Inject(ctx, propagation.HeaderCarrier(req.Header))

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, true, Refuse(CodeUpstreamUnavailable)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, true, Refuse(CodeUpstreamUnavailable)
	}
	if len(raw) > MaxResponseBytes {
		return nil, resp.StatusCode, false, Refuse(CodeUpstreamInvalid)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return raw, resp.StatusCode, false, nil
	case resp.StatusCode >= 500:
		return nil, resp.StatusCode, true, Refuse(CodeUpstreamUnavailable)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden ||
		resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusConflict:
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil && upstreamCodes[e.Error] {
			return nil, resp.StatusCode, false, Refuse(e.Error)
		}
		return nil, resp.StatusCode, false, Refuse(CodeUpstreamInvalid)
	}
	return nil, resp.StatusCode, false, Refuse(CodeUpstreamInvalid)
}
