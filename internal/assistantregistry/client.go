// Package assistantregistry reads assistant definitions from the mctl-api
// registry (#1020, docs/assistants/spec.md "Registry form"): the install
// path fetches the exact materialized definition it pins, and a background
// refresh keeps each pinned version's lifecycle current. Claims never call
// it; they render from the database snapshot the install stored.
package assistantregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// fetchTimeout bounds one registry read; an install waits on it and a hung
// mctl-api must not hold the admin request open.
const fetchTimeout = 15 * time.Second

// maxResponseBytes caps a definition response. The materialized
// hr-recruiter document is a few KiB; the cap only keeps a misbehaving
// upstream from making this process allocate without bound.
const maxResponseBytes = 1 << 20

var (
	// ErrNotFound means the registry answered that name@version does not
	// exist (404 assistant_not_found): an observation, not a failed read.
	ErrNotFound = errors.New("assistant not found in registry")
	// ErrUnavailable means the registry could not be read: a network
	// error, a timeout, a 5xx, an auth failure or any other answer that is
	// not one of the documented ones. It never says anything about the
	// assistant itself.
	ErrUnavailable = errors.New("assistant registry unavailable")
	// ErrDigestMismatch means the document's recomputed digest is not the
	// contentHash the registry reported for it.
	ErrDigestMismatch = errors.New("assistant registry digest mismatch")
	// ErrInvalid means the registry answered 200 with something that is not
	// a valid materialized definition of the requested name@version.
	ErrInvalid = errors.New("assistant registry returned an invalid definition")
)

// Definition is one fetched and checked registry definition.
type Definition struct {
	Lifecycle string
	// Entry is the parsed materialized document; Entry.Digest is recomputed
	// from its canonical form and equals the registry's contentHash.
	Entry *assistant.Entry
}

// Client reads the registry as the surface:telegram principal.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient builds a Client for mctl-api at baseURL (MCTL_API_BASE_URL)
// with the surface:telegram bearer token. hc may be nil.
func NewClient(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: hc}
}

type definitionResponse struct {
	Name        string          `json:"name"`
	Version     string          `json:"version"`
	Lifecycle   string          `json:"lifecycle"`
	ContentHash string          `json:"contentHash"`
	Definition  json.RawMessage `json:"definition"`
}

// Fetch reads name@version's materialized definition and lifecycle. The
// definition comes back as stored by the registry (JSONB, so key order and
// whitespace are not the publisher's): it is canonicalized by
// assistant.ParseMaterialized and its recomputed digest must equal the
// reported contentHash, or ErrDigestMismatch.
func (c *Client) Fetch(ctx context.Context, name, version string) (*Definition, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	u := c.baseURL + "/api/v1/assistant-catalog/" + url.PathEscape(name) +
		"/versions/" + url.PathEscape(version) + "/definition"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %v", ErrUnavailable, err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		// Only a 200 is held to the size of a definition; an oversized
		// error page from a proxy is still just an unavailable registry.
		if len(body) > maxResponseBytes {
			return nil, fmt.Errorf("%w: response exceeds %d bytes", ErrInvalid, maxResponseBytes)
		}
	case http.StatusNotFound:
		// Only the registry's own answer is an observation. A bare 404
		// (route not deployed, a proxy in between) is a failed read.
		var e struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(body, &e) == nil && e.Code == "assistant_not_found" {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("%w: status 404 without assistant_not_found", ErrUnavailable)
	default:
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	var r definitionResponse
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("%w: decode response", ErrInvalid)
	}
	if r.Name != name || r.Version != version {
		return nil, fmt.Errorf("%w: answered %s@%s", ErrInvalid, r.Name, r.Version)
	}
	switch r.Lifecycle {
	case db.AssistantLifecyclePublished, db.AssistantLifecycleDeprecated, db.AssistantLifecycleDisabled:
	default:
		return nil, fmt.Errorf("%w: unknown lifecycle %q", ErrInvalid, r.Lifecycle)
	}
	if len(r.Definition) == 0 {
		return nil, fmt.Errorf("%w: no definition", ErrInvalid)
	}
	// The parse error can quote document content; it stays out of the
	// returned error, which reaches logs.
	entry, err := assistant.ParseMaterialized(r.Definition)
	if err != nil {
		return nil, fmt.Errorf("%w: definition does not parse", ErrInvalid)
	}
	if entry.Definition.Metadata.Name != name || entry.Definition.Metadata.Version != version {
		return nil, fmt.Errorf("%w: document names another assistant", ErrInvalid)
	}
	if entry.Digest != r.ContentHash {
		return nil, fmt.Errorf("%w: computed %s, registry reports %q", ErrDigestMismatch, entry.Digest, r.ContentHash)
	}
	return &Definition{Lifecycle: r.Lifecycle, Entry: entry}, nil
}
