// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package cimd resolves OAuth Client ID Metadata Documents: an https URL used
// as a client_id whose document, fetched from that URL, names the client's
// redirect URIs. The document says which CLIENT is asking; it can never name
// a principal, tenant or group (those come from the upstream sign-in only).
//
// Everything fails closed: an unknown host, a failed or rate-limited fetch and
// a malformed document are all refusals.
//
// Ported from mctlhq/mctl-api internal/auth/cimd, which has served CIMD in
// production since 2026-10-18; the mctl-api#NNN references below point to
// that repository. The private_key_jwt key-set cache is not ported yet
// (mctl-telegram#773): parseDocument still validates such a document, and
// the OAuth server refuses it.
package cimd

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/singleflight"

	"github.com/mctlhq/mctl-telegram/internal/netsafe"
)

// Typed failures, for logs and metrics. The HTTP answer is the same 400.
var (
	ErrNotAllowed      = errors.New("cimd: host is not allowed")
	ErrFetch           = errors.New("cimd: metadata document could not be fetched")
	ErrInvalidDocument = errors.New("cimd: invalid metadata document")
	ErrRateLimited     = errors.New("cimd: fetch refused by rate limit")
)

const (
	maxURLBytes      = 512
	maxBodyBytes     = 64 << 10
	maxRedirectURIs  = 20
	maxRedirectBytes = 2048
	maxNameRunes     = 100
	minTTL           = 30 * time.Second
	maxTTL           = 24 * time.Hour
	defaultTTL       = time.Hour
	// negativeTTL is how long a document refused for its content
	// (ErrInvalidDocument) is remembered: the client's own configuration,
	// which does not change from one request to the next.
	negativeTTL = 5 * time.Minute
	// fetchErrTTL is how long a failed fetch (ErrFetch) is remembered. Since
	// mctl-api#694 every token request resolves the document, so a fetch
	// failure refuses the client's refreshes too, not only new sign-ins; it
	// is kept as short as the fetch floor (mctl-api#702).
	fetchErrTTL  = minTTL
	cacheEntries = 1024
	// hostPerMinute budgets fetches per host, shared by every document on
	// it. It assumes the production policy of one known client per exact
	// allowlisted host: a host serving 6 or more no-store documents under
	// steady sign-ins would exceed it at the minTTL floor (mctl-api#687).
	// A private_key_jwt client's key set is fetched under the same budget,
	// so a no-store document and key set together use twice the fetches
	// and leave half the headroom (mctl-api#694).
	hostPerMinute = 10
	// knownTTL is how long a client_id whose document once validated keeps
	// its claim on the reserved half of the host budget (see allowHost). It
	// must outlast the longest cache entry (maxTTL): the refetch that the
	// reserve exists for happens when that entry expires, and a claim that
	// lapsed with it would leave the refetch to the unreserved budget.
	knownTTL      = 2 * maxTTL
	maxConcurrent = 8
	fetchTimeout  = 10 * time.Second
)

// Document is the validated subset of a metadata document.
type Document struct {
	ClientID     string
	ClientName   string
	RedirectURIs []string
	// DroppedRedirectURIs lists the well-formed entries outside the scheme
	// allowlist that parseDocument ignored. They never match; they are kept
	// only so a refused redirect can be explained in the logs.
	DroppedRedirectURIs []string
	// AuthMethod is the token endpoint authentication the client declared:
	// AuthMethodNone or AuthMethodPrivateKeyJWT. A private_key_jwt client
	// must authenticate every token request; it is never served as none.
	AuthMethod string
	// SigningAlg and JWKSURI are set for AuthMethodPrivateKeyJWT only: the one
	// algorithm its assertions may use and the key set they verify against,
	// on the client_id's own host.
	SigningAlg string
	JWKSURI    string
}

// Token endpoint authentication methods a document may declare.
const (
	AuthMethodNone          = "none"
	AuthMethodPrivateKeyJWT = "private_key_jwt"
)

// signingAlgs are the assertion algorithms a document may name. HMAC
// algorithms are absent on purpose: a public key set cannot verify them.
var signingAlgs = []string{"RS256", "ES256"}

// SigningAlgs returns the assertion algorithms a document may name.
func SigningAlgs() []string { return slices.Clone(signingAlgs) }

// IsCIMDURL reports whether s has the shape of a CIMD client_id: https, a
// host name (no IP literal), port absent or 443, a non-empty path other than
// "/", no userinfo, query, fragment or dot segments, at most 512 bytes. It
// does no network access and does not consult the allowlist.
func IsCIMDURL(s string) bool {
	_, ok := parseCIMDURL(s)
	return ok
}

func parseCIMDURL(s string) (*url.URL, bool) {
	if s == "" || len(s) > maxURLBytes || strings.ContainsAny(s, "\\#?") {
		return nil, false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" {
		return nil, false
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, false
	}
	host := u.Hostname()
	if host == "" || net.ParseIP(host) != nil || strings.Contains(host, ":") {
		return nil, false
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, false
	}
	if u.Port() == "" && strings.HasSuffix(u.Host, ":") {
		return nil, false
	}
	if u.Path == "" || u.Path == "/" {
		return nil, false
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		d := strings.ToLower(seg)
		if d == "." || d == ".." || d == "%2e" || d == "%2e%2e" || d == ".%2e" || d == "%2e." {
			return nil, false
		}
	}
	return u, true
}

// ParseAllowedHosts parses OAUTH_CIMD_ALLOWED_HOSTS: a comma list of exact
// host names or ".suffix" entries (matching subdomains). An empty list, an
// empty entry, or an entry that is not a plain host name is an error.
func ParseAllowedHosts(raw string) ([]string, error) {
	var out []string
	for _, e := range strings.Split(raw, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			if strings.TrimSpace(raw) == "" {
				break
			}
			return nil, errors.New("OAUTH_CIMD_ALLOWED_HOSTS: empty entry")
		}
		h := strings.TrimPrefix(e, ".")
		if h == "" || strings.ContainsAny(h, "/:@*? #\\") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
			return nil, fmt.Errorf("OAUTH_CIMD_ALLOWED_HOSTS: %q is not a host name or .suffix", e)
		}
		if net.ParseIP(h) != nil {
			return nil, fmt.Errorf("OAUTH_CIMD_ALLOWED_HOSTS: %q is an IP literal", e)
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, errors.New("OAUTH_CIMD_ALLOWED_HOSTS: required (and non-empty) when OAUTH_CIMD_ACCEPT=true")
	}
	return out, nil
}

// Options configures a Resolver.
type Options struct {
	// AllowedHosts is the mandatory host allowlist (see ParseAllowedHosts).
	AllowedHosts []string
	// HTTPClient fetches documents. Default netsafe.Client.
	HTTPClient *http.Client
	// Now overrides the clock in tests.
	Now func() time.Time
	// HostPerMinute, MaxConcurrent and FetchTimeout override the limits in
	// tests.
	HostPerMinute int
	MaxConcurrent int
	FetchTimeout  time.Duration
}

// Resolver fetches, validates and caches metadata documents.
type Resolver struct {
	allowed []string
	client  *http.Client
	now     func() time.Time
	perHost int
	timeout time.Duration
	sem     chan struct{}
	sf      singleflight.Group

	mu    sync.Mutex
	lru   *list.List
	cache map[string]*list.Element
	rate  map[string][]time.Time
	// known holds the client_ids whose document validated, with the time
	// of the last success. Their refetches (and their key sets) draw on the
	// reserved half of the host budget, which a caller spraying unseen
	// client_ids on the same host cannot spend.
	known map[string]time.Time
}

type cacheEntry struct {
	key     string
	doc     Document
	err     error
	expires time.Time
}

// NewResolver builds a Resolver.
func NewResolver(o Options) *Resolver {
	c := o.HTTPClient
	if c == nil {
		c = netsafe.Client(netsafe.Options{Timeout: 5 * time.Second})
	}
	now := o.Now
	if now == nil {
		now = time.Now
	}
	per := o.HostPerMinute
	if per <= 0 {
		per = hostPerMinute
	}
	conc := o.MaxConcurrent
	if conc <= 0 {
		conc = maxConcurrent
	}
	timeout := o.FetchTimeout
	if timeout <= 0 {
		timeout = fetchTimeout
	}
	allowed := make([]string, 0, len(o.AllowedHosts))
	for _, h := range o.AllowedHosts {
		allowed = append(allowed, strings.ToLower(strings.TrimSpace(h)))
	}
	return &Resolver{
		allowed: allowed, client: c, now: now, perHost: per, timeout: timeout,
		sem: make(chan struct{}, conc), lru: list.New(),
		cache: map[string]*list.Element{}, rate: map[string][]time.Time{},
		known: map[string]time.Time{},
	}
}

// maxRateHosts is the hard bound on the per-host rate map: a host not yet in
// it is refused while it is full of hosts seen within the last minute.
const maxRateHosts = 1024

func (r *Resolver) hostAllowed(host string) bool {
	host = strings.ToLower(host)
	for _, a := range r.allowed {
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(host, a) && len(host) > len(a) {
				return true
			}
		} else if host == a {
			return true
		}
	}
	return false
}

// Resolve returns the validated document for clientID.
func (r *Resolver) Resolve(ctx context.Context, clientID string) (Document, error) {
	u, ok := parseCIMDURL(clientID)
	if !ok {
		return Document{}, fmt.Errorf("%w: not a CIMD URL", ErrInvalidDocument)
	}
	if !r.hostAllowed(u.Hostname()) {
		return Document{}, ErrNotAllowed
	}
	if doc, err, hit := r.cached(clientID); hit {
		return doc, err
	}
	v, err, _ := r.sf.Do(clientID, func() (any, error) {
		if doc, err, hit := r.cached(clientID); hit {
			return doc, err
		}
		// Detach from the first caller's lifetime: the shared fetch must not be
		// aborted (or cached as a failure) because one browser went away.
		// WithoutCancel also drops the caller's deadline, so the fetch gets its
		// own here rather than relying on the injected client's timeout.
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), r.timeout)
		defer cancel()
		doc, ttl, err := r.fetch(fctx, u, clientID)
		if errors.Is(err, ErrRateLimited) {
			// Not the document's fault: refuse, but do not cache it.
			return Document{}, err
		}
		if err != nil && ctx.Err() != nil {
			// The caller went away: that says nothing about the document.
			return Document{}, err
		}
		r.store(clientID, doc, err, ttl)
		return doc, err
	})
	if err != nil {
		return Document{}, err
	}
	return v.(Document), nil
}

func (r *Resolver) cached(key string) (Document, error, bool) {
	e, ok := r.cachedEntry(key)
	if !ok {
		return Document{}, nil, false
	}
	return e.doc, e.err, true
}

// cachedEntry returns a copy of the live entry for key.
func (r *Resolver) cachedEntry(key string) (cacheEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.cache[key]
	if !ok {
		return cacheEntry{}, false
	}
	e := el.Value.(*cacheEntry)
	if !r.now().Before(e.expires) {
		r.lru.Remove(el)
		delete(r.cache, key)
		return cacheEntry{}, false
	}
	r.lru.MoveToFront(el)
	return *e, true
}

func (r *Resolver) store(key string, doc Document, err error, ttl time.Duration) {
	if err == nil {
		r.markKnown(key)
	}
	switch {
	case errors.Is(err, ErrFetch):
		ttl = fetchErrTTL
	case err != nil:
		ttl = negativeTTL
	}
	r.storeEntry(&cacheEntry{key: key, doc: doc, err: err, expires: r.now().Add(ttl)})
}

func (r *Resolver) storeEntry(e *cacheEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.cache[e.key]; ok {
		r.lru.Remove(el)
	}
	r.cache[e.key] = r.lru.PushFront(e)
	for r.lru.Len() > cacheEntries {
		old := r.lru.Back()
		r.lru.Remove(old)
		delete(r.cache, old.Value.(*cacheEntry).key)
	}
}

// markKnown records that key's document validated. The set is bounded like
// the cache: when full, entries past knownTTL go first, then the oldest.
func (r *Resolver) markKnown(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if _, ok := r.known[key]; !ok && len(r.known) >= cacheEntries {
		oldest, oldestAt, found := "", time.Time{}, false
		for k, t := range r.known {
			if now.Sub(t) >= knownTTL {
				delete(r.known, k)
				continue
			}
			if !found || t.Before(oldestAt) {
				oldest, oldestAt, found = k, t, true
			}
		}
		if len(r.known) >= cacheEntries {
			delete(r.known, oldest)
		}
	}
	r.known[key] = now
}

// isKnown reports whether key's document validated within knownTTL.
func (r *Resolver) isKnown(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.known[key]
	return ok && r.now().Sub(t) < knownTTL
}

// allowHost spends one fetch of host's per-minute budget. A fetch for a
// client_id never seen to validate (reserved=false) may use only the
// unreserved part of the budget: the host is public and the path is the
// caller's choice, so without the reserve ~10 unauthenticated requests a
// minute with fresh paths would hold the budget at zero and, once the real
// document's cache entry expired, refuse its sign-ins and refreshes for as
// long as they continued. A known document's refetch and its key set
// (reserved=true) may use the whole budget.
func (r *Resolver) allowHost(host string, reserved bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	cut := now.Add(-time.Minute)
	if _, known := r.rate[host]; !known && len(r.rate) >= maxRateHosts {
		for h, ts := range r.rate {
			if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
				delete(r.rate, h)
			}
		}
		if len(r.rate) >= maxRateHosts {
			// Every slot was used within the minute: refuse the new host
			// rather than grow past the bound. With a .suffix allowlist entry
			// a caller picks the hosts and can fill the map, refusing other
			// untracked hosts for a minute; that is why SECURITY.md asks for
			// exact hosts in production.
			return false
		}
	}
	kept := r.rate[host][:0]
	for _, t := range r.rate[host] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	limit := r.perHost
	if !reserved {
		limit -= r.perHost / 2
	}
	if len(kept) >= limit {
		r.rate[host] = kept
		return false
	}
	r.rate[host] = append(kept, now)
	return true
}

func (r *Resolver) fetch(ctx context.Context, u *url.URL, clientID string) (Document, time.Duration, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return Document{}, 0, ErrRateLimited
	}
	if !r.allowHost(strings.ToLower(u.Hostname()), r.isKnown(clientID)) {
		return Document{}, 0, ErrRateLimited
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return Document{}, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return Document{}, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return Document{}, 0, fmt.Errorf("%w: status %d", ErrFetch, resp.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		return Document{}, 0, fmt.Errorf("%w: content type %q", ErrFetch, resp.Header.Get("Content-Type"))
	}
	body, err := netsafe.ReadLimited(resp, maxBodyBytes)
	if err != nil {
		return Document{}, 0, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	doc, err := parseDocument(body, clientID)
	if err != nil {
		return Document{}, 0, err
	}
	return doc, cacheTTL(resp.Header.Get("Cache-Control")), nil
}

// cacheTTL is how long a document served with Cache-Control cc is cached:
// the smallest max-age when several are given, defaultTTL with none, and
// minTTL for no-store, a bare no-cache or max-age=0, always within
// [minTTL, maxTTL]. The short floor lets a client that revokes a redirect URI
// see it take effect within seconds while a busy client's sign-ins are not
// refused by the per-host rate limit. An invalid max-age is ignored (RFC 9111
// section 5.2) and an over-large one is clamped (section 1.2.2). A qualified
// no-cache="field" restricts only header fields this cache never reuses.
func cacheTTL(cc string) time.Duration {
	ttl, seen := defaultTTL, false
	for _, d := range strings.Split(cc, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "no-store" || d == "no-cache" {
			return minTTL
		}
		if v, ok := strings.CutPrefix(d, "max-age="); ok {
			v = strings.Trim(v, `"`)
			if v == "" || strings.Trim(v, "0123456789") != "" {
				continue
			}
			t := maxTTL
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n < int64(maxTTL/time.Second) {
				t = time.Duration(n) * time.Second
			}
			if !seen || t < ttl {
				ttl, seen = t, true
			}
		}
	}
	return min(max(ttl, minTTL), maxTTL)
}

func parseDocument(body []byte, clientID string) (Document, error) {
	bad := func(format string, a ...any) (Document, error) {
		return Document{}, fmt.Errorf("%w: %s", ErrInvalidDocument, fmt.Sprintf(format, a...))
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return bad("not a JSON object")
	}
	str := func(k string) (string, bool) {
		v, ok := raw[k]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(v, &s) != nil {
			return "", false
		}
		return s, true
	}
	if id, ok := str("client_id"); !ok || id != clientID {
		return bad("client_id does not equal the document URL")
	}
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := raw[k]; ok {
			return bad("%s must not be present", k)
		}
	}
	method, _ := str("token_endpoint_auth_method")
	var alg, jwksURI string
	switch method {
	case AuthMethodNone:
	case AuthMethodPrivateKeyJWT:
		// The key set must come from the client_id's own host, fetched under
		// the same allowlist and limits as the document. An inline jwks would
		// let any document carry its own keys past that boundary.
		if _, ok := raw["jwks"]; ok {
			return bad("jwks must not be present; publish the keys at jwks_uri")
		}
		jwksURI, _ = str("jwks_uri")
		ju, ok := parseCIMDURL(jwksURI)
		cu, _ := parseCIMDURL(clientID)
		if !ok || cu == nil || !strings.EqualFold(ju.Hostname(), cu.Hostname()) {
			return bad("jwks_uri must be an https URL on the client_id's host")
		}
		alg, _ = str("token_endpoint_auth_signing_alg")
		if !slices.Contains(signingAlgs, alg) {
			return bad("token_endpoint_auth_signing_alg must be one of %s", strings.Join(signingAlgs, ", "))
		}
	default:
		return bad("token_endpoint_auth_method must be none or private_key_jwt")
	}
	var uris []string
	if v, ok := raw["redirect_uris"]; !ok || json.Unmarshal(v, &uris) != nil || len(uris) == 0 {
		return bad("redirect_uris must be a non-empty list of strings")
	}
	if len(uris) > maxRedirectURIs {
		return bad("too many redirect_uris")
	}
	accepted := make([]string, 0, len(uris))
	var dropped []string
	for _, s := range uris {
		if len(s) > maxRedirectBytes {
			return bad("redirect_uri too long")
		}
		u, err := url.Parse(s)
		if err != nil || !u.IsAbs() || u.Scheme == "" {
			return bad("redirect_uri %q is not an absolute URI", s)
		}
		if u.Fragment != "" || u.User != nil {
			return bad("redirect_uri %q must not contain a fragment or userinfo", s)
		}
		// An allowlist, not a denylist: https with a host, or http on a
		// loopback IP literal (RFC 8252 section 7.3). url.Parse lower-cases
		// the scheme. Any other entry that passed the checks above is
		// dropped rather than refusing the document, so a client that also
		// lists, say, http://localhost/callback (Codex does) keeps its usable
		// entries; RedirectAllowed only ever sees the accepted set. A
		// malformed entry (relative, fragment, userinfo, too long) stays
		// fatal by choice, even when its scheme would have been dropped.
		switch {
		case u.Scheme == "https" && u.Host != "" && u.Hostname() != "":
		case u.Scheme == "http" && isLoopbackIP(u.Hostname()):
		default:
			dropped = append(dropped, s)
			continue
		}
		accepted = append(accepted, s)
	}
	if len(accepted) == 0 {
		return bad("no redirect_uri is https or loopback http")
	}
	name, _ := str("client_name")
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxNameRunes {
		name = string([]rune(name)[:maxNameRunes])
	}
	// Both slices are clipped so an append by a caller can never write into
	// the backing array of a cached document shared by concurrent requests.
	return Document{
		ClientID: clientID, ClientName: name, RedirectURIs: slices.Clip(accepted), DroppedRedirectURIs: slices.Clip(dropped),
		AuthMethod: method, SigningAlg: alg, JWKSURI: jwksURI,
	}, nil
}

// RedirectAllowed reports whether uri matches an entry of the document's
// redirect_uris: exactly, or (RFC 8252 §7.3) for an http entry on the IP
// literal 127.0.0.1 or [::1], with any port. Scheme, host, path and query
// must still match exactly. "localhost" gets no port exemption (§8.3).
func RedirectAllowed(entries []string, uri string) bool {
	if uri == "" || strings.Contains(uri, "\\") {
		return false
	}
	for _, e := range entries {
		if e == uri {
			return true
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Fragment != "" || !isLoopbackIP(u.Hostname()) {
		return false
	}
	for _, e := range entries {
		if strings.Contains(e, "\\") {
			continue
		}
		eu, err := url.Parse(e)
		if err != nil || eu.Scheme != "http" || eu.User != nil || eu.Fragment != "" || !isLoopbackIP(eu.Hostname()) {
			continue
		}
		if eu.Hostname() == u.Hostname() && eu.EscapedPath() == u.EscapedPath() && eu.RawQuery == u.RawQuery && eu.ForceQuery == u.ForceQuery {
			return true
		}
	}
	return false
}

// isLoopbackIP accepts only the host text 127.0.0.1 or ::1, so other spellings
// of the same addresses are refused too. This is deliberately stricter
// than RFC 8252 section 7.3, which allows any loopback address: no known native
// client uses another one, and every accepted form widens what a document can
// name. Do not widen it to 127.0.0.0/8 without such a client (mctl-api#687).
func isLoopbackIP(h string) bool { return h == "127.0.0.1" || h == "::1" }
