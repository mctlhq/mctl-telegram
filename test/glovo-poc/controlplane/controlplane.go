// Package controlplane is an in-memory stand-in for the mctl-api side of the
// design: identity chain, order index, handoff tokens, and the schedule fire.
// It is the only component that may start or signal workflows.
package controlplane

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Typed refusals for the identity chain.
var (
	ErrNoLink          = errors.New("no_link")
	ErrLinkRevoked     = errors.New("link_revoked")
	ErrNoTenant        = errors.New("no_tenant")
	ErrAmbiguousTenant = errors.New("ambiguous_tenant")
	ErrNoInstall       = errors.New("no_install")
	ErrNoConnection    = errors.New("no_connection")
	ErrStaleInstall    = errors.New("stale_install")
	// ErrNotFound is returned for unknown AND foreign orders alike.
	ErrNotFound = errors.New("not_found")
	ErrRefused  = errors.New("handoff_refused")
	ErrBadParam = errors.New("unsupported_parameter")
)

type Scope struct {
	TenantID        string
	OwnerPrincipal  string
	InstallID       string
	InstallRevision int64
	ConnectionRef   string
}

type install struct {
	id       string
	revision int64
	active   bool
	connRef  string
	connLive bool
}

type Order struct {
	ID, Tenant, Owner string
}

type CP struct {
	mu            sync.Mutex
	Now           func() time.Time
	links         map[int64]string // telegram id -> principal
	revoked       map[int64]bool
	members       map[string][]string // principal -> tenants
	installs      map[[2]string]*install
	orders        map[string]Order
	tokens        map[string]*token // by hash
	started       map[string]bool   // workflow IDs ever started (RejectDuplicate)
	Outbox        []string          // owner-channel deliveries (tokens, never in history)
	DefaultTenant string            // deployment work-context tenant; must never be used
}

type token struct {
	order, owner, tenant, fingerprint string
	installRevision                   int64
	expires                          time.Time
	used                             bool
}

func New(now func() time.Time) *CP {
	return &CP{Now: now, DefaultTenant: "mctl",
		links: map[int64]string{}, revoked: map[int64]bool{}, members: map[string][]string{},
		installs: map[[2]string]*install{}, orders: map[string]Order{},
		tokens: map[string]*token{}, started: map[string]bool{}}
}

func (c *CP) Link(tg int64, principal string) { c.mu.Lock(); c.links[tg] = principal; c.mu.Unlock() }
func (c *CP) RevokeLink(tg int64)             { c.mu.Lock(); c.revoked[tg] = true; c.mu.Unlock() }
func (c *CP) AddMember(principal, tenant string) {
	c.mu.Lock()
	c.members[principal] = append(c.members[principal], tenant)
	c.mu.Unlock()
}
func (c *CP) Install(tenant, principal, id, connRef string) {
	c.mu.Lock()
	c.installs[[2]string{tenant, principal}] = &install{id: id, revision: 1, active: true, connRef: connRef, connLive: true}
	c.mu.Unlock()
}
func (c *CP) BumpRevision(tenant, principal string) {
	c.mu.Lock()
	c.installs[[2]string{tenant, principal}].revision++
	c.mu.Unlock()
}
func (c *CP) Deactivate(tenant, principal string) {
	c.mu.Lock()
	c.installs[[2]string{tenant, principal}].active = false
	c.mu.Unlock()
}

// Resolve walks the identity chain. It never falls back to DefaultTenant.
func (c *CP) Resolve(tg int64, explicitTenant string) (Scope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.links[tg]
	if !ok {
		return Scope{}, ErrNoLink
	}
	if c.revoked[tg] {
		return Scope{}, ErrLinkRevoked
	}
	tenants := c.members[p]
	var tenant string
	switch {
	case explicitTenant != "":
		for _, t := range tenants {
			if t == explicitTenant {
				tenant = t
			}
		}
		if tenant == "" {
			return Scope{}, ErrNoTenant
		}
	case len(tenants) == 0:
		return Scope{}, ErrNoTenant
	case len(tenants) > 1:
		return Scope{}, ErrAmbiguousTenant
	default:
		tenant = tenants[0]
	}
	in := c.installs[[2]string{tenant, p}]
	if in == nil || !in.active {
		return Scope{}, ErrNoInstall
	}
	if !in.connLive {
		return Scope{}, ErrNoConnection
	}
	return Scope{TenantID: tenant, OwnerPrincipal: p, InstallID: in.id, InstallRevision: in.revision, ConnectionRef: in.connRef}, nil
}

// Revalidate is RevalidateScope: install active, revision equal, membership
// and connection live.
func (c *CP) Revalidate(s Scope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	member := false
	for _, t := range c.members[s.OwnerPrincipal] {
		if t == s.TenantID {
			member = true
		}
	}
	in := c.installs[[2]string{s.TenantID, s.OwnerPrincipal}]
	if !member || in == nil || !in.active || in.revision != s.InstallRevision || !in.connLive {
		return ErrStaleInstall
	}
	return nil
}

func (c *CP) DropConnection(tenant, principal string) {
	c.mu.Lock()
	c.installs[[2]string{tenant, principal}].connLive = false
	c.mu.Unlock()
}

func (c *CP) RegisterOrder(o Order) { c.mu.Lock(); c.orders[o.ID] = o; c.mu.Unlock() }

// Request is the whole surface API. It has no namespace, workflow, run or
// queue field, and DecodeRequest refuses unknown fields.
type Request struct {
	Principal string `json:"principal"`
	Tenant    string `json:"tenant"`
	OrderID   string `json:"order_id"`
}

func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrBadParam, err)
	}
	return r, nil
}

// Authorize checks (tenant, owner, order) against the server-side index. An
// unknown order and another tenant's order produce the identical error.
func (c *CP) Authorize(r Request) (Order, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o, ok := c.orders[r.OrderID]
	if !ok || o.Tenant != r.Tenant || o.Owner != r.Principal {
		return Order{}, ErrNotFound
	}
	return o, nil
}

// List returns only the caller's own orders, from the index.
func (c *CP) List(principal, tenant string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for id, o := range c.orders {
		if o.Tenant == tenant && o.Owner == principal {
			out = append(out, id)
		}
	}
	return out
}

func hash(t string) string { h := sha256.Sum256([]byte(t)); return hex.EncodeToString(h[:]) }

// IssueHandoff mints a single-use token, stores only its hash, delivers the
// token to the owner channel, and returns the hash.
func (c *CP) IssueHandoff(order, owner, fingerprint string, ttl time.Duration) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	t := hex.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	h := hash(t)
	var tenant string
	var revision int64
	if o, ok := c.orders[order]; ok && o.Owner == owner {
		tenant = o.Tenant
		if in := c.installs[[2]string{tenant, owner}]; in != nil {
			revision = in.revision
		}
	}
	c.tokens[h] = &token{order: order, owner: owner, tenant: tenant, installRevision: revision,
		fingerprint: fingerprint, expires: c.Now().Add(ttl)}
	c.Outbox = append(c.Outbox, t)
	return h
}

// OpenHandoff compare-and-sets the token to used. Any mismatch, reuse or
// expiry is refused and changes nothing except that a used token stays used.
func (c *CP) OpenHandoff(tok string, r Request, fingerprint string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.tokens[hash(tok)]
	if t == nil || t.used || c.Now().After(t.expires) || t.order != r.OrderID ||
		t.owner != r.Principal || t.tenant != r.Tenant || t.fingerprint != fingerprint {
		return ErrRefused
	}
	// Re-evaluate the owner's authority at click time, not only when the
	// token was issued. A revoked install or replaced revision fences a
	// handoff immediately, even if its Temporal signal has not been handled.
	o, ok := c.orders[r.OrderID]
	in := c.installs[[2]string{r.Tenant, r.Principal}]
	if !ok || o.Tenant != r.Tenant || o.Owner != r.Principal ||
		in == nil || !in.active || !in.connLive || in.revision != t.installRevision {
		return ErrRefused
	}
	member := false
	for _, tenant := range c.members[r.Principal] {
		if tenant == r.Tenant {
			member = true
			break
		}
	}
	if !member {
		return ErrRefused
	}
	t.used = true
	return nil
}

func (c *CP) ExpireHandoffs(order string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.tokens {
		if t.order == order {
			t.used = true
		}
	}
}

// WorkflowID is the schedule occurrence ID.
func WorkflowID(tenant, install, schedule string, occurrence time.Time) string {
	return fmt.Sprintf("glovo-order/%s/%s/%s/%s", tenant, install, schedule, occurrence.UTC().Format("20060102T150405Z"))
}

// Fire mocks the Automation Control Plane. It mimics WorkflowIDReusePolicy
// RejectDuplicate: an ID is started at most once, even across restarts of the
// caller, because the ledger lives here.
func (c *CP) Fire(s Scope, schedule string, occurrence time.Time, start func(id string) error) (string, bool, error) {
	if err := c.Revalidate(s); err != nil {
		return "", false, err
	}
	id := WorkflowID(s.TenantID, s.InstallID, schedule, occurrence)
	c.mu.Lock()
	if c.started[id] {
		c.mu.Unlock()
		return id, false, nil
	}
	c.started[id] = true
	c.mu.Unlock()
	if err := start(id); err != nil {
		c.mu.Lock()
		delete(c.started, id)
		c.mu.Unlock()
		return id, false, err
	}
	return id, true, nil
}
