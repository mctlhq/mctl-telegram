// Package bridgefake is an httptest fake of the mctl-api command bridge, for
// tests only. It models the server rules the provider depends on: per-credential
// tenants and audience, lease TTL and epoch, reclaim under a new token,
// expires_at, cancel, the write-permit fence, result schema validation, the
// worker_identity/execution_id/attempt binding, digest replay, result_conflict
// and the effect-state rules (reclaim and cancel turn permitted into unknown;
// applied needs permitted; a permit needs effect_state none).
package bridgefake

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// PermitMode is what the write fence answers.
type PermitMode int

const (
	PermitAllow PermitMode = iota
	PermitRefuse
	PermitUnavailable
)

// Command statuses and effect states (a subset of mctl-api's).
const (
	StatusPending   = "pending"
	StatusLeased    = "leased"
	StatusCompleted = "completed"
	StatusCancelled = "cancelled"
	StatusExpired   = "expired"

	EffectNone      = "none"
	EffectPermitted = "permitted"
	EffectSucceeded = "succeeded"
	EffectUnknown   = "unknown"
	EffectNotPerf   = "not_performed"
)

// Request is one recorded request.
type Request struct {
	Method, Path, Authorization string
	Body                        []byte
}

// Fault replaces a response. AfterStore (result route only) processes the
// request normally and then answers with the fault, like a lost response.
type Fault struct {
	Status     int
	Body       string
	RetryAfter string
	AfterStore bool
}

type principal struct {
	identity string
	tenants  map[string]bool
}

type command struct {
	doc          map[string]any
	status       string
	effect       string
	leaseToken   string
	leaseExpires time.Time
	epoch        int
	claims       int
	digest       string
	completeTok  string
}

// Fake is the fake bridge.
type Fake struct {
	Server *httptest.Server

	mu                 sync.Mutex
	creds              map[string]principal
	cmds               map[string]*command
	order              []string
	reqs               []Request
	faults             map[string][]Fault
	permitMode         PermitMode
	leaseTTL           time.Duration
	claimV             string
	claimBody          []byte // when set, returned verbatim by claim
	reclaimAfterPermit bool
	forced             []json.RawMessage
	tokSeq             int
	counts             map[string]int
	Now                func() time.Time
}

// New starts a fake with a 60s lease TTL and the v1alpha1 claim envelope.
func New() *Fake {
	f := &Fake{creds: map[string]principal{}, cmds: map[string]*command{}, faults: map[string][]Fault{},
		leaseTTL: 60 * time.Second, claimV: v1alpha1.ClaimVersion, counts: map[string]int{}, Now: time.Now}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *Fake) Close()      { f.Server.Close() }
func (f *Fake) URL() string { return f.Server.URL }

// AddProvider registers a bearer credential for one worker identity and the
// tenant_refs it may touch.
func (f *Fake) AddProvider(credential, identity string, tenants ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := principal{identity: identity, tenants: map[string]bool{}}
	for _, t := range tenants {
		p.tenants[t] = true
	}
	f.creds[credential] = p
}

func (f *Fake) SetPermitMode(m PermitMode)  { f.mu.Lock(); f.permitMode = m; f.mu.Unlock() }
func (f *Fake) SetLeaseTTL(d time.Duration) { f.mu.Lock(); f.leaseTTL = d; f.mu.Unlock() }
func (f *Fake) SetClaimVersion(v string)    { f.mu.Lock(); f.claimV = v; f.mu.Unlock() }

// SetReclaimAfterPermit makes the fake reclaim a command right after it grants
// a permit, as if the lease expired mid-execution: the epoch rises, the token
// rotates and effect_state goes permitted -> unknown.
func (f *Fake) SetReclaimAfterPermit(v bool) { f.mu.Lock(); f.reclaimAfterPermit = v; f.mu.Unlock() }
func (f *Fake) SetClaimBody(b []byte)        { f.mu.Lock(); f.claimBody = b; f.mu.Unlock() }
func (f *Fake) ForceClaim(r json.RawMessage) {
	f.mu.Lock()
	f.forced = append(f.forced, r)
	f.mu.Unlock()
}

// FailNext queues faults for a route ("claim", "permit", "result"), each used once.
func (f *Fake) FailNext(route string, faults ...Fault) {
	f.mu.Lock()
	f.faults[route] = append(f.faults[route], faults...)
	f.mu.Unlock()
}

// Enqueue adds a pending command document and returns its command_id.
func (f *Fake) Enqueue(doc map[string]any) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := doc["command_id"].(string)
	d := map[string]any{}
	for k, v := range doc {
		d[k] = v
	}
	delete(d, "lease_token")
	f.cmds[id] = &command{doc: d, status: StatusPending, effect: EffectNone}
	f.order = append(f.order, id)
	return id
}

// Cancel cancels a pending or leased command; a permitted effect becomes unknown.
func (f *Fake) Cancel(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.cmds[id]; c != nil && (c.status == StatusPending || c.status == StatusLeased) {
		c.status = StatusCancelled
		if c.effect == EffectPermitted {
			c.effect = EffectUnknown
		}
	}
}

// ExpireLease makes the current lease run out now, so the next claim reclaims.
func (f *Fake) ExpireLease(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.cmds[id]; c != nil {
		c.leaseExpires = f.Now().Add(-time.Second)
	}
}

// Reclaim expires the lease and claims the command again under epoch+1 as the
// named credential would, returning the new lease token. It is the
// "reclaim mid-execution" hook.
func (f *Fake) Reclaim(id string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.cmds[id]
	if c == nil {
		return ""
	}
	f.reclaimLocked(c)
	return c.leaseToken
}

func (f *Fake) reclaimLocked(c *command) {
	c.epoch++
	f.tokSeq++
	c.leaseToken = fmt.Sprintf("lt_reclaimed%016d", f.tokSeq)
	c.leaseExpires = f.Now().Add(f.leaseTTL)
	c.status = StatusLeased
	if c.effect == EffectPermitted {
		c.effect = EffectUnknown
	}
}

// State reads back (status, effect_state, epoch).
func (f *Fake) State(id string) (status, effect string, epoch int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.cmds[id]; c != nil {
		return c.status, c.effect, c.epoch
	}
	return "", "", 0
}

// Requests returns a copy of everything received.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.reqs...)
}

// Count returns the number of requests seen on a route: "claim", "permit", "result".
func (f *Fake) Count(route string) int { f.mu.Lock(); defer f.mu.Unlock(); return f.counts[route] }

// ResultBodies returns every body posted to the result route, in order.
func (f *Fake) ResultBodies() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [][]byte
	for _, r := range f.reqs {
		if strings.HasSuffix(r.Path, "/result") {
			out = append(out, r.Body)
		}
	}
	return out
}

func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "code": code})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *Fake) fault(route string, w http.ResponseWriter) (Fault, bool) {
	q := f.faults[route]
	if len(q) == 0 {
		return Fault{}, false
	}
	ft := q[0]
	f.faults[route] = q[1:]
	return ft, true
}

func writeFault(w http.ResponseWriter, ft Fault) {
	if ft.RetryAfter != "" {
		w.Header().Set("Retry-After", ft.RetryAfter)
	}
	w.WriteHeader(ft.Status)
	_, _ = io.WriteString(w, ft.Body)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, Request{Method: r.Method, Path: r.URL.Path, Authorization: r.Header.Get("Authorization"), Body: body})
	const prefix = "/api/v1/bridge/commands/"
	if r.Method != http.MethodPost || !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, prefix)
	route, id := "", ""
	switch {
	case rest == "claim":
		route = "claim"
	case strings.HasSuffix(rest, "/write-permit"):
		route, id = "permit", strings.TrimSuffix(rest, "/write-permit")
	case strings.HasSuffix(rest, "/result"):
		route, id = "result", strings.TrimSuffix(rest, "/result")
	default:
		http.NotFound(w, r)
		return
	}
	f.counts[route]++
	p, ok := f.creds[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !ok {
		// writeError in mctl-api: {"error"} without a code.
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		return
	}
	ft, faulty := f.fault(route, w)
	if faulty && !ft.AfterStore {
		writeFault(w, ft)
		return
	}
	switch route {
	case "claim":
		f.claim(w, p, body)
	case "permit":
		f.permit(w, p, id, body)
	case "result":
		if faulty {
			f.result(httptest.NewRecorder(), p, id, body)
			writeFault(w, ft)
			return
		}
		f.result(w, p, id, body)
	}
}

func (f *Fake) visible(p principal, id string) *command {
	c := f.cmds[id]
	if c == nil || !p.tenants[fmt.Sprint(c.doc["tenant_ref"])] || c.doc["audience"] != p.identity {
		return nil
	}
	return c
}

func (f *Fake) sweep(c *command) {
	exp, err := time.Parse(time.RFC3339Nano, fmt.Sprint(c.doc["expires_at"]))
	if err == nil && f.Now().After(exp) && (c.status == StatusPending || c.status == StatusLeased) {
		c.status = StatusExpired
		if c.effect == EffectPermitted {
			c.effect = EffectUnknown
		}
	}
}

func (f *Fake) claim(w http.ResponseWriter, p principal, body []byte) {
	if f.claimBody != nil {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(f.claimBody)
		return
	}
	var req struct {
		Max int `json:"max"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Max < 1 || req.Max > v1alpha1.MaxClaimCommands {
		req.Max = 1
	}
	var out []json.RawMessage
	for len(f.forced) > 0 && len(out) < req.Max {
		out = append(out, f.forced[0])
		f.forced = f.forced[1:]
	}
	for _, id := range f.order {
		if len(out) >= req.Max {
			break
		}
		c := f.visible(p, id)
		if c == nil {
			continue
		}
		f.sweep(c)
		due := c.status == StatusPending || (c.status == StatusLeased && f.Now().After(c.leaseExpires))
		if !due {
			continue
		}
		if c.status == StatusLeased {
			f.reclaimLocked(c)
		} else {
			f.tokSeq++
			c.leaseToken = fmt.Sprintf("lt_lease%018d", f.tokSeq)
			c.leaseExpires = f.Now().Add(f.leaseTTL)
			c.status = StatusLeased
		}
		c.claims++
		d := map[string]any{}
		for k, v := range c.doc {
			d[k] = v
		}
		d["lease_token"] = c.leaseToken
		b, _ := json.Marshal(d)
		out = append(out, b)
	}
	if out == nil {
		out = []json.RawMessage{}
	}
	writeJSON(w, map[string]any{"schema_version": f.claimV, "commands": out})
}

// leaseCheck applies the lease rules shared by permit and result.
func (f *Fake) leaseCheck(w http.ResponseWriter, c *command, token string) bool {
	f.sweep(c)
	switch c.status {
	case StatusCancelled:
		writeErr(w, 409, "command_cancelled")
		return false
	case StatusExpired:
		writeErr(w, 409, "command_expired")
		return false
	}
	if c.status != StatusLeased || token != c.leaseToken || f.Now().After(c.leaseExpires) {
		writeErr(w, 409, "lease_stale")
		return false
	}
	return true
}

func (f *Fake) permit(w http.ResponseWriter, p principal, id string, body []byte) {
	c := f.visible(p, id)
	if c == nil {
		writeErr(w, 404, "command_not_found")
		return
	}
	var req struct {
		LeaseToken string `json:"lease_token"`
	}
	if json.Unmarshal(body, &req) != nil || req.LeaseToken == "" {
		writeErr(w, 400, "invalid_input")
		return
	}
	if !f.leaseCheck(w, c, req.LeaseToken) {
		return
	}
	if !v1alpha1.Mutating(fmt.Sprint(c.doc["kind"])) {
		writeErr(w, 409, "not_mutating")
		return
	}
	if c.effect != EffectNone {
		writeErr(w, 409, "permit_already_issued")
		return
	}
	switch f.permitMode {
	case PermitRefuse:
		writeErr(w, 403, "write_fence_refused")
		return
	case PermitUnavailable:
		writeErr(w, 503, "write_fence_unavailable")
		return
	}
	c.effect = EffectPermitted
	if f.reclaimAfterPermit {
		f.reclaimLocked(c)
	}
	writeJSON(w, map[string]string{"command_id": id, "fence_ref": "fnc_fake", "issued_at": f.Now().UTC().Format(time.RFC3339)})
}

func (f *Fake) result(w http.ResponseWriter, p principal, id string, body []byte) {
	c := f.visible(p, id)
	if c == nil {
		writeErr(w, 404, "command_not_found")
		return
	}
	if err := v1alpha1.ValidateResult(body); err != nil {
		writeErr(w, 400, "invalid_document")
		return
	}
	var res v1alpha1.Result
	if err := json.Unmarshal(body, &res); err != nil {
		writeErr(w, 400, "invalid_document")
		return
	}
	if res.CommandID != id || res.WorkerIdentity != p.identity || res.ExecutionID != c.doc["execution_id"] || fmt.Sprint(res.Attempt) != fmt.Sprint(c.doc["attempt"]) {
		writeErr(w, 409, "binding_mismatch")
		return
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if c.status == StatusCompleted {
		if c.digest == digest {
			writeJSON(w, f.ack(id, c, true))
			return
		}
		writeErr(w, 409, "result_conflict")
		return
	}
	if !f.leaseCheck(w, c, res.LeaseToken) {
		return
	}
	if (res.ProviderEffect == v1alpha1.EffectApplied && c.effect != EffectPermitted) ||
		(res.Outcome == v1alpha1.OutcomeApprovalRefused && res.ProviderEffect != v1alpha1.EffectNone) {
		writeErr(w, 422, "result_inconsistent")
		return
	}
	switch res.ProviderEffect {
	case v1alpha1.EffectApplied:
		c.effect = EffectSucceeded
	case v1alpha1.EffectUnknown:
		c.effect = EffectUnknown
	default:
		if c.effect == EffectNone {
			c.effect = EffectNotPerf
		}
	}
	c.status, c.digest, c.completeTok = StatusCompleted, digest, res.LeaseToken
	writeJSON(w, f.ack(id, c, false))
}

func (f *Fake) ack(id string, c *command, replayed bool) map[string]any {
	return map[string]any{"command_id": id, "status": c.status, "effect_state": c.effect, "result_digest": c.digest, "replayed": replayed}
}
