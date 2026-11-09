// Package fakeapi is an in-memory HARNESS of the candidate mctl-api wire
// protocol glovo-facade-mctl-api/v1alpha1. It exists so the facade can be
// built and tested before mctl-api M1a/M1b merge. It is NOT mctl-api and NOT
// evidence that the facade works against it: that needs contract tests
// against the real handlers (mctl-api#957). Personas are synthetic: Alice and
// Bob in team-alpha, Carol in team-beta, Dana a team-alpha member who is not
// in the pilot allowlist.
package fakeapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
)

// Synthetic subjects.
const (
	Alice = "usr_alice"
	Bob   = "usr_bob"
	Carol = "usr_carol"
	Dana  = "usr_dana"

	TeamAlpha = "team-alpha"
	TeamBeta  = "team-beta"
)

// Call is one recorded request to a protocol endpoint.
type Call struct {
	Method string
	Path   string // relative to BasePath
	Effect bool   // the call actually created state (set at the mutation site)
}

// Override replaces the response of any endpoint whose path ends in Suffix.
type Override struct {
	Status int
	Body   string
	Delay  time.Duration
}

// Options configures a Fake.
type Options struct {
	Issuer     string
	Resource   string
	Credential string // facade workload credential
}

type scopeRec struct {
	tokHash, sub, tenant string
	exp                  time.Time
}

type order struct {
	id, aar, owner, state, fingerprint string
	hir                                []string
}

// Fake is the harness server state.
type Fake struct {
	opt Options
	key *rsa.PrivateKey
	kid string

	mu        sync.Mutex
	members   map[string]map[string]bool
	pilot     map[string]bool
	ambiguous map[string]bool
	revoked   map[string]bool
	scopes    map[string]scopeRec
	conns     map[string]string // owner -> gcn
	connIdem  map[string]string
	history   map[string][]string // owner -> order refs
	previews  map[string]preview
	orders    map[string]*order
	orderIdem map[string]string
	calls     []Call
	overrides map[string]Override
	healthy   bool
	// BasketWrites counts provider basket mutations. The harness has no code
	// path that increments it: it is the physical fence the tests assert on.
	BasketWrites int
}

type preview struct{ owner, fingerprint string }

// New builds a seeded Fake.
func New(opt Options) *Fake {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	f := &Fake{
		opt: opt, key: key, kid: "fake-kid-1",
		members:   map[string]map[string]bool{TeamAlpha: {Alice: true, Bob: true, Dana: true}, TeamBeta: {Carol: true}},
		pilot:     map[string]bool{TeamAlpha + "|" + Alice: true, TeamAlpha + "|" + Bob: true, TeamBeta + "|" + Carol: true},
		ambiguous: map[string]bool{}, revoked: map[string]bool{},
		scopes: map[string]scopeRec{}, conns: map[string]string{}, connIdem: map[string]string{},
		history:  map[string][]string{},
		previews: map[string]preview{}, orders: map[string]*order{}, orderIdem: map[string]string{},
		overrides: map[string]Override{}, healthy: true,
	}
	f.history[TeamAlpha+"|"+Alice] = []string{"ref_alice_1", "ref_alice_2"}
	f.history[TeamAlpha+"|"+Bob] = []string{"ref_bob_1"}
	f.history[TeamBeta+"|"+Carol] = []string{"ref_carol_1"}
	return f
}

// MintOpts describes a token to mint; zero values give a valid token.
type MintOpts struct {
	Sub, Tenant string
	Scope       string // default "glovo:read glovo:basket:prepare"
	Iss         string
	Aud         []string
	Exp, NBF    time.Time
	JTI         string
	Key         *rsa.PrivateKey // default: the fake's key
	KID         string
}

// Mint returns an RS256 JWT.
func (f *Fake) Mint(o MintOpts) string {
	if o.Scope == "" {
		o.Scope = "glovo:read glovo:basket:prepare"
	}
	if o.Iss == "" {
		o.Iss = f.opt.Issuer
	}
	if o.Aud == nil {
		o.Aud = []string{f.opt.Resource}
	}
	if o.Exp.IsZero() {
		o.Exp = time.Now().Add(10 * time.Minute)
	}
	key, kid := o.Key, o.KID
	if key == nil {
		key = f.key
	}
	if kid == "" {
		kid = f.kid
	}
	sg, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		panic(err)
	}
	cl := jwt.Claims{Issuer: o.Iss, Subject: o.Sub, Audience: o.Aud, Expiry: jwt.NewNumericDate(o.Exp), ID: o.JTI}
	if !o.NBF.IsZero() {
		cl.NotBefore = jwt.NewNumericDate(o.NBF)
	}
	tok, err := jwt.Signed(sg).Claims(cl).Claims(map[string]any{"scope": o.Scope, "mctl_tenant": o.Tenant}).Serialize()
	if err != nil {
		panic(err)
	}
	return tok
}

// SetMember adds or removes (ok=false) a team membership: the revocation
// knob for "membership revoked between two calls".
func (f *Fake) SetMember(tenant, sub string, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.members[tenant] == nil {
		f.members[tenant] = map[string]bool{}
	}
	f.members[tenant][sub] = ok
}

// SetAmbiguous makes Resolve report ambiguous_tenant for sub.
func (f *Fake) SetAmbiguous(sub string) { f.mu.Lock(); f.ambiguous[sub] = true; f.mu.Unlock() }

// RevokeToken marks a jti revoked.
func (f *Fake) RevokeToken(jti string) { f.mu.Lock(); f.revoked[jti] = true; f.mu.Unlock() }

// SetHealthy toggles /healthz.
func (f *Fake) SetHealthy(ok bool) { f.mu.Lock(); f.healthy = ok; f.mu.Unlock() }

// SetOverride installs a response override for paths ending in suffix.
func (f *Fake) SetOverride(suffix string, o Override) {
	f.mu.Lock()
	f.overrides[suffix] = o
	f.mu.Unlock()
}

// Calls returns the recorded protocol calls.
func (f *Fake) Calls() []Call {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Call(nil), f.calls...)
}

// EffectCalls returns the recorded calls that created state.
func (f *Fake) EffectCalls() []Call {
	var out []Call
	for _, c := range f.Calls() {
		if c.Effect {
			out = append(out, c)
		}
	}
	return out
}

// ResetCalls clears the recorder.
func (f *Fake) ResetCalls() { f.mu.Lock(); f.calls = nil; f.mu.Unlock() }

// Approve is the separate human approval endpoint's effect (never reachable
// through the facade).
func (f *Fake) Approve(aar string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.orders {
		if o.aar == aar {
			o.state = "approved"
			return true
		}
	}
	return false
}

// Handler returns the HTTP handler.
func (f *Fake) Handler() http.Handler { return http.HandlerFunc(f.serve) }

func rid(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/healthz":
		f.mu.Lock()
		ok := f.healthy
		f.mu.Unlock()
		if !ok {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
		return
	case r.URL.Path == "/.well-known/jwks.json":
		pub := jose.JSONWebKey{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"}
		writeJSON(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
		return
	case strings.HasPrefix(r.URL.Path, "/_fake/approve/") && r.Method == http.MethodPost:
		if f.Approve(strings.TrimPrefix(r.URL.Path, "/_fake/approve/")) {
			writeJSON(w, 200, map[string]string{"state": "approved"})
		} else {
			refuse(w, 404, mctlapi.CodeNotFound)
		}
		return
	case strings.HasPrefix(r.URL.Path, "/_fake/hir/") && r.Method == http.MethodPost:
		f.mu.Lock()
		o := f.orders[strings.TrimPrefix(r.URL.Path, "/_fake/hir/")]
		if o != nil {
			o.hir = append(o.hir, rid("hir_")) // a handoff record never changes state
		}
		f.mu.Unlock()
		writeJSON(w, 200, map[string]bool{"recorded": o != nil})
		return
	case !strings.HasPrefix(r.URL.Path, mctlapi.BasePath+"/"):
		http.NotFound(w, r)
		return
	}
	rel := strings.TrimPrefix(r.URL.Path, mctlapi.BasePath)
	f.mu.Lock()
	f.calls = append(f.calls, Call{Method: r.Method, Path: rel})
	callIdx := len(f.calls) - 1
	ov, hasOv := Override{}, false
	for suf, o := range f.overrides {
		if strings.HasSuffix(rel, suf) {
			ov, hasOv = o, true
		}
	}
	f.mu.Unlock()
	if hasOv {
		time.Sleep(ov.Delay)
		if ov.Status != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(ov.Status)
			_, _ = io.WriteString(w, ov.Body)
			return
		}
	}

	sub, tenant, tokHash, ok := f.authenticate(w, r)
	if !ok {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if rel == "/resolve" && r.Method == http.MethodPost {
		code := f.resolveLocked(sub, tenant)
		if code != "" {
			refuse(w, 403, code)
			return
		}
		ref := rid("gsc_")
		exp := time.Now().Add(60 * time.Second)
		f.scopes[ref] = scopeRec{tokHash: tokHash, sub: sub, tenant: tenant, exp: exp}
		writeJSON(w, 200, map[string]any{"scope_ref": ref, "tenant": tenant, "expires_at": exp.UTC().Format(time.RFC3339)})
		return
	}
	sc, found := f.scopes[r.Header.Get(mctlapi.HeaderScopeRef)]
	if !found || sc.tokHash != tokHash || sc.sub != sub || time.Now().After(sc.exp) {
		refuse(w, 403, mctlapi.CodeNotAuthorized)
		return
	}
	// Membership and pilot are re-checked on every call.
	if code := f.resolveLocked(sub, sc.tenant); code != "" {
		refuse(w, 403, code)
		return
	}
	owner := sc.tenant + "|" + sub
	var body map[string]any
	if r.Method == http.MethodPost {
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		if err := dec.Decode(&body); err != nil {
			refuse(w, 400, mctlapi.CodeInvalidArguments)
			return
		}
	}
	str := func(k string) string { s, _ := body[k].(string); return s }
	exp := time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339)

	switch {
	case rel == "/connection" && r.Method == http.MethodGet:
		if id, ok := f.conns[owner]; ok {
			writeJSON(w, 200, map[string]any{"connection_state": "pending_handoff", "connection_id": id, "expires_at": exp})
			return
		}
		writeJSON(w, 200, map[string]any{"connection_state": "none"})
	case rel == "/connections" && r.Method == http.MethodPost:
		key := owner + "|" + str("idempotency_key")
		id, ok := f.connIdem[key]
		if !ok {
			if id, ok = f.conns[owner]; !ok {
				id = rid("gcn_")
				f.calls[callIdx].Effect = true
			}
			f.conns[owner], f.connIdem[key] = id, id
		}
		writeJSON(w, 200, map[string]any{"connection_id": id, "state": "pending_handoff",
			"handoff_url": "https://glovo.mctl.ai/handoff/" + rid("h"), "expires_at": exp})
	case rel == "/orders:list" && r.Method == http.MethodPost:
		orders := []map[string]any{}
		for _, ref := range f.history[owner] {
			orders = append(orders, map[string]any{"order_ref": ref, "store_name": "Fake Pizzeria",
				"placed_at": "2026-01-02T03:04:05Z", "total_label": "EUR 12.00", "item_count": 2})
		}
		writeJSON(w, 200, map[string]any{"orders": orders})
	case rel == "/previews" && r.Method == http.MethodPost:
		known := false
		for _, ref := range f.history[owner] {
			known = known || ref == str("order_ref")
		}
		if !known {
			refuse(w, 404, mctlapi.CodeNotFound)
			return
		}
		sum := sha256.Sum256([]byte(owner + str("order_ref")))
		id, fp := rid("prv_"), "fp_"+hex.EncodeToString(sum[:6])
		f.previews[id] = preview{owner: owner, fingerprint: fp}
		writeJSON(w, 200, map[string]any{"preview_id": id, "fingerprint": fp, "expires_at": exp,
			"items":             []map[string]any{{"name": "Margherita", "quantity": 1}},
			"unavailable_items": []map[string]any{}})
	case rel == "/basket" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"store_name": "Fake Pizzeria", "totals_label": "EUR 0.00",
			"fingerprint": "fp_basket", "items": []map[string]any{{"name": "Margherita", "quantity": 1}}})
	case rel == "/orders:prepare" && r.Method == http.MethodPost:
		pv, ok := f.previews[str("preview_id")]
		if !ok || pv.owner != owner {
			refuse(w, 404, mctlapi.CodeNotFound)
			return
		}
		key := owner + "|" + str("idempotency_key")
		id, ok := f.orderIdem[key]
		if !ok {
			id = rid("ord_")
			f.calls[callIdx].Effect = true
			f.orderIdem[key] = id
			f.orders[id] = &order{id: id, aar: rid("aar_"), owner: owner, state: "awaiting_consent", fingerprint: pv.fingerprint}
		}
		o := f.orders[id]
		writeJSON(w, 200, map[string]any{"order_id": id, "fingerprint": o.fingerprint, "consent_request_id": o.aar, "expires_at": exp})
	case strings.HasPrefix(rel, "/orders/") && r.Method == http.MethodGet:
		o := f.orders[strings.TrimPrefix(rel, "/orders/")]
		if o == nil || o.owner != owner {
			refuse(w, 404, mctlapi.CodeNotFound)
			return
		}
		writeJSON(w, 200, map[string]any{"state": o.state, "outcome": "OUTCOME_UNKNOWN"})
	default:
		http.NotFound(w, r)
	}
}

// authenticate checks the workload credential and re-verifies the forwarded
// subject token (signature, issuer, audience, expiry, revocation). The
// selected tenant is taken from the VERIFIED token claim, never from the
// X-Mctl-Selected-Tenant header.
func (f *Fake) authenticate(w http.ResponseWriter, r *http.Request) (sub, tenant, tokHash string, ok bool) {
	if r.Header.Get("Authorization") != "Bearer "+f.opt.Credential {
		refuse(w, 401, mctlapi.CodeNotAuthorized)
		return
	}
	raw := r.Header.Get(mctlapi.HeaderSubjectToken)
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	var c struct {
		jwt.Claims
		Tenant string `json:"mctl_tenant"`
	}
	if err != nil || tok.Claims(&f.key.PublicKey, &c) != nil ||
		c.Issuer != f.opt.Issuer || !c.Audience.Contains(f.opt.Resource) ||
		c.Expiry == nil || !time.Now().Before(c.Expiry.Time()) || c.Subject == "" {
		refuse(w, 401, mctlapi.CodeNotAuthorized)
		return
	}
	f.mu.Lock()
	revoked := f.revoked[c.ID]
	f.mu.Unlock()
	if revoked {
		refuse(w, 401, mctlapi.CodeNotAuthorized)
		return
	}
	sum := sha256.Sum256([]byte(raw))
	return c.Subject, c.Tenant, hex.EncodeToString(sum[:8]), true
}

func (f *Fake) resolveLocked(sub, tenant string) string {
	switch {
	case tenant == "":
		return mctlapi.CodeNoTenant
	case f.ambiguous[sub]:
		return mctlapi.CodeAmbiguousTenant
	case strings.HasPrefix(tenant, "personal:"):
		return mctlapi.CodeScopeUnsupported
	case !f.members[tenant][sub]:
		return mctlapi.CodeNotAuthorized
	case !f.pilot[tenant+"|"+sub]:
		return mctlapi.CodeNotInPilot
	}
	return ""
}
