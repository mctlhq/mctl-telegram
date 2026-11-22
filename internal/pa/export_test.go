package pa

// export_test.go hands the run-loop harness to the connector dispatch
// acceptance tests (package pa_test, dispatch_acceptance_test.go), which
// cannot live in package pa: the connector imports pa.

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// Synthetic personas of this package's tests.
const (
	TestAliceID = aliceID
	TestBobID   = bobID
)

// DispatchHarness is a run loop with a webhook, conversations and the job
// ledger on one store.
type DispatchHarness struct {
	h           *runLoopHarness
	failDisable atomic.Bool
}

// NewDispatchHarness builds the harness on store.
func NewDispatchHarness(t *testing.T, store *db.Store) *DispatchHarness {
	t.Helper()
	d := &DispatchHarness{}
	d.h = newRunLoopHarnessOn(t, store, withStore(func(s *db.Store) RunLoopStore {
		return &toggleDisable{Store: s, fail: &d.failDisable}
	}))
	return d
}

func (d *DispatchHarness) Loop() *RunLoop           { return d.h.loop }
func (d *DispatchHarness) Issuer() *localjwt.Issuer { return d.h.issuer }
func (d *DispatchHarness) Now() time.Time           { return d.h.now }
func (d *DispatchHarness) Advance(dur time.Duration) {
	d.h.now = d.h.now.Add(dur)
}
func (d *DispatchHarness) SetTools(tools []string) { d.h.tools = tools }
func (d *DispatchHarness) SetConns(conns map[int64][]ConnectionRevision) {
	d.h.conns = conns
}
func (d *DispatchHarness) Consent(user int64) { d.h.consent(user) }
func (d *DispatchHarness) Text(user int64, s string) {
	if code := d.h.text(user, s); code != http.StatusOK {
		d.h.t.Fatalf("message: %d", code)
	}
}
func (d *DispatchHarness) Count(q string, args ...any) int { return d.h.count(q, args...) }

// FailDisableReads makes the run loop's principal-disable read fail (on)
// or read the store again (off).
func (d *DispatchHarness) FailDisableReads(on bool) { d.failDisable.Store(on) }

// Deny takes user off the run loop's and the conversations' allowlist.
func (d *DispatchHarness) Deny(user int64) { d.h.allow.deny(user) }

// Claim claims the next job as the pool.
func (d *DispatchHarness) Claim() (token string, jobID int64, attempt int, code int) {
	c, code := d.h.claim()
	return c.Token, c.JobID, c.Attempt, code
}

// ClaimRaw claims the next job as the pool and returns the response body
// as the worker receives it (S1-K2 scans it for token material).
func (d *DispatchHarness) ClaimRaw() (body []byte, token string, code int) {
	w := d.h.post(RouteClaim, d.h.pool, nil)
	var c claimResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			d.h.t.Fatal(err)
		}
	}
	return w.Body.Bytes(), c.Token, w.Code
}

// TurnRaw asks for a model turn under token and returns the raw body.
func (d *DispatchHarness) TurnRaw(token string) (body []byte, code int) {
	w := d.h.post(RouteTurn, token, turnRequest{ContextTokens: 10})
	return w.Body.Bytes(), w.Code
}

// RevokePool revokes the pool credential every job token inherits and
// refreshes the revocation cache, as its TTL running out would.
func (d *DispatchHarness) RevokePool(t *testing.T) {
	t.Helper()
	if err := d.h.convoHarness.store.RevokeWorkerToken(t.Context(), "pool-jti", 0, "test", 1); err != nil {
		t.Fatal(err)
	}
	if err := d.h.cache.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
}
