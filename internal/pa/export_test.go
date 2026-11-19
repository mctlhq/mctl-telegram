package pa

// export_test.go hands the run-loop harness to the connector dispatch
// acceptance tests (package pa_test, dispatch_acceptance_test.go), which
// cannot live in package pa: the connector imports pa.

import (
	"net/http"
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
type DispatchHarness struct{ h *runLoopHarness }

// NewDispatchHarness builds the harness on store.
func NewDispatchHarness(t *testing.T, store *db.Store) *DispatchHarness {
	t.Helper()
	return &DispatchHarness{h: newRunLoopHarnessOn(t, store)}
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

// Claim claims the next job as the pool.
func (d *DispatchHarness) Claim() (token string, jobID int64, attempt int, code int) {
	c, code := d.h.claim()
	return c.Token, c.JobID, c.Attempt, code
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
