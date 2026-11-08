//go:build l2finance

package policy

import "testing"

// L2 outcome rubric for the finance-assistant owner-private spike (#1244).
const (
	l2Pass           = "PASS"
	l2FailGap        = "FAIL/GAP"
	l2NotImplemented = "NOT-IMPLEMENTED"
	l2CannotObserve  = "CANNOT-OBSERVE"
)

// l2Record emits one structured result line. Harness success is not a
// security-gate pass: FINANCE_SECURITY_GATE stays BLOCKED while any row is
// not PASS.
func l2Record(t testing.TB, id, outcome, evidence string) {
	t.Helper()
	t.Logf("L2RESULT id=%s outcome=%s rev=248db4f evidence=%s", id, outcome, evidence)
}

// expectGap records FAIL/GAP when the unsafe behaviour is observed and fails
// the test when it no longer reproduces, so a gap is never renamed to PASS
// silently.
func expectGap(t testing.TB, id string, observed bool, evidence string) {
	t.Helper()
	if !observed {
		t.Fatalf("%s: gap no longer reproduces; update rubric via reviewed PR", id)
	}
	l2Record(t, id, l2FailGap, evidence)
}
