//go:build l2finance

package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

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
	t.Logf("L2RESULT id=%s outcome=%s rev=%s evidence=fixture_id=%s %s", id, outcome, l2SourceRev, l2Fixture(id), evidence)
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

var errL2ExternalDial = errors.New("l2finance: external dial refused")

var (
	l2SourceRev string
	l2RevRe     = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// l2Fixture returns the stable synthetic fixture identifier of a case.
func l2Fixture(id string) string { return "L2SYNTH-" + id }

// l2GuardDial allows only loopback TCP/UDP. It guards the default transport
// only; it is not a whole-process egress firewall.
func l2GuardDial(_ context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || strings.HasPrefix(network, "unix") {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("%w: %s", errL2ExternalDial, addr)
	}
	var d net.Dialer
	return d.DialContext(context.Background(), network, addr)
}

func TestMain(m *testing.M) {
	l2SourceRev = os.Getenv("L2FINANCE_SOURCE_REV")
	if !l2RevRe.MatchString(l2SourceRev) {
		fmt.Fprintln(os.Stderr, "l2finance: L2FINANCE_SOURCE_REV must be a 40-hex commit sha")
		os.Exit(2)
	}
	_ = os.Unsetenv("TG_API_ID")
	_ = os.Unsetenv("TG_API_HASH")
	_ = os.Unsetenv("DATABASE_URL")
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errL2ExternalDial
		},
	}
	if tr, ok := http.DefaultTransport.(*http.Transport); ok {
		tr.DialContext = l2GuardDial
	}
	os.Exit(m.Run())
}
