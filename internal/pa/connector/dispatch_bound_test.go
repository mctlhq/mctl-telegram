package connector

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// allSecurityReasons is the security refusal class, spelled out so that a
// reason dropped from securityReasons fails here.
var allSecurityReasons = []string{
	ReasonConnectionUnbound, ReasonToolNotInSet, ReasonJobStale,
	ReasonTokenExpired, ReasonTokenRevoked, ReasonTokenInvalid, ReasonTokenUnverifiable,
}

func (e *surfaceEnv) refuseN(principal int64, reason string, n int) {
	for i := 0; i < n; i++ {
		e.d.refuse(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, RouteTool, nil),
			Refusal{Principal: principal, Reason: reason}, http.StatusForbidden)
	}
}

func boundEnv(t *testing.T) (*surfaceEnv, *lockedSink) {
	t.Helper()
	e := newSurfaceEnv(t)
	sink := &lockedSink{}
	e.d.cfg.Executor = &Executor{Sink: sink, Now: time.Now}
	return e, sink
}

// written counts the rows of reason for principal.
func (s *lockedSink) written(principal int64, reason string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.entries {
		if e.Principal == principal && e.Reason == reason {
			n++
		}
	}
	return n
}

// summary returns principal's summary count for reason (0: no row).
func (s *lockedSink) summary(t *testing.T, principal int64, reason string) int64 {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out int64
	rows := 0
	for _, e := range s.entries {
		if e.Principal == principal && e.Reason == reason {
			out = e.Suppressed
			rows++
		}
	}
	if rows > 1 {
		t.Fatalf("%d %s rows for %d", rows, reason, principal)
	}
	return out
}

func (e *surfaceEnv) closeWindows() {
	e.d.recordSuppressed(context.Background(), e.d.closedRefusalWindows())
}

func TestSecurityReasonsClass(t *testing.T) {
	got := make([]string, 0, len(securityReasons))
	for r := range securityReasons {
		got = append(got, r)
	}
	want := append([]string(nil), allSecurityReasons...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("securityReasons %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("securityReasons %v, want %v", got, want)
		}
	}
}

// P2 of the #1341 review, round 4: every security reason is bounded (no
// line-rate chain flood) by its own, larger bound with its own summary
// row, and neither class uses up the other's bound.
func TestRefusalSecurityBound(t *testing.T) {
	for _, reason := range allSecurityReasons {
		t.Run(reason, func(t *testing.T) {
			// General traffic first: the security bound is still whole.
			e, sink := boundEnv(t)
			e.refuseN(555, ReasonBadRequest, refusalAuditBurst+3)
			e.refuseN(555, reason, securityAuditBurst+7)
			if n := sink.written(555, reason); n != securityAuditBurst {
				t.Fatalf("%d %s rows, want %d", n, reason, securityAuditBurst)
			}
			if n := sink.written(555, ReasonBadRequest); n != refusalAuditBurst {
				t.Fatalf("%d bad_request rows, want %d", n, refusalAuditBurst)
			}
			if got := testutil.ToFloat64(e.reg.PADispatchTotal.WithLabelValues(invalidServer, statusRefusedUnaudited, reason)); got != 7 {
				t.Fatalf("unaudited %s counted %v, want 7", reason, got)
			}
			e.advance(refusalAuditWindow)
			e.closeWindows()
			if n := sink.summary(t, 555, ReasonRefusalsSuppressedSecurity); n != 7 {
				t.Fatalf("security summary %d, want 7", n)
			}
			if n := sink.summary(t, 555, ReasonRefusalsSuppressed); n != 3 {
				t.Fatalf("general summary %d, want 3", n)
			}

			// Security traffic first: the general bound is still whole.
			e, sink = boundEnv(t)
			e.refuseN(556, reason, securityAuditBurst+1)
			e.refuseN(556, ReasonBadRequest, refusalAuditBurst)
			if n := sink.written(556, ReasonBadRequest); n != refusalAuditBurst {
				t.Fatalf("%d bad_request rows after %s, want %d", n, reason, refusalAuditBurst)
			}
			e.advance(refusalAuditWindow)
			e.closeWindows()
			if n := sink.summary(t, 556, ReasonRefusalsSuppressed); n != 0 {
				t.Fatalf("general summary %d, want none", n)
			}
			if n := sink.summary(t, 556, ReasonRefusalsSuppressedSecurity); n != 1 {
				t.Fatalf("security summary %d, want 1", n)
			}
		})
	}
}

// A flood of one probe cannot hide the first of another: the first
// refusal of each reason in a window is written past the bound.
func TestRefusalFirstOfReasonWritten(t *testing.T) {
	e, sink := boundEnv(t)
	e.refuseN(555, ReasonToolNotInSet, securityAuditBurst+10)
	e.refuseN(555, ReasonJobStale, 2)
	if n := sink.written(555, ReasonJobStale); n != 1 {
		t.Fatalf("%d job_stale rows past the bound, want 1", n)
	}
	e.refuseN(555, ReasonBadRequest, refusalAuditBurst+2)
	e.refuseN(555, ReasonServerUnavailable, 2)
	if n := sink.written(555, ReasonServerUnavailable); n != 1 {
		t.Fatalf("%d server_unavailable rows past the bound, want 1", n)
	}
}

// R23: a new principal past maxRefusalPrincipals closes the ended windows
// and writes their summaries at once, without waiting for Run.
func TestRefusalEvictionWritesSummaries(t *testing.T) {
	old := maxRefusalPrincipals
	maxRefusalPrincipals = 2
	t.Cleanup(func() { maxRefusalPrincipals = old })
	e, sink := boundEnv(t)
	e.refuseN(555, ReasonBadRequest, refusalAuditBurst+2)
	e.refuseN(556, ReasonToolNotInSet, securityAuditBurst+3)
	e.advance(refusalAuditWindow)
	e.refuseN(557, ReasonBadRequest, 1)
	if n := sink.summary(t, 555, ReasonRefusalsSuppressed); n != 2 {
		t.Fatalf("555 summary %d, want 2", n)
	}
	if n := sink.summary(t, 556, ReasonRefusalsSuppressedSecurity); n != 3 {
		t.Fatalf("556 summary %d, want 3", n)
	}
	e.d.mu.Lock()
	open := len(e.d.refusals)
	e.d.mu.Unlock()
	if open != 1 {
		t.Fatalf("%d windows open after eviction, want 1", open)
	}
}

// startSlow starts a listing of connection c1 that blocks after reading
// its answer, and returns when it is on the wire.
func (e *surfaceEnv) startSlow(t *testing.T) (release chan struct{}, done chan struct{}) {
	t.Helper()
	release, done = make(chan struct{}), make(chan struct{})
	e.ep.mu.Lock()
	before := e.ep.lists["tok-c1"]
	e.ep.block = map[string]chan struct{}{"tok-c1": release}
	e.ep.mu.Unlock()
	go func() { e.observe("c1", 1); close(done) }()
	for {
		e.ep.mu.Lock()
		started := e.ep.lists["tok-c1"] > before
		e.ep.mu.Unlock()
		if started {
			return release, done
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *surfaceEnv) cachedDrift(t *testing.T) (drift, cached bool) {
	t.Helper()
	e.d.mu.Lock()
	c, ok := e.d.listings[listingKey{server: "tg", connection: "c1", revision: 1}]
	e.d.mu.Unlock()
	if !ok {
		return false, false
	}
	drift, _, _ = PinDrift(c.s)
	return drift, true
}

// P3 of the #1341 review, round 4: the listing cache is ordered by start
// time like the observations, so an older read that finishes late neither
// replaces nor deletes a newer cached listing, and calls authorize against
// the listing the gauges report.
func TestListingCacheOrderedByStart(t *testing.T) {
	t.Run("clean read late", func(t *testing.T) {
		e := newSurfaceEnv(t)
		e.ep.pages["tok-c1"] = tgListing(t, nil)
		release, done := e.startSlow(t)
		e.ep.mu.Lock()
		e.ep.pages["tok-c1"] = driftedTG(t)
		e.ep.mu.Unlock()
		e.advance(time.Second)
		e.observe("c1", 1)
		close(release)
		<-done
		if drift, cached := e.cachedDrift(t); !cached || !drift {
			t.Fatalf("cache drift %v cached %v: the older clean read replaced the newer drifted one", drift, cached)
		}
		if d, _ := gaugeOf(t, e.reg, "tg"); d != 1 {
			t.Fatalf("gauge drift %v, want 1", d)
		}
	})
	for name, err := range map[string]error{"failed read late": errors.New("down"), "refused token late": ErrMCPUnauthorized} {
		t.Run(name, func(t *testing.T) {
			e := newSurfaceEnv(t)
			e.ep.errs["tok-c1"] = err
			release, done := e.startSlow(t)
			e.ep.mu.Lock()
			delete(e.ep.errs, "tok-c1")
			e.ep.pages["tok-c1"] = driftedTG(t)
			e.ep.mu.Unlock()
			e.advance(time.Second)
			e.observe("c1", 1)
			close(release)
			<-done
			if drift, cached := e.cachedDrift(t); !cached || !drift {
				t.Fatalf("cache drift %v cached %v: the older failure dropped the newer listing", drift, cached)
			}
		})
	}
}

// Every configured server's failure series exist at 0 from the start, so
// increase() sees the first failure of each reason.
func TestListingFailuresPreInitialized(t *testing.T) {
	e := newSurfaceEnv(t)
	for _, server := range []string{"tg", "alice"} {
		for _, reason := range ListingFailureReasons {
			c, err := e.reg.PAPinListingFailures.GetMetricWithLabelValues(server, reason)
			if err != nil {
				t.Fatal(err)
			}
			if v := testutil.ToFloat64(c); v != 0 {
				t.Fatalf("%s/%s = %v, want 0", server, reason, v)
			}
		}
	}
	if n := testutil.CollectAndCount(e.reg.PAPinListingFailures); n != 2*len(ListingFailureReasons) {
		t.Fatalf("%d failure series, want %d", n, 2*len(ListingFailureReasons))
	}
}
