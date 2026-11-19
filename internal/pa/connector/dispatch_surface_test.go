package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// tokenEP is tg's endpoint answering tools/list per bearer: each
// connection's token sees its own listing (or error).
type tokenEP struct {
	server string // "tg" when empty
	mu     sync.Mutex
	pages  map[string][]byte
	errs   map[string]error
	lists  map[string]int
	// block holds the next ListTools of a token (its page is read before
	// it waits) until the channel is closed.
	block map[string]chan struct{}
}

func (e *tokenEP) Server() string {
	if e.server == "" {
		return "tg"
	}
	return e.server
}

func (e *tokenEP) ListTools(_ context.Context, tok connection.Secret) ([][]byte, error) {
	e.mu.Lock()
	e.lists[tok.Reveal()]++
	err, page := e.errs[tok.Reveal()], e.pages[tok.Reveal()]
	ch := e.block[tok.Reveal()]
	delete(e.block, tok.Reveal())
	e.mu.Unlock()
	if ch != nil {
		<-ch
	}
	if err != nil {
		return nil, err
	}
	return [][]byte{page}, nil
}

func (e *tokenEP) CallTool(context.Context, connection.Secret, string, json.RawMessage) ([]byte, error) {
	return nil, errors.New("not used")
}

type noJobs struct{}

func (noJobs) AuthenticateAttributed(*http.Request) (pa.PAJob, pa.TokenRefusal, error) {
	return pa.PAJob{}, pa.TokenRefusal{}, errors.New("not used")
}
func (noJobs) AdmitToolCall(context.Context, pa.PAJob, string, string) (pa.Policy, error) {
	return pa.Policy{}, errors.New("not used")
}
func (noJobs) StillRunning(context.Context, pa.PAJob) error { return errors.New("not used") }

type noConns struct{}

func (noConns) List(context.Context, int64) ([]connection.Connection, error) {
	return nil, errors.New("not used")
}
func (noConns) BeginCall(context.Context, int64, string, int64) (*connection.Call, error) {
	return nil, errors.New("not used")
}
func (noConns) AccessToken(context.Context, int64, string, int64) (connection.Secret, connection.Connection, error) {
	return connection.Secret{}, connection.Connection{}, errors.New("not used")
}

type surfaceEnv struct {
	d     *Dispatcher
	ep    *tokenEP
	alice *tokenEP
	reg   *metrics.Registry
	clock sync.Mutex
	now   time.Time
}

func (e *surfaceEnv) advance(d time.Duration) {
	e.clock.Lock()
	e.now = e.now.Add(d)
	e.clock.Unlock()
}

func newSurfaceEnv(t *testing.T) *surfaceEnv {
	t.Helper()
	e := &surfaceEnv{
		ep:    &tokenEP{pages: map[string][]byte{}, errs: map[string]error{}, lists: map[string]int{}},
		alice: &tokenEP{server: "alice", pages: map[string][]byte{}, errs: map[string]error{}, lists: map[string]int{}},
		reg:   metrics.New(),
		now:   t0,
	}
	d, err := NewDispatcher(DispatcherConfig{
		Jobs: noJobs{}, Connections: noConns{}, Pin: loadPin(t),
		Endpoints: map[string]MCPEndpoint{"tg": e.ep, "alice": e.alice},
		Executor:  newExecutor(&fakeSink{ev: &events{}}),
		Flags:     func() (Flags, error) { return Flags{}, nil },
		Metrics:   e.reg,
		Now: func() time.Time {
			e.clock.Lock()
			defer e.clock.Unlock()
			return e.now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	e.d = d
	return e
}

// observe reads the listing of connection id at revision rev.
func (e *surfaceEnv) observe(id string, rev int64) bool {
	_, listed := e.d.surface(context.Background(), e.ep, connection.NewSecret("tok-"+id),
		pa.ConnectionRevision{ConnectionID: id, AuthorityRevision: rev})
	return listed
}

func (e *surfaceEnv) gauges(t *testing.T) (drift float64, driftSeries int, unknown float64, deniedSeries int) {
	t.Helper()
	driftSeries = testutil.CollectAndCount(e.reg.PAPinDrift)
	if driftSeries > 0 {
		drift = testutil.ToFloat64(e.reg.PAPinDrift.WithLabelValues("tg"))
	}
	if testutil.CollectAndCount(e.reg.PAPinListingUnknown) > 0 {
		unknown = testutil.ToFloat64(e.reg.PAPinListingUnknown.WithLabelValues("tg"))
	}
	return drift, driftSeries, unknown, testutil.CollectAndCount(e.reg.PAPinDeniedTools)
}

// TestPinGaugesAggregateConnections (P2 of the #1341 review): listings are
// read per connection, the gauges are per server. Drift seen on one
// connection stays reported while another connection's listing fails or
// its token is refused; unknown is reported only when no connection has a
// fresh listing; a refused token is a problem of that connection, counted
// but never "listing unknown".
func TestPinGaugesAggregateConnections(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-c1"] = tgListing(t, func(tools []map[string]any) []map[string]any {
		for _, tool := range tools {
			if tool["name"] == "get_messages" {
				tool["description"] = "changed"
			}
		}
		return tools
	})
	e.ep.pages["tok-c2"] = tgListing(t, nil)
	e.ep.errs["tok-c3"] = errors.New("connection reset")
	e.ep.errs["tok-c4"] = ErrMCPUnauthorized

	step := func(name, id string, wantListed bool, wantDrift float64, wantSeries int, wantUnknown float64) {
		t.Helper()
		if listed := e.observe(id, 1); listed != wantListed {
			t.Fatalf("%s: listed %v", name, listed)
		}
		drift, series, unknown, _ := e.gauges(t)
		if series != wantSeries || drift != wantDrift || unknown != wantUnknown {
			t.Fatalf("%s: drift %v (%d series) unknown %v, want %v (%d) %v", name, drift, series, unknown, wantDrift, wantSeries, wantUnknown)
		}
	}
	step("c1 drifts", "c1", true, 1, 1, 0)
	step("c3 fails", "c3", true, 1, 1, 0)
	step("c4 refused", "c4", false, 1, 1, 0)
	step("c2 matches", "c2", true, 1, 1, 0)
	e.now = e.now.Add(time.Minute)
	step("c3 fails again", "c3", true, 1, 1, 0)
	if got := testutil.ToFloat64(e.reg.PAPinListingFailures.WithLabelValues("tg", "unauthorized")); got != 1 {
		t.Fatalf("unauthorized failures %v, want 1", got)
	}
	if got := testutil.ToFloat64(e.reg.PAPinListingFailures.WithLabelValues("tg", "unavailable")); got != 2 {
		t.Fatalf("unavailable failures %v, want 2", got)
	}

	// c1's drift ages out; c2 still matches.
	e.now = e.now.Add(PinObservationWindow)
	step("c2 alone", "c2", true, 0, 1, 0)
	// Nothing fresh but a failure: unknown, and no drift or denied series.
	e.now = e.now.Add(PinObservationWindow + time.Second)
	step("only failures", "c3", true, 0, 0, 1)
	if _, _, _, denied := e.gauges(t); denied != 0 {
		t.Fatalf("%d denied-tool series while unknown", denied)
	}
	// A refused token on top of that changes nothing.
	step("refused while unknown", "c4", false, 0, 0, 1)
}

// TestPinGaugesAgeOut (#1341 review thread on recordPinLocked): an
// observation that leaves the window takes the server's gauges with it,
// whoever triggers the refresh. A fresh drift ages into unknown, never into
// a stale 1 or a 0 that claims "no drift"; a fresh clean listing clears it.
func TestPinGaugesAgeOut(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-c1"] = tgListing(t, func(tools []map[string]any) []map[string]any {
		for _, tool := range tools {
			if tool["name"] == "get_messages" {
				tool["description"] = "changed"
			}
		}
		return tools
	})
	e.ep.pages["tok-c2"] = tgListing(t, nil)
	e.alice.errs["tok-a1"] = errors.New("connection reset")
	want := func(name string, wantDrift float64, wantSeries int, wantUnknown float64) {
		t.Helper()
		drift, series, unknown, denied := e.gauges(t)
		if series != wantSeries || drift != wantDrift || unknown != wantUnknown {
			t.Fatalf("%s: drift %v (%d series) unknown %v, want %v (%d) %v", name, drift, series, unknown, wantDrift, wantSeries, wantUnknown)
		}
		if wantSeries == 0 && denied != 0 {
			t.Fatalf("%s: %d denied-tool series while unknown", name, denied)
		}
	}
	e.observe("c1", 1)
	want("fresh drift", 1, 1, 0)

	// Idle: a refresh with no dispatch ages the drift out to unknown.
	e.now = e.now.Add(PinObservationWindow + time.Second)
	e.d.RefreshPins()
	want("drift aged out", 0, 0, 1)
	// The aged observation is dropped, not only ignored: the map does not
	// grow with every connection and revision ever seen.
	e.d.mu.Lock()
	kept := len(e.d.observations)
	e.d.mu.Unlock()
	if kept != 0 {
		t.Fatalf("%d aged observations kept", kept)
	}

	e.observe("c2", 1)
	want("fresh clean listing", 0, 1, 0)

	// Another server's dispatch also ages tg's clean listing out: no 0
	// stays behind without a fresh listing.
	e.now = e.now.Add(PinObservationWindow + time.Second)
	e.d.surface(context.Background(), e.alice, connection.NewSecret("tok-a1"), pa.ConnectionRevision{ConnectionID: "a1", AuthorityRevision: 1})
	want("clean aged out by alice", 0, 0, 1)

	// Run does the refresh on its own.
	e.observe("c1", 2)
	want("fresh drift again", 1, 1, 0)
	e.d.mu.Lock()
	e.now = e.now.Add(PinObservationWindow + time.Second)
	e.d.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.d.Run(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		e.d.mu.Lock()
		series := testutil.CollectAndCount(e.reg.PAPinDrift)
		e.d.mu.Unlock()
		if series == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("Run never aged the drift out")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	want("drift aged out by Run", 0, 0, 1)
}

func driftedTG(t *testing.T) []byte {
	return tgListing(t, func(tools []map[string]any) []map[string]any {
		for _, tool := range tools {
			if tool["name"] == "get_messages" {
				tool["description"] = "changed"
			}
		}
		return tools
	})
}

// gaugeOf reads one server's drift and unknown gauges; -1 when the series
// is absent.
func gaugeOf(t *testing.T, reg *metrics.Registry, server string) (drift, unknown float64) {
	t.Helper()
	read := func(c prometheus.Collector) float64 {
		ch := make(chan prometheus.Metric, 16)
		c.Collect(ch)
		close(ch)
		v := -1.0
		for m := range ch {
			var pb dto.Metric
			if err := m.Write(&pb); err != nil {
				t.Fatal(err)
			}
			for _, l := range pb.GetLabel() {
				if l.GetName() == "server" && l.GetValue() == server {
					v = pb.GetGauge().GetValue()
				}
			}
		}
		return v
	}
	return read(reg.PAPinDrift), read(reg.PAPinListingUnknown)
}

// TestPinFailureKeepsFreshDrift (P2-A of the #1341 round-2 review): a
// connection's own failed listing does not erase the drift it saw while
// that drift is fresh. A server alternating a drifted listing with 500s
// keeps drift=1; it never flaps to 0 or to absent.
func TestPinFailureKeepsFreshDrift(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-carol"] = tgListing(t, nil)
	e.ep.pages["tok-alice"] = driftedTG(t)
	e.observe("carol", 1)
	e.observe("alice", 1)
	if d, u := gaugeOf(t, e.reg, "tg"); d != 1 || u != 0 {
		t.Fatalf("carol clean + alice drift: drift %v unknown %v", d, u)
	}
	for i := 0; i < 4; i++ {
		e.advance(catalog.ReadListingTTL + time.Second)
		if i%2 == 0 {
			e.ep.errs["tok-alice"] = errors.New("500")
		} else {
			delete(e.ep.errs, "tok-alice")
		}
		e.observe("alice", 1)
		if d, u := gaugeOf(t, e.reg, "tg"); d != 1 || u != 0 {
			t.Fatalf("step %d: drift %v unknown %v, want 1 0", i, d, u)
		}
	}

	// Alice alone: drift, then only failures. Drift holds while fresh,
	// then becomes unknown (drift absent), never 0.
	e2 := newSurfaceEnv(t)
	e2.ep.pages["tok-alice"] = driftedTG(t)
	e2.observe("alice", 1)
	e2.ep.errs["tok-alice"] = errors.New("500")
	e2.advance(catalog.ReadListingTTL + time.Second)
	e2.observe("alice", 1)
	if d, u := gaugeOf(t, e2.reg, "tg"); d != 1 || u != 0 {
		t.Fatalf("alice alone after a 500: drift %v unknown %v", d, u)
	}
	e2.advance(PinObservationWindow)
	e2.observe("alice", 1)
	if d, u := gaugeOf(t, e2.reg, "tg"); d != -1 || u != 1 {
		t.Fatalf("only failures in the window: drift %v unknown %v, want absent 1", d, u)
	}
}

// TestPinObservationOrderedByStart: a listing that started earlier but
// finished later does not replace a newer one of the same connection.
func TestPinObservationOrderedByStart(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-c1"] = driftedTG(t)
	release := make(chan struct{})
	e.ep.block = map[string]chan struct{}{"tok-c1": release}
	done := make(chan struct{})
	go func() { e.observe("c1", 1); close(done) }()
	for {
		e.ep.mu.Lock()
		started := e.ep.lists["tok-c1"] == 1
		e.ep.mu.Unlock()
		if started {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// The slow (drifted) read is on the wire; a newer read is clean.
	e.ep.mu.Lock()
	e.ep.pages["tok-c1"] = tgListing(t, nil)
	e.ep.mu.Unlock()
	e.advance(time.Second)
	e.observe("c1", 1)
	close(release)
	<-done
	if d, _ := gaugeOf(t, e.reg, "tg"); d != 0 {
		t.Fatalf("drift %v: the older read replaced the newer one", d)
	}
}

// N6: a server's gauges use only its own observations.
func TestPinGaugesPerServer(t *testing.T) {
	e := newSurfaceEnv(t)
	page, err := os.ReadFile(filepath.Join("..", "catalog", "testdata", "alice.tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	e.alice.pages["tok-a1"] = []byte(strings.Replace(string(page), `"description": "`, `"description": "changed `, 1))
	e.ep.pages["tok-c1"] = tgListing(t, nil)
	e.d.surface(context.Background(), e.alice, connection.NewSecret("tok-a1"), pa.ConnectionRevision{ConnectionID: "a1", AuthorityRevision: 1})
	e.observe("c1", 1)
	if d, u := gaugeOf(t, e.reg, "alice"); d != 1 || u != 0 {
		t.Fatalf("alice drift %v unknown %v, want 1 0", d, u)
	}
	if d, u := gaugeOf(t, e.reg, "tg"); d != 0 || u != 0 {
		t.Fatalf("tg drift %v unknown %v, want 0 0", d, u)
	}
}

// P2-B: with only refused tokens after a clean listing, the window still
// moves: past it the server reads unknown, not a stale 0.
func TestPinGaugesOnlyUnauthorizedAgesOut(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-carol"] = tgListing(t, nil)
	e.ep.errs["tok-dana"] = ErrMCPUnauthorized
	e.observe("carol", 1)
	for i := 0; i < 12; i++ {
		e.advance(time.Minute)
		e.observe("dana", 1)
	}
	if d, u := gaugeOf(t, e.reg, "tg"); d != -1 || u != 1 {
		t.Fatalf("after 12 minutes of 401s: drift %v unknown %v, want absent 1", d, u)
	}
}

// A listing that answers but does not parse is a failed attempt too
// (reason invalid): the unknown alert's gate counts it.
func TestPinListingInvalidCounted(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.pages["tok-c1"] = []byte(`{"tools":"not a list"}`)
	e.observe("c1", 1)
	if got := testutil.ToFloat64(e.reg.PAPinListingFailures.WithLabelValues("tg", "invalid")); got != 1 {
		t.Fatalf("invalid failures %v, want 1", got)
	}
	if _, u := gaugeOf(t, e.reg, "tg"); u != 1 {
		t.Fatalf("unknown %v, want 1", u)
	}
}

// A refused token alone never raises "listing unknown".
func TestPinGaugesRefusedTokenIsNotUnknown(t *testing.T) {
	e := newSurfaceEnv(t)
	e.ep.errs["tok-c4"] = ErrMCPUnauthorized
	if e.observe("c4", 1) {
		t.Fatal("refused token reported as listed")
	}
	if n := testutil.CollectAndCount(e.reg.PAPinListingUnknown); n != 0 {
		t.Fatalf("unknown has %d series after a refused token", n)
	}
}

// The listing cache is per server, connection and revision: another
// connection, or the same one at another revision, reads its own listing
// with its own token.
func TestListingCacheKey(t *testing.T) {
	e := newSurfaceEnv(t)
	for _, id := range []string{"c1", "c2"} {
		e.ep.pages["tok-"+id] = tgListing(t, nil)
	}
	e.observe("c1", 1)
	e.observe("c1", 1)
	if n := e.ep.lists["tok-c1"]; n != 1 {
		t.Fatalf("same key listed %d times, want 1 (cached)", n)
	}
	e.observe("c1", 2)
	if n := e.ep.lists["tok-c1"]; n != 2 {
		t.Fatalf("another revision listed %d times in all, want 2", n)
	}
	e.observe("c2", 1)
	if n := e.ep.lists["tok-c2"]; n != 1 {
		t.Fatalf("another connection listed %d times, want 1", n)
	}
}

func TestToolResultIsError(t *testing.T) {
	for in, want := range map[string]bool{
		`{"content":[],"isError":true}`: true,
		`{"content":[]}`:                false,
		` {"isError":false} `:           false,
	} {
		got, err := toolResultIsError([]byte(in))
		if err != nil || got != want {
			t.Errorf("%s: %v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "null", "[]", `"x"`, `{"isError":"yes"}`, "{"} {
		if _, err := toolResultIsError([]byte(in)); !errors.Is(err, ErrMCPProtocol) {
			t.Errorf("%q accepted: %v", in, err)
		}
	}
}

// refusingJobs refuses every token with a fixed refusal.
type refusingJobs struct {
	noJobs
	tr pa.TokenRefusal
}

func (j refusingJobs) AuthenticateAttributed(*http.Request) (pa.PAJob, pa.TokenRefusal, error) {
	return pa.PAJob{}, j.tr, errors.New("refused")
}

// A refused token is answered with its closed label: expired and revoked
// as such, an unreadable revocation state as 503 token_unverifiable, any
// other label as token_invalid. Only an attributed refusal is recorded.
func TestTokenRefusalAnswers(t *testing.T) {
	cases := []struct {
		tr       pa.TokenRefusal
		code     int
		stop     string
		recorded bool
	}{
		{pa.TokenRefusal{Principal: 555, Reason: ReasonTokenExpired}, http.StatusUnauthorized, ReasonTokenExpired, true},
		{pa.TokenRefusal{Principal: 555, Reason: ReasonTokenRevoked}, http.StatusUnauthorized, ReasonTokenRevoked, true},
		{pa.TokenRefusal{Reason: ReasonTokenUnverifiable}, http.StatusServiceUnavailable, ReasonTokenUnverifiable, false},
		{pa.TokenRefusal{Principal: 555, Reason: "made_up"}, http.StatusUnauthorized, ReasonTokenInvalid, true},
		{pa.TokenRefusal{}, http.StatusUnauthorized, ReasonTokenInvalid, false},
	}
	for _, c := range cases {
		sink := &fakeSink{ev: &events{}}
		d, err := NewDispatcher(DispatcherConfig{
			Jobs: refusingJobs{tr: c.tr}, Connections: noConns{}, Pin: loadPin(t),
			Executor: newExecutor(sink), Flags: func() (Flags, error) { return Flags{}, nil },
		})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		d.ServeHTTP(w, httptest.NewRequest(http.MethodPost, RouteTool, strings.NewReader(`{}`)))
		var got refusalResponse
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != c.code || got.Stop != c.stop || (len(sink.entries) == 1) != c.recorded {
			t.Errorf("%+v: %d %q, %d entries", c.tr, w.Code, got.Stop, len(sink.entries))
		}
	}
}

// answerExecuteError keeps an unbound connection apart from an invalid
// call: only the first is the worker's choice of connection.
func TestAnswerExecuteError(t *testing.T) {
	d := newSurfaceEnv(t).d
	for _, c := range []struct {
		err  error
		code int
		stop string
	}{
		{fmt.Errorf("%w: %w", ErrInvalidCall, ErrUnboundConnection), http.StatusForbidden, ReasonConnectionUnbound},
		{fmt.Errorf("%w: no principal", ErrInvalidCall), http.StatusInternalServerError, ReasonInternal},
		{fmt.Errorf("%w: x", ErrAuditUnavailable), http.StatusServiceUnavailable, ReasonAuditUnavailable},
		{fmt.Errorf("%w: x", ErrDispatchFenced), http.StatusConflict, ReasonFenced},
		{fmt.Errorf("%w: x", ErrDispatchRefused), http.StatusBadGateway, ReasonServerRefused},
		{errors.New("reset"), http.StatusBadGateway, ReasonOutcomeUnknown},
	} {
		w := httptest.NewRecorder()
		d.answerExecuteError(w, "tg", c.err)
		var got refusalResponse
		_ = json.Unmarshal(w.Body.Bytes(), &got)
		if w.Code != c.code || got.Stop != c.stop {
			t.Errorf("%v: %d %q, want %d %q", c.err, w.Code, got.Stop, c.code, c.stop)
		}
	}
}

// lockedSink is a sink safe to append to from Run's goroutine.
type lockedSink struct {
	mu      sync.Mutex
	entries []Entry
}

func (s *lockedSink) Append(_ context.Context, e Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}

func (s *lockedSink) suppressed() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Entry
	for _, e := range s.entries {
		if e.Reason == ReasonRefusalsSuppressed {
			out = append(out, e)
		}
	}
	return out
}

// A principal that stops after its window overflowed still gets its
// summary row: Run writes it once the window closes.
func TestRunWritesSuppressedSummary(t *testing.T) {
	e := newSurfaceEnv(t)
	sink := &lockedSink{}
	e.d.cfg.Executor = &Executor{Sink: sink, Now: time.Now}
	for i := 0; i < refusalAuditBurst+3; i++ {
		e.d.refuse(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, RouteTool, nil),
			Refusal{Principal: 555, Reason: ReasonBadRequest}, http.StatusBadRequest)
	}
	if n := len(sink.suppressed()); n != 0 {
		t.Fatalf("%d summaries while the window is open", n)
	}
	e.advance(refusalAuditWindow)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.d.Run(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for len(sink.suppressed()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	got := sink.suppressed()
	if len(got) != 1 || got[0].Principal != 555 || got[0].Suppressed != 3 || got[0].Status != StatusRefused {
		t.Fatalf("summaries %+v", got)
	}
	rec, err := FormatRecord(Entry{CallID: "c", Phase: PhaseResult, Principal: 555, Server: "tg", Tool: "t", ConnectionID: "-x", ArgsSHA256: "a", Taint: TaintExternal, Status: StatusRefused, Reason: ReasonRefusalsSuppressed, Suppressed: 3})
	if err != nil || !strings.HasSuffix(rec, " reason=refusals_suppressed suppressed=3") {
		t.Fatalf("record %q err %v", rec, err)
	}
	plain, _ := FormatRecord(Entry{CallID: "c", Phase: PhaseResult, Principal: 555, Server: "tg", Tool: "t", ConnectionID: "-x", ArgsSHA256: "a", Taint: TaintExternal, Status: StatusRefused, Reason: ReasonBadRequest})
	if strings.Contains(plain, "suppressed") {
		t.Fatalf("plain record carries a count: %q", plain)
	}
}
