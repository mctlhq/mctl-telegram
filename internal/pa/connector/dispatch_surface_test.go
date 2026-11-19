package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// tokenEP is tg's endpoint answering tools/list per bearer: each
// connection's token sees its own listing (or error).
type tokenEP struct {
	mu    sync.Mutex
	pages map[string][]byte
	errs  map[string]error
	lists map[string]int
}

func (e *tokenEP) Server() string { return "tg" }

func (e *tokenEP) ListTools(_ context.Context, tok connection.Secret) ([][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lists[tok.Reveal()]++
	if err := e.errs[tok.Reveal()]; err != nil {
		return nil, err
	}
	return [][]byte{e.pages[tok.Reveal()]}, nil
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
	d   *Dispatcher
	ep  *tokenEP
	reg *metrics.Registry
	now time.Time
}

func newSurfaceEnv(t *testing.T) *surfaceEnv {
	t.Helper()
	e := &surfaceEnv{
		ep:  &tokenEP{pages: map[string][]byte{}, errs: map[string]error{}, lists: map[string]int{}},
		reg: metrics.New(),
		now: t0,
	}
	d, err := NewDispatcher(DispatcherConfig{
		Jobs: noJobs{}, Connections: noConns{}, Pin: loadPin(t),
		Endpoints: map[string]MCPEndpoint{"tg": e.ep},
		Executor:  newExecutor(&fakeSink{ev: &events{}}),
		Flags:     func() (Flags, error) { return Flags{}, nil },
		Metrics:   e.reg,
		Now:       func() time.Time { return e.now },
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
