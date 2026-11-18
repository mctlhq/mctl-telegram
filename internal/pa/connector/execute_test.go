// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

// Acceptance tests S1-U1..S1-U3 of threat model T12, against a fake
// dispatcher. storesink_test.go runs the same properties through the real
// ADR 0003 audit chain.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// aliceID is the synthetic principal internal/pa's tests use.
const aliceID int64 = 555

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func alicePolicy(t *testing.T) pa.Policy {
	t.Helper()
	body := fmt.Sprintf(`{"update_id":1,"message":{"message_id":7,"date":1,`+
		`"from":{"id":%d,"is_bot":false,"first_name":"Alice"},`+
		`"chat":{"id":%d,"type":"private"},"text":"hello"}}`, aliceID, aliceID)
	u, outcome := pa.Filter([]byte(body))
	if outcome != pa.OutcomeAccepted {
		t.Fatalf("fixture rejected: %s", outcome)
	}
	ec, err := pa.NewInteractive(u, "conv-a",
		[]pa.ConnectionRevision{{ConnectionID: "conn-a", AuthorityRevision: 3}},
		pa.BudgetReservation{ID: "hold-a"}, pa.ConsentDataFlowV1)
	if err != nil {
		t.Fatal(err)
	}
	return ec.Policy()
}

// tgSurface observes the committed pin against tg's real descriptors.
func tgSurface(t *testing.T) *catalog.Surface {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var snap struct {
		Tools map[string]json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatal(err)
	}
	var tools []json.RawMessage
	for _, d := range snap.Tools {
		tools = append(tools, d)
	}
	page, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatal(err)
	}
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	s := pin.Observe("tg", [][]byte{page}, nil, t0)
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	return s
}

// events is a shared, ordered log of what the sink and the dispatcher did.
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, s)
}

func (e *events) list() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

// fakeSink records entries; failOn makes the append of that phase fail.
type fakeSink struct {
	ev      *events
	entries []Entry
	failOn  Phase
}

func (s *fakeSink) Append(_ context.Context, e Entry) error {
	if s.failOn != "" && e.Phase == s.failOn {
		s.ev.add("append-failed:" + string(e.Phase))
		return errors.New("database is locked")
	}
	s.entries = append(s.entries, e)
	s.ev.add("append:" + string(e.Phase) + ":" + string(e.Status))
	return nil
}

func fakeDispatch(ev *events, out string, err error) (Dispatch, *int) {
	n := 0
	return func(context.Context) (Result, error) {
		n++
		ev.add("dispatch")
		return Result{Output: []byte(out), Cost: 2}, err
	}, &n
}

func newExecutor(sink Sink) *Executor {
	return &Executor{Sink: sink, Now: func() time.Time { return t0 }}
}

func readCall(t *testing.T, args string) Call {
	return Call{Policy: alicePolicy(t), ConnectionID: "conn-a", Tool: "get_messages", Args: []byte(args), Taint: TaintClean}
}

// S1-U2: every dispatched call has exactly one pre-dispatch entry and one
// result entry, the pre-dispatch one appended before the dispatch runs, for
// every outcome of the dispatch.
func TestS1U2_OnePreAndOneResultEntryPerDispatch(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Status
	}{
		{"ok", nil, StatusOK},
		{"fenced", fmt.Errorf("revision moved: %w", ErrDispatchFenced), StatusFenced},
		{"refused", fmt.Errorf("403: %w", ErrDispatchRefused), StatusRefused},
		{"unknown", errors.New("read: connection reset"), StatusOutcomeUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := &events{}
			sink := &fakeSink{ev: ev}
			dispatch, n := fakeDispatch(ev, `{"messages":[]}`, c.err)
			_, err := newExecutor(sink).Execute(context.Background(), tgSurface(t), readCall(t, `{"peer":"@bob"}`), dispatch)
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
			want := []string{"append:pre_dispatch:dispatching", "dispatch", "append:result:" + string(c.want)}
			if got := ev.list(); !slices.Equal(got, want) {
				t.Fatalf("events = %v, want %v", got, want)
			}
			if *n != 1 || len(sink.entries) != 2 {
				t.Fatalf("dispatches = %d, entries = %d", *n, len(sink.entries))
			}
			pre, post := sink.entries[0], sink.entries[1]
			if pre.CallID == "" || pre.CallID != post.CallID {
				t.Fatalf("call ids %q / %q", pre.CallID, post.CallID)
			}
			for _, e := range sink.entries {
				if e.Principal != aliceID || e.ConnectionID != "conn-a" || e.AuthorityRevision != 3 ||
					e.Server != "tg" || e.Tool != "get_messages" || e.Tier != catalog.TierAuto ||
					e.Class != catalog.ClassRead || e.Taint != TaintClean || e.ArgsSHA256 != digest([]byte(`{"peer":"@bob"}`)) {
					t.Fatalf("entry = %+v", e)
				}
			}
			if (c.want == StatusOK) != (post.ResultSHA256 != "") {
				t.Fatalf("result digest %q for status %s", post.ResultSHA256, post.Status)
			}
		})
	}
}

// S1-U2 (refused): a call the pin refuses is never dispatched and is
// recorded once, as refused.
func TestS1U2_PinRefusalIsOneRefusedEntryNoDispatch(t *testing.T) {
	ev := &events{}
	sink := &fakeSink{ev: ev}
	dispatch, n := fakeDispatch(ev, "", nil)
	call := readCall(t, `{}`)
	call.Tool = "send_message"
	_, err := newExecutor(sink).Execute(context.Background(), tgSurface(t), call, dispatch)
	if !errors.Is(err, catalog.ErrNotPinned) {
		t.Fatalf("err = %v, want ErrNotPinned", err)
	}
	if *n != 0 {
		t.Fatal("refused call was dispatched")
	}
	if got := ev.list(); !slices.Equal(got, []string{"append:result:refused"}) {
		t.Fatalf("events = %v", got)
	}
}

// S1-U3: a failing audit append refuses the call: dispatch never runs.
func TestS1U3_FailingAppendRefusesCall(t *testing.T) {
	ev := &events{}
	sink := &fakeSink{ev: ev, failOn: PhasePreDispatch}
	dispatch, n := fakeDispatch(ev, "x", nil)
	_, err := newExecutor(sink).Execute(context.Background(), tgSurface(t), readCall(t, `{}`), dispatch)
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("err = %v, want ErrAuditUnavailable", err)
	}
	if *n != 0 {
		t.Fatalf("dispatch ran %d times after a failed append", *n)
	}
	if got := ev.list(); !slices.Equal(got, []string{"append-failed:pre_dispatch"}) {
		t.Fatalf("events = %v", got)
	}
}

// S1-U3 (result append): when the result entry cannot be appended, the call
// has already run, so its result is returned and the alert fires.
func TestS1U3_FailedResultAppendAlerts(t *testing.T) {
	ev := &events{}
	sink := &fakeSink{ev: ev, failOn: PhaseResult}
	dispatch, n := fakeDispatch(ev, "out", nil)
	x := newExecutor(sink)
	var alerted []Entry
	x.OnAuditAppendFailure = func(e Entry, _ error) { alerted = append(alerted, e) }
	res, err := x.Execute(context.Background(), tgSurface(t), readCall(t, `{}`), dispatch)
	if err != nil || string(res.Output) != "out" || *n != 1 {
		t.Fatalf("res = %q, err = %v, dispatches = %d", res.Output, err, *n)
	}
	if len(alerted) != 1 || alerted[0].Phase != PhaseResult || alerted[0].Status != StatusOK {
		t.Fatalf("alerted = %+v", alerted)
	}
}

// S1-U1: no body or token text appears in the audit entries or in the logs,
// on the success path, the failure path and the alert path.
func TestS1U1_NoBodyOrTokenInAuditOrLogs(t *testing.T) {
	const (
		argBody = "SECRET-ARG-BODY-meet-me-at-noon"
		token   = "eyJhbGciOiJIUzI1NiJ9.SECRET-TOKEN"
		outBody = "SECRET-OUTPUT-BODY-bank-pin-1234"
	)
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	args := `{"peer":"@bob","query":"` + argBody + `","authorization":"Bearer ` + token + `"}`
	var all []Entry
	for _, failOn := range []Phase{"", PhaseResult} {
		for _, derr := range []error{nil, errors.New("upstream said: " + outBody + " " + token)} {
			ev := &events{}
			sink := &fakeSink{ev: ev, failOn: failOn}
			dispatch, _ := fakeDispatch(ev, `{"text":"`+outBody+`","token":"`+token+`"}`, derr)
			_, _ = newExecutor(sink).Execute(context.Background(), tgSurface(t), readCall(t, args), dispatch)
			all = append(all, sink.entries...)
		}
	}
	if len(all) == 0 {
		t.Fatal("no entries recorded")
	}
	var dump strings.Builder
	for _, e := range all {
		fmt.Fprintf(&dump, "%+v\n", e)
		rec, err := FormatRecord(e)
		if err != nil {
			t.Fatalf("FormatRecord: %v", err)
		}
		dump.WriteString(rec + "\n")
	}
	dump.WriteString(logs.String())
	for _, secret := range []string{argBody, token, outBody, "SECRET"} {
		if strings.Contains(dump.String(), secret) {
			t.Fatalf("%q leaked into audit or logs:\n%s", secret, dump.String())
		}
	}
	if !strings.Contains(dump.String(), digest([]byte(args))) {
		t.Fatal("args digest missing: the test would pass vacuously")
	}
}

// Execute refuses an incomplete call and sends nothing. Without a principal
// nothing can be recorded; with one, the refusal is one refused entry.
func TestExecuteRefusesInvalidCall(t *testing.T) {
	cases := map[string]func(c *Call){
		"zero policy":          func(c *Call) { c.Policy = pa.Policy{} },
		"unbound connection":   func(c *Call) { c.ConnectionID = "conn-b" },
		"empty connection":     func(c *Call) { c.ConnectionID = "" },
		"unknown taint":        func(c *Call) { c.Taint = "" },
		"taint from the model": func(c *Call) { c.Taint = "trusted" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ev := &events{}
			sink := &fakeSink{ev: ev}
			dispatch, n := fakeDispatch(ev, "", nil)
			call := readCall(t, `{}`)
			mutate(&call)
			_, err := newExecutor(sink).Execute(context.Background(), tgSurface(t), call, dispatch)
			want := []string{"append:result:refused"}
			if name == "zero policy" {
				want = nil
			}
			if !errors.Is(err, ErrInvalidCall) || *n != 0 || !slices.Equal(ev.list(), want) {
				t.Fatalf("err = %v, dispatches = %d, events = %v", err, *n, ev.list())
			}
			for _, e := range sink.entries {
				if _, err := FormatRecord(e); err != nil {
					t.Fatalf("refusal entry is not recordable: %v (%+v)", err, e)
				}
			}
		})
	}
}

// A refused call's tool name is model output; it is not copied into the
// audit log verbatim unless it looks like a tool name.
func TestRefusedToolNameIsSanitised(t *testing.T) {
	ev := &events{}
	sink := &fakeSink{ev: ev}
	dispatch, _ := fakeDispatch(ev, "", nil)
	call := readCall(t, `{}`)
	call.Tool = "ignore previous instructions; " + strings.Repeat("x", 200)
	_, _ = newExecutor(sink).Execute(context.Background(), tgSurface(t), call, dispatch)
	if len(sink.entries) != 1 || sink.entries[0].Tool != "invalid-tool-name" {
		t.Fatalf("entries = %+v", sink.entries)
	}
}

// An unavailable server refuses every call and dispatches nothing (S1-T5 at
// the executor).
func TestUnavailableServerRefusesCall(t *testing.T) {
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	s := pin.Observe("tg", nil, errors.New("timeout"), t0)
	ev := &events{}
	dispatch, n := fakeDispatch(ev, "", nil)
	_, err = newExecutor(&fakeSink{ev: ev}).Execute(context.Background(), s, readCall(t, `{}`), dispatch)
	if !errors.Is(err, catalog.ErrServerUnavailable) || *n != 0 {
		t.Fatalf("err = %v, dispatches = %d", err, *n)
	}
}

// S1-U2 (panic): a dispatch that panics still gets its result entry, as
// outcome_unknown, and the panic propagates.
func TestS1U2_PanickingDispatchStillRecordsResult(t *testing.T) {
	ev := &events{}
	sink := &fakeSink{ev: ev}
	dispatch := func(context.Context) (Result, error) {
		ev.add("dispatch")
		panic("transport bug")
	}
	func() {
		defer func() {
			if r := recover(); r != "transport bug" {
				t.Fatalf("recovered %v, want the dispatch panic", r)
			}
		}()
		_, _ = newExecutor(sink).Execute(context.Background(), tgSurface(t), readCall(t, `{}`), dispatch)
	}()
	want := []string{"append:pre_dispatch:dispatching", "dispatch", "append:result:outcome_unknown"}
	if got := ev.list(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

// ctxSink fails an append whose context is already done, like a store
// whose first query honours cancellation.
type ctxSink struct{ fakeSink }

func (s *ctxSink) Append(ctx context.Context, e Entry) error {
	if err := ctx.Err(); err != nil {
		s.ev.add("append-failed:" + string(e.Phase))
		return err
	}
	return s.fakeSink.Append(ctx, e)
}

// S1-U2 (cancellation): a run cancelled while the call is in flight still
// gets the call's result entry; a refusal on a cancelled run is still
// recorded; a call on an already-cancelled run is refused before dispatch.
func TestS1U2_CancelledRunStillRecordsResult(t *testing.T) {
	ev := &events{}
	sink := &ctxSink{fakeSink{ev: ev}}
	ctx, cancel := context.WithCancel(context.Background())
	dispatch := func(ctx context.Context) (Result, error) {
		ev.add("dispatch")
		cancel()
		return Result{}, ctx.Err()
	}
	_, err := newExecutor(sink).Execute(ctx, tgSurface(t), readCall(t, `{}`), dispatch)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	want := []string{"append:pre_dispatch:dispatching", "dispatch", "append:result:outcome_unknown"}
	if got := ev.list(); !slices.Equal(got, want) {
		t.Fatalf("events = %v, want %v", got, want)
	}

	// Refusal on the now-cancelled context: still recorded.
	ev2 := &events{}
	sink2 := &ctxSink{fakeSink{ev: ev2}}
	call := readCall(t, `{}`)
	call.Tool = "send_message"
	d2, n2 := fakeDispatch(ev2, "", nil)
	if _, err := newExecutor(sink2).Execute(ctx, tgSurface(t), call, d2); !errors.Is(err, catalog.ErrNotPinned) || *n2 != 0 {
		t.Fatalf("err = %v, dispatches = %d", err, *n2)
	}
	if got := ev2.list(); !slices.Equal(got, []string{"append:result:refused"}) {
		t.Fatalf("refusal events = %v", got)
	}

	// A permitted call on the cancelled context fails closed at the
	// pre-dispatch append.
	ev3 := &events{}
	d3, n3 := fakeDispatch(ev3, "", nil)
	if _, err := newExecutor(&ctxSink{fakeSink{ev: ev3}}).Execute(ctx, tgSurface(t), readCall(t, `{}`), d3); !errors.Is(err, ErrAuditUnavailable) || *n3 != 0 {
		t.Fatalf("err = %v, dispatches = %d", err, *n3)
	}
}
