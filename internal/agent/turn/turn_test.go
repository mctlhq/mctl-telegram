package turn

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func at(msec int64) time.Time { return t0.Add(time.Duration(msec) * time.Millisecond) }

func newC(t *testing.T, cfg Config) *Coalescer {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

var base = Config{QuietMS: 1000, MaxWaitMS: 5000, MaxMsgs: 10, MaxBytes: 1000}

func TestNewValidates(t *testing.T) {
	for _, cfg := range []Config{{}, {QuietMS: 1, MaxWaitMS: 1, MaxMsgs: 1}, {QuietMS: -1, MaxWaitMS: 1, MaxMsgs: 1, MaxBytes: 1}} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v): want error", cfg)
		}
	}
}

func TestSessionKey(t *testing.T) {
	if got := SessionKey(7, 42); got != "telegram:7:42" {
		t.Fatalf("got %q", got)
	}
}

func TestBurstOneTurn(t *testing.T) { // (a)
	c := newC(t, base)
	for i, id := range []string{"e1", "e2", "e3"} {
		if got := c.Offer(Event{ID: id, SessionKey: "s", At: at(int64(i) * 400), Bytes: 10}); len(got) != 0 {
			t.Fatalf("offer %s closed %v", id, got)
		}
	}
	if got := c.Tick(at(800 + 1000)); len(got) != 0 {
		t.Fatalf("tick at exactly quiet boundary closed %v", got)
	}
	got := c.Tick(at(800 + 1001))
	if len(got) != 1 || !reflect.DeepEqual(got[0].SourceEventIDs, []string{"e1", "e2", "e3"}) || got[0].State != StateReady {
		t.Fatalf("got %+v", got)
	}
	if got[0].Bytes != 30 || !got[0].WindowOpenedAt.Equal(at(0)) {
		t.Fatalf("got %+v", got[0])
	}
}

func TestEventAfterQuietOpensNewTurn(t *testing.T) { // (b)
	c := newC(t, base)
	c.Offer(Event{ID: "e1", SessionKey: "s", At: at(0), Bytes: 1})
	got := c.Offer(Event{ID: "e2", SessionKey: "s", At: at(1001), Bytes: 1})
	if len(got) != 1 || got[0].State != StateReady || !reflect.DeepEqual(got[0].SourceEventIDs, []string{"e1"}) {
		t.Fatalf("got %+v", got)
	}
	if len(c.open["s"].SourceEventIDs) != 1 || c.open["s"].SourceEventIDs[0] != "e2" {
		t.Fatal("e2 should open a new turn")
	}
}

func TestMaxWaitAlone(t *testing.T) { // (c)
	c := newC(t, Config{QuietMS: 1000, MaxWaitMS: 2500, MaxMsgs: 100, MaxBytes: 1000})
	var closed []Turn
	for i := 0; i < 8; i++ { // every 500ms: always inside the quiet window
		closed = append(closed, c.Offer(Event{ID: string(rune('a' + i)), SessionKey: "s", At: at(int64(i) * 500), Bytes: 1})...)
	}
	if len(closed) != 1 {
		t.Fatalf("closed %d turns, want 1", len(closed))
	}
	if n := len(closed[0].SourceEventIDs); n != 6 { // 0..2500ms
		t.Fatalf("first turn has %d events, want 6", n)
	}
	// Tick-driven close while events keep arriving.
	c2 := newC(t, Config{QuietMS: 1000, MaxWaitMS: 2500, MaxMsgs: 100, MaxBytes: 1000})
	c2.Offer(Event{ID: "x", SessionKey: "s", At: at(0)})
	c2.Offer(Event{ID: "y", SessionKey: "s", At: at(900)})
	c2.Offer(Event{ID: "z", SessionKey: "s", At: at(1800)})
	c2.Offer(Event{ID: "w", SessionKey: "s", At: at(2600 - 100)})
	if got := c2.Tick(at(2501)); len(got) != 1 {
		t.Fatalf("tick: %+v", got)
	}
}

func TestMaxMsgsAlone(t *testing.T) { // (d)
	c := newC(t, Config{QuietMS: 10000, MaxWaitMS: 100000, MaxMsgs: 3, MaxBytes: 1000})
	var closed []Turn
	for i, id := range []string{"1", "2", "3", "4"} {
		closed = append(closed, c.Offer(Event{ID: id, SessionKey: "s", At: at(int64(i)), Bytes: 1})...)
	}
	if len(closed) != 1 || len(closed[0].SourceEventIDs) != 3 {
		t.Fatalf("got %+v", closed)
	}
	if c.open["s"] == nil || c.open["s"].SourceEventIDs[0] != "4" {
		t.Fatal("event 4 should open a new turn")
	}
}

func TestMaxBytesAlone(t *testing.T) { // (e)
	c := newC(t, Config{QuietMS: 10000, MaxWaitMS: 100000, MaxMsgs: 100, MaxBytes: 100})
	c.Offer(Event{ID: "1", SessionKey: "s", At: at(0), Bytes: 60})
	got := c.Offer(Event{ID: "2", SessionKey: "s", At: at(1), Bytes: 60}) // overflow
	if len(got) != 1 || !reflect.DeepEqual(got[0].SourceEventIDs, []string{"1"}) {
		t.Fatalf("got %+v", got)
	}
	// Oversized single event: its own READY turn, never dropped.
	got = c.Offer(Event{ID: "3", SessionKey: "s", At: at(2), Bytes: 500})
	if len(got) != 2 {
		t.Fatalf("want turn 2 and turn 3 closed, got %+v", got)
	}
	if !reflect.DeepEqual(got[1].SourceEventIDs, []string{"3"}) || got[1].State != StateReady {
		t.Fatalf("got %+v", got[1])
	}
	if c.open["s"] != nil {
		t.Fatal("no open turn expected")
	}
}

func TestInvalidTransitions(t *testing.T) { // (f)
	c := newC(t, base)
	c.Offer(Event{ID: "e", SessionKey: "s", At: at(0)})
	id := c.open["s"].TurnID
	for name, err := range map[string]error{
		"claim collecting": c.Claim(id),
		"done collecting":  c.Done(id),
		"claim unknown":    c.Claim("nope"),
	} {
		if !errors.Is(err, ErrInvalidTransition) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	c.Tick(at(5000))
	if err := c.Done(id); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("done ready: %v", err)
	}
	if err := c.Claim(id); err != nil {
		t.Fatal(err)
	}
	if err := c.Claim(id); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("double claim: %v", err)
	}
	if err := c.Done(id); err != nil {
		t.Fatal(err)
	}
	if err := c.Done(id); !errors.Is(err, ErrInvalidTransition) {
		t.Errorf("double done: %v", err)
	}
}

func TestDeterministicTurnID(t *testing.T) { // (g)
	run := func() string {
		c := newC(t, base)
		c.Offer(Event{ID: "e1", SessionKey: "s", At: at(0)})
		return c.open["s"].TurnID
	}
	if a, b := run(), run(); a != b || len(a) != len("turn:v1:")+24 {
		t.Fatalf("ids %q %q", a, b)
	}
	c := newC(t, base)
	c.Offer(Event{ID: "e1", SessionKey: "s1", At: at(0)})
	c.Offer(Event{ID: "e1", SessionKey: "s2", At: at(0)})
	if c.open["s1"].TurnID == c.open["s2"].TurnID {
		t.Fatal("different sessions must differ")
	}
}

func TestSessionsIndependent(t *testing.T) { // (h)
	c := newC(t, base)
	c.Offer(Event{ID: "a1", SessionKey: "A", At: at(0)})
	c.Offer(Event{ID: "b1", SessionKey: "B", At: at(10)})
	c.Offer(Event{ID: "a2", SessionKey: "A", At: at(20)})
	got := c.Tick(at(5000))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if !reflect.DeepEqual(got[0].SourceEventIDs, []string{"a1", "a2"}) || !reflect.DeepEqual(got[1].SourceEventIDs, []string{"b1"}) {
		t.Fatalf("got %+v", got)
	}
}
