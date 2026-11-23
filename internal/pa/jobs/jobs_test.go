package jobs

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// A budget whose job cost exceeds any window would hold every job at every
// reset, without end; it is refused up front.
func TestBudgetValid(t *testing.T) {
	ok := Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20, MinTurnUSD: DefaultMinTurnUSD}
	if !ok.Valid() {
		t.Fatal("default-shaped budget refused")
	}
	for name, mut := range map[string]func(*Budget){
		"zero job":         func(b *Budget) { b.PerJobUSD = 0 },
		"job above day":    func(b *Budget) { b.PerJobUSD = 3 },
		"day above month":  func(b *Budget) { b.PrincipalDayUSD = 30 },
		"job above global": func(b *Budget) { b.GlobalDayUSD = 0.1 },
		"global not set":   func(b *Budget) { b.GlobalDayUSD = 0 },
		"no turn floor":    func(b *Budget) { b.MinTurnUSD = 0 },
		"floor above job":  func(b *Budget) { b.MinTurnUSD = 0.3 },
	} {
		b := ok
		mut(&b)
		if b.Valid() {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestSettle pins owner decisions 2 and 3 (2026-11-19):
// max(turns x floor, min(reported, 4 x reservation)), the reservation
// when unreported, and at least one turn's floor.
func TestSettle(t *testing.T) {
	for _, tc := range []struct {
		name               string
		reported, reserved float64
		turns              int
		want               float64
	}{
		{"below the reservation", 0.07, 0.25, 1, 0.07},
		{"exactly 4x", 1.0, 0.25, 1, 1.0},
		{"above 4x", 5, 0.25, 1, 1.0},
		{"4x of a small reservation", 0.5, 0.1, 1, 0.4},
		{"no absolute ceiling", 2, 0.3, 1, 1.2},
		{"no ceiling on a large reservation", 10, 1.5, 1, 6},
		{"unreported", -1, 0.25, 3, 0.25},
		{"zero, three turns", 0, 0.25, 3, 0.015},
		{"zero, no turn", 0, 0.25, 0, 0.005},
		{"above the floor", 0.02, 0.25, 3, 0.02},
	} {
		if got := Settle(tc.reported, tc.reserved, tc.turns, DefaultMinTurnUSD); got < tc.want-1e-12 || got > tc.want+1e-12 {
			t.Errorf("%s: Settle = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestClaimsEnded(t *testing.T) {
	var b Budget
	now := time.Date(2030, 6, 15, 0, 0, 0, 0, time.UTC)
	if b.ClaimsEnded(now) {
		t.Fatal("no cutoff ended claims")
	}
	b.ClaimNotAfter = now
	if b.ClaimsEnded(now.Add(-time.Nanosecond)) || !b.ClaimsEnded(now) || !b.ClaimsEnded(now.Add(time.Second)) {
		t.Fatal("cutoff is not [ClaimNotAfter, ...)")
	}
}

// A connection-level outbox row (#1318 slice C2b) names its connection and
// nothing else; no other kind may carry a connection id.
func TestOutboxItemValid_ConnectionLevel(t *testing.T) {
	ok := OutboxItem{Principal: 4242001, Kind: OutboxConnectionExpired, ConnectionID: "pac_a"}
	if !ok.Valid() {
		t.Fatalf("%+v should be valid", ok)
	}
	for name, mut := range map[string]func(*OutboxItem){
		"no connection": func(o *OutboxItem) { o.ConnectionID = "" },
		"long id":       func(o *OutboxItem) { o.ConnectionID = strings.Repeat("a", MaxOutboxConnectionID+1) },
		"job":           func(o *OutboxItem) { o.JobID = 1 },
		"update":        func(o *OutboxItem) { o.UpdateID = 1 },
		"button":        func(o *OutboxItem) { o.Button = "b" },
		"conversation":  func(o *OutboxItem) { o.ConversationID = "c" },
		"fragment":      func(o *OutboxItem) { o.FragmentSeq = 1 },
	} {
		o := ok
		mut(&o)
		if o.Valid() {
			t.Errorf("%s: %+v accepted", name, o)
		}
	}
	if (OutboxItem{Principal: 4242001, Kind: OutboxForgotten, UpdateID: 7, ConnectionID: "pac_a"}).Valid() {
		t.Error("a conversation-level row with a connection id accepted")
	}
	if (OutboxItem{Principal: 4242001, Kind: OutboxBudgetHold, JobID: 1, ConnectionID: "pac_a"}).Valid() {
		t.Error("a job-level row with a connection id accepted")
	}
	if !slices.Contains(OutboxKinds(), OutboxConnectionExpired) || !OutboxConnectionExpired.Valid() {
		t.Error("connection_expired is not a known kind")
	}
}
