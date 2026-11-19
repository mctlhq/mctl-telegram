package jobs

import (
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
		"job above $1":     func(b *Budget) { b.PerJobUSD, b.PrincipalDayUSD = 1.5, 1.5 },
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
// max(turns x floor, min(reported, 4 x reservation, $1)), the reservation
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
		{"never above $1", 2, 0.3, 1, MaxSettleUSD},
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
