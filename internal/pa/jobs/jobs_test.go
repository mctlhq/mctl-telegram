package jobs

import "testing"

// A budget whose job cost exceeds any window would hold every job at every
// reset, without end; it is refused up front.
func TestBudgetValid(t *testing.T) {
	ok := Budget{PerJobUSD: 0.25, PrincipalDayUSD: 2, PrincipalMonthUSD: 20, GlobalDayUSD: 20}
	if !ok.Valid() {
		t.Fatal("default-shaped budget refused")
	}
	for name, mut := range map[string]func(*Budget){
		"zero job":         func(b *Budget) { b.PerJobUSD = 0 },
		"job above day":    func(b *Budget) { b.PerJobUSD = 3 },
		"day above month":  func(b *Budget) { b.PrincipalDayUSD = 30 },
		"job above global": func(b *Budget) { b.GlobalDayUSD = 0.1 },
		"global not set":   func(b *Budget) { b.GlobalDayUSD = 0 },
	} {
		b := ok
		mut(&b)
		if b.Valid() {
			t.Errorf("%s: accepted", name)
		}
	}
}
