package basket

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConcurrentApplyOneEffect(t *testing.T) {
	l := NewLedger()
	k := Key{"t", "o", "h"}
	var effects, deduped atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, d, err := l.Do(k, func() (Entry, error) { effects.Add(1); return Entry{Fingerprint: "fp"}, nil })
			if err != nil {
				t.Error(err)
			}
			if d {
				deduped.Add(1)
			}
		}()
	}
	wg.Wait()
	if effects.Load() != 1 || deduped.Load() != 31 {
		t.Fatalf("effects=%d deduped=%d", effects.Load(), deduped.Load())
	}
}

func TestFailedApplyRecordsNothing(t *testing.T) {
	l := NewLedger()
	k := Key{"t", "o", "h"}
	if _, _, err := l.Do(k, func() (Entry, error) { return Entry{}, errors.New("boom") }); err == nil {
		t.Fatal("want error")
	}
	if _, ok := l.Get(k); ok {
		t.Fatal("failed apply recorded")
	}
	if _, d, _ := l.Do(k, func() (Entry, error) { return Entry{Fingerprint: "x"}, nil }); d {
		t.Fatal("must apply after failure")
	}
}

func TestKeysAreTenantScoped(t *testing.T) {
	l := NewLedger()
	l.Do(Key{"a", "o", "h"}, func() (Entry, error) { return Entry{"x"}, nil })
	if _, ok := l.Get(Key{"b", "o", "h"}); ok {
		t.Fatal("ledger entry leaked across tenants")
	}
	l.Forget("a", "o")
	if _, ok := l.Get(Key{"a", "o", "h"}); ok {
		t.Fatal("forget failed")
	}
}
