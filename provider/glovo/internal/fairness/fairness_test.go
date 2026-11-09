package fairness

import (
	"testing"
	"time"
)

// T18: tenant alpha's 429s open only the glovo breaker; beta keeps progressing
// and a second provider is untouched.
func TestT18_ProviderIsolation(t *testing.T) {
	glovo, other := NewBreaker(3), NewBreaker(3)
	for i := 0; i < 3; i++ {
		glovo.Record(true)
	}
	if glovo.Allow() {
		t.Fatal("glovo breaker should be open")
	}
	if !other.Allow() {
		t.Fatal("second provider must not be affected")
	}
	l := NewLimiter(1)
	if !l.TryAcquire("tenant-alpha") {
		t.Fatal("alpha first slot")
	}
	if l.TryAcquire("tenant-alpha") {
		t.Fatal("alpha over limit must be refused without blocking")
	}
	if !l.TryAcquire("tenant-beta") {
		t.Fatal("beta must progress while alpha is saturated")
	}
	l.Release("tenant-alpha")
	if !l.TryAcquire("tenant-alpha") {
		t.Fatal("slot not released")
	}
}

func TestBreakerRecoversAfterCooldown(t *testing.T) {
	b := NewBreaker(2)
	now := time.Unix(1000, 0)
	b.now = func() time.Time { return now }
	b.Record(true)
	b.Record(true)
	if b.Allow() || !b.IsOpen() {
		t.Fatal("breaker should be open")
	}
	now = now.Add(DefaultCooldown)
	if b.IsOpen() {
		t.Fatal("cooldown elapsed: not reported open")
	}
	if !b.Allow() {
		t.Fatal("probe should be admitted after cooldown")
	}
	if b.Allow() {
		t.Fatal("only one probe while half-open")
	}
	b.Record(true)
	if b.Allow() {
		t.Fatal("failed probe reopens")
	}
	now = now.Add(DefaultCooldown)
	if !b.Allow() {
		t.Fatal("second probe")
	}
	b.Record(false)
	if !b.Allow() || b.IsOpen() {
		t.Fatal("successful probe closes breaker")
	}
}
