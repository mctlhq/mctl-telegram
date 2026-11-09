// Package fairness holds the per-provider circuit breaker and the per-tenant
// concurrency limiter. Both are non-blocking so a stuck tenant or provider
// cannot stall the control queue.
package fairness

import (
	"sync"
	"time"
)

// DefaultCooldown is how long an open breaker refuses before letting one
// probe call through (half-open).
const DefaultCooldown = 30 * time.Second

type Breaker struct {
	mu        sync.Mutex
	threshold int
	failures  int
	open      bool
	openedAt  time.Time
	cooldown  time.Duration
	now       func() time.Time
}

func NewBreaker(threshold int) *Breaker {
	return &Breaker{threshold: threshold, cooldown: DefaultCooldown, now: time.Now}
}

// Allow reports whether a provider call may proceed. When the breaker is open
// and the cooldown has elapsed it admits a single probe (half-open) and
// restarts the cooldown, so further calls are refused until the probe's
// result is recorded.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true
	}
	if b.now().Sub(b.openedAt) >= b.cooldown {
		b.openedAt = b.now()
		return true
	}
	return false
}

// IsOpen is a non-consuming view for health and metrics: true while the
// breaker is open and the cooldown has not elapsed.
func (b *Breaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.open && b.now().Sub(b.openedAt) < b.cooldown
}

func (b *Breaker) Record(rateLimited bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !rateLimited {
		b.failures = 0
		b.open = false
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.open = true
		b.openedAt = b.now()
	}
}

type Limiter struct {
	mu    sync.Mutex
	limit int
	used  map[string]int
}

func NewLimiter(limit int) *Limiter { return &Limiter{limit: limit, used: map[string]int{}} }

func (l *Limiter) TryAcquire(tenant string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used[tenant] >= l.limit {
		return false
	}
	l.used[tenant]++
	return true
}

func (l *Limiter) Release(tenant string) { l.mu.Lock(); l.used[tenant]--; l.mu.Unlock() }
