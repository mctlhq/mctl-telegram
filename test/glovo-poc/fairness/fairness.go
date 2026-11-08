// Package fairness holds the per-provider circuit breaker and the per-tenant
// concurrency limiter. Both are non-blocking so a stuck tenant or provider
// cannot stall the control queue.
package fairness

import "sync"

type Breaker struct {
	mu        sync.Mutex
	threshold int
	failures  int
	open      bool
}

func NewBreaker(threshold int) *Breaker { return &Breaker{threshold: threshold} }

func (b *Breaker) Allow() bool { b.mu.Lock(); defer b.mu.Unlock(); return !b.open }

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
