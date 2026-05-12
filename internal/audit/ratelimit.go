package audit

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// RateLimiter is a per-identity in-memory token bucket. Capacity is `RatePerMin`
// tokens with a refill of `RatePerMin`/60 per second. Anonymous requests
// (no Identity in context) all share a single "anon" bucket — this matches the
// /healthz semantics where anonymous polling is fine.
type RateLimiter struct {
	RatePerMin int
	now        func() time.Time
	mu         sync.Mutex
	buckets    map[string]*bucket
}

type bucket struct {
	tokens   float64
	lastFill time.Time
}

func NewRateLimiter(perMin int) *RateLimiter {
	return &RateLimiter{
		RatePerMin: perMin,
		now:        time.Now,
		buckets:    make(map[string]*bucket),
	}
}

func (r *RateLimiter) allow(key string) bool {
	if r.RatePerMin <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	b, ok := r.buckets[key]
	now := r.now()
	if !ok {
		b = &bucket{tokens: float64(r.RatePerMin), lastFill: now}
		r.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * float64(r.RatePerMin) / 60.0
	if b.tokens > float64(r.RatePerMin) {
		b.tokens = float64(r.RatePerMin)
	}
	b.lastFill = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (r *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			key := "anon"
			if id := auth.From(req.Context()); id != nil && id.UserID > 0 {
				key = identityKey(id)
			}
			if !r.allow(key) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

func identityKey(id *auth.Identity) string {
	// Prefer GitHubLogin (stable string), fall back to user_id digits.
	if id.GitHubLogin != "" {
		return "u:" + id.GitHubLogin
	}
	return "uid:" + intToString(id.UserID)
}

func intToString(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
