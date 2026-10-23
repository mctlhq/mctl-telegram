package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
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
	// metrics is optional; when non-nil, 429 responses are counted.
	metrics *metrics.Registry
	// peerSecret keys the HMAC that turns a canonical peer key into a
	// bucket name, so raw Telegram ids and handles never sit in buckets.
	// Random per process: buckets are in memory and die with it anyway.
	peerSecret []byte
	lastSweep  time.Time
}

type bucket struct {
	tokens   float64
	lastFill time.Time
	// max and perSec let sweep tell a full bucket, which behaves exactly
	// like an absent one, from a draining one without knowing its caller.
	max    float64
	perSec float64
}

// sweepEvery bounds how often a call walks the bucket map to drop full
// buckets. Per-peer keys grow with the number of distinct recipients, so
// without eviction the map would only ever grow.
const sweepEvery = 10 * time.Minute

func NewRateLimiter(perMin int) *RateLimiter {
	return &RateLimiter{
		RatePerMin: perMin,
		now:        time.Now,
		buckets:    make(map[string]*bucket),
		peerSecret: newPeerSecret(),
	}
}

func newPeerSecret() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; a fixed key
		// still separates peers, it only loses the at-rest blinding.
		return []byte("mctl-telegram-peer-limiter")
	}
	return b
}

// refill tops b up to now. Caller holds r.mu.
func (b *bucket) refill(now time.Time) {
	b.tokens += now.Sub(b.lastFill).Seconds() * b.perSec
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastFill = now
}

// sweep drops every bucket that has refilled to capacity. Caller holds r.mu.
func (r *RateLimiter) sweep(now time.Time) {
	if now.Sub(r.lastSweep) < sweepEvery {
		return
	}
	r.lastSweep = now
	for k, b := range r.buckets {
		b.refill(now)
		if b.tokens >= b.max {
			delete(r.buckets, k)
		}
	}
}

// WithMetrics wires a *metrics.Registry so 429 responses are counted in
// mctl_rate_limit_events_total. Returns the receiver for chaining.
// Passing nil is a no-op (safe to call on an existing limiter to detach).
func (r *RateLimiter) WithMetrics(m *metrics.Registry) *RateLimiter {
	r.metrics = m
	return r
}

func (r *RateLimiter) allow(key string) bool {
	if r.RatePerMin <= 0 {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.sweep(now)
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(r.RatePerMin), lastFill: now, max: float64(r.RatePerMin), perSec: float64(r.RatePerMin) / 60.0}
		r.buckets[key] = b
	}
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// PeerSendCap is the default per-(identity, peer) send budget. Counted in
// 1-hour windows. Independent of the global per-identity quota so a user
// can fan out 30 sends/min across many peers but is still capped at
// PeerSendCap to a single recipient over an hour — which is the spam path
// we actually care about.
const PeerSendCap = 20

// PeerCleanupCap is the per-(identity, peer) budget for writes that only
// take something back: deleting messages, removing a reaction, unpinning.
// It is a separate bucket so that a caller who hit PeerSendCap can still
// clean up what it sent, and it is larger because cleanup reaches nobody.
const PeerCleanupCap = 60

// PeerWindow is the bucket capacity refill horizon for AllowPeer.
const PeerWindow = time.Hour

// PeerDecision is the outcome of a per-peer debit.
type PeerDecision struct {
	Allowed bool
	// RetryAfter is how long until the bucket holds enough tokens for the
	// same cost. Zero when Allowed, and zero with TooLarge set when the
	// cost exceeds the bucket's capacity and can never fit.
	RetryAfter time.Duration
	TooLarge   bool
}

// AllowPeer is a separate token bucket for per-(identity, peer) sends.
// max is the burst capacity; the bucket refills at max/window-seconds.
// peerKey must identify the recipient — telegram.PeerLimitKey, never the
// RedactPeer audit tag, which collapses every user:<id> into one value.
// The limiter stores only an HMAC of it.
//
// Called from the write gates (send, forward, edit, reaction, pin, and the
// cleanup budget for delete/unreact/unpin) in addition to the per-request
// middleware limiter. A user can issue many reads per minute but only N
// writes per peer per hour.
func (r *RateLimiter) AllowPeer(id *auth.Identity, peerKey string, max int, window time.Duration) bool {
	return r.AllowPeerN(id, peerKey, 1, max, window)
}

// AllowPeerN is AllowPeer but debits cost tokens atomically instead of 1 —
// for calls whose single invocation covers a batch (e.g. forward_messages
// forwarding N messages in one call), so the bucket reflects actual message
// volume rather than call count. cost <= 0 is treated as 1. Denies (without
// debiting) when fewer than cost tokens are available, even if some tokens
// remain — a batch either fits within the budget or is rejected outright.
func (r *RateLimiter) AllowPeerN(id *auth.Identity, peerKey string, cost, max int, window time.Duration) bool {
	return r.DecidePeer(id, peerKey, cost, max, window).Allowed
}

// DecidePeer is AllowPeerN that also reports when a denied debit could
// succeed, so a refusal can tell the caller how long to wait.
func (r *RateLimiter) DecidePeer(id *auth.Identity, peerKey string, cost, max int, window time.Duration) PeerDecision {
	if max <= 0 || window <= 0 {
		return PeerDecision{Allowed: true}
	}
	if cost <= 0 {
		cost = 1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := identityKey(id) + ":peer:" + r.peerDigest(peerKey)
	now := r.now()
	r.sweep(now)
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: float64(max), lastFill: now, max: float64(max), perSec: float64(max) / window.Seconds()}
		r.buckets[key] = b
	}
	b.refill(now)
	if cost > max {
		return PeerDecision{TooLarge: true}
	}
	if b.tokens < float64(cost) {
		wait := math.Ceil((float64(cost) - b.tokens) / b.perSec)
		return PeerDecision{RetryAfter: time.Duration(wait) * time.Second}
	}
	b.tokens -= float64(cost)
	return PeerDecision{Allowed: true}
}

// peerDigest blinds a peer key for use as a map key. Caller holds r.mu.
func (r *RateLimiter) peerDigest(peerKey string) string {
	if r.peerSecret == nil {
		r.peerSecret = newPeerSecret()
	}
	m := hmac.New(sha256.New, r.peerSecret)
	m.Write([]byte(peerKey))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

func (r *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			id := auth.From(req.Context())
			key := "anon"
			identityKind := "anon"
			if id != nil && id.UserID > 0 {
				key = identityKey(id)
				identityKind = "user"
			}
			if !r.allow(key) {
				if r.metrics != nil {
					r.metrics.RateLimitEventsTotal.WithLabelValues(identityKind).Inc()
				}
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
	// Prefer Subject (e.g. "tg:<id>" from localjwt) since it is the
	// canonical identifier across providers; fall back to GitHubLogin
	// (set by sharedhmac-legacy and localdev) for older tokens, then to
	// the numeric user_id as a last resort. Without the Subject branch a
	// localjwt-authed caller would lose its per-identity bucket because
	// GitHubLogin is empty and every caller would collapse onto the same
	// "uid:<int>" key only when user_id happens to be the only difference.
	if id.Subject != "" {
		return "u:" + id.Subject
	}
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
