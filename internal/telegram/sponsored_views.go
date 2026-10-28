package telegram

import (
	"sync"
	"time"
)

// SponsoredViewTTL is how long a reported sponsored item stays reported for
// one user. A model paging a channel with before_id, or re-reading it, gets
// the same items again; within this window their views are not reported a
// second time (issue #906).
const SponsoredViewTTL = 5 * time.Minute

// maxSponsoredViewsPerUser bounds one user's set. Past it the set is
// cleared: the cost is a repeated report, never a missed one.
const maxSponsoredViewsPerUser = 1024

// SponsoredViews remembers, per user, which sponsored items (by RandomID)
// had a view reported in the last TTL. The zero value is not usable; a nil
// *SponsoredViews remembers nothing, so every item is reported.
type SponsoredViews struct {
	ttl time.Duration
	now func() time.Time

	mu        sync.Mutex
	users     map[int64]map[string]viewClaim // userID -> RandomID -> claim
	lastSweep time.Time
	seq       uint64 // last claim token handed out
}

// viewClaim is one recorded report: when it stops counting, and the token of
// the Claim call that made it, so Release undoes only that call's entries.
type viewClaim struct {
	exp   time.Time
	token uint64
}

// NewSponsoredViews returns an empty set whose entries live for ttl.
func NewSponsoredViews(ttl time.Duration) *SponsoredViews {
	return &SponsoredViews{ttl: ttl, now: time.Now, users: map[int64]map[string]viewClaim{}}
}

// Claim returns the items of msgs whose view is due for userID and records
// them as reported, plus a token for Release. An item claimed by an earlier
// call within the TTL, or earlier in msgs, is left out. Items without a
// RandomID cannot be told apart and are always returned. Claim before
// reporting, so two concurrent reads of the same channel report an item
// once; give back the items whose report never went out with Release.
func (v *SponsoredViews) Claim(userID int64, msgs []SponsoredMessage) ([]SponsoredMessage, uint64) {
	if v == nil || len(msgs) == 0 {
		return msgs, 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	v.sweepLocked(now)
	v.seq++
	token := v.seq
	seen := v.users[userID]
	if seen == nil || len(seen) >= maxSponsoredViewsPerUser {
		seen = map[string]viewClaim{}
		v.users[userID] = seen
	}
	fresh := make([]SponsoredMessage, 0, len(msgs))
	for _, m := range msgs {
		if m.RandomID == "" {
			fresh = append(fresh, m)
			continue
		}
		if c, ok := seen[m.RandomID]; ok && now.Before(c.exp) {
			continue
		}
		seen[m.RandomID] = viewClaim{exp: now.Add(v.ttl), token: token}
		fresh = append(fresh, m)
	}
	return fresh, token
}

// Release forgets msgs for userID, so the next read reports them. Use it for
// items claimed under token whose report was never sent. An entry a later
// Claim has made since (after expiry, or after the set was cleared) belongs
// to that call and is kept: its report may have gone out.
func (v *SponsoredViews) Release(userID int64, token uint64, msgs []SponsoredMessage) {
	if v == nil || len(msgs) == 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	seen := v.users[userID]
	for _, m := range msgs {
		if c, ok := seen[m.RandomID]; ok && c.token == token {
			delete(seen, m.RandomID)
		}
	}
}

// sweepLocked drops expired entries and empty users, at most once per TTL,
// so the set stays bounded by what was reported in the last two TTLs.
func (v *SponsoredViews) sweepLocked(now time.Time) {
	if now.Sub(v.lastSweep) < v.ttl {
		return
	}
	v.lastSweep = now
	for uid, seen := range v.users {
		for id, c := range seen {
			if !now.Before(c.exp) {
				delete(seen, id)
			}
		}
		if len(seen) == 0 {
			delete(v.users, uid)
		}
	}
}
