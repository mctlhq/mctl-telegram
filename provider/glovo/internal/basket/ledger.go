// Package basket holds the idempotency ledger for synthetic basket effects.
package basket

import "sync"

// Key identifies one intended effect.
type Key struct{ Tenant, Order, IntentHash string }

// Entry is the recorded outcome of an applied effect.
// A ledger entry is handoff-authoritative only if ConsumeApproval succeeded
// for this exact execution and receipt before the provider effect. Merely
// observing a pre-existing matching basket does not establish consent.
type Entry struct {
	Fingerprint  string
	ExecutionRef string
	ApprovalRef  string
}

type slot struct {
	mu    sync.Mutex
	entry *Entry
}

// Ledger serialises work per key and remembers applied effects. It is safe
// for concurrent use.
type Ledger struct {
	mu    sync.Mutex
	slots map[Key]*slot
}

func NewLedger() *Ledger { return &Ledger{slots: map[Key]*slot{}} }

func (l *Ledger) slot(k Key) *slot {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.slots[k]
	if !ok {
		s = &slot{}
		l.slots[k] = s
	}
	return s
}

// Get returns the recorded entry, if any.
func (l *Ledger) Get(k Key) (Entry, bool) {
	s := l.slot(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entry == nil {
		return Entry{}, false
	}
	return *s.entry, true
}

// Do runs apply at most once successfully per key. Concurrent callers for the
// same key are serialised; if an effect is already recorded, apply is not
// called and deduped is true. apply receives the recorded entry state: it is
// only invoked when nothing is recorded. A failed apply records nothing.
func (l *Ledger) Do(k Key, apply func() (Entry, error)) (e Entry, deduped bool, err error) {
	s := l.slot(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entry != nil {
		return *s.entry, true, nil
	}
	e, err = apply()
	if err != nil {
		return Entry{}, false, err
	}
	s.entry = &e
	return e, false, nil
}

// Forget drops every entry of one order.
func (l *Ledger) Forget(tenant, order string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k := range l.slots {
		if k.Tenant == tenant && k.Order == order {
			delete(l.slots, k)
		}
	}
}
