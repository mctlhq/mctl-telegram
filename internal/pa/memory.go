package pa

import (
	"context"
	"errors"
)

// Provenance marks where a fragment of state came from (threat model T5).
// The zero value is unknown, and unknown is treated as external (I6, I9).
type Provenance string

const (
	ProvenanceUser     Provenance = "user"
	ProvenanceExternal Provenance = "external"
)

// Effective returns the provenance a gate must act on: only an explicit
// ProvenanceUser is user; everything else, including the zero value, is
// external.
func (p Provenance) Effective() Provenance {
	if p == ProvenanceUser {
		return ProvenanceUser
	}
	return ProvenanceExternal
}

// MemoryItem is one remembered fragment. It always carries a provenance mark,
// so nothing unmarked can be stored or loaded.
type MemoryItem struct {
	Text       string
	Provenance Provenance
}

// ErrMemoryDisabled is returned by NoopMemoryStore.Remember: nothing was
// stored, and a caller must not believe otherwise.
var ErrMemoryDisabled = errors.New("pa: long-term memory is not enabled")

// MemoryStore is long-term memory. It is out of scope for Phase 1 (ADR 0011)
// and exists as an interface so the run loop has one seam for it. Every call
// is scoped by the run's ExecutionContext, whose principal is the key (I10);
// no method takes a principal or user id from anywhere else.
type MemoryStore interface {
	// Recall returns items for the context's principal. A failed read is an
	// error, never an empty result (I9).
	Recall(ctx context.Context, ec ExecutionContext) ([]MemoryItem, error)
	// Remember stores an item for the context's principal.
	Remember(ctx context.Context, ec ExecutionContext, item MemoryItem) error
	// Forget deletes everything stored for the context's principal.
	Forget(ctx context.Context, ec ExecutionContext) error
}

// NoopMemoryStore is the only MemoryStore in Phase 1. It holds nothing.
type NoopMemoryStore struct{}

var _ MemoryStore = NoopMemoryStore{}

// Recall returns no items: there is no memory, which is the true answer, not
// a masked failure.
func (NoopMemoryStore) Recall(_ context.Context, ec ExecutionContext) ([]MemoryItem, error) {
	if !ec.Valid() {
		return nil, ErrInvalidContext
	}
	return nil, nil
}

// Remember stores nothing and says so.
func (NoopMemoryStore) Remember(_ context.Context, ec ExecutionContext, _ MemoryItem) error {
	if !ec.Valid() {
		return ErrInvalidContext
	}
	return ErrMemoryDisabled
}

// Forget has nothing to delete.
func (NoopMemoryStore) Forget(_ context.Context, ec ExecutionContext) error {
	if !ec.Valid() {
		return ErrInvalidContext
	}
	return nil
}
