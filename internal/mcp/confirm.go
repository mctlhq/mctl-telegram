package mcp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// ConfirmationTTL is the window between prepare_* and the matching live
// send/pin. 10 minutes accommodates multi-turn LLM reasoning delays and
// connectors (e.g. ChatGPT) that pause for a user turn between the two calls.
const ConfirmationTTL = 10 * time.Minute

// Confirmation is the server-side handle for an in-flight destructive
// action that needs a two-step prepare→confirm dance. Stored in-memory only:
// short-lived (≤10m), single-shot, lost on pod restart by design. A user
// who refreshes their workflow simply prepares again.
type Confirmation struct {
	ID          string
	UserID      int64
	Action      string // "send" | "pin" | "unpin"
	PayloadHash string // sha256(canonical input) for tamper-detection
	ExpiresAt   time.Time
}

// ConfirmStore is a tiny in-memory single-shot TTL map.
type ConfirmStore struct {
	mu sync.Mutex
	m  map[string]*Confirmation
	// now is overridable so tests can pin wall-clock to a deterministic point.
	now func() time.Time
}

func NewConfirmStore() *ConfirmStore {
	return &ConfirmStore{m: map[string]*Confirmation{}, now: time.Now}
}

// Issue mints a new confirmation, stores it, and returns the public ID. The
// returned ID is a 16-byte hex string with a fixed prefix so it is easy to
// recognise in audit logs.
func (s *ConfirmStore) Issue(userID int64, action, payloadHash string) (*Confirmation, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	c := &Confirmation{
		ID:          "c" + action[:1] + "_" + hex.EncodeToString(raw),
		UserID:      userID,
		Action:      action,
		PayloadHash: payloadHash,
		ExpiresAt:   s.now().Add(ConfirmationTTL),
	}
	s.mu.Lock()
	s.m[c.ID] = c
	s.mu.Unlock()
	return c, nil
}

// ErrConfirmationNotFound means the ID was never issued, expired, or
// already consumed. We deliberately collapse all three into one error so a
// caller probing the surface cannot distinguish "expired" from "wrong id".
var ErrConfirmationNotFound = errors.New("confirmation not found, expired, or already used")

// ErrConfirmationMismatch means the caller supplied a valid ID but with a
// different payload than the one Prepare snapshotted. Either the LLM tried
// to swap the body silently or the user changed it between prepare and
// confirm; either way, refuse.
var ErrConfirmationMismatch = errors.New("confirmation payload hash does not match the prepared call")

// ErrConfirmationWrongUser means the ID belongs to a different identity. We
// surface this distinctly from NotFound so suspicious cross-user attempts
// can be flagged in audit logs without conflating with the "expired" path.
var ErrConfirmationWrongUser = errors.New("confirmation belongs to a different identity")

// Consume validates and removes a confirmation. Returns the Confirmation
// when everything checks out; otherwise returns one of the Err* sentinels
// above. Single-shot — even on mismatch the row is dropped to prevent a
// follow-up retry from observing the same id.
func (s *ConfirmStore) Consume(id string, userID int64, payloadHash string) (*Confirmation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[id]
	if !ok {
		return nil, ErrConfirmationNotFound
	}
	delete(s.m, id)
	if s.now().After(c.ExpiresAt) {
		return nil, ErrConfirmationNotFound
	}
	if c.UserID != userID {
		return nil, ErrConfirmationWrongUser
	}
	if c.PayloadHash != payloadHash {
		return nil, ErrConfirmationMismatch
	}
	return c, nil
}

// Sweep removes expired entries. Called from a goroutine in NewConfirmStore
// is overkill; callers typically run it from a periodic context. For now
// Consume handles cleanup on access, so a stale entry just sits in the map
// until the next Consume probe — bounded by the user's request volume.
// Exported so a future sweeper can call it if memory pressure shows up.
func (s *ConfirmStore) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	n := 0
	for id, c := range s.m {
		if now.After(c.ExpiresAt) {
			delete(s.m, id)
			n++
		}
	}
	return n
}

// HashSendPayload computes the canonical hash for a send_message call so
// prepare/confirm agree on what "the same payload" means. Peer first, NUL
// separator, text — collapsing any peer/text content into a single
// dependency.
func HashSendPayload(peer, text string) string {
	h := sha256.New()
	h.Write([]byte(peer))
	h.Write([]byte{0})
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// HashPinPayload is the equivalent for pin_message.
func HashPinPayload(peer string, messageID int64, unpin bool) string {
	h := sha256.New()
	h.Write([]byte(peer))
	h.Write([]byte{0})
	if unpin {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	var idBytes [8]byte
	for i := 0; i < 8; i++ {
		idBytes[7-i] = byte(messageID >> (8 * i))
	}
	h.Write(idBytes[:])
	return hex.EncodeToString(h.Sum(nil))
}
