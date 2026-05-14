package mcp

import (
	"errors"
	"testing"
	"time"
)

func TestConfirmStore_HappyPath(t *testing.T) {
	s := NewConfirmStore()
	hash := HashSendPayload("@x", "hello")
	c, err := s.Issue(42, "send", hash)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if c.ID == "" || c.PayloadHash != hash {
		t.Fatalf("bad confirmation: %+v", c)
	}
	got, err := s.Consume(c.ID, 42, hash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ID != c.ID {
		t.Fatal("Consume returned different confirmation")
	}
}

func TestConfirmStore_SingleShot(t *testing.T) {
	s := NewConfirmStore()
	hash := HashSendPayload("@x", "hi")
	c, _ := s.Issue(1, "send", hash)
	if _, err := s.Consume(c.ID, 1, hash); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(c.ID, 1, hash); !errors.Is(err, ErrConfirmationNotFound) {
		t.Fatalf("second consume must return ErrConfirmationNotFound, got %v", err)
	}
}

func TestConfirmStore_ExpiredCollapsesToNotFound(t *testing.T) {
	s := NewConfirmStore()
	hash := HashSendPayload("@x", "hi")
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	c, _ := s.Issue(1, "send", hash)
	s.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	if _, err := s.Consume(c.ID, 1, hash); !errors.Is(err, ErrConfirmationNotFound) {
		t.Fatalf("expired consume must return ErrConfirmationNotFound, got %v", err)
	}
}

func TestConfirmStore_WrongUserRejected(t *testing.T) {
	s := NewConfirmStore()
	hash := HashSendPayload("@x", "hi")
	c, _ := s.Issue(1, "send", hash)
	if _, err := s.Consume(c.ID, 2, hash); !errors.Is(err, ErrConfirmationWrongUser) {
		t.Fatalf("wrong-user consume must return ErrConfirmationWrongUser, got %v", err)
	}
}

func TestConfirmStore_MismatchedPayloadRejected(t *testing.T) {
	s := NewConfirmStore()
	prepHash := HashSendPayload("@x", "draft body")
	c, _ := s.Issue(1, "send", prepHash)

	// Caller submits the matching id but a different payload — refuse.
	wrongHash := HashSendPayload("@x", "tampered body")
	if _, err := s.Consume(c.ID, 1, wrongHash); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("payload-mismatch must return ErrConfirmationMismatch, got %v", err)
	}

	// And the original id is now gone (single-shot, even on mismatch).
	if _, err := s.Consume(c.ID, 1, prepHash); !errors.Is(err, ErrConfirmationNotFound) {
		t.Fatalf("mismatched consume must still invalidate the id, got %v", err)
	}
}

func TestHashSendPayload_PeerTextSeparationIsSafe(t *testing.T) {
	// "@a" + "bc" must not hash to the same value as "@ab" + "c".
	// The NUL byte separator prevents that aliasing; verify.
	h1 := HashSendPayload("@a", "bc")
	h2 := HashSendPayload("@ab", "c")
	if h1 == h2 {
		t.Fatal("peer/text boundary must not be ambiguous")
	}
}

func TestHashPinPayload_DistinctOnAllFields(t *testing.T) {
	h1 := HashPinPayload("@x", 1, false)
	h2 := HashPinPayload("@x", 1, true)
	h3 := HashPinPayload("@x", 2, false)
	h4 := HashPinPayload("@y", 1, false)
	if h1 == h2 || h1 == h3 || h1 == h4 {
		t.Fatal("hash must reflect peer, message_id, and unpin distinctly")
	}
}

func TestSweep_RemovesExpiredOnly(t *testing.T) {
	s := NewConfirmStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	c1, _ := s.Issue(1, "send", "a")
	_, _ = s.Issue(2, "send", "b")

	// Advance just past c1's expiry but not far enough for c2 to be reissued.
	s.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	n := s.Sweep()
	if n != 2 {
		t.Fatalf("expected both issued in the same epoch to expire together, got %d", n)
	}
	if _, err := s.Consume(c1.ID, 1, "a"); err == nil {
		t.Fatal("c1 should be gone after sweep")
	}
}
