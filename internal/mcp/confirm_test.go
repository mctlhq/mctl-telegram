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

func TestConfirmStore_Claim_HappyPath(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	c, err := s.Issue(1, "media", hash)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Claim(c.ID, 1, hash)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !got.InFlight {
		t.Fatal("Claim must set InFlight=true")
	}
	// Entry must still be present (not deleted).
	s.mu.Lock()
	_, ok := s.m[c.ID]
	s.mu.Unlock()
	if !ok {
		t.Fatal("Claim must not delete the entry")
	}
}

func TestConfirmStore_Claim_InFlight(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	c, _ := s.Issue(1, "media", hash)
	if _, err := s.Claim(c.ID, 1, hash); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := s.Claim(c.ID, 1, hash); !errors.Is(err, ErrConfirmationInFlight) {
		t.Fatalf("second claim must return ErrConfirmationInFlight, got %v", err)
	}
}

func TestConfirmStore_Claim_ThenFinalize(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	c, _ := s.Issue(1, "media", hash)
	if _, err := s.Claim(c.ID, 1, hash); err != nil {
		t.Fatalf("claim: %v", err)
	}
	s.Finalize(c.ID)
	// Entry must now be gone.
	if _, err := s.Claim(c.ID, 1, hash); !errors.Is(err, ErrConfirmationNotFound) {
		t.Fatalf("after Finalize, Claim must return ErrConfirmationNotFound, got %v", err)
	}
}

func TestConfirmStore_Claim_Expired(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return fixed }
	c, _ := s.Issue(1, "media", hash)
	s.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	if _, err := s.Claim(c.ID, 1, hash); !errors.Is(err, ErrConfirmationNotFound) {
		t.Fatalf("expired Claim must return ErrConfirmationNotFound, got %v", err)
	}
	// Claim must NOT delete on expiry — entry remains for Sweep.
	s.mu.Lock()
	_, ok := s.m[c.ID]
	s.mu.Unlock()
	if !ok {
		t.Fatal("Claim must not delete the entry on expiry — leave it for Sweep")
	}
}

func TestConfirmStore_Claim_WrongUser(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	c, _ := s.Issue(1, "media", hash)
	if _, err := s.Claim(c.ID, 2, hash); !errors.Is(err, ErrConfirmationWrongUser) {
		t.Fatalf("wrong-user Claim must return ErrConfirmationWrongUser, got %v", err)
	}
}

func TestConfirmStore_Claim_MismatchedPayload(t *testing.T) {
	s := NewConfirmStore()
	hash := HashMediaPayload("@x", 42)
	c, _ := s.Issue(1, "media", hash)
	wrong := HashMediaPayload("@y", 99)
	if _, err := s.Claim(c.ID, 1, wrong); !errors.Is(err, ErrConfirmationMismatch) {
		t.Fatalf("mismatched-payload Claim must return ErrConfirmationMismatch, got %v", err)
	}
}

func TestConfirmStore_Consume_Unchanged(t *testing.T) {
	// Consume must still delete on first call and not set InFlight.
	s := NewConfirmStore()
	hash := HashSendPayload("@x", "hello")
	c, _ := s.Issue(1, "send", hash)
	got, err := s.Consume(c.ID, 1, hash)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.InFlight {
		t.Fatal("Consume must not set InFlight")
	}
	// Entry must be gone after Consume.
	if _, err2 := s.Consume(c.ID, 1, hash); !errors.Is(err2, ErrConfirmationNotFound) {
		t.Fatalf("second Consume must return ErrConfirmationNotFound, got %v", err2)
	}
}
