package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
)

func TestWrapMsgs_RedactsTelegramLoginSecrets(t *testing.T) {
	in := []tg.Message{
		{
			ID:   1,
			Peer: "user:42",
			Text: "Login code: 31535. Do not share.\nIP: 2001:db8::1",
		},
	}

	out := wrapMsgs(in)
	if strings.Contains(out[0].Text, "31535") {
		t.Fatalf("login code leaked: %q", out[0].Text)
	}
	if strings.Contains(out[0].Text, "2001:db8::1") {
		t.Fatalf("login IP leaked: %q", out[0].Text)
	}
	if !strings.Contains(out[0].Text, "Login code: [redacted]") {
		t.Fatalf("missing redacted login code marker: %q", out[0].Text)
	}
	if !strings.Contains(out[0].Text, "IP: [redacted]") {
		t.Fatalf("missing redacted IP marker: %q", out[0].Text)
	}
	if !strings.HasPrefix(out[0].Text, `<telegram-content origin="telegram"`) {
		t.Fatalf("message was not wrapped as untrusted Telegram content: %q", out[0].Text)
	}
}

func TestLocalMediaStore_Claim_HappyPath(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})

	got, err := s.claim(confID, "peer:1", 10)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if !got.inFlight {
		t.Fatal("claim must set inFlight=true")
	}
	s.mu.Lock()
	_, stillPresent := s.m[confID]
	s.mu.Unlock()
	if !stillPresent {
		t.Fatal("claim must not delete the entry")
	}
}

func TestLocalMediaStore_Claim_InFlight(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})

	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if _, err := s.claim(confID, "peer:1", 10); !errors.Is(err, errLocalMediaInFlight) {
		t.Fatalf("second claim must return errLocalMediaInFlight, got %v", err)
	}
}

func TestLocalMediaStore_Claim_ThenFinalize(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})

	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	s.finalize(confID)
	if _, err := s.claim(confID, "peer:1", 10); !errors.Is(err, errLocalMediaNotFound) {
		t.Fatalf("after finalize, claim must return errLocalMediaNotFound, got %v", err)
	}
}

func TestLocalMediaStore_Claim_WrongPair(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})

	if _, err := s.claim(confID, "peer:2", 10); !errors.Is(err, errLocalMediaNotFound) {
		t.Fatalf("wrong peer must return errLocalMediaNotFound, got %v", err)
	}
	// A wrong-pair probe is a terminal failure — the entry must be dropped so
	// a follow-up retry with the correct pair cannot observe the same id.
	s.mu.Lock()
	_, stillPresent := s.m[confID]
	s.mu.Unlock()
	if stillPresent {
		t.Fatal("claim must delete the entry on a wrong-pair probe")
	}
}

func TestLocalMediaStore_Claim_WrongMessageID(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})

	if _, err := s.claim(confID, "peer:1", 99); !errors.Is(err, errLocalMediaNotFound) {
		t.Fatalf("wrong message_id must return errLocalMediaNotFound, got %v", err)
	}
}

func TestLocalMediaStore_Claim_InFlightBeatsExpiry(t *testing.T) {
	// The retry race this mechanism exists to fix: a download starts just
	// before the TTL, runs long, and a retry lands after the nominal
	// expiresAt but while the original claim is still in flight. It must see
	// errLocalMediaInFlight, not a false "not found/expired".
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})
	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	s.mu.Lock()
	e := s.m[confID]
	e.expiresAt = time.Now().Add(-time.Minute)
	s.m[confID] = e
	s.mu.Unlock()

	if _, err := s.claim(confID, "peer:1", 10); !errors.Is(err, errLocalMediaInFlight) {
		t.Fatalf("retry after nominal expiry but while in-flight must return errLocalMediaInFlight, got %v", err)
	}
}

func TestLocalMediaStore_Claim_InFlightBeatsWrongPair(t *testing.T) {
	// An in-flight entry must not be invalidated by an unrelated wrong-pair
	// probe against the same id — that would let a stray/buggy call kill a
	// legitimate in-flight download.
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})
	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := s.claim(confID, "peer:2", 99); !errors.Is(err, errLocalMediaInFlight) {
		t.Fatalf("wrong-pair probe against an in-flight entry must return errLocalMediaInFlight, got %v", err)
	}
	s.mu.Lock()
	_, stillPresent := s.m[confID]
	s.mu.Unlock()
	if !stillPresent {
		t.Fatal("in-flight entry must survive an unrelated wrong-pair probe")
	}
}

func TestLocalMediaStore_Claim_Expired(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})
	s.mu.Lock()
	e := s.m[confID]
	e.expiresAt = time.Now().Add(-time.Minute)
	s.m[confID] = e
	s.mu.Unlock()

	if _, err := s.claim(confID, "peer:1", 10); !errors.Is(err, errLocalMediaNotFound) {
		t.Fatalf("expired claim must return errLocalMediaNotFound, got %v", err)
	}
	// Nothing periodically sweeps this map outside of put()'s opportunistic
	// pass, so an expired entry must be dropped on access.
	s.mu.Lock()
	_, stillPresent := s.m[confID]
	s.mu.Unlock()
	if stillPresent {
		t.Fatal("claim must delete the entry on expiry")
	}
}

func TestLocalMediaStore_Put_SweepSkipsInFlight(t *testing.T) {
	// An in-flight download can legitimately outlive its nominal TTL. The
	// opportunistic sweep in put() must not delete it out from under the
	// running get_media call, or a concurrent retry would see "not found"
	// instead of the in-flight response it's meant to get.
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})
	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	s.mu.Lock()
	e := s.m[confID]
	e.expiresAt = time.Now().Add(-time.Minute)
	s.m[confID] = e
	s.mu.Unlock()

	// Trigger another put(), which runs the opportunistic sweep.
	s.put("peer:2", 20, tg.MediaInfo{}, tg.MediaFileLocation{})

	s.mu.Lock()
	_, stillPresent := s.m[confID]
	s.mu.Unlock()
	if !stillPresent {
		t.Fatal("sweep must not delete an in-flight entry, even past its expiresAt")
	}
}

func TestLocalMediaStore_Unclaim_AllowsRetryClaim(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	confID, _ := s.put("peer:1", 10, tg.MediaInfo{}, tg.MediaFileLocation{})
	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim: %v", err)
	}
	s.unclaim(confID)
	if _, err := s.claim(confID, "peer:1", 10); err != nil {
		t.Fatalf("claim after unclaim: %v", err)
	}
}

func TestLocalMediaStore_Unclaim_MissingIDIsNoop(t *testing.T) {
	s := &localMediaStore{m: map[string]localMediaEntry{}}
	s.unclaim("does-not-exist") // must not panic
}
