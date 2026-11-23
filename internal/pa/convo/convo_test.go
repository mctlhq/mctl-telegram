package convo

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Synthetic personas, matching internal/db/agent_turn_claim_test.go
// (Alice=555, Bob=556).
const (
	aliceID int64 = 555
	bobID   int64 = 556
)

func testKey() []byte { return bytes.Repeat([]byte{0x42}, 32) }

// pinnedConsent maps every consent version this build has ever shipped to
// the SHA-256 of its text. A version's text never changes once shipped.
var pinnedConsent = map[string]string{
	// Re-pinned in place on 2026-11-19 (owner decision: name Nebius and
	// Cloudflare AI Gateway) without a version bump: PA_ENABLED has never
	// been on, so no consent to the earlier v1 text was ever stored and
	// nobody is held to a text they did not see. Once a consent exists,
	// a text change needs a new version.
	"pa-data-flow/v1": "3f17dd0710ee22d18cec23bbf8a35633bf5a9018626b3a07797930792120718f",
}

// pinnedConsentRU pins ConsentTextRU the same way. Added to v1 on
// 2026-11-23 (owner decision on #1318): a translation of the same data
// flow, with its own hash, so a principal who accepted the English text is
// still bound to exactly that text.
var pinnedConsentRU = map[string]string{
	"pa-data-flow/v1": "346462f326d6a5a0b4b59376a07ec69cc6f944f97c163d76c7e5f8dcf77c6822",
}

// TestConsentTextPinnedToVersion_S1N3 is the CI half of S1-N3: changing the
// consent text without bumping ConsentVersion fails here, so nobody is held
// to a text they did not see. Bumping the version adds a new pin; the old
// pin stays, and Satisfied then refuses every record of the old version.
func TestConsentTextPinnedToVersion_S1N3(t *testing.T) {
	want, ok := pinnedConsent[ConsentVersion]
	if !ok {
		t.Fatalf("ConsentVersion %q has no pinned text hash: add one", ConsentVersion)
	}
	if got := ConsentTextSHA256(); got != want {
		t.Fatalf("consent text for %s changed (sha256 %s, pinned %s): bump ConsentVersion and pin the new text", ConsentVersion, got, want)
	}
	// T13: the text names the provider class, the data categories and the
	// retention.
	for _, must := range []string{ConsentVersion, "AI model provider", "Nebius", "Cloudflare AI Gateway", "/privacy", "messages you write", "forward", "24 hours", "/consent withdraw", "/forget", "/new"} {
		if !strings.Contains(ConsentText, must) {
			t.Errorf("consent text does not mention %q", must)
		}
	}
	if got, want := ConsentTextSHA256RU(), pinnedConsentRU[ConsentVersion]; got != want {
		t.Fatalf("Russian consent text for %s changed (sha256 %s, pinned %s): bump ConsentVersion and pin the new texts", ConsentVersion, got, want)
	}
	// The translation names the same recipients, categories, retention
	// and commands.
	for _, must := range []string{ConsentVersion, "провайдеру ИИ-модели", "Nebius", "Cloudflare AI Gateway", "/privacy", "сообщения, которые вы пишете", "пересылаете", "24 часов", "/consent withdraw", "/forget", "/new", "только читает"} {
		if !strings.Contains(ConsentTextRU, must) {
			t.Errorf("Russian consent text does not mention %q", must)
		}
	}
}

// TestSatisfied_S1N3: only an accepted record of the current version and
// text satisfies consent.
func TestSatisfied_S1N3(t *testing.T) {
	cur := ConsentRecord{Principal: aliceID, Version: ConsentVersion, TextSHA256: ConsentTextSHA256(), State: ConsentAccepted}
	if !Satisfied(cur) {
		t.Fatal("current accepted consent not satisfied")
	}
	ru := cur
	ru.TextSHA256 = ConsentTextSHA256RU()
	if !Satisfied(ru) {
		t.Fatal("current accepted Russian consent not satisfied")
	}
	for name, mut := range map[string]func(*ConsentRecord){
		"old version":   func(r *ConsentRecord) { r.Version = "pa-data-flow/v0" },
		"other text":    func(r *ConsentRecord) { r.TextSHA256 = strings.Repeat("0", 64) },
		"withdrawn":     func(r *ConsentRecord) { r.State = ConsentWithdrawn },
		"unknown state": func(r *ConsentRecord) { r.State = "maybe" },
		"zero record":   func(r *ConsentRecord) { *r = ConsentRecord{} },
	} {
		r := cur
		mut(&r)
		if Satisfied(r) {
			t.Errorf("%s: satisfied", name)
		}
	}
}

// TestFragment_S1I4: a fragment without provenance is external, and so is
// any mark this build does not know. Captions, replies, quotes and tool
// output are external whatever the caller passes.
func TestFragment_S1I4(t *testing.T) {
	for _, p := range []Provenance{"", "unknown", "USER", " user"} {
		if p.Effective() != ProvenanceExternal {
			t.Errorf("Provenance(%q).Effective() = %q, want external", p, p.Effective())
		}
		if f := NewFragment(KindText, p, "x"); f.Provenance() != ProvenanceExternal {
			t.Errorf("NewFragment with mark %q stored as %q", p, f.Provenance())
		}
	}
	if (Fragment{}).Provenance() != ProvenanceExternal {
		t.Error("zero Fragment is not external")
	}
	for _, k := range []Kind{KindCaption, KindReply, KindQuote, KindTool} {
		if f := NewFragment(k, ProvenanceUser, "x"); f.Provenance() != ProvenanceExternal {
			t.Errorf("%s fragment marked user", k)
		}
	}
	if f := NewFragment(KindText, ProvenanceUser, "hi"); f.Provenance() != ProvenanceUser {
		t.Error("user text lost its mark")
	}
}

// TestSealer_MarkIsBound_S1I2: the provenance mark, kind, conversation,
// position and principal are bound into the ciphertext. Flipping a stored
// mark from external to user, moving a blob, or opening under another
// principal fails, and an unmarked row is never decoded.
func TestSealer_MarkIsBound_S1I2(t *testing.T) {
	s, err := NewSealer(testKey())
	if err != nil {
		t.Fatal(err)
	}
	sf, err := s.Seal(aliceID, "conv-a", 1, NewFragment(KindText, ProvenanceExternal, "forwarded text"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sf.Sealed, []byte("forwarded text")) {
		t.Fatal("sealed blob contains the plaintext")
	}
	f, err := s.Open(aliceID, sf)
	if err != nil {
		t.Fatal(err)
	}
	if text, prov := f.Text(); text != "forwarded text" || prov != ProvenanceExternal {
		t.Fatalf("round trip = %q/%q", text, prov)
	}

	tamper := map[string]func(*SealedFragment){
		"mark flipped to user": func(x *SealedFragment) { x.Provenance = ProvenanceUser },
		"kind changed":         func(x *SealedFragment) { x.Kind = KindAssistant },
		"moved conversation":   func(x *SealedFragment) { x.ConversationID = "conv-b" },
		"moved position":       func(x *SealedFragment) { x.Seq = 2 },
		"ciphertext bit":       func(x *SealedFragment) { x.Sealed[len(x.Sealed)-1] ^= 1 },
		"version byte":         func(x *SealedFragment) { x.Sealed[0] = 0x02 },
		"truncated":            func(x *SealedFragment) { x.Sealed = x.Sealed[:5] },
	}
	for name, mut := range tamper {
		x := sf
		x.Sealed = bytes.Clone(sf.Sealed)
		mut(&x)
		if _, err := s.Open(aliceID, x); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: err = %v, want ErrUnreadable", name, err)
		}
	}

	// Bob's key does not open Alice's fragment, even with the row's
	// principal rewritten to Bob.
	x := sf
	x.Principal = bobID
	if _, err := s.Open(bobID, x); !errors.Is(err, ErrUnreadable) {
		t.Errorf("open under bob: err = %v, want ErrUnreadable", err)
	}
	if _, err := s.Open(bobID, sf); !errors.Is(err, ErrUnreadable) {
		t.Errorf("open alice's row as bob: err = %v, want ErrUnreadable", err)
	}

	for _, mark := range []Provenance{"", "legacy"} {
		x := sf
		x.Provenance = mark
		if _, err := s.Open(aliceID, x); !errors.Is(err, ErrUnmarked) {
			t.Errorf("mark %q: err = %v, want ErrUnmarked", mark, err)
		}
	}
}

func TestSealer_RefusesBadInput(t *testing.T) {
	for _, k := range [][]byte{nil, make([]byte, 16), make([]byte, 33)} {
		if _, err := NewSealer(k); !errors.Is(err, ErrSealerKey) {
			t.Errorf("key of %d bytes: err = %v", len(k), err)
		}
	}
	s, _ := NewSealer(testKey())
	good := NewFragment(KindText, ProvenanceUser, "x")
	if _, err := s.Seal(0, "c", 1, good); err == nil {
		t.Error("sealed without a principal")
	}
	if _, err := s.Seal(aliceID, "", 1, good); err == nil {
		t.Error("sealed without a conversation")
	}
	if _, err := s.Seal(aliceID, "c", 0, good); err == nil {
		t.Error("sealed at position 0")
	}
	if _, err := s.Seal(aliceID, "c", 1, Fragment{kind: KindText}); err == nil {
		t.Error("sealed an unmarked fragment")
	}
	big := NewFragment(KindText, ProvenanceUser, strings.Repeat("a", MaxFragmentBytes+1))
	if _, err := s.Seal(aliceID, "c", 1, big); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversize fragment: err = %v, want ErrInvalid", err)
	}
	if _, err := s.Seal(aliceID, "c", 1, NewFragment(KindText, ProvenanceUser, strings.Repeat("a", MaxFragmentBytes))); err != nil {
		t.Errorf("fragment at the bound: %v", err)
	}
}

// TestKind_Valid: every listed kind is valid, and nothing else is.
func TestKind_Valid(t *testing.T) {
	for _, k := range Kinds() {
		if !k.Valid() {
			t.Errorf("%q not valid", k)
		}
	}
	for _, k := range []Kind{"", "sticker", "TEXT"} {
		if k.Valid() {
			t.Errorf("%q valid", k)
		}
	}
}
