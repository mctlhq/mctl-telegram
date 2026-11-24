package convo

import (
	"strings"
	"testing"
)

// pinnedActionConsent pins ActionConsentText to its version and
// pinnedActionConsentRU the Russian text, as pinnedConsent does for the
// data-flow consent. A version's texts never change once shipped.
var (
	pinnedActionConsent = map[string]string{
		"pa-actions/v1": "dbb8fd57e8b6ef4f171d6645f86b23d7acf1778e55d0da457d78c0f5936226c2",
	}
	pinnedActionConsentRU = map[string]string{
		"pa-actions/v1": "5279977c9da85a91354020d35c8dac71dc9eb8c6f222f29e62bfb1fef8e9c977",
	}
)

// TestActionConsentTextPinnedToVersion is S1-N3 for the consent to
// actions (#1320 P2-S14c): changing either text without bumping
// ActionConsentVersion fails here, so nobody is held to a text they did
// not see. It also holds each text to what the consent must say: what the
// assistant may do, that the principal's tap decides, how to revoke, and
// what is recorded.
func TestActionConsentTextPinnedToVersion(t *testing.T) {
	if ActionConsentVersion == ConsentVersion {
		t.Fatal("the consent to actions shares its version with the data-flow consent")
	}
	want, ok := pinnedActionConsent[ActionConsentVersion]
	if !ok {
		t.Fatalf("ActionConsentVersion %q has no pinned text hash: add one", ActionConsentVersion)
	}
	if got := ActionConsentTextSHA256For(false); got != want {
		t.Fatalf("action consent text for %s changed (sha256 %s, pinned %s): bump ActionConsentVersion and pin the new texts", ActionConsentVersion, got, want)
	}
	if got, want := ActionConsentTextSHA256For(true), pinnedActionConsentRU[ActionConsentVersion]; got != want {
		t.Fatalf("Russian action consent text for %s changed (sha256 %s, pinned %s): bump ActionConsentVersion and pin the new texts", ActionConsentVersion, got, want)
	}
	if ActionConsentTextSHA256For(true) == ActionConsentTextSHA256For(false) {
		t.Fatal("the two texts share a hash")
	}
	for _, must := range []string{ActionConsentVersion, ConsentVersion,
		"playback", "volume", "light", "music",
		"card", "Approve", "standing permission", "Starting music always needs a card",
		"/permissions", "/disconnect", "/consent withdraw",
		"audit log", "fingerprint", "encrypted", "cannot be taken back"} {
		if !strings.Contains(ActionConsentText, must) {
			t.Errorf("action consent text does not mention %q", must)
		}
	}
	for _, must := range []string{ActionConsentVersion, ConsentVersion,
		"воспроизведением", "громкость", "свет", "музыку",
		"карточке", "«Подтвердить»", "постоянное разрешение", "Для включения музыки карточка нужна всегда",
		"/permissions", "/disconnect", "/consent withdraw",
		"журнал аудита", "отпечаток", "зашифрованном", "отменить не можем"} {
		if !strings.Contains(ActionConsentTextRU, must) {
			t.Errorf("Russian action consent text does not mention %q", must)
		}
	}
	// Nothing the owner ruled out is promised: no phrase to say aloud, no
	// free-form command (the quasar scope is not used).
	for _, text := range []string{ActionConsentText, ActionConsentTextRU} {
		for _, not := range []string{"quasar", "say a phrase", "произнести", "any command", "любую команду"} {
			if strings.Contains(text, not) {
				t.Errorf("action consent text mentions %q", not)
			}
		}
	}
}

// TestActionsSatisfied: only an accepted record of the current actions
// version and of one of its two texts is consent to actions. A record of
// the data-flow consent is not, nor the other way round.
func TestActionsSatisfied(t *testing.T) {
	cur := ConsentRecord{Principal: aliceID, Version: ActionConsentVersion, TextSHA256: ActionConsentTextSHA256For(false), State: ConsentAccepted}
	if !ActionsSatisfied(cur) {
		t.Fatal("current accepted consent to actions not satisfied")
	}
	ru := cur
	ru.TextSHA256 = ActionConsentTextSHA256For(true)
	if !ActionsSatisfied(ru) {
		t.Fatal("current accepted Russian consent to actions not satisfied")
	}
	for name, mut := range map[string]func(*ConsentRecord){
		"old version":       func(r *ConsentRecord) { r.Version = "pa-actions/v0" },
		"data-flow version": func(r *ConsentRecord) { r.Version = ConsentVersion },
		"other text":        func(r *ConsentRecord) { r.TextSHA256 = strings.Repeat("0", 64) },
		"data-flow text":    func(r *ConsentRecord) { r.TextSHA256 = ConsentTextSHA256() },
		"withdrawn":         func(r *ConsentRecord) { r.State = ConsentWithdrawn },
		"unknown state":     func(r *ConsentRecord) { r.State = "maybe" },
		"zero record":       func(r *ConsentRecord) { *r = ConsentRecord{} },
	} {
		r := cur
		mut(&r)
		if ActionsSatisfied(r) {
			t.Errorf("%s: satisfied", name)
		}
	}
	dataFlow := ConsentRecord{Principal: aliceID, Version: ConsentVersion, TextSHA256: ConsentTextSHA256(), State: ConsentAccepted}
	if ActionsSatisfied(dataFlow) || Satisfied(cur) {
		t.Fatal("one consent satisfies the other")
	}
}
