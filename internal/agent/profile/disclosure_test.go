package profile

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// aliceProfileJSON mirrors the shape of a real recruiter-agent profile with
// synthetic values only.
const aliceProfileJSON = `{
	"identity":{"name":"Alice Example","role":"Backend Engineer","company":"Nordbank GmbH","location":"Lisbon, Portugal","education":"Example University"},
	"public_profile":{"summary":"Eight years of payments infrastructure in Go.","open_to":"Staff roles in fintech"},
	"preferences":{"region":"EMEA","work_mode":"hybrid"},
	"skills":["Go","Kubernetes","PostgreSQL"],
	"restricted":{"current_salary":{"value":"98765","approval_required":true}}
}`

func mustParse(t *testing.T, raw string) Data {
	t.Helper()
	d, err := ParseJSON([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func withDisclosure(t *testing.T, disclosure string) Data {
	t.Helper()
	raw := strings.TrimSuffix(strings.TrimSpace(aliceProfileJSON), "}") + `,"disclosure":` + disclosure + `}`
	return mustParse(t, raw)
}

// TestAgentProfile_ColdSenderSeesOnlyNameRoleSkills is the #953 baseline: a
// profile without a disclosure section shows a cold sender name, role and
// skills, and nothing about employer, location, summary or preferences.
func TestAgentProfile_ColdSenderSeesOnlyNameRoleSkills(t *testing.T) {
	out := agentProfile(mustParse(t, aliceProfileJSON), false)
	identity, _ := out["identity"].(map[string]any)
	if identity["name"] != "Alice Example" || identity["role"] != "Backend Engineer" {
		t.Fatalf("identity = %+v, want name and role", identity)
	}
	for _, k := range []string{"company", "location", "education"} {
		if _, ok := identity[k]; ok {
			t.Fatalf("identity.%s visible to a cold sender: %+v", k, identity)
		}
	}
	if skills, _ := out["skills"].([]string); len(skills) != 3 {
		t.Fatalf("skills = %+v, want 3", out["skills"])
	}
	for _, sec := range []string{"public_profile", "preferences", "restricted", "disclosure"} {
		if _, ok := out[sec]; ok {
			t.Fatalf("%s visible to a cold sender: %+v", sec, out)
		}
	}
	b, _ := json.Marshal(out)
	for _, leak := range []string{"Nordbank", "Lisbon", "fintech", "EMEA", "hybrid", "98765"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("cold view leaks %q: %s", leak, b)
		}
	}
}

func TestAgentProfile_EngagedSeesAfterOwnerEngagedFields(t *testing.T) {
	out := agentProfile(mustParse(t, aliceProfileJSON), true)
	identity, _ := out["identity"].(map[string]any)
	if identity["company"] != "Nordbank GmbH" || identity["location"] != "Lisbon, Portugal" {
		t.Fatalf("identity = %+v, want company and location once engaged", identity)
	}
	if _, ok := out["public_profile"]; !ok {
		t.Fatalf("public_profile missing once engaged: %+v", out)
	}
	if _, ok := out["preferences"]; !ok {
		t.Fatalf("preferences missing once engaged: %+v", out)
	}
	if _, ok := out["restricted"]; ok {
		t.Fatalf("restricted leaked once engaged: %+v", out)
	}
}

func TestAgentProfile_NeverFieldHiddenEvenWhenEngaged(t *testing.T) {
	d := withDisclosure(t, `{"identity.company":"never","skills":"never","preferences.region":"public"}`)
	for _, engaged := range []bool{false, true} {
		out := agentProfile(d, engaged)
		identity, _ := out["identity"].(map[string]any)
		if _, ok := identity["company"]; ok {
			t.Fatalf("engaged=%v: never field identity.company visible", engaged)
		}
		if _, ok := out["skills"]; ok {
			t.Fatalf("engaged=%v: never skills visible", engaged)
		}
		prefs, _ := out["preferences"].(map[string]any)
		if prefs["region"] != "EMEA" {
			t.Fatalf("engaged=%v: public preferences.region missing: %+v", engaged, out)
		}
	}
}

func TestParseJSON_DisclosureValidation(t *testing.T) {
	for _, bad := range []string{
		`{"identity.company":"secret"}`,          // unknown level
		`{"identity.compnay":"never"}`,           // typo: no such field
		`{"identity":"never"}`,                   // section, not a field
		`{"restricted.current_salary":"public"}`, // restricted is not a disclosure section
		`{"identity.":"never"}`,
	} {
		raw := strings.TrimSuffix(strings.TrimSpace(aliceProfileJSON), "}") + `,"disclosure":` + bad + `}`
		if _, err := ParseJSON([]byte(raw)); err == nil {
			t.Fatalf("disclosure %s accepted", bad)
		}
	}
	if _, err := ParseYAML([]byte("identity:\n  name: Alice\ndisclosure:\n  identity.nmae: never\n")); err == nil {
		t.Fatal("YAML disclosure typo accepted")
	}
	withDisclosure(t, `{"identity.company":"public","public_profile.summary":"never","skills":"after_owner_engaged"}`)
}

func TestMatchProtected_Levels(t *testing.T) {
	d := withDisclosure(t, `{"identity.education":"never"}`)
	cases := []struct {
		name      string
		text      string
		engaged   bool
		wantKey   string
		wantLevel DisclosureLevel
	}{
		{"after_owner_engaged before engagement", "I work at Nordbank GmbH.", false, "identity.company", DisclosureAfterOwnerEngaged},
		{"case-insensitive", "based in LISBON these days", false, "identity.location", DisclosureAfterOwnerEngaged},
		{"comma part of a value", "I am in Lisbon.", false, "identity.location", DisclosureAfterOwnerEngaged},
		{"never outranks after_owner_engaged", "Nordbank GmbH, studied at Example University", false, "identity.education", DisclosureNever},
		{"never still matches once engaged", "studied at Example University", true, "identity.education", DisclosureNever},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, level, matched := matchProtected(d, tc.text, "", tc.engaged)
			if !matched || key != tc.wantKey || level != tc.wantLevel {
				t.Fatalf("matchProtected(%q, engaged=%v) = %q %q %v, want %q %q", tc.text, tc.engaged, key, level, matched, tc.wantKey, tc.wantLevel)
			}
		})
	}
	// Public fields and engaged after_owner_engaged fields never match.
	for _, text := range []string{
		"I'm Alice Example, a Backend Engineer working with Go and Kubernetes.",
	} {
		if key, _, matched := matchProtected(d, text, "", false); matched {
			t.Fatalf("public text %q matched %q", text, key)
		}
	}
	if key, _, matched := matchProtected(d, "I work at Nordbank GmbH in Lisbon.", "", true); matched {
		t.Fatalf("after_owner_engaged value matched while engaged: %q", key)
	}
}

// TestMatchProtected_SenderWordsExempt pins #992: a fragment of an
// after_owner_engaged field the peer wrote first in the turn is not a
// disclosure, every other fragment still is, and never fields get no
// exemption.
func TestMatchProtected_SenderWordsExempt(t *testing.T) {
	d := withDisclosure(t, `{"identity.education":"never"}`)
	const reply = "Happy to talk about the Lisbon role."
	if key, _, matched := matchProtected(d, reply, "Hi, we are hiring for an office in Lisbon.", false); matched {
		t.Fatalf("sender's own word matched %q", key)
	}
	if _, _, matched := matchProtected(d, reply, "", false); !matched {
		t.Fatal("without inbound text the same reply did not match")
	}
	// Only a whole-word use by the sender exempts a fragment.
	if _, _, matched := matchProtected(d, reply, "Our Lisbonia office is hiring.", false); !matched {
		t.Fatal("a longer word in the inbound text exempted the fragment")
	}
	// A fragment the sender never used still counts.
	key, level, matched := matchProtected(d, "Lisbon works; I am at Nordbank GmbH.", "The role is in Lisbon.", false)
	if !matched || key != "identity.company" || level != DisclosureAfterOwnerEngaged {
		t.Fatalf("unused fragment: %q %q %v, want identity.company", key, level, matched)
	}
	// never fields are matched even when the sender wrote the value.
	key, level, matched = matchProtected(d, "Example University, sure.", "Did you study at Example University?", false)
	if !matched || key != "identity.education" || level != DisclosureNever {
		t.Fatalf("never field: %q %q %v, want identity.education never", key, level, matched)
	}
}

// TestMatchProtected_FalsePositives pins the two heuristics that keep
// literal matching usable: fragments under minProtectedNeedleRunes are
// ignored, and a match must sit on word boundaries.
func TestMatchProtected_FalsePositives(t *testing.T) {
	d := mustParse(t, `{
		"identity":{"name":"Alice","location":"Rome, UK"},
		"preferences":{"region":"EU"}
	}`)
	for _, text := range []string{
		"Romeo and Juliet",          // "rome" inside a longer word
		"I know the UK market well", // "UK" is shorter than the minimum
		"EU timezone works",         // "EU" likewise
		"Happy to talk.",
	} {
		if key, _, matched := matchProtected(d, text, "", false); matched {
			t.Fatalf("%q matched %q", text, key)
		}
	}
	if _, _, matched := matchProtected(d, "I live in Rome.", "", false); !matched {
		t.Fatal("whole-word Rome not matched")
	}
	// The whole value is still a needle even when its parts are short.
	if _, _, matched := matchProtected(d, "Rome, UK is home", "", false); !matched {
		t.Fatal("whole value not matched")
	}
}

func TestTenantProvider_DisclosureByEngagement(t *testing.T) {
	const aliceID int64 = 11
	provider := NewTenantProvider(fakeTenantStore{aliceID: []byte(aliceProfileJSON)})
	ctx := context.Background()
	cold, err := provider.PublicProfile(ctx, aliceID, false)
	if err != nil {
		t.Fatalf("cold profile: %v", err)
	}
	if _, ok := cold["preferences"]; ok {
		t.Fatalf("cold profile has preferences: %+v", cold)
	}
	key, never, matched, err := provider.MatchProtected(ctx, aliceID, "hybrid works for me", "", false)
	if err != nil || !matched || key != "preferences.work_mode" || never {
		t.Fatalf("MatchProtected = %q never=%v matched=%v err=%v", key, never, matched, err)
	}
	if _, _, _, err := provider.MatchProtected(ctx, 999, "x", "", false); err == nil {
		t.Fatal("missing tenant profile did not error")
	}
}
