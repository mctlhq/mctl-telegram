package profile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var errTenantProfileMissing = errors.New("tenant profile missing")

type fakeTenantStore map[int64][]byte

func (s fakeTenantStore) GetAgentOwnerProfile(_ context.Context, userID int64) ([]byte, error) {
	raw, ok := s[userID]
	if !ok {
		return nil, errTenantProfileMissing
	}
	return raw, nil
}

const testYAML = `
identity:
  name: "Jane Doe"
  title: "Senior Backend Engineer"
public_profile:
  summary: "8 years building distributed systems in Go."
skills:
  - Go
  - Kubernetes
  - PostgreSQL
preferences:
  remote: true
  min_salary: 150000
restricted:
  current_salary:
    value: 145000
    approval_required: true
  references:
    value: "available on request, contact via email"
    never_auto_send: true
`

func writeTestProfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return path
}

func TestLoad_PublicProfile_OmitsRestricted(t *testing.T) {
	path := writeTestProfile(t, testYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, err := p.PublicProfile(555)
	if err != nil {
		t.Fatalf("public profile: %v", err)
	}
	if _, ok := out["restricted"]; ok {
		t.Fatalf("restricted section leaked into PublicProfile output: %+v", out)
	}
	identity, ok := out["identity"].(map[string]any)
	if !ok || identity["name"] != "Jane Doe" {
		t.Fatalf("identity = %+v, want name Jane Doe", out["identity"])
	}
	skills, ok := out["skills"].([]string)
	if !ok || len(skills) != 3 {
		t.Fatalf("skills = %+v, want 3 entries", out["skills"])
	}
	prefs, ok := out["preferences"].(map[string]any)
	if !ok || prefs["remote"] != true {
		t.Fatalf("preferences = %+v, want remote=true", out["preferences"])
	}
}

func TestParseJSON_StrictSafetyMarkers(t *testing.T) {
	if _, err := ParseJSON([]byte(`{"restricted":{"salary":{"value":"secret","never_auto_sent":true}}}`)); err == nil {
		t.Fatal("misspelled restricted marker was accepted")
	}
	for _, raw := range []string{
		`{"restricted":{"salary":{"value":"secret","never_auto_send":true}},"restricted":{}}`,
		`{"restricted":{"salary":{"value":"secret","never_auto_send":true,"never_auto_send":false}}}`,
	} {
		if _, err := ParseJSON([]byte(raw)); err == nil {
			t.Fatalf("duplicate-key document %q was accepted", raw)
		}
	}
	for _, raw := range []string{"null", "[]", `{}` + `{}`} {
		if _, err := ParseJSON([]byte(raw)); err == nil {
			t.Fatalf("invalid document %q was accepted", raw)
		}
	}
}

func TestParseJSON_PreservesRestrictedNumericLiterals(t *testing.T) {
	d, err := ParseJSON([]byte(`{
		"restricted":{
			"salary":{"value":1000000,"never_auto_send":true},
			"account":{"value":9007199254740993,"never_auto_send":true}
		}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, tc := range []struct {
		text string
		key  string
	}{
		{text: "salary is 1000000", key: "salary"},
		{text: "account 9007199254740993", key: "account"},
	} {
		key, never, _, matched := matchRestricted(d, tc.text)
		if !matched || key != tc.key || !never {
			t.Fatalf("match %q = key=%q never=%v matched=%v", tc.text, key, never, matched)
		}
	}
}

func TestTenantProvider_IsolatesPublicAndRestrictedData(t *testing.T) {
	const aliceID int64 = 11
	const bobID int64 = 22
	provider := NewTenantProvider(fakeTenantStore{
		aliceID: []byte(`{
			"identity":{"name":"Alice"},
			"restricted":{"secret":{"value":"ALICE-SECRET","never_auto_send":true}}
		}`),
		bobID: []byte(`{
			"identity":{"name":"Bob"},
			"restricted":{"secret":{"value":"BOB-SECRET","approval_required":true}}
		}`),
	})
	ctx := context.Background()

	alice, err := provider.PublicProfile(ctx, aliceID, 555)
	if err != nil {
		t.Fatalf("alice public profile: %v", err)
	}
	bob, err := provider.PublicProfile(ctx, bobID, 555)
	if err != nil {
		t.Fatalf("bob public profile: %v", err)
	}
	if alice["identity"].(map[string]any)["name"] != "Alice" {
		t.Fatalf("alice profile = %+v", alice)
	}
	if bob["identity"].(map[string]any)["name"] != "Bob" {
		t.Fatalf("bob profile = %+v", bob)
	}
	if _, ok := alice["restricted"]; ok {
		t.Fatalf("restricted data leaked: %+v", alice)
	}

	key, never, approval, matched, err := provider.MatchRestricted(ctx, aliceID, "value ALICE-SECRET")
	if err != nil || !matched || key != "secret" || !never || approval {
		t.Fatalf("alice restriction = key=%q never=%v approval=%v matched=%v err=%v",
			key, never, approval, matched, err)
	}
	_, _, _, matched, err = provider.MatchRestricted(ctx, bobID, "value ALICE-SECRET")
	if err != nil {
		t.Fatalf("bob restriction: %v", err)
	}
	if matched {
		t.Fatal("Alice restricted value matched in Bob's tenant")
	}
	if _, err := provider.PublicProfile(ctx, 999, 555); !errors.Is(err, errTenantProfileMissing) {
		t.Fatalf("missing tenant err = %v", err)
	}
}

func TestLoad_RestrictedField_AccessibleOnlyViaDedicatedMethod(t *testing.T) {
	path := writeTestProfile(t, testYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	f, ok := p.RestrictedField("current_salary")
	if !ok {
		t.Fatal("current_salary not found")
	}
	if !f.ApprovalRequired {
		t.Fatal("approval_required = false, want true")
	}
	if f.NeverAutoSend {
		t.Fatal("never_auto_send = true, want false for current_salary")
	}

	refs, ok := p.RestrictedField("references")
	if !ok {
		t.Fatal("references not found")
	}
	if !refs.NeverAutoSend {
		t.Fatal("references.never_auto_send = false, want true")
	}

	if _, ok := p.RestrictedField("does_not_exist"); ok {
		t.Fatal("unknown restricted key reported found")
	}
}

func TestLoad_MissingFile_Errors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing profile file")
	}
}

func TestLoad_InvalidYAML_Errors(t *testing.T) {
	path := writeTestProfile(t, "identity: [this is not a map")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestPublicProfile_EmptySectionsOmitted(t *testing.T) {
	path := writeTestProfile(t, "identity:\n  name: Jane\n")
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, err := p.PublicProfile(0)
	if err != nil {
		t.Fatalf("public profile: %v", err)
	}
	for _, key := range []string{"public_profile", "skills", "preferences", "restricted"} {
		if _, ok := out[key]; ok {
			t.Fatalf("empty section %q present in output: %+v", key, out)
		}
	}
	if _, ok := out["identity"]; !ok {
		t.Fatalf("identity section missing: %+v", out)
	}
}

// TestPublicProfile_NestedYAMLMapsAreJSONMarshalable guards against the P2
// found in review: older YAML decoders decode a nested object into any as
// map[interface{}]interface{}, which encoding/json cannot marshal at all —
// GET /recruiters/{peer} would write a 200 status and then silently emit a
// truncated body the moment its json.Encoder hit that value. A profile with
// nested objects under identity/public_profile/preferences must produce
// output that actually round-trips through json.Marshal.
func TestPublicProfile_NestedYAMLMapsAreJSONMarshalable(t *testing.T) {
	const nestedYAML = `
identity:
  name: "Jane Doe"
  links:
    linkedin: "https://linkedin.com/in/janedoe"
    github: "https://github.com/janedoe"
preferences:
  locations:
    - remote
    - "Berlin, DE"
  compensation:
    currency: USD
    range:
      min: 140000
      max: 180000
`
	path := writeTestProfile(t, nestedYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, err := p.PublicProfile(0)
	if err != nil {
		t.Fatalf("public profile: %v", err)
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal public profile: %v (nested YAML maps not normalized)", err)
	}
	var roundTripped map[string]any
	if err := json.Unmarshal(b, &roundTripped); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}
	identity, ok := roundTripped["identity"].(map[string]any)
	if !ok {
		t.Fatalf("identity missing or wrong type after round-trip: %+v", roundTripped)
	}
	links, ok := identity["links"].(map[string]any)
	if !ok || links["github"] != "https://github.com/janedoe" {
		t.Fatalf("nested links not preserved: %+v", identity)
	}
}

// TestMatchRestricted_FindsValueInText and its "no match" counterpart cover
// the executor's send-time gate: a restricted field's string value appearing
// verbatim in a proposed reply must be caught regardless of never_auto_send
// vs approval_required, and an unrelated draft must not false-positive.
func TestMatchRestricted_FindsValueInText(t *testing.T) {
	path := writeTestProfile(t, testYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	key, neverAutoSend, approvalRequired, matched := p.MatchRestricted(
		"Sure, here are my references: available on request, contact via email")
	if !matched {
		t.Fatal("expected a match on the references restricted field")
	}
	if key != "references" {
		t.Fatalf("key = %q, want references", key)
	}
	if !neverAutoSend {
		t.Fatal("never_auto_send = false, want true")
	}
	if approvalRequired {
		t.Fatal("approval_required = true, want false for references")
	}
}

// TestMatchRestricted_FindsNumericValueInText covers the Codex-flagged gap
// on #307: a non-string restricted value (current_salary: 145000) used to be
// skipped by MatchRestricted entirely — verbatim string values were the only
// ones ever enforced, and nothing else in the codebase called RestrictedField
// to enforce numeric ones by key.
func TestMatchRestricted_FindsNumericValueInText(t *testing.T) {
	path := writeTestProfile(t, testYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	key, _, approvalRequired, matched := p.MatchRestricted("My current comp is 145000 base")
	if !matched {
		t.Fatal("expected a match on the numeric current_salary restricted field")
	}
	if key != "current_salary" {
		t.Fatalf("key = %q, want current_salary", key)
	}
	if !approvalRequired {
		t.Fatal("approval_required = false, want true for current_salary")
	}
}

// TestMatchRestricted_NeverAutoSendWinsOverApprovalRequired covers a Codex
// finding on #307: when a draft echoes TWO restricted fields at once — one
// never_auto_send, one approval_required-only — MatchRestricted must always
// return the never_auto_send field, never the weaker one, regardless of Go's
// unspecified map iteration order. Run in a loop so a build that regresses
// to "return on first match" is caught even though map order varies from
// run to run rather than failing deterministically on any single iteration.
func TestMatchRestricted_NeverAutoSendWinsOverApprovalRequired(t *testing.T) {
	path := writeTestProfile(t, `
restricted:
  current_salary:
    value: 145000
    approval_required: true
  references:
    value: "available on request, contact via email"
    never_auto_send: true
`)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	text := "My current comp is 145000 base, and references: available on request, contact via email"
	for i := 0; i < 50; i++ {
		key, neverAutoSend, _, matched := p.MatchRestricted(text)
		if !matched {
			t.Fatal("expected a match")
		}
		if !neverAutoSend || key != "references" {
			t.Fatalf("iteration %d: got key=%q neverAutoSend=%v, want key=references neverAutoSend=true (the approval_required-only match must not shadow the never_auto_send one)", i, key, neverAutoSend)
		}
	}
}

// TestMatchRestricted_ApprovalRequiredWinsOverUnmarkedField covers a
// follow-up Codex finding on #307: the first fix only special-cased
// never_auto_send, so an approval_required match could still lose to an
// UNMARKED restricted field (both booleans false — tracked for some other
// reason, with no enforcement flag at all) visited first by map iteration.
// restrictedFieldBlocks only inspects approvalRequired when neverAutoSend
// is false, so returning the unmarked match let an approval-gated value
// auto-send with no review at all. approval_required must win over a
// completely unmarked match.
func TestMatchRestricted_ApprovalRequiredWinsOverUnmarkedField(t *testing.T) {
	path := writeTestProfile(t, `
restricted:
  internal_note:
    value: "team-alpha"
  current_salary:
    value: 145000
    approval_required: true
`)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	text := "My current comp is 145000 base, internally tagged team-alpha"
	for i := 0; i < 50; i++ {
		key, neverAutoSend, approvalRequired, matched := p.MatchRestricted(text)
		if !matched {
			t.Fatal("expected a match")
		}
		if neverAutoSend || !approvalRequired || key != "current_salary" {
			t.Fatalf("iteration %d: got key=%q neverAutoSend=%v approvalRequired=%v, want key=current_salary approvalRequired=true (the unmarked field must not shadow the approval_required one)", i, key, neverAutoSend, approvalRequired)
		}
	}
}

// TestLoad_RejectsMisspelledRestrictedFieldMarker covers a Codex finding on
// #307: a misspelled safety marker under a restricted-section entry (e.g.
// never_auto_sent instead of never_auto_send) used to decode silently as an
// ignored unknown key, loading successfully with both real markers
// defaulting to false — the restricted value would still MATCH in
// MatchRestricted, but with no enforcement at all, and nothing would ever
// reveal the typo. Load must now fail loudly instead.
func TestLoad_RejectsMisspelledRestrictedFieldMarker(t *testing.T) {
	path := writeTestProfile(t, `
restricted:
  current_salary:
    value: 145000
    never_auto_sent: true
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected an error for a misspelled restricted-field marker, got nil")
	}
}

func TestMatchRestricted_NoMatchOnUnrelatedText(t *testing.T) {
	path := writeTestProfile(t, testYAML)
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, _, _, matched := p.MatchRestricted("Happy to chat about the role!"); matched {
		t.Fatal("expected no match on unrelated text")
	}
}

func TestReload_PicksUpChangedFile(t *testing.T) {
	path := writeTestProfile(t, "identity:\n  name: Original\n")
	p, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := os.WriteFile(path, []byte("identity:\n  name: Updated\n"), 0o600); err != nil {
		t.Fatalf("rewrite profile: %v", err)
	}
	if err := p.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	out, err := p.PublicProfile(0)
	if err != nil {
		t.Fatalf("public profile: %v", err)
	}
	identity := out["identity"].(map[string]any)
	if identity["name"] != "Updated" {
		t.Fatalf("name = %v, want Updated", identity["name"])
	}
}
