package profile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
// found in review: yaml.v2 decodes a nested object into any as
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
