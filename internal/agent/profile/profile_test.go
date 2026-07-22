package profile

import (
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
