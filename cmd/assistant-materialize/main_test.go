package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

func TestRunWritesParsableDocuments(t *testing.T) {
	out := t.TempDir()
	if err := run(out, ""); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "hr-recruiter-0.1.0.json"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := assistant.ParseMaterialized(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.Definition.Metadata.Name != "hr-recruiter" || !strings.HasPrefix(e.Digest, "sha256:") {
		t.Fatalf("entry = %s %s", e.Definition.Metadata.Name, e.Digest)
	}
	// An output path that cannot be a directory is an error, not a skip.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(blocker, "sub"), ""); err == nil {
		t.Fatal("run succeeded with an unusable output directory")
	}
}
