package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/mcp"
)

func writeSnapshot(t *testing.T, dir, name string, mutate func(map[string]json.RawMessage)) string {
	t.Helper()
	s, err := mcp.ToolDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(s.Tools)
	}
	raw, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheCommittedSnapshotIsTheCurrentRegistry(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-old", filepath.Join("..", "..", "docs", "tool-descriptors.json"), "-from", "HEAD", "-to", "build"}, &out, &errOut)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var got report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Diff.Empty() || got.From != "HEAD" || got.To != "build" {
		t.Fatalf("report = %+v", got)
	}
}

func TestADroppedToolReadsAsAddedFromThePreviousRelease(t *testing.T) {
	dir := t.TempDir()
	old := writeSnapshot(t, dir, "old.json", func(tools map[string]json.RawMessage) { delete(tools, "list_dialogs") })
	var out, errOut bytes.Buffer
	if code := run([]string{"-old", old, "-from", "0.68.0", "-to", "HEAD"}, &out, &errOut); code != exitOK {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var got report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Diff.Added) != 1 || got.Diff.Added[0] != "list_dialogs" || len(got.Diff.Removed) != 0 || len(got.Diff.Changed) != 0 {
		t.Fatalf("diff = %+v", got.Diff)
	}
}

func TestUsageAndUnreadableInputsAreDistinctFailures(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"-old", "x.json"}, &out, &errOut); code != exitUsage {
		t.Fatalf("missing -from/-to: exit %d", code)
	}
	if code := run([]string{"-old", filepath.Join(t.TempDir(), "absent.json"), "-from", "a", "-to", "b"}, &out, &errOut); code != exitFailed {
		t.Fatalf("absent snapshot: exit %d", code)
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte(`{"schema":"other/v9","surface":{},"tools":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run([]string{"-old", bad, "-from", "a", "-to", "b"}, &out, &errOut); code != exitFailed || !strings.Contains(errOut.String(), "schema") {
		t.Fatalf("foreign schema: exit %d, %s", code, errOut.String())
	}
}
