package mcp

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
)

var updateDescriptors = flag.Bool("update-descriptors", false, "rewrite docs/tool-descriptors.json from the registry")

var descriptorsFile = filepath.Join("..", "..", "docs", "tool-descriptors.json")

// TestToolDescriptorsSnapshotMatchesRegistry holds docs/tool-descriptors.json
// to the tools the server registers, byte for byte. The committed file is
// what a release is diffed against (`git show <tag>:docs/tool-descriptors.json`),
// so a tool change that did not update it would ship with no evidence that
// it happened.
func TestToolDescriptorsSnapshotMatchesRegistry(t *testing.T) {
	snapshot, err := ToolDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	want, err := snapshot.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if *updateDescriptors {
		if err := os.WriteFile(descriptorsFile, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(descriptorsFile)
	if err != nil {
		t.Fatalf("%v (generate it with: go test ./internal/mcp -run TestToolDescriptorsSnapshotMatchesRegistry -update-descriptors)", err)
	}
	if !bytes.Equal(got, want) {
		committed, parseErr := productupdate.ParseSnapshot(got)
		if parseErr != nil {
			t.Fatalf("docs/tool-descriptors.json is unreadable: %v", parseErr)
		}
		diff, cmpErr := productupdate.Compare(committed, snapshot)
		t.Fatalf("docs/tool-descriptors.json is stale (diff %+v, err %v); regenerate with: "+
			"go test ./internal/mcp -run TestToolDescriptorsSnapshotMatchesRegistry -update-descriptors", diff, cmpErr)
	}
}

// TestToolDescriptorsAreDeterministic: two enumerations give the same bytes.
// A descriptor that carried a clock, a map iteration order or the build
// version would make every release look like it changed every tool.
func TestToolDescriptorsAreDeterministic(t *testing.T) {
	first, err := ToolDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	second, err := (&Server{
		ToolFilter: DescriptorSurface.ToolFilter, AppsEnabled: DescriptorSurface.AppsEnabled, Version: "9.9.9",
	}).descriptors()
	if err != nil {
		t.Fatal(err)
	}
	a, err := first.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("tool descriptors differ between two enumerations (or depend on the server version)")
	}
	if len(first.Tools) == 0 {
		t.Fatal("no tools enumerated")
	}
}

// TestToolDescriptorsAreTheFullSurface: the snapshot's label is what was
// enumerated. The committed file claims the full surface, so it must hold
// strictly more tools than a read-only server, and every one of them.
func TestToolDescriptorsAreTheFullSurface(t *testing.T) {
	full, err := ToolDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	if full.Surface != DescriptorSurface {
		t.Fatalf("snapshot labelled %+v, want %+v", full.Surface, DescriptorSurface)
	}
	readOnly, err := (&Server{ToolFilter: "read-only", AppsEnabled: DescriptorSurface.AppsEnabled}).descriptors()
	if err != nil {
		t.Fatal(err)
	}
	if readOnly.Surface.ToolFilter != "read-only" {
		t.Fatalf("read-only snapshot labelled %+v", readOnly.Surface)
	}
	if len(full.Tools) <= len(readOnly.Tools) {
		t.Fatalf("full surface has %d tools, read-only %d", len(full.Tools), len(readOnly.Tools))
	}
	for name := range readOnly.Tools {
		if _, ok := full.Tools[name]; !ok {
			t.Fatalf("read-only tool %s is missing from the full surface", name)
		}
	}
	// The zero-valued filter is the same surface under the same label.
	zero, err := (&Server{AppsEnabled: DescriptorSurface.AppsEnabled}).descriptors()
	if err != nil {
		t.Fatal(err)
	}
	if zero.Surface != DescriptorSurface {
		t.Fatalf("zero-valued ToolFilter labelled %+v, want %+v", zero.Surface, DescriptorSurface)
	}
	unfiltered := (&Server{ToolFilter: "", AppsEnabled: true}).newMCPServer().ListTools()
	if len(unfiltered) != len(full.Tools) {
		t.Fatalf("snapshot has %d tools, the unfiltered server registers %d", len(full.Tools), len(unfiltered))
	}
}
