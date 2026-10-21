package mcp

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/toolprofile"
)

var updateDescriptors = flag.Bool("update-descriptors", false, "rewrite docs/tool-descriptors.json and the per-profile snapshots from the registry")

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

// TestProfileDescriptorSnapshotsMatchRegistry holds each
// docs/tool-descriptors.<profile>.json to what a caller bound to that profile
// is listed, byte for byte, as the full snapshot is held to the registry
// (design: core-profiles, decision 7).
func TestProfileDescriptorSnapshotsMatchRegistry(t *testing.T) {
	for _, name := range toolprofile.Names() {
		t.Run(name, func(t *testing.T) {
			snapshot, err := ProfileToolDescriptors(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := snapshot.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", ProfileDescriptorsFile(name))
			if *updateDescriptors {
				if err := os.WriteFile(path, want, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (generate it with: go test ./internal/mcp -run TestProfileDescriptorSnapshotsMatchRegistry -update-descriptors)", err)
			}
			if !bytes.Equal(got, want) {
				committed, parseErr := productupdate.ParseSnapshot(got)
				if parseErr != nil {
					t.Fatalf("%s is unreadable: %v", path, parseErr)
				}
				diff, cmpErr := productupdate.Compare(committed, snapshot)
				t.Fatalf("%s is stale (diff %+v, err %v); regenerate with: "+
					"go test ./internal/mcp -run TestProfileDescriptorSnapshotsMatchRegistry -update-descriptors", path, diff, cmpErr)
			}
		})
	}
}

// TestProfileDescriptorsAreTheProfilesView: a profile snapshot lists exactly
// the profile's tools -- every one, so no scope the enumeration lacked hid a
// tool -- labelled with the profile, and shows each tool with the profile's
// rules applied rather than as the full surface does.
func TestProfileDescriptorsAreTheProfilesView(t *testing.T) {
	full, err := ToolDescriptors()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range toolprofile.Names() {
		p, _ := toolprofile.Lookup(name)
		snap, err := ProfileToolDescriptors(name)
		if err != nil {
			t.Fatal(err)
		}
		if snap.Surface.Profile != name || snap.Surface.ToolFilter != DescriptorSurface.ToolFilter || snap.Surface.AppsEnabled != DescriptorSurface.AppsEnabled {
			t.Fatalf("%s: snapshot labelled %+v", name, snap.Surface)
		}
		if len(snap.Tools) != len(p.Tools) {
			t.Fatalf("%s: snapshot has %d tools, the profile lists %d", name, len(snap.Tools), len(p.Tools))
		}
		for tool, rule := range p.Tools {
			got, ok := snap.Tools[tool]
			if !ok {
				t.Fatalf("%s: profile tool %s missing from its snapshot", name, tool)
			}
			ruled := len(rule.Required) > 0 || len(rule.Forbidden) > 0 || rule.LimitMax != 0 || rule.LimitDefault != 0
			if same := bytes.Equal(got, full.Tools[tool]); ruled == same {
				t.Fatalf("%s: tool %s has rules=%v but its descriptor equals the full one=%v", name, tool, ruled, same)
			}
		}
	}
	if _, err := ProfileToolDescriptors("no-such-profile"); err == nil {
		t.Fatal("an unknown profile was enumerated")
	}
}

// TestNoStrayProfileSnapshots: every docs/tool-descriptors.<x>.json is a
// profile this build knows. A snapshot left behind by a removed or renamed
// profile would otherwise sit in the tree, held to nothing.
func TestNoStrayProfileSnapshots(t *testing.T) {
	matches, err := filepath.Glob(filepath.Join("..", "..", "docs", "tool-descriptors.*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, m := range matches {
		found = append(found, strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "tool-descriptors."), ".json"))
	}
	slices.Sort(found)
	want := slices.Clone(toolprofile.Names())
	slices.Sort(want)
	if !slices.Equal(found, want) {
		t.Fatalf("profile snapshots in docs/ %v, profiles %v", found, want)
	}
}
