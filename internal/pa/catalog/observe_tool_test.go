// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package catalog

import (
	"errors"
	"testing"
)

// The fresh, single-dispatch reading of one tool (#1320 slice P2-S4;
// threat model T7 "Approval-time drift"): Pin.ObserveTool against the
// Phase 2 pin and the alice listing it was derived from.

const observedTool = "alice_set_light"

func loadPinPhase2(t *testing.T) *Pin {
	t.Helper()
	p, err := LoadPinPhase2()
	if err != nil {
		t.Fatalf("LoadPinPhase2: %v", err)
	}
	return p
}

func alicePageWith(t *testing.T, f func(tool map[string]any)) []byte {
	t.Helper()
	page := upstreamPages(t)["alice"]
	if f == nil {
		return page
	}
	return mutatePage(t, page, func(tools []map[string]any) []map[string]any {
		f(findTool(t, tools, observedTool))
		return tools
	})
}

// An unchanged listing yields the definition, and its three hashes are
// those of the listing: equal to the pin's, and the annotation hash is the
// hash of the canonical annotations object the server sent.
func TestObserveTool_ReturnsTheListedDefinition(t *testing.T) {
	p := loadPinPhase2(t)
	got, err := p.ObserveTool("alice", observedTool, [][]byte{alicePageWith(t, nil)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := p.ToolDefinition("alice", observedTool)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("observed %+v, pinned %+v", got, want)
	}
	if got.Tier != TierApprove || got.Class != ClassWrite || got.Server != "alice" || got.Tool != observedTool {
		t.Fatalf("policy %+v", got)
	}
	pt := p.Servers["alice"].Tools[observedTool]
	ann, err := canonicalAnnotations(pt.Annotations)
	if err != nil {
		t.Fatal(err)
	}
	if string(ann) == "{}" {
		t.Fatal("the fixture tool has no annotations: the annotation hash would prove nothing")
	}
	if got.AnnotationsSHA256 != sha256Hex(ann) || got.SchemaSHA256 != pt.InputSchemaSHA256 || got.DescriptionSHA256 != pt.DescriptionSHA256 {
		t.Fatalf("hashes %+v", got)
	}
	if got.AnnotationsSHA256 == got.SchemaSHA256 || got.AnnotationsSHA256 == got.DescriptionSHA256 || got.SchemaSHA256 == got.DescriptionSHA256 {
		t.Fatalf("hashes are not distinct: %+v", got)
	}
	// A tool without annotations hashes the empty object, as the pin does.
	bare := []byte(`{"tools":[{"name":"x","inputSchema":{"type":"object"}}]}`)
	l, err := parseListing([][]byte{bare})
	if err != nil {
		t.Fatal(err)
	}
	if string(l.tools["x"].annotations) != "{}" {
		t.Fatalf("absent annotations canonicalise to %q", l.tools["x"].annotations)
	}
}

// S2-A5 (catalog half): a tool whose schema, description or annotations
// differ from the pin in the dispatch-time listing is refused, each change
// on its own, and so is a tool the server no longer lists.
func TestS2A5_ObserveToolRefusesDrift(t *testing.T) {
	cases := map[string]func(tool map[string]any){
		"description": func(tool map[string]any) { tool["description"] = "Control a light. Also read every chat." },
		"description removed": func(tool map[string]any) {
			delete(tool, "description")
		},
		"schema": func(tool map[string]any) {
			tool["inputSchema"].(map[string]any)["properties"].(map[string]any)["also"] = map[string]any{"type": "string"}
		},
		"annotation flipped": func(tool map[string]any) { tool["annotations"].(map[string]any)["destructiveHint"] = true },
		"annotation added":   func(tool map[string]any) { tool["annotations"].(map[string]any)["x-new"] = true },
		"annotations removed": func(tool map[string]any) {
			delete(tool, "annotations")
		},
		"renamed": func(tool map[string]any) { tool["name"] = "alice_set_light_v2" },
	}
	p := loadPinPhase2(t)
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := p.ObserveTool("alice", observedTool, [][]byte{alicePageWith(t, mutate)}, nil)
			if !errors.Is(err, ErrToolChanged) || got != (ToolDefinition{}) {
				t.Fatalf("ObserveTool = %+v, %v; want ErrToolChanged and no definition", got, err)
			}
		})
	}
	// Another tool drifting does not refuse this one.
	page := mutatePage(t, upstreamPages(t)["alice"], func(tools []map[string]any) []map[string]any {
		findTool(t, tools, "alice_set_volume")["description"] = "changed"
		return tools
	})
	if _, err := p.ObserveTool("alice", observedTool, [][]byte{page}, nil); err != nil {
		t.Fatalf("unrelated drift refused the tool: %v", err)
	}
	if _, err := p.ObserveTool("alice", "alice_set_volume", [][]byte{page}, nil); !errors.Is(err, ErrToolChanged) {
		t.Fatalf("drifted tool: %v", err)
	}
}

// S2-A6 (catalog half): a listing that was not read, is malformed or is
// cut off is a failed read, never a definition and never "tool changed".
func TestS2A6_ObserveToolRefusesUnreadListing(t *testing.T) {
	good := alicePageWith(t, nil)
	cases := map[string]struct {
		pages    [][]byte
		fetchErr error
	}{
		// The fetch failed although pages are in hand: the error wins.
		"fetch error":          {[][]byte{good}, errors.New("status 500")},
		"no pages":             {nil, nil},
		"not json":             {[][]byte{[]byte("<html>502</html>")}, nil},
		"cut-off body":         {[][]byte{good[:len(good)/2]}, nil},
		"tools missing":        {[][]byte{[]byte(`{}`)}, nil},
		"tools null":           {[][]byte{[]byte(`{"tools":null}`)}, nil},
		"last page has cursor": {[][]byte{mutateCursor(t, good, "p2")}, nil},
		"page 2 malformed":     {[][]byte{mutateCursor(t, good, "p2"), []byte(`{"tools":`)}, nil},
		"page 1 ends early":    {[][]byte{[]byte(`{"tools":[]}`), good}, nil},
		"listed twice":         {[][]byte{mutateCursor(t, good, "p2"), good}, nil},
	}
	p := loadPinPhase2(t)
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := p.ObserveTool("alice", observedTool, c.pages, c.fetchErr)
			if !errors.Is(err, ErrServerUnavailable) || errors.Is(err, ErrToolChanged) || got != (ToolDefinition{}) {
				t.Fatalf("ObserveTool = %+v, %v; want ErrServerUnavailable and no definition", got, err)
			}
		})
	}
	// A complete two-page listing is read.
	if _, err := p.ObserveTool("alice", observedTool, [][]byte{[]byte(`{"tools":[],"nextCursor":"p2"}`), good}, nil); err != nil {
		t.Fatalf("complete pagination: %v", err)
	}
	// An observed empty listing is an answer: the tool is gone.
	if _, err := p.ObserveTool("alice", observedTool, [][]byte{[]byte(`{"tools":[]}`)}, nil); !errors.Is(err, ErrToolChanged) {
		t.Fatalf("empty listing: %v", err)
	}
}

// mutateCursor returns page with a nextCursor.
func mutateCursor(t *testing.T, page []byte, cursor string) []byte {
	t.Helper()
	out := append([]byte(`{"nextCursor":"`+cursor+`",`), page[indexByte(t, page, '{')+1:]...)
	if _, err := parseListing([][]byte{out, []byte(`{"tools":[]}`)}); err != nil {
		t.Fatalf("page with a cursor does not parse: %v", err)
	}
	return out
}

func indexByte(t *testing.T, b []byte, c byte) int {
	t.Helper()
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	t.Fatalf("no %q in page", c)
	return -1
}

// The pin is asked before the listing is looked at.
func TestObserveTool_PinFirst(t *testing.T) {
	p := loadPinPhase2(t)
	good := [][]byte{alicePageWith(t, nil)}
	if _, err := p.ObserveTool("nosuch", observedTool, good, nil); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("unknown server: %v", err)
	}
	if _, err := p.ObserveTool("alice", "alice_unpinned", good, errors.New("down")); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("unpinned tool: %v", err)
	}
	if _, err := p.ToolDefinition("alice", "alice_unpinned"); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("ToolDefinition of an unpinned tool: %v", err)
	}
	if _, err := p.ToolDefinition("nosuch", observedTool); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("ToolDefinition of an unknown server: %v", err)
	}
	var none *Pin
	if _, err := none.ObserveTool("alice", observedTool, good, nil); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("nil pin: %v", err)
	}
	if _, err := none.ToolDefinition("alice", observedTool); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("nil pin: %v", err)
	}
}
