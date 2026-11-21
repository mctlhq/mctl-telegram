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
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var updatePin = flag.Bool("update-pin", false, "rewrite internal/pa/catalog/pin.json's server-derived fields from the upstream descriptors")

const regenerateHint = "go test ./internal/pa/catalog -run TestPinMatchesUpstream -update-pin"

// upstreamPages returns the tools/list result page each pinned server's
// fields are derived from:
//
//   - tg: docs/tool-descriptors.json, which TestToolDescriptorsSnapshotMatchesRegistry
//     in internal/mcp keeps equal to the registered tools. A change to a
//     pinned tg tool therefore fails that test until the snapshot is
//     regenerated, and then this one until the pin is.
//   - alice: testdata/alice.tools.json, the tools/list of mctl-alice at the
//     commit the pin's "upstream" field names.
func upstreamPages(t *testing.T) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "tool-descriptors.json"))
	if err != nil {
		t.Fatalf("read tg descriptors: %v", err)
	}
	var snap struct {
		Tools map[string]json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("decode tg descriptors: %v", err)
	}
	if len(snap.Tools) == 0 {
		t.Fatal("tg descriptors: no tools (a failed read is not an empty surface)")
	}
	names := make([]string, 0, len(snap.Tools))
	for n := range snap.Tools {
		names = append(names, n)
	}
	slices.Sort(names)
	tools := make([]json.RawMessage, 0, len(names))
	for _, n := range names {
		tools = append(tools, snap.Tools[n])
	}
	tgPage, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		t.Fatal(err)
	}
	alicePage, err := os.ReadFile(filepath.Join("testdata", "alice.tools.json"))
	if err != nil {
		t.Fatalf("read alice upstream: %v", err)
	}
	return map[string][]byte{"tg": tgPage, "alice": alicePage}
}

// regeneratePin recomputes every server-derived field of the pin from the
// upstream pages and keeps the hand-authored policy fields as they are.
// Which tools are pinned is hand-authored too: the generator never adds one.
func regeneratePin(t *testing.T, current []byte, upstream map[string][]byte) []byte {
	t.Helper()
	var p Pin
	if err := json.Unmarshal(current, &p); err != nil {
		t.Fatalf("decode pin.json: %v", err)
	}
	for server, sp := range p.Servers {
		page, ok := upstream[server]
		if !ok {
			t.Fatalf("pin server %s has no upstream source in this test", server)
		}
		var wp struct {
			Tools []wireTool `json:"tools"`
		}
		if err := json.Unmarshal(page, &wp); err != nil {
			t.Fatalf("decode upstream %s: %v", server, err)
		}
		byName := map[string]wireTool{}
		for _, w := range wp.Tools {
			byName[*w.Name] = w
		}
		for name, pt := range sp.Tools {
			w, ok := byName[name]
			if !ok {
				t.Fatalf("pinned tool %s/%s does not exist upstream", server, name)
			}
			schema, err := canonicalObject(w.InputSchema)
			if err != nil {
				t.Fatalf("%s/%s schema: %v", server, name, err)
			}
			ann, err := canonicalAnnotations(w.Annotations)
			if err != nil {
				t.Fatalf("%s/%s annotations: %v", server, name, err)
			}
			desc := ""
			if w.Description != nil {
				desc = *w.Description
			}
			pt.DescriptionSHA256 = sha256Hex([]byte(desc))
			pt.InputSchema = schema
			pt.InputSchemaSHA256 = sha256Hex(schema)
			pt.Annotations = ann
			sp.Tools[name] = pt
		}
		p.Servers[server] = sp
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(&p); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestPinMatchesUpstream is the drift gate: a change upstream to a pinned
// tool's schema, description or annotations fails CI until pin.json (and
// pin_phase2.json, which no runtime code loads) is regenerated, which makes
// the update a reviewed diff (ADR 0007 pattern).
func TestPinMatchesUpstream(t *testing.T) {
	for _, file := range []string{"pin.json", "pin_phase2.json"} {
		t.Run(file, func(t *testing.T) {
			current, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			want := regeneratePin(t, current, upstreamPages(t))
			if *updatePin {
				if err := os.WriteFile(file, want, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			if !bytes.Equal(current, want) {
				t.Fatalf("%s is out of date with its upstream descriptors; regenerate it with:\n  %s\nand review the diff", file, regenerateHint)
			}
		})
	}
}

// TestLoadPin: the committed pin parses, validates and has no write path.
func TestLoadPin(t *testing.T) {
	p, err := LoadPin()
	if err != nil {
		t.Fatalf("LoadPin: %v", err)
	}
	if got := p.ServerNames(); !slices.Equal(got, []string{"alice", "tg"}) {
		t.Fatalf("servers = %v", got)
	}
}

// TestPhase1PinIsExactlyTheThreatModelReadSet pins the pin: the tools of
// threat model T8 "Phase 1 pinned tools", nothing more. Widening the pin
// means changing this list too, in the same reviewed diff.
func TestPhase1PinIsExactlyTheThreatModelReadSet(t *testing.T) {
	p, err := LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		// The tools of the two tg read scopes (#1326 ceiling:
		// telegram:dialogs:read, telegram:messages:read) the threat model
		// allows, plus get_my_identity, which every identity may call.
		// get_unread_messages, get_media and prepare_get_media are excluded.
		"tg":    {"get_messages", "get_my_identity", "list_dialogs", "list_folders", "list_topics", "search_messages"},
		"alice": {"alice_get_device_history", "alice_get_device_state", "alice_get_home_summary", "alice_list_devices"},
	}
	for server, names := range want {
		var got []string
		for n := range p.Servers[server].Tools {
			got = append(got, n)
		}
		slices.Sort(got)
		if !slices.Equal(got, names) {
			t.Errorf("%s pins %v, want %v", server, got, names)
		}
	}
	for _, sp := range p.Servers {
		for _, n := range []string{"alice_say_phrase", "alice_send_command", "get_unread_messages", "get_media", "prepare_get_media", "send_message"} {
			if _, ok := sp.Tools[n]; ok {
				t.Errorf("%s must not be in the Phase 1 pin", n)
			}
		}
	}
}

func validTool() PinnedTool {
	schema := json.RawMessage(`{"type":"object"}`)
	c, _ := canonicalObject(schema)
	return PinnedTool{
		Tier: TierAuto, Class: ClassRead, Lowerable: LowerableNever,
		CatalogDescription: "Reads a thing.",
		DescriptionSHA256:  sha256Hex([]byte("server text")),
		InputSchema:        schema,
		InputSchemaSHA256:  sha256Hex(c),
		Annotations:        json.RawMessage(`{"readOnlyHint":true}`),
	}
}

func pinWith(name string, pt PinnedTool) *Pin {
	return &Pin{Schema: PinSchema, Servers: map[string]ServerPin{"alice": {Tools: map[string]PinnedTool{name: pt}}}}
}

// TestPinPolicyRules: the per-tool policy of threat model T6 cannot be
// relaxed by editing the pin. say_phrase and send_command are disclosure
// and never lowerable; disclosure is never lowerable; reads are auto.
func TestPinPolicyRules(t *testing.T) {
	approve := func(c Class, l Lowerable) PinnedTool {
		pt := validTool()
		pt.Tier, pt.Class, pt.Lowerable = TierApprove, c, l
		pt.Annotations = json.RawMessage(`{}`)
		return pt
	}
	cases := []struct {
		name string
		tool string
		pt   PinnedTool
		ok   bool
	}{
		{"valid read", "alice_list_devices", validTool(), true},
		{"say_phrase lowerable", "alice_say_phrase", approve(ClassDisclosure, LowerableYes), false},
		{"say_phrase as write", "alice_say_phrase", approve(ClassWrite, LowerableNever), false},
		{"say_phrase disclosure never", "alice_say_phrase", approve(ClassDisclosure, LowerableNever), true},
		{"send_command conditional", "alice_send_command", approve(ClassDisclosure, LowerableConditional), false},
		{"control_room lowerable", "alice_control_room", approve(ClassWrite, LowerableYes), false},
		{"any disclosure lowerable", "some_disclosure", approve(ClassDisclosure, LowerableYes), false},
		{"read approve", "alice_list_devices", func() PinnedTool { p := validTool(); p.Tier = TierApprove; return p }(), false},
		{"write auto", "alice_set_light", func() PinnedTool { p := approve(ClassWrite, LowerableYes); p.Tier = TierAuto; return p }(), false},
		{"read annotated not read-only", "x_read", func() PinnedTool {
			p := validTool()
			p.Annotations = json.RawMessage(`{"readOnlyHint":false}`)
			return p
		}(), false},
		// The hint is read by its exact name; a case variant of it is
		// refused, not ignored and not read as the hint.
		{"read annotated ReadOnlyHint", "x_read", func() PinnedTool {
			p := validTool()
			p.Annotations = json.RawMessage(`{"ReadOnlyHint":true}`)
			return p
		}(), false},
		{"read annotated READONLYHINT false", "x_read", func() PinnedTool {
			p := validTool()
			p.Annotations = json.RawMessage(`{"READONLYHINT":false}`)
			return p
		}(), false},
		{"read annotated readOnlyHint not a bool", "x_read", func() PinnedTool {
			p := validTool()
			p.Annotations = json.RawMessage(`{"readOnlyHint":"yes"}`)
			return p
		}(), false},
		{"read with other annotations only", "x_read", func() PinnedTool {
			p := validTool()
			p.Annotations = json.RawMessage(`{"title":"x"}`)
			return p
		}(), true},
		{"schema hash mismatch", "x_read", func() PinnedTool {
			p := validTool()
			p.InputSchema = json.RawMessage(`{"type":"object","x":1}`)
			return p
		}(), false},
		{"empty catalog description", "x_read", func() PinnedTool { p := validTool(); p.CatalogDescription = " "; return p }(), false},
		{"bad tier", "x_read", func() PinnedTool { p := validTool(); p.Tier = "never"; return p }(), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := pinWith(c.tool, c.pt).Validate()
			if c.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !c.ok && !errors.Is(err, ErrInvalidPin) {
				t.Fatalf("want ErrInvalidPin, got %v", err)
			}
		})
	}
}

// TestValidatePhase1RefusesAWrite: a valid write entry is still refused by
// the Phase 1 loader, so no write path can be pinned in Phase 1.
func TestValidatePhase1RefusesAWrite(t *testing.T) {
	pt := validTool()
	pt.Tier, pt.Class, pt.Lowerable = TierApprove, ClassWrite, LowerableYes
	pt.Annotations = json.RawMessage(`{}`)
	p := pinWith("alice_set_light", pt)
	if err := p.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := p.ValidatePhase1(); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("ValidatePhase1 = %v, want ErrInvalidPin", err)
	}
}

// TestParsePinRefusesUnknownFields: a misspelt policy field fails instead of
// being ignored.
func TestParsePinRefusesUnknownFields(t *testing.T) {
	raw := strings.Replace(string(pinJSON), `"lowerable"`, `"lowerabel"`, 1)
	if _, err := ParsePin([]byte(raw)); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("ParsePin = %v, want ErrInvalidPin", err)
	}
}

// TestParsePinRefusesTrailingData: only a clean EOF ends the pin. A stray
// closing bracket is the case dec.More() let through (#1331 follow-up).
func TestParsePinRefusesTrailingData(t *testing.T) {
	if _, err := ParsePin(pinJSON); err != nil {
		t.Fatalf("committed pin: %v", err)
	}
	if _, err := ParsePin(append(append([]byte{}, pinJSON...), "\n\t "...)); err != nil {
		t.Fatalf("trailing whitespace refused: %v", err)
	}
	for _, tail := range []string{"]", "}", "{}", "null", "x", ",{}"} {
		raw := append(append([]byte{}, pinJSON...), tail...)
		if _, err := ParsePin(raw); !errors.Is(err, ErrInvalidPin) {
			t.Errorf("trailing %q: ParsePin = %v, want ErrInvalidPin", tail, err)
		}
	}
}

// TestCommittedPinAcceptsItsUpstream: the committed pin, observed against
// its own upstream listings, makes every pinned tool usable. This is the
// "green on a converged input" half of the drift detector; surface_test.go
// holds the mutations.
func TestCommittedPinAcceptsItsUpstream(t *testing.T) {
	p, err := LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for server, page := range upstreamPages(t) {
		s := p.Observe(server, [][]byte{page}, nil, now)
		tools, err := s.ModelTools(now)
		if err != nil {
			t.Fatalf("%s: %v", server, err)
		}
		if len(tools) != len(p.Servers[server].Tools) {
			t.Fatalf("%s: %d usable tools, want %d; denied %v", server, len(tools), len(p.Servers[server].Tools), s.Denied())
		}
	}
}
