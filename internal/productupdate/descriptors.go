// Package productupdate holds the deterministic evidence a product update is
// written from (issue-440). A product update may say "a new tool exists" or
// "this tool changed" only when the tool surface of two releases says so; the
// wording can be curated or rewritten later, the facts cannot.
//
// This file is the first half of that evidence: a canonical snapshot of every
// MCP tool descriptor the server registers, and a diff between two snapshots
// that tells added, removed, schema-changed, annotation-changed and
// text-changed tools apart. The snapshot is committed as
// docs/tool-descriptors.json and held to the registry by a test in
// internal/mcp, so the previous release's surface is always
// `git show <tag>:docs/tool-descriptors.json`.
package productupdate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// SnapshotSchema names the snapshot format. A change to what a descriptor
// contains is a new schema, so two snapshots of different schemas are never
// diffed as if they were comparable.
const SnapshotSchema = "mctl-telegram.tool-descriptors/v1"

// Surface records which server configuration a snapshot enumerates. The tool
// set depends on it (ToolFilter drops write tools, AppsEnabled adds a tool and
// the _meta.ui links), so a snapshot says which one it is and two snapshots of
// different surfaces are refused rather than diffed.
type Surface struct {
	AppsEnabled bool   `json:"appsEnabled"`
	ToolFilter  string `json:"toolFilter"`
}

// Snapshot is every registered tool's descriptor, keyed by tool name, exactly
// as tools/list serves it but in canonical JSON (sorted keys, no insignificant
// whitespace inside a descriptor).
type Snapshot struct {
	Schema  string                     `json:"schema"`
	Surface Surface                    `json:"surface"`
	Tools   map[string]json.RawMessage `json:"tools"`
}

// Canonical re-encodes one descriptor so that two descriptors are equal iff
// they say the same thing: object keys sorted, numbers and strings as
// encoding/json writes them, no whitespace. The result is what a snapshot
// stores and what Diff compares.
func Canonical(descriptor []byte) (json.RawMessage, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(descriptor))
	// Numbers stay as written: a schema's "maximum": 4096 must not become
	// 4096.0 on the way through a float.
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode descriptor: %w", err)
	}
	if decoder.More() {
		return nil, fmt.Errorf("decode descriptor: trailing data")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode descriptor: %w", err)
	}
	return encoded, nil
}

// NewSnapshot builds a snapshot from marshalled descriptors keyed by name. The
// name inside each descriptor must match its key: a snapshot whose keys and
// contents disagree would let a diff report a tool under the wrong name.
// A surface with no tools is refused too: diffed against it, a release would
// appear to add every tool it has.
func NewSnapshot(surface Surface, descriptors map[string][]byte) (Snapshot, error) {
	if len(descriptors) == 0 {
		return Snapshot{}, fmt.Errorf("snapshot has no tools")
	}
	tools := make(map[string]json.RawMessage, len(descriptors))
	for name, raw := range descriptors {
		canonical, err := canonicalNamed(name, raw)
		if err != nil {
			return Snapshot{}, err
		}
		tools[name] = canonical
	}
	return Snapshot{Schema: SnapshotSchema, Surface: surface, Tools: tools}, nil
}

// canonicalNamed canonicalises one descriptor and checks it names itself as
// the key it is filed under.
func canonicalNamed(name string, raw []byte) (json.RawMessage, error) {
	canonical, err := Canonical(raw)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	var head struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(canonical, &head); err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	if head.Name != name {
		return nil, fmt.Errorf("tool %s: descriptor names itself %q", name, head.Name)
	}
	return canonical, nil
}

// Marshal is the one serialization of a snapshot: indented at the top level
// for a reviewable diff in a release pull request, one canonical line per
// tool, tools in name order, trailing newline. Each descriptor is
// re-canonicalised on the way out, so a snapshot assembled or edited by hand
// cannot write bytes ParseSnapshot would reject.
func (s Snapshot) Marshal() ([]byte, error) {
	if len(s.Tools) == 0 {
		return nil, fmt.Errorf("snapshot has no tools")
	}
	names := s.names()
	var out bytes.Buffer
	surface, err := json.Marshal(s.Surface)
	if err != nil {
		return nil, fmt.Errorf("encode surface: %w", err)
	}
	schema, err := json.Marshal(s.Schema)
	if err != nil {
		return nil, fmt.Errorf("encode schema: %w", err)
	}
	fmt.Fprintf(&out, "{\n  \"schema\": %s,\n  \"surface\": %s,\n  \"tools\": {", schema, surface)
	for i, name := range names {
		key, err := json.Marshal(name)
		if err != nil {
			return nil, fmt.Errorf("encode tool name: %w", err)
		}
		descriptor, err := canonicalNamed(name, s.Tools[name])
		if err != nil {
			return nil, err
		}
		if i > 0 {
			out.WriteString(",")
		}
		fmt.Fprintf(&out, "\n    %s: %s", key, descriptor)
	}
	out.WriteString("\n  }\n}\n")
	return out.Bytes(), nil
}

// ParseSnapshot reads a snapshot and refuses one this code cannot compare.
func ParseSnapshot(raw []byte) (Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return Snapshot{}, fmt.Errorf("parse snapshot: %w", err)
	}
	if s.Schema != SnapshotSchema {
		return Snapshot{}, fmt.Errorf("snapshot schema %q is not %q", s.Schema, SnapshotSchema)
	}
	descriptors := make(map[string][]byte, len(s.Tools))
	for name, descriptor := range s.Tools {
		descriptors[name] = descriptor
	}
	return NewSnapshot(s.Surface, descriptors)
}

func (s Snapshot) names() []string {
	names := make([]string, 0, len(s.Tools))
	for name := range s.Tools {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Change kinds for a tool present in both snapshots. A tool may carry several.
const (
	// ChangeSchema: inputSchema or outputSchema differs -- what a caller sends
	// or receives changed.
	ChangeSchema = "schema"
	// ChangeAnnotations: a behaviour hint (readOnlyHint, destructiveHint,
	// idempotentHint, openWorldHint, title) differs. A flipped destructiveHint
	// is a material change even when nothing else moved.
	ChangeAnnotations = "annotations"
	// ChangeText: title or description differs.
	ChangeText = "text"
	// ChangeOther: any other descriptor field (_meta, icons, execution...).
	ChangeOther = "other"
)

// ToolChange is one tool whose descriptor differs between two snapshots.
type ToolChange struct {
	Tool string `json:"tool"`
	// Kinds is the sorted set of Change* constants that apply.
	Kinds []string `json:"kinds"`
	// Fields is every top-level descriptor field that differs, sorted.
	Fields []string `json:"fields"`
	// Annotations names each annotation key whose value differs, sorted, so a
	// reviewer sees "destructiveHint" rather than "annotations".
	Annotations []string `json:"annotations,omitempty"`
}

// Diff is the deterministic difference between two tool surfaces. Every list
// is sorted, so the same two snapshots always give the same bytes.
type Diff struct {
	Added   []string     `json:"added"`
	Removed []string     `json:"removed"`
	Changed []ToolChange `json:"changed"`
}

// Empty reports a release that changed no tool: no product update to draft.
func (d Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Compare diffs two snapshots. Snapshots of different schemas or surfaces
// are refused: comparing a read-only surface with a full one would report
// every write tool as removed.
//
// A renamed tool is reported as one removal and one addition. The descriptor
// carries no identity other than its name, and guessing that two tools are
// "the same" would be exactly the inference a product update may not make.
func Compare(previous, current Snapshot) (Diff, error) {
	if previous.Schema != current.Schema {
		return Diff{}, fmt.Errorf("snapshot schemas differ: %q vs %q", previous.Schema, current.Schema)
	}
	if previous.Surface != current.Surface {
		return Diff{}, fmt.Errorf("snapshot surfaces differ: %+v vs %+v", previous.Surface, current.Surface)
	}
	diff := Diff{Added: []string{}, Removed: []string{}, Changed: []ToolChange{}}
	for _, name := range current.names() {
		if _, ok := previous.Tools[name]; !ok {
			diff.Added = append(diff.Added, name)
		}
	}
	for _, name := range previous.names() {
		now, ok := current.Tools[name]
		if !ok {
			diff.Removed = append(diff.Removed, name)
			continue
		}
		change, err := compareTool(name, previous.Tools[name], now)
		if err != nil {
			return Diff{}, err
		}
		if change != nil {
			diff.Changed = append(diff.Changed, *change)
		}
	}
	return diff, nil
}

func compareTool(name string, before, after json.RawMessage) (*ToolChange, error) {
	// Canonicalise both sides first: a Snapshot assembled by hand may hold a
	// pretty-printed descriptor, and whether a tool changed must not depend on
	// its whitespace (mctl-telegram#681).
	before, err := Canonical(before)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	after, err = Canonical(after)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	if bytes.Equal(before, after) {
		return nil, nil
	}
	old, err := fields(before)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	now, err := fields(after)
	if err != nil {
		return nil, fmt.Errorf("tool %s: %w", name, err)
	}
	changed := differingKeys(old, now)
	kinds := map[string]bool{}
	for _, field := range changed {
		switch field {
		case "inputSchema", "outputSchema":
			kinds[ChangeSchema] = true
		case "annotations":
			kinds[ChangeAnnotations] = true
		case "title", "description":
			kinds[ChangeText] = true
		default:
			kinds[ChangeOther] = true
		}
	}
	change := &ToolChange{Tool: name, Fields: changed, Kinds: sortedKeys(kinds)}
	if kinds[ChangeAnnotations] {
		oldAnnotations, _ := old["annotations"].(map[string]any)
		newAnnotations, _ := now["annotations"].(map[string]any)
		change.Annotations = differingKeys(oldAnnotations, newAnnotations)
	}
	return change, nil
}

func fields(descriptor json.RawMessage) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(descriptor))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode descriptor: %w", err)
	}
	return value, nil
}

// differingKeys lists every key present in either map whose value differs,
// sorted. A key present on one side only differs.
func differingKeys(a, b map[string]any) []string {
	keys := map[string]bool{}
	for key := range a {
		keys[key] = true
	}
	for key := range b {
		keys[key] = true
	}
	out := []string{}
	for _, key := range sortedKeys(keys) {
		left, inLeft := a[key]
		right, inRight := b[key]
		if inLeft != inRight || !reflect.DeepEqual(left, right) {
			out = append(out, key)
		}
	}
	return out
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
