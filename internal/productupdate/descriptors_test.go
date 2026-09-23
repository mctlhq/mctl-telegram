package productupdate

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

var full = Surface{AppsEnabled: true, ToolFilter: "all"}

func snapshot(t *testing.T, tools ...string) Snapshot {
	t.Helper()
	raw := map[string][]byte{}
	for _, descriptor := range tools {
		var head struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal([]byte(descriptor), &head); err != nil {
			t.Fatal(err)
		}
		raw[head.Name] = []byte(descriptor)
	}
	s, err := NewSnapshot(full, raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

const (
	listDialogs   = `{"name":"list_dialogs","description":"List dialogs.","inputSchema":{"type":"object","properties":{"limit":{"type":"integer","maximum":100}}},"annotations":{"readOnlyHint":true,"destructiveHint":false,"title":"List dialogs"}}`
	sendMessage   = `{"name":"send_message","description":"Send a message.","inputSchema":{"type":"object","properties":{"text":{"type":"string"}}},"annotations":{"readOnlyHint":false,"destructiveHint":false,"title":"Send"}}`
	deleteMessage = `{"name":"delete_messages","description":"Delete messages.","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":false,"destructiveHint":true,"title":"Delete"}}`
)

func compare(t *testing.T, previous, current Snapshot) Diff {
	t.Helper()
	d, err := Compare(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNoOpReleaseIsEmpty(t *testing.T) {
	a := snapshot(t, listDialogs, sendMessage)
	// Same content, different key order and whitespace: still no change.
	b := snapshot(t, sendMessage, `{ "annotations": {"title":"List dialogs","destructiveHint":false,"readOnlyHint":true},
		"inputSchema": {"properties":{"limit":{"maximum":100,"type":"integer"}},"type":"object"},
		"description": "List dialogs.", "name": "list_dialogs" }`)
	d := compare(t, a, b)
	if !d.Empty() {
		t.Fatalf("no-op release reported %+v", d)
	}
}

func TestAddedAndRemovedAreDistinct(t *testing.T) {
	d := compare(t, snapshot(t, listDialogs, sendMessage), snapshot(t, listDialogs, deleteMessage))
	if !reflect.DeepEqual([]string{"delete_messages"}, d.Added) {
		t.Fatalf("added = %v", d.Added)
	}
	if !reflect.DeepEqual([]string{"send_message"}, d.Removed) {
		t.Fatalf("removed = %v", d.Removed)
	}
	if len(d.Changed) != 0 {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

// A rename is not inferred: one removal and one addition, never a "change"
// asserting the two are the same capability.
func TestRenameIsARemovalAndAnAddition(t *testing.T) {
	renamed := strings.Replace(sendMessage, `"send_message"`, `"send_text"`, 1)
	d := compare(t, snapshot(t, sendMessage), snapshot(t, renamed))
	if !reflect.DeepEqual([]string{"send_text"}, d.Added) || !reflect.DeepEqual([]string{"send_message"}, d.Removed) {
		t.Fatalf("rename reported as %+v", d)
	}
}

func TestSchemaOnlyChange(t *testing.T) {
	wider := strings.Replace(listDialogs, `"maximum":100`, `"maximum":500`, 1)
	d := compare(t, snapshot(t, listDialogs), snapshot(t, wider))
	want := []ToolChange{{Tool: "list_dialogs", Kinds: []string{ChangeSchema}, Fields: []string{"inputSchema"}}}
	if !reflect.DeepEqual(want, d.Changed) {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

// What a tool returns is part of its schema too: an output change is a
// schema change, not "other".
func TestOutputSchemaChangeIsASchemaChange(t *testing.T) {
	before := strings.Replace(listDialogs, `"annotations"`, `"outputSchema":{"type":"object"},"annotations"`, 1)
	after := strings.Replace(listDialogs, `"annotations"`, `"outputSchema":{"type":"object","properties":{"total":{"type":"integer"}}},"annotations"`, 1)
	d := compare(t, snapshot(t, before), snapshot(t, after))
	want := []ToolChange{{Tool: "list_dialogs", Kinds: []string{ChangeSchema}, Fields: []string{"outputSchema"}}}
	if !reflect.DeepEqual(want, d.Changed) {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

func TestAnnotationChangeNamesTheHint(t *testing.T) {
	destructive := strings.Replace(sendMessage, `"destructiveHint":false`, `"destructiveHint":true`, 1)
	d := compare(t, snapshot(t, sendMessage), snapshot(t, destructive))
	want := []ToolChange{{
		Tool: "send_message", Kinds: []string{ChangeAnnotations},
		Fields: []string{"annotations"}, Annotations: []string{"destructiveHint"},
	}}
	if !reflect.DeepEqual(want, d.Changed) {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

func TestTextAndOtherChangesAreSeparateKinds(t *testing.T) {
	changed := strings.Replace(sendMessage, `"Send a message."`, `"Send a text message."`, 1)
	changed = strings.Replace(changed, `{"name"`, `{"_meta":{"ui":{"resourceUri":"ui://x"}},"name"`, 1)
	d := compare(t, snapshot(t, sendMessage), snapshot(t, changed))
	want := []ToolChange{{Tool: "send_message", Kinds: []string{ChangeOther, ChangeText}, Fields: []string{"_meta", "description"}}}
	if !reflect.DeepEqual(want, d.Changed) {
		t.Fatalf("changed = %+v", d.Changed)
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	a := snapshot(t, listDialogs, sendMessage)
	b := snapshot(t, deleteMessage, strings.Replace(listDialogs, `"maximum":100`, `"maximum":1`, 1))
	first, _ := json.Marshal(compare(t, a, b))
	for i := 0; i < 20; i++ {
		again, _ := json.Marshal(compare(t, a, b))
		if !bytes.Equal(first, again) {
			t.Fatalf("diff differs between runs:\n%s\n%s", first, again)
		}
	}
}

func TestDifferentSurfacesOrSchemasAreRefused(t *testing.T) {
	a := snapshot(t, listDialogs)
	readOnly := a
	readOnly.Surface = Surface{AppsEnabled: true, ToolFilter: "read-only"}
	if _, err := Compare(a, readOnly); err == nil {
		t.Fatal("diffing a read-only surface against the full one must be refused")
	}
	other := a
	other.Schema = "something/v2"
	if _, err := Compare(a, other); err == nil {
		t.Fatal("diffing snapshots of different schemas must be refused")
	}
}

func TestSnapshotRoundTripsAndRefusesAMisnamedDescriptor(t *testing.T) {
	s := snapshot(t, listDialogs, sendMessage)
	raw, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := back.Marshal()
	if !bytes.Equal(raw, again) {
		t.Fatalf("round trip changed bytes:\n%s\n%s", raw, again)
	}
	if _, err := NewSnapshot(full, map[string][]byte{"other_name": []byte(listDialogs)}); err == nil {
		t.Fatal("a descriptor filed under another tool's name must be refused")
	}
	if _, err := ParseSnapshot([]byte(`{"schema":"x","surface":{},"tools":{}}`)); err == nil {
		t.Fatal("an unknown schema must be refused")
	}
}

// Numbers survive exactly: 4096 must not become 4096.0, or every release
// would report a schema change nobody made.
func TestCanonicalKeepsNumbersAsWritten(t *testing.T) {
	got, err := Canonical([]byte(`{"b":4096,"a":1.50}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1.50,"b":4096}` {
		t.Fatalf("canonical = %s", got)
	}
	if _, err := Canonical([]byte(`{} {}`)); err == nil {
		t.Fatal("trailing data must be refused")
	}
}
