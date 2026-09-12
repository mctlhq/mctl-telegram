package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// closedSubschemas walks a decoded JSON schema and returns a JSON pointer for
// every subschema that pins "additionalProperties": false.
//
// Only the boolean form counts. A map-valued additionalProperties describes
// what the extra keys must look like — that is a real constraint someone
// chose, not the reflector's default — so it is left alone.
func closedSubschemas(node any, ptr string) []string {
	var out []string
	switch v := node.(type) {
	case map[string]any:
		if ap, ok := v["additionalProperties"]; ok {
			if closed, isBool := ap.(bool); isBool && !closed {
				out = append(out, ptr+"/additionalProperties")
			}
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, closedSubschemas(v[k], ptr+"/"+k)...)
		}
	case []any:
		for i, item := range v {
			out = append(out, closedSubschemas(item, fmt.Sprintf("%s/%d", ptr, i))...)
		}
	}
	return out
}

// publishedOutputSchema returns the outputSchema exactly as it reaches the
// wire. It marshals the whole Tool rather than reading t.OutputSchema so the
// Raw-vs-typed branch in Tool.MarshalJSON is part of what is under test.
func publishedOutputSchema(t *testing.T, tool any) any {
	t.Helper()
	raw, err := json.Marshal(tool)
	if err != nil {
		t.Fatalf("marshal tool: %v", err)
	}
	var envelope struct {
		OutputSchema json.RawMessage `json:"outputSchema"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode tool: %v", err)
	}
	if len(envelope.OutputSchema) == 0 {
		return nil
	}
	// jsonschema.UnmarshalJSON, not json.Unmarshal: the validator reads
	// numeric keywords as json.Number, and its own helper is what produces
	// them. No reflected schema here carries a numeric keyword today, so the
	// two agree -- but the first result struct to grow a `minimum` would make
	// that stop being true, and the symptom would be a puzzle rather than a
	// clear failure.
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(envelope.OutputSchema))
	if err != nil {
		t.Fatalf("decode outputSchema: %v", err)
	}
	return doc
}

// TestOutputSchemasStayOpenToAdditiveFields pins the invariant that broke the
// portal on 2026-09-12 (#637).
//
// An output schema describes what this server returns. Closing it constrains
// nobody but us, and it turns every added field into a breaking change for
// any client still holding an older copy of the schema — a cached tools/list,
// or an MCP session that fixed its tool list at establishment. The Cloudflare
// portal's catalogue for `tg` froze on 09-10; when #631 added five fields to
// db.AuditEntry, every audit call through it started failing against that
// snapshot, with the deployed server and its own declared schema in perfect
// agreement.
//
// So: no tool published from this repository may pin
// "additionalProperties": false anywhere in its output schema.
func TestOutputSchemasStayOpenToAdditiveFields(t *testing.T) {
	// Enumerate through the unfiltered server rather than a hand-kept table.
	// The table in output_schema_test.go is already missing the media tools,
	// which is exactly how the next tool would slip past this guard.
	registered := (&Server{ToolFilter: ""}).newMCPServer().ListTools()
	if len(registered) == 0 {
		t.Fatal("no tools registered: the enumeration is broken, not the invariant")
	}

	names := make([]string, 0, len(registered))
	for name := range registered {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		doc := publishedOutputSchema(t, registered[name].Tool)
		if doc == nil {
			t.Errorf("%s: publishes no outputSchema; every tool here declares one", name)
			continue
		}
		for _, ptr := range closedSubschemas(doc, "") {
			t.Errorf("%s: closed output schema at %q — an added field would break any client holding an older copy", name, ptr)
		}
	}
}

// TestNoToolUsesTheLibraryOutputSchemaOption stops the fix from being undone
// by copy-paste. mcplib.WithOutputSchema stamps additionalProperties:false;
// outputSchema (output_schema.go) is the same reflection with that stamp
// removed. A new tool added by copying an old call site must not reintroduce
// the library form.
func TestNoToolUsesTheLibraryOutputSchemaOption(t *testing.T) {
	// Walk the whole module rather than naming the packages that build tools
	// today. An allowlist here would be the same shape of gap as the
	// hand-kept table in output_schema_test.go that this test replaced: a
	// package added later would get no coverage and, worse, no signal.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	var scanned int
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Vendored or generated trees are not ours to police, and .git
			// holds blobs that would match on old content.
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		scanned++
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		for i, line := range strings.Split(string(src), "\n") {
			// Match the selector, not the alias: a file importing the package
			// under a different name would otherwise slip past.
			if !strings.Contains(line, ".WithOutputSchema[") {
				continue
			}
			// A doc comment discussing the option by name is prose, not a
			// call. tools.go has two such comments.
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			t.Errorf("%s:%d: uses the library WithOutputSchema; use outputSchema[T]() so the schema stays open to additive fields", rel, i+1)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}
	// A walk that found nothing would pass silently, which is the failure
	// mode of every guard that can only succeed by not running.
	if scanned == 0 {
		t.Fatal("scanned no Go files; the walk is broken, not the invariant")
	}
}

// TestPublishedSchemaIsTheReflectedSchemaMinusTheStamps pins the load-bearing
// claim: what we publish is the reflected schema with the additionalProperties
// stamps removed, and nothing else.
//
// The comparison is against the RAW reflected bytes, not against
// mcplib.WithOutputSchema[T]. Comparing the two options would be weaker than
// it looks: both finish by decoding into the typed mcplib.ToolOutputSchema,
// which keeps only the keys that struct has fields for, so a mcp-go bump that
// started emitting $defs or a top-level title would drop it on both paths
// identically and leave the two documents equal. Comparing against what the
// reflector actually produced catches that -- the published schema would no
// longer match its own source.
//
// Today they agree for every type here: the result structs are flat and
// non-recursive, so the reflector emits nothing the typed struct cannot hold.
// The day that stops being true, this test says so.
func TestPublishedSchemaIsTheReflectedSchemaMinusTheStamps(t *testing.T) {
	// One flat type and one nested type, so the comparison covers a schema
	// with a nested item schema rather than only a top-level object.
	t.Run("auditLogResult", func(t *testing.T) {
		assertPublishedMatchesReflected[auditLogResult](t)
	})
	t.Run("messagesResult", func(t *testing.T) {
		assertPublishedMatchesReflected[messagesResult](t)
	})
}

func assertPublishedMatchesReflected[T any](t *testing.T) {
	t.Helper()
	raw, err := mcplib.SchemaForRaw[T]()
	if err != nil {
		t.Fatalf("reflect schema: %v", err)
	}
	var reflected any
	if err := json.Unmarshal(raw, &reflected); err != nil {
		t.Fatalf("decode reflected schema: %v", err)
	}
	// The one transformation the option is allowed to make.
	openAdditiveFields(reflected)
	// Both options also stamp the top-level "type" the MCP spec requires, so
	// match it before comparing rather than treating it as a difference.
	if m, ok := reflected.(map[string]any); ok {
		m["type"] = "object"
	}

	wantJSON, err := json.Marshal(reflected)
	if err != nil {
		t.Fatalf("marshal reflected schema: %v", err)
	}
	gotJSON, err := json.Marshal(publishedOutputSchema(t, mcplib.NewTool("probe", outputSchema[T]())))
	if err != nil {
		t.Fatalf("marshal published schema: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("published schema is not the reflected schema minus the stamps:\n reflected: %s\n published: %s", wantJSON, gotJSON)
	}
}

// compileSchema compiles a decoded JSON schema document for validation.
func compileSchema(t *testing.T, doc any) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	if err := c.AddResource("tool-output.json", doc); err != nil {
		t.Fatalf("add schema resource: %v", err)
	}
	sch, err := c.Compile("tool-output.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func mustDecode(t *testing.T, payload string) any {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return inst
}

// TestAuditLogSchemaAcceptsUnknownEntryFields is the one-line statement of
// the property #631 violated, written against the tool that broke.
//
// The unknown key stands in for the next field someone adds: a client
// validating a live response against this schema must not reject it. The
// wrong-type case is there so the test cannot pass by not validating.
func TestAuditLogSchemaAcceptsUnknownEntryFields(t *testing.T) {
	srv := &Server{}
	for _, tc := range []struct {
		name  string
		build func() (mcplib.Tool, mcpserver.ToolHandlerFunc)
	}{
		{"get_my_audit_log", srv.toolGetMyAuditLog},
		{"get_user_audit_log", srv.toolGetUserAuditLog},
	} {
		tool, _ := tc.build()
		sch := compileSchema(t, publishedOutputSchema(t, tool))

		forward := mustDecode(t, `{"entries":[{"ts":"2026-09-12T00:00:00Z","tool_name":"send_message","status":"ok","future_field_added_in_2027":"v"}],"count":1}`)
		if err := sch.Validate(forward); err != nil {
			t.Errorf("%s: rejected an entry carrying an unknown field, so the next added field is a breaking change again: %v", tc.name, err)
		}

		wrong := mustDecode(t, `{"entries":[{"ts":"2026-09-12T00:00:00Z","tool_name":"send_message","status":"ok"}],"count":"not-a-number"}`)
		if err := sch.Validate(wrong); err == nil {
			t.Errorf("%s: accepted a string where count is an integer — the schema is not being validated at all", tc.name)
		}
	}
}
