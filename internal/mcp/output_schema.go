package mcp

import (
	"encoding/json"
	"fmt"
	"os"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// outputSchema declares a tool's output schema from Go type T, the way
// mcplib.WithOutputSchema does, minus the "additionalProperties": false that
// the reflector stamps on every struct.
//
// Why that stamp has to go. An output schema describes what this server
// returns, so closing it constrains nobody but us — but clients validate
// responses against it, and they do not necessarily hold the copy we are
// serving today. A closed schema therefore makes every added field a
// breaking change for any client still holding an older copy: a connector
// that caches tools/list, or an MCP session that fixed its tool list when it
// was established.
//
// That is not hypothetical. On 2026-09-12, #631 added five correlation
// fields to db.AuditEntry. The deployed binary and its own declared schema
// agreed — eleven properties advertised, eleven emitted — but the Cloudflare
// MCP portal's catalogue for this server had frozen on 09-10 with the
// previous six, and every audit call through it began failing with
// "data/entries/0 must NOT have additional properties", five times per entry.
// See #637 and mctlhq/.github#64.
//
// An open schema does not repair a snapshot already taken. It means the next
// added field costs nobody anything.
func outputSchema[T any]() mcplib.ToolOption {
	return func(t *mcplib.Tool) {
		// SchemaForRaw is the same reflection WithOutputSchema performs
		// internally (mcp/schema_cache.go), returning the bytes so we can
		// edit them before they become the declaration.
		raw, err := mcplib.SchemaForRaw[T]()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		openAdditiveFields(doc)
		opened, err := json.Marshal(doc)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		if err := json.Unmarshal(opened, &t.OutputSchema); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		// Mirrors WithOutputSchema: the MCP spec requires the top-level
		// output schema to be an object.
		t.OutputSchema.Type = "object"
	}
}

// openAdditiveFields removes every boolean-false "additionalProperties" in a
// decoded JSON schema, at any depth.
//
// Only the boolean form is removed. A map-valued additionalProperties says
// what the extra keys must look like — that comes from a Go map field and is
// a constraint someone chose, not the reflector's default — so it stays.
func openAdditiveFields(node any) {
	switch v := node.(type) {
	case map[string]any:
		if ap, ok := v["additionalProperties"]; ok {
			if closed, isBool := ap.(bool); isBool && !closed {
				delete(v, "additionalProperties")
			}
		}
		for _, child := range v {
			openAdditiveFields(child)
		}
	case []any:
		for _, item := range v {
			openAdditiveFields(item)
		}
	}
}
