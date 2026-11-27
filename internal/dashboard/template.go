// Package dashboard is the flag-gated Telegram dashboard template model:
// a tg-dashboard/v1 document, the built-in set, and the checks that keep a
// template on the read tools plus mark_read / save_draft.
//
// The MCP App renders a template. This package decides whether a template
// may be stored. It does not call Telegram.
package dashboard

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	// SchemaID is the document's schema field. A template with any other
	// value is rejected.
	SchemaID = "tg-dashboard/v1"

	// MaxTemplateBytes is the largest canonical template this server stores.
	MaxTemplateBytes = 24 * 1024

	// MaxCustomTemplates is how many templates one account may store.
	// Built-ins do not count.
	MaxCustomTemplates = 20

	// DefaultRefreshSec is used when a template omits refreshIntervalSec.
	DefaultRefreshSec = 60
)

//go:embed schema.json
var schemaJSON []byte

//go:embed templates/*.json
var builtinFS embed.FS

// Template is one dashboard document after it has passed the schema and
// the semantic checks.
type Template struct {
	Schema             string       `json:"schema"`
	ID                 string       `json:"id"`
	Title              string       `json:"title"`
	Layout             Layout       `json:"layout"`
	RefreshIntervalSec int          `json:"refreshIntervalSec,omitempty"`
	Inputs             []Input      `json:"inputs,omitempty"`
	DataSources        []DataSource `json:"dataSources"`
	Tiles              []Tile       `json:"tiles"`
}

// Layout is the tile grid.
type Layout struct {
	Columns int `json:"columns"`
	Gap     int `json:"gap"`
}

// Input is a value the person fills in before a refresh (a forum peer, a
// search query). Templates reference it as @input:<id>.
type Input struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Required bool   `json:"required,omitempty"`
}

// DataSource is one allowlisted read tool plus the arguments the App will
// pass. Lazy sources are not polled; a tile asks for them (a preview, the
// dialogs inside one folder).
type DataSource struct {
	ID   string         `json:"id"`
	Tool string         `json:"tool"`
	Lazy bool           `json:"lazy,omitempty"`
	Args map[string]any `json:"args,omitempty"`
}

// Tile is one cell. Props may contain @data:<source>.<path> bindings.
// Actions may name only mark_read and save_draft.
type Tile struct {
	ID        string         `json:"id"`
	Component string         `json:"component"`
	ColSpan   int            `json:"colSpan"`
	Props     map[string]any `json:"props"`
	Filters   []Filter       `json:"filters,omitempty"`
	Actions   []Action       `json:"actions,omitempty"`
}

// Filter narrows the array a tile renders. It runs in the App, on data the
// server already returned.
type Filter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value any    `json:"value"`
}

// Action is a write the tile may offer. The App must prepare it and the
// server must accept the confirmation; the action entry is not itself
// authorization.
type Action struct {
	Action string         `json:"action"`
	Label  string         `json:"label"`
	Args   map[string]any `json:"args,omitempty"`
}

// Summary is a template without its body, for the picker.
type Summary struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	Builtin bool   `json:"builtin"`
}

var builtinOrder = []string{
	"unread_pulse",
	"groups_tiles",
	"folders_board",
	"forum_topics",
	"watchlist_digest",
}

var builtins map[string]Template

func init() {
	builtins = make(map[string]Template, len(builtinOrder))
	for _, id := range builtinOrder {
		raw, err := builtinFS.ReadFile("templates/" + id + ".json")
		if err != nil {
			panic("dashboard: read builtin " + id + ": " + err.Error())
		}
		tpl, err := Parse(raw)
		if err != nil {
			panic("dashboard: builtin " + id + ": " + err.Error())
		}
		if tpl.ID != id {
			panic("dashboard: builtin file " + id + " declares id " + tpl.ID)
		}
		builtins[id] = *tpl
	}
}

// BuiltinIDs returns the built-in ids in display order.
func BuiltinIDs() []string {
	out := make([]string, len(builtinOrder))
	copy(out, builtinOrder)
	return out
}

// IsBuiltin reports whether id is one of the shipped templates.
func IsBuiltin(id string) bool {
	_, ok := builtins[id]
	return ok
}

// Builtin returns a copy of a shipped template.
func Builtin(id string) (Template, bool) {
	tpl, ok := builtins[id]
	if !ok {
		return Template{}, false
	}
	return tpl, true
}

// Builtins returns the shipped templates in display order.
func Builtins() []Template {
	out := make([]Template, 0, len(builtinOrder))
	for _, id := range builtinOrder {
		out = append(out, builtins[id])
	}
	return out
}

// Summaries returns picker rows for the built-ins followed by custom, custom
// sorted by id.
func Summaries(custom []Template) []Summary {
	out := make([]Summary, 0, len(builtinOrder)+len(custom))
	for _, id := range builtinOrder {
		out = append(out, Summary{ID: id, Title: builtins[id].Title, Builtin: true})
	}
	sort.Slice(custom, func(i, j int) bool { return custom[i].ID < custom[j].ID })
	for _, tpl := range custom {
		out = append(out, Summary{ID: tpl.ID, Title: tpl.Title, Builtin: false})
	}
	return out
}

// Canonical is the compact JSON this server stores and returns. Refresh is
// filled in when the document omitted it, so the App always has a poll
// interval.
func (t Template) Canonical() ([]byte, error) {
	if t.RefreshIntervalSec == 0 {
		t.RefreshIntervalSec = DefaultRefreshSec
	}
	raw, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("encode template: %w", err)
	}
	if len(raw) > MaxTemplateBytes {
		return nil, fmt.Errorf("template is %d bytes, the maximum is %d", len(raw), MaxTemplateBytes)
	}
	return raw, nil
}

// MustCanonical encodes a template that already validated. A failure here is
// a bug in the encoder, not a user error.
func (t Template) MustCanonical() []byte {
	raw, err := t.Canonical()
	if err != nil {
		panic(err)
	}
	return raw
}

// EqualJSON reports whether a and b are the same canonical document.
func EqualJSON(a, b []byte) bool {
	var left, right any
	if json.Unmarshal(a, &left) != nil || json.Unmarshal(b, &right) != nil {
		return bytes.Equal(a, b)
	}
	la, err1 := json.Marshal(left)
	lb, err2 := json.Marshal(right)
	if err1 != nil || err2 != nil {
		return false
	}
	return bytes.Equal(la, lb)
}
