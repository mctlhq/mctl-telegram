package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ReadTools are the only tools a data source may name.
var ReadTools = map[string]struct{}{
	"list_dialogs":        {},
	"list_folders":        {},
	"list_topics":         {},
	"get_unread_messages": {},
	"get_messages":        {},
	"search_messages":     {},
}

// WriteActions are the only actions a tile may name. send and delete are
// intentionally absent: a template cannot reach them.
var WriteActions = map[string]struct{}{
	"mark_read":  {},
	"save_draft": {},
}

// argField is the kind of one tool argument a template may set.
type argField int

const (
	argString argField = iota
	argNumber
)

// toolArgs is the argument allowlist for one read tool. A key not listed
// here is rejected, which is what keeps fetch_media and any future write
// argument out of a template.
var toolArgs = map[string]map[string]argField{
	"list_dialogs":        {"limit": argNumber, "query": argString, "folder": argNumber},
	"list_folders":        {},
	"list_topics":         {"peer": argString, "query": argString, "limit": argNumber},
	"get_unread_messages": {"peer": argString, "folder": argNumber, "limit": argNumber},
	"get_messages":        {"peer": argString, "limit": argNumber, "before_id": argNumber, "topic_id": argNumber},
	"search_messages":     {"query": argString, "peer": argString, "topic_id": argNumber, "limit": argNumber},
}

var limitMax = map[string]float64{
	"list_dialogs":        200,
	"get_unread_messages": 200,
	"get_messages":        200,
	"list_topics":         100,
	"search_messages":     100,
}

var (
	inputBinding = regexp.MustCompile(`^@input:([a-z][a-z0-9_]{0,31})$`)
	tileBinding  = regexp.MustCompile(`^@tile:([a-z_][a-z0-9_]{0,31})$`)
	dataBinding  = regexp.MustCompile(`^@data:([a-z][a-z0-9_]{0,31})(\.[a-z_][a-z0-9_]*)*$`)
)

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

func compiledSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaJSON))
		if err != nil {
			schemaErr = fmt.Errorf("parse dashboard schema: %w", err)
			return
		}
		const name = "tg-dashboard-v1.schema.json"
		if err := c.AddResource(name, doc); err != nil {
			schemaErr = fmt.Errorf("add dashboard schema: %w", err)
			return
		}
		schema, schemaErr = c.Compile(name)
	})
	return schema, schemaErr
}

// Parse validates raw against the JSON Schema and the semantic rules and
// returns the template. The error is safe to show to the author: it names
// the rule, not a Telegram message.
func Parse(raw []byte) (*Template, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("template is empty")
	}
	if len(raw) > MaxTemplateBytes {
		return nil, fmt.Errorf("template is %d bytes, the maximum is %d", len(raw), MaxTemplateBytes)
	}
	sch, err := compiledSchema()
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("template is not JSON: %w", err)
	}
	if err := sch.Validate(doc); err != nil {
		return nil, fmt.Errorf("template does not match %s: %s", SchemaID, schemaError(err))
	}
	var tpl Template
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&tpl); err != nil {
		return nil, fmt.Errorf("template is not JSON: %w", err)
	}
	if err := checkTemplate(&tpl); err != nil {
		return nil, err
	}
	normalizeNumbers(&tpl)
	if tpl.RefreshIntervalSec == 0 {
		tpl.RefreshIntervalSec = DefaultRefreshSec
	}
	return &tpl, nil
}

func schemaError(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return err.Error()
	}
	var parts []string
	var walk func(*jsonschema.ValidationError)
	walk = func(v *jsonschema.ValidationError) {
		if v == nil {
			return
		}
		if len(v.Causes) == 0 {
			loc := "/"
			if len(v.InstanceLocation) > 0 {
				loc = "/" + strings.Join(v.InstanceLocation, "/")
			}
			kw := "invalid"
			if kp := v.ErrorKind.KeywordPath(); len(kp) > 0 {
				kw = kp[len(kp)-1]
			}
			parts = append(parts, loc+": "+kw)
			return
		}
		for _, c := range v.Causes {
			walk(c)
		}
	}
	walk(ve)
	if len(parts) == 0 {
		return "invalid document"
	}
	msg := strings.Join(parts, "; ")
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return msg
}

func checkTemplate(tpl *Template) error {
	if tpl.Schema != SchemaID {
		return fmt.Errorf("schema must be %s", SchemaID)
	}
	inputs := map[string]struct{}{}
	for _, in := range tpl.Inputs {
		if _, dup := inputs[in.ID]; dup {
			return fmt.Errorf("duplicate input %q", in.ID)
		}
		inputs[in.ID] = struct{}{}
	}
	sources := map[string]DataSource{}
	for _, src := range tpl.DataSources {
		if _, dup := sources[src.ID]; dup {
			return fmt.Errorf("duplicate data source %q", src.ID)
		}
		if _, ok := ReadTools[src.Tool]; !ok {
			return fmt.Errorf("data source %q uses %q, which is not an allowed read tool", src.ID, src.Tool)
		}
		if err := checkArgs(src.Tool, src.Args, src.Lazy, inputs); err != nil {
			return fmt.Errorf("data source %q: %w", src.ID, err)
		}
		sources[src.ID] = src
	}
	seenTile := map[string]struct{}{}
	for _, tile := range tpl.Tiles {
		if _, dup := seenTile[tile.ID]; dup {
			return fmt.Errorf("duplicate tile %q", tile.ID)
		}
		seenTile[tile.ID] = struct{}{}
		if tile.ColSpan > tpl.Layout.Columns {
			return fmt.Errorf("tile %q colSpan %d is wider than the grid (%d)", tile.ID, tile.ColSpan, tpl.Layout.Columns)
		}
		if err := checkProps(tile, sources, inputs); err != nil {
			return fmt.Errorf("tile %q: %w", tile.ID, err)
		}
		for _, act := range tile.Actions {
			if _, ok := WriteActions[act.Action]; !ok {
				return fmt.Errorf("tile %q action %q is not allowed", tile.ID, act.Action)
			}
			if err := checkActionArgs(act, inputs); err != nil {
				return fmt.Errorf("tile %q action %s: %w", tile.ID, act.Action, err)
			}
		}
	}
	return nil
}

func checkArgs(tool string, args map[string]any, lazy bool, inputs map[string]struct{}) error {
	spec := toolArgs[tool]
	for key, val := range args {
		kind, ok := spec[key]
		if !ok {
			return fmt.Errorf("argument %q is not allowed on %s", key, tool)
		}
		if err := checkArgValue(tool, key, kind, val, lazy, inputs); err != nil {
			return err
		}
	}
	return nil
}

func checkArgValue(tool, key string, kind argField, val any, lazy bool, inputs map[string]struct{}) error {
	switch v := val.(type) {
	case string:
		if inputBinding.MatchString(v) {
			name := inputBinding.FindStringSubmatch(v)[1]
			if _, ok := inputs[name]; !ok {
				return fmt.Errorf("argument %q references unknown input %q", key, name)
			}
			return nil
		}
		if tileBinding.MatchString(v) {
			if !lazy {
				return fmt.Errorf("argument %q uses %s, which is only valid on a lazy data source", key, v)
			}
			return nil
		}
		if kind != argString {
			return fmt.Errorf("argument %q must be a number", key)
		}
		if strings.Contains(v, "@") {
			return fmt.Errorf("argument %q has an unknown binding %q", key, v)
		}
		return nil
	case json.Number:
		if kind != argNumber {
			return fmt.Errorf("argument %q must be a string", key)
		}
		return checkNumber(tool, key, v)
	case float64:
		if kind != argNumber {
			return fmt.Errorf("argument %q must be a string", key)
		}
		return checkNumber(tool, key, json.Number(strconv.FormatFloat(v, 'f', -1, 64)))
	default:
		return fmt.Errorf("argument %q has an unsupported value", key)
	}
}

func checkNumber(tool, key string, n json.Number) error {
	f, err := n.Float64()
	if err != nil || f != math.Trunc(f) {
		return fmt.Errorf("argument %q must be a whole number", key)
	}
	if key == "limit" {
		max := limitMax[tool]
		if f < 1 || f > max {
			return fmt.Errorf("argument limit must be from 1 to %.0f", max)
		}
	}
	if (key == "before_id" || key == "topic_id" || key == "folder") && f < 1 {
		return fmt.Errorf("argument %q must be a positive number", key)
	}
	return nil
}

func checkProps(tile Tile, sources map[string]DataSource, inputs map[string]struct{}) error {
	for key, val := range tile.Props {
		s, ok := val.(string)
		if !ok {
			continue
		}
		if strings.HasPrefix(s, "@") && !dataBinding.MatchString(s) && !inputBinding.MatchString(s) {
			return fmt.Errorf("prop %q has an unknown binding %q", key, s)
		}
		if dataBinding.MatchString(s) {
			name := dataBinding.FindStringSubmatch(s)[1]
			if _, ok := sources[name]; !ok {
				return fmt.Errorf("prop %q references unknown data source %q", key, name)
			}
		}
		if inputBinding.MatchString(s) {
			name := inputBinding.FindStringSubmatch(s)[1]
			if _, ok := inputs[name]; !ok {
				return fmt.Errorf("prop %q references unknown input %q", key, name)
			}
		}
	}
	switch tile.Component {
	case "kpi":
		if _, ok := tile.Props["label"]; !ok {
			return fmt.Errorf("kpi requires prop label")
		}
		if _, ok := tile.Props["value"]; !ok {
			return fmt.Errorf("kpi requires prop value")
		}
	case "banner":
		if _, ok := tile.Props["text"].(string); !ok {
			return fmt.Errorf("banner requires prop text")
		}
		if tone, ok := tile.Props["tone"].(string); ok && tone != "info" && tone != "warning" {
			return fmt.Errorf("banner tone must be info or warning")
		}
	case "message_list", "dialog_cards", "folder_board", "topic_cards", "search_digest":
		src, _ := tile.Props["source"].(string)
		if src == "" {
			return fmt.Errorf("%s requires prop source", tile.Component)
		}
		ds, ok := sources[src]
		if !ok {
			return fmt.Errorf("prop source references unknown data source %q", src)
		}
		if ds.Lazy {
			return fmt.Errorf("prop source %q is lazy; a tile source is polled", src)
		}
	}
	if tile.Component == "dialog_cards" {
		if kind, ok := tile.Props["kind"].(string); ok && kind != "groups" && kind != "all" {
			return fmt.Errorf("dialog_cards kind must be groups or all")
		}
		if err := checkLazyRef(tile.Props["preview"], "get_messages", sources); err != nil {
			return fmt.Errorf("preview: %w", err)
		}
	}
	if tile.Component == "folder_board" {
		if err := checkLazyRef(tile.Props["members"], "list_dialogs", sources); err != nil {
			return fmt.Errorf("members: %w", err)
		}
	}
	return nil
}

func checkLazyRef(val any, tool string, sources map[string]DataSource) error {
	if val == nil {
		return nil
	}
	id, ok := val.(string)
	if !ok || id == "" {
		return fmt.Errorf("must name a data source")
	}
	ds, ok := sources[id]
	if !ok {
		return fmt.Errorf("unknown data source %q", id)
	}
	if !ds.Lazy {
		return fmt.Errorf("data source %q must be lazy", id)
	}
	if ds.Tool != tool {
		return fmt.Errorf("data source %q must use %s", id, tool)
	}
	return nil
}

func checkActionArgs(act Action, inputs map[string]struct{}) error {
	allowed := map[string]argField{"peer": argString}
	switch act.Action {
	case "mark_read":
		allowed["max_id"] = argNumber
		allowed["topic_id"] = argNumber
	case "save_draft":
		allowed["text"] = argString
		allowed["topic_id"] = argNumber
		allowed["overwrite"] = argString
	default:
		return fmt.Errorf("not allowed")
	}
	for key, val := range act.Args {
		kind, ok := allowed[key]
		if !ok {
			return fmt.Errorf("argument %q is not allowed", key)
		}
		// Action arguments are resolved per row, so @tile is expected and
		// @data / @input are also accepted. overwrite stays a boolean.
		if key == "overwrite" {
			if _, ok := val.(bool); !ok {
				return fmt.Errorf("argument overwrite must be a boolean")
			}
			continue
		}
		if err := checkBindingArg(key, kind, val, inputs); err != nil {
			return err
		}
	}
	return nil
}

func checkBindingArg(key string, kind argField, val any, inputs map[string]struct{}) error {
	switch v := val.(type) {
	case string:
		switch {
		case inputBinding.MatchString(v):
			name := inputBinding.FindStringSubmatch(v)[1]
			if _, ok := inputs[name]; !ok {
				return fmt.Errorf("argument %q references unknown input %q", key, name)
			}
		case tileBinding.MatchString(v), dataBinding.MatchString(v):
		case kind == argString && !strings.Contains(v, "@"):
		default:
			return fmt.Errorf("argument %q has an unknown binding %q", key, v)
		}
		return nil
	case json.Number:
		if kind != argNumber {
			return fmt.Errorf("argument %q must be a string", key)
		}
		return nil
	case float64:
		if kind != argNumber {
			return fmt.Errorf("argument %q must be a string", key)
		}
		return nil
	case bool:
		return fmt.Errorf("argument %q must not be a boolean", key)
	default:
		return fmt.Errorf("argument %q has an unsupported value", key)
	}
}

// normalizeNumbers turns json.Number values into float64 so Canonical emits
// ordinary JSON numbers.
func normalizeNumbers(tpl *Template) {
	for i := range tpl.DataSources {
		tpl.DataSources[i].Args = normalizeMap(tpl.DataSources[i].Args)
	}
	for i := range tpl.Tiles {
		tpl.Tiles[i].Props = normalizeMap(tpl.Tiles[i].Props)
		for j := range tpl.Tiles[i].Filters {
			tpl.Tiles[i].Filters[j].Value = normalizeValue(tpl.Tiles[i].Filters[j].Value)
		}
		for j := range tpl.Tiles[i].Actions {
			tpl.Tiles[i].Actions[j].Args = normalizeMap(tpl.Tiles[i].Actions[j].Args)
		}
	}
}

func normalizeMap(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	for k, v := range m {
		m[k] = normalizeValue(v)
	}
	return m
}

func normalizeValue(v any) any {
	n, ok := v.(json.Number)
	if !ok {
		return v
	}
	if i, err := n.Int64(); err == nil {
		return float64(i)
	}
	f, err := n.Float64()
	if err != nil {
		return v
	}
	return f
}
