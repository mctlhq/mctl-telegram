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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// PinSchema identifies the pin file format.
const PinSchema = "mctl-telegram.pa-catalog-pin/v1"

// Tier is how a call to a pinned tool is admitted (threat model T6, T8).
type Tier string

const (
	// TierAuto runs without a card. Only reads have it (Phase 1).
	TierAuto Tier = "auto"
	// TierApprove needs a per-call approval or a standing permission.
	TierApprove Tier = "approve"
)

// Class is the kind of effect a tool has (threat model T6). It is assigned
// per tool in the pin, never decided from argument content.
type Class string

const (
	ClassRead       Class = "read"
	ClassWrite      Class = "write"
	ClassDisclosure Class = "disclosure"
)

// Lowerable says whether a standing permission may lower a tool's tier
// (threat model I5, T6).
type Lowerable string

const (
	LowerableNever       Lowerable = "never"
	LowerableYes         Lowerable = "yes"
	LowerableConditional Lowerable = "conditional"
)

// neverLowerable lists the tools the threat model makes "never" lowerable
// (T6). A pin entry for one of them with any other value is invalid, so the
// rule cannot be relaxed by editing the pin alone.
var neverLowerable = map[string]Class{
	"alice_say_phrase":       ClassDisclosure,
	"alice_send_command":     ClassDisclosure,
	"alice_control_room":     ClassWrite,
	"alice_trigger_scenario": ClassWrite,
}

// PinnedTool is one tool entry of the pin. The json field names are the
// file format.
type PinnedTool struct {
	// Hand-authored policy.
	Tier               Tier      `json:"tier"`
	Class              Class     `json:"class"`
	Lowerable          Lowerable `json:"lowerable"`
	CatalogDescription string    `json:"catalog_description"`
	// Constraints are optional, hand-authored limits on a write or
	// disclosure tool (threat model T6). Only ValidatePhase2 gives them
	// meaning; a read never has them.
	Constraints *Constraints `json:"constraints,omitempty"`

	// Derived from the server's descriptor by -update-pin.
	DescriptionSHA256 string          `json:"description_sha256"`
	InputSchema       json.RawMessage `json:"input_schema"`
	InputSchemaSHA256 string          `json:"input_schema_sha256"`
	Annotations       json.RawMessage `json:"annotations"`
}

// Constraints are the per-tool limits of threat model T6 that a Phase 2
// pin records. They narrow what a standing permission may cover or what an
// argument may hold; none of them widens a tool. Each argument they name
// must be a property of the tool's pinned input schema.
type Constraints struct {
	// PlaybackActions are the values of one enum argument a standing
	// permission may cover (alice_media_control: "playback controls
	// only"). Every other value of that argument needs a card.
	PlaybackActions *EnumSubset `json:"playback_actions,omitempty"`
	// IntegerBounds are inclusive bounds of numeric arguments, in the
	// device units the server takes (alice_set_volume level 1..10). They
	// bound integers only, even where the schema type is "number": the
	// slice that enforces them must refuse a value that is not an integer
	// (5.5) rather than round or compare it,
	// so no fractional value is ever inside a bound.
	IntegerBounds map[string]IntBound `json:"integer_bounds,omitempty"`
	// AllowedTypePrefixes are the device type prefixes a standing
	// permission may cover (alice_control_device: light and media_device
	// only). Each must be one of allowedDeviceTypePrefixes exactly; a type
	// matches a prefix when it equals it or continues it after a dot.
	AllowedTypePrefixes []string `json:"allowed_type_prefixes,omitempty"`
	// TextCap is the maximum length, in characters, of string arguments
	// (disclosure text: 1000).
	TextCap map[string]int `json:"text_cap,omitempty"`
}

// EnumSubset names an enum argument and the subset of its values allowed.
type EnumSubset struct {
	Arg    string   `json:"arg"`
	Values []string `json:"values"`
}

// IntBound is an inclusive integer range.
type IntBound struct {
	Min int64 `json:"min"`
	Max int64 `json:"max"`
}

// ServerPin is the pin of one catalog server.
type ServerPin struct {
	// Upstream names where the server-derived fields come from, for a
	// reviewer. It is not interpreted.
	Upstream string                `json:"upstream"`
	Tools    map[string]PinnedTool `json:"tools"`
}

// Pin is the whole catalog pin. Use LoadPin or ParsePin; a Pin built any
// other way has not been validated.
type Pin struct {
	Schema  string               `json:"schema"`
	Servers map[string]ServerPin `json:"servers"`
}

//go:embed pin.json
var pinJSON []byte

// pinPhase2JSON is the Phase 2 pin. No runtime code loads it: LoadPin is
// the only loader the service calls until Phase 2 is enabled by a reviewed
// change (TestNoRuntimePhase2PinLoad in internal/pa guards this).
//
//go:embed pin_phase2.json
var pinPhase2JSON []byte

// ErrInvalidPin is wrapped by every pin validation failure.
var ErrInvalidPin = errors.New("pa catalog: invalid pin")

var (
	toolNameRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	serverNameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	sha256HexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// maxCatalogDescription bounds what the catalog shows the model per tool.
const maxCatalogDescription = 1000

// LoadPin returns the embedded, committed pin, validated for Phase 1: every
// pinned tool is a read (no write path exists, threat model I5).
func LoadPin() (*Pin, error) {
	p, err := ParsePin(pinJSON)
	if err != nil {
		return nil, err
	}
	if err := p.ValidatePhase1(); err != nil {
		return nil, err
	}
	return p, nil
}

// LoadPinPhase2 returns the embedded Phase 2 pin, validated by
// ValidatePhase2. It is not called by any runtime code (P2-S1): the
// service runs on LoadPin, which admits reads only.
func LoadPinPhase2() (*Pin, error) {
	p, err := ParsePin(pinPhase2JSON)
	if err != nil {
		return nil, err
	}
	if err := p.ValidatePhase2(); err != nil {
		return nil, err
	}
	return p, nil
}

// ParsePin decodes and validates a pin. Unknown fields are refused so a
// misspelt policy field cannot be silently ignored, and so is a duplicate
// key anywhere in the file, keys that differ only in case included:
// encoding/json keeps the last one silently and matches fields
// case-insensitively, so a reviewer reading "lowerable": "never" ahead of
// a "Lowerable": "yes" would review the wrong policy.
func ParsePin(raw []byte) (*Pin, error) {
	if err := strictJSON(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPin, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Pin
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%w: decode: %v", ErrInvalidPin, err)
	}
	// Only a clean EOF ends the pin. dec.More reports false for a stray
	// closing bracket ("{...}]"), so it would let that through; Token
	// returns a syntax error for it instead (#1331 follow-up).
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidPin)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks the structure of the pin and the per-tool policy rules of
// threat model T6 and T8 that hold in every phase.
func (p *Pin) Validate() error {
	if p.Schema != PinSchema {
		return fmt.Errorf("%w: schema %q, want %q", ErrInvalidPin, p.Schema, PinSchema)
	}
	if len(p.Servers) == 0 {
		return fmt.Errorf("%w: no servers", ErrInvalidPin)
	}
	for server, sp := range p.Servers {
		if !serverNameRE.MatchString(server) {
			return fmt.Errorf("%w: server name %q", ErrInvalidPin, server)
		}
		if len(sp.Tools) == 0 {
			return fmt.Errorf("%w: server %s pins no tools", ErrInvalidPin, server)
		}
		for name, t := range sp.Tools {
			if err := validateTool(name, t); err != nil {
				return fmt.Errorf("%w: %s/%s: %v", ErrInvalidPin, server, name, err)
			}
		}
	}
	return nil
}

func validateTool(name string, t PinnedTool) error {
	if !toolNameRE.MatchString(name) {
		return errors.New("bad tool name")
	}
	switch t.Tier {
	case TierAuto, TierApprove:
	default:
		return fmt.Errorf("tier %q", t.Tier)
	}
	switch t.Class {
	case ClassRead, ClassWrite, ClassDisclosure:
	default:
		return fmt.Errorf("class %q", t.Class)
	}
	if err := checkPolicy(name, t); err != nil {
		return err
	}
	desc := strings.TrimSpace(t.CatalogDescription)
	if desc == "" || len(t.CatalogDescription) > maxCatalogDescription {
		return errors.New("catalog_description must be 1..1000 bytes")
	}
	if !sha256HexRE.MatchString(t.DescriptionSHA256) {
		return errors.New("description_sha256 is not a hex SHA-256")
	}
	if !sha256HexRE.MatchString(t.InputSchemaSHA256) {
		return errors.New("input_schema_sha256 is not a hex SHA-256")
	}
	schema, err := canonicalObject(t.InputSchema)
	if err != nil {
		return fmt.Errorf("input_schema: %v", err)
	}
	if sha256Hex(schema) != t.InputSchemaSHA256 {
		return errors.New("input_schema_sha256 does not match input_schema")
	}
	if _, err := canonicalAnnotations(t.Annotations); err != nil {
		return fmt.Errorf("annotations: %v", err)
	}
	// A read whose server says it is not read-only is a contradiction the
	// pin must not paper over.
	if t.Class == ClassRead {
		var ann struct {
			ReadOnly *bool `json:"readOnlyHint"`
		}
		if len(t.Annotations) > 0 {
			if err := json.Unmarshal(t.Annotations, &ann); err != nil {
				return fmt.Errorf("annotations: %v", err)
			}
		}
		if ann.ReadOnly != nil && !*ann.ReadOnly {
			return errors.New("class read but the server annotates readOnlyHint=false")
		}
	}
	return nil
}

// checkPolicy holds the tier, class and lowerable rules of threat model T6
// and I5 that every phase keeps. Validate and ValidatePhase2 both run it.
func checkPolicy(name string, t PinnedTool) error {
	switch t.Lowerable {
	case LowerableNever, LowerableYes, LowerableConditional:
	default:
		return fmt.Errorf("lowerable %q", t.Lowerable)
	}
	// Reads are auto and have nothing to lower; everything else needs a
	// decision of the principal (I5), so it is never auto.
	if t.Class == ClassRead {
		if t.Tier != TierAuto || t.Lowerable != LowerableNever {
			return errors.New("a read must be tier auto, lowerable never")
		}
	} else if t.Tier != TierApprove {
		return errors.New("a write or disclosure must be tier approve")
	}
	if t.Class == ClassDisclosure && t.Lowerable != LowerableNever {
		return errors.New("a disclosure tool is never lowerable")
	}
	if want, ok := neverLowerable[name]; ok {
		if t.Lowerable != LowerableNever {
			return errors.New("this tool is never lowerable (threat model T6)")
		}
		if t.Class != want {
			return fmt.Errorf("this tool is class %s (threat model T6)", want)
		}
	}
	if t.Class == ClassRead && t.Constraints != nil {
		return errors.New("a read has no constraints")
	}
	return nil
}

// IsNeverLowerable reports whether the threat model makes tool never
// lowerable by name (T6), whatever a pin says.
func IsNeverLowerable(tool string) bool {
	_, ok := neverLowerable[tool]
	return ok
}

// ValidatePhase1 checks that the pin has no write path (threat model I5):
// every pinned tool is a read.
func (p *Pin) ValidatePhase1() error {
	for server, sp := range p.Servers {
		for name, t := range sp.Tools {
			if t.Class != ClassRead || t.Tier != TierAuto {
				return fmt.Errorf("%w: %s/%s is not a read; Phase 1 pins reads only", ErrInvalidPin, server, name)
			}
		}
	}
	return nil
}

// phase2Server is the only server Phase 2 pins writes on: Phase 2 is "a
// small set of approved Alice actions" (threat model Scope, T6).
const phase2Server = "alice"

// phase2Policy is the T6 table: the only write and disclosure tools a
// Phase 2 pin may hold, with their class and the most a pin may lower
// them. A pin may be stricter (lowerable "never"), never looser.
var phase2Policy = map[string]struct {
	class Class
	max   Lowerable
}{
	"alice_say_phrase":       {ClassDisclosure, LowerableNever},
	"alice_send_command":     {ClassDisclosure, LowerableNever},
	"alice_media_control":    {ClassWrite, LowerableConditional},
	"alice_set_volume":       {ClassWrite, LowerableYes},
	"alice_set_light":        {ClassWrite, LowerableYes},
	"alice_control_device":   {ClassWrite, LowerableConditional},
	"alice_control_room":     {ClassWrite, LowerableNever},
	"alice_trigger_scenario": {ClassWrite, LowerableNever},
}

// MaxDisclosureText is the T6 cap on disclosure text, in characters.
const MaxDisclosureText = 1000

// allowedDeviceTypePrefixes are the only device types T6 lets a standing
// permission cover (alice_control_device): lights and media devices.
var allowedDeviceTypePrefixes = map[string]bool{
	"devices.types.light":        true,
	"devices.types.media_device": true,
}

// DeviceTypeAllowed reports whether a device type read fresh at dispatch
// falls under one of prefixes: it equals a prefix or continues it after a
// dot. An empty type (unknown or unreadable, T6) never matches.
func DeviceTypeAllowed(prefixes []string, deviceType string) bool {
	if deviceType == "" {
		return false
	}
	for _, p := range prefixes {
		if !allowedDeviceTypePrefixes[p] {
			continue
		}
		if deviceType == p || strings.HasPrefix(deviceType, p+".") {
			return true
		}
	}
	return false
}

// ValidatePhase2 checks a pin for Phase 2. No runtime code calls it (P2-S1).
// On top of Validate (structure and the per-phase rules: a write or
// disclosure is tier approve, a disclosure is never lowerable, the
// neverLowerable tools stay never), it requires:
//
//   - every write or disclosure is a T6 tool on the alice server, with the
//     T6 class, lowered no further than T6 allows;
//   - every write or disclosure has a plain object input schema: type
//     "object", and no top-level keyword other than those of
//     schemaTopLevel, so no patternProperties, combinator or $ref can
//     declare arguments the properties do not list, and an
//     additionalProperties that is present is false;
//   - every disclosure argument is a scalar (string, number, integer or
//     boolean): an object, an array, a null, a missing or an unknown type
//     could carry text no cap covers; and every free-text (non-enum
//     string) argument is capped at MaxDisclosureText or less;
//   - a "conditional" tool names its condition (playback actions or device
//     type prefixes), and only a conditional write carries one;
//   - every argument a constraint names is a property of the pinned input
//     schema with the right type, and the schema has no duplicate key.
//
// Undeclared arguments are not refused here, and cannot be: the upstream
// schemas leave additionalProperties unset (open), and input_schema is
// derived from upstream, so pinning false would itself be drift. The
// slice that enforces a write must refuse them at dispatch with
// PinnedTool.CheckDeclaredArgs, so that no argument outside the reviewed
// properties, and therefore outside every cap and bound, reaches the
// server.
func (p *Pin) ValidatePhase2() error {
	if err := p.Validate(); err != nil {
		return err
	}
	for server, sp := range p.Servers {
		for name, t := range sp.Tools {
			if err := validatePhase2Tool(server, name, t); err != nil {
				return fmt.Errorf("%w: %s/%s: %v", ErrInvalidPin, server, name, err)
			}
		}
	}
	return nil
}

func validatePhase2Tool(server, name string, t PinnedTool) error {
	// Validate ran checkPolicy already; run it again so ValidatePhase2
	// never depends on its caller having validated the pin first.
	if err := checkPolicy(name, t); err != nil {
		return err
	}
	if t.Class == ClassRead {
		return nil
	}
	want, ok := phase2Policy[name]
	if server != phase2Server || !ok {
		return errors.New("not a Phase 2 tool (threat model T6)")
	}
	if t.Class != want.class {
		return fmt.Errorf("class %s, threat model T6 says %s", t.Class, want.class)
	}
	if t.Lowerable != LowerableNever && t.Lowerable != want.max {
		return fmt.Errorf("lowerable %s, threat model T6 allows at most %s", t.Lowerable, want.max)
	}
	if err := strictJSON(t.InputSchema); err != nil {
		return fmt.Errorf("input_schema: %v", err)
	}
	if err := checkSchemaShape(t.InputSchema); err != nil {
		return fmt.Errorf("input_schema: %v", err)
	}
	props, err := schemaProperties(t.InputSchema)
	if err != nil {
		return fmt.Errorf("input_schema: %v", err)
	}
	c := t.Constraints
	if c == nil {
		c = &Constraints{}
	}
	if t.Class == ClassDisclosure {
		// Everything a disclosure carries reaches a third party (T6), so
		// every free-text argument is capped, the target device included.
		// An enum string is not free text. Only scalars are admitted: an
		// object or array holds strings this check cannot see, and a
		// property with no single known type may be either.
		for arg, pr := range props {
			switch pr.Type {
			case "string":
				if _, ok := c.TextCap[arg]; !ok && len(pr.Enum) == 0 {
					return fmt.Errorf("text_cap: free-text argument %q is not capped", arg)
				}
			case "number", "integer", "boolean":
			case "":
				return fmt.Errorf("disclosure argument %q has no single type", arg)
			default:
				return fmt.Errorf("disclosure argument %q is of type %q, not a scalar", arg, pr.Type)
			}
		}
		if len(c.TextCap) == 0 {
			return errors.New("a disclosure caps its text (text_cap)")
		}
	}
	for arg, n := range c.TextCap {
		if pr, ok := props[arg]; !ok || pr.Type != "string" {
			return fmt.Errorf("text_cap: %q is not a string argument", arg)
		}
		if n < 1 || n > MaxDisclosureText {
			return fmt.Errorf("text_cap: %q must be 1..%d", arg, MaxDisclosureText)
		}
	}
	if len(c.IntegerBounds) > 0 && t.Class != ClassWrite {
		return errors.New("integer_bounds: only a write has them")
	}
	for arg, b := range c.IntegerBounds {
		if pr, ok := props[arg]; !ok || (pr.Type != "number" && pr.Type != "integer") {
			return fmt.Errorf("integer_bounds: %q is not a numeric argument", arg)
		}
		if b.Min > b.Max {
			return fmt.Errorf("integer_bounds: %q min > max", arg)
		}
	}
	conditional := t.Class == ClassWrite && t.Lowerable == LowerableConditional
	if (c.PlaybackActions != nil || len(c.AllowedTypePrefixes) > 0) && !conditional {
		return errors.New("playback_actions and allowed_type_prefixes are conditions of a conditional write only")
	}
	if conditional && c.PlaybackActions == nil && len(c.AllowedTypePrefixes) == 0 {
		return errors.New("a conditional write names its condition")
	}
	if pa := c.PlaybackActions; pa != nil {
		pr, ok := props[pa.Arg]
		if !ok || pr.Type != "string" || len(pr.Enum) == 0 {
			return fmt.Errorf("playback_actions: %q is not a string enum argument", pa.Arg)
		}
		if len(pa.Values) == 0 {
			return errors.New("playback_actions: no values")
		}
		seen := map[string]bool{}
		for _, v := range pa.Values {
			if seen[v] || !slices.Contains(pr.Enum, v) {
				return fmt.Errorf("playback_actions: %q is repeated or not in the enum", v)
			}
			seen[v] = true
		}
	}
	seen := map[string]bool{}
	for _, pfx := range c.AllowedTypePrefixes {
		if seen[pfx] || !allowedDeviceTypePrefixes[pfx] {
			return fmt.Errorf("allowed_type_prefixes: %q is repeated or not allowed by threat model T6", pfx)
		}
		seen[pfx] = true
	}
	return nil
}

// schemaTopLevel are the only top-level keywords a write or disclosure
// input schema may have, with the value each must hold where that is
// fixed. Every other keyword is refused rather than interpreted:
// patternProperties, dependentSchemas, an anyOf/oneOf/allOf/not/if
// branch or a $ref could each declare or reshape an argument outside
// "properties", where no constraint check looks.
var schemaTopLevel = map[string]bool{
	"type":                 true,
	"properties":           true,
	"required":             true,
	"additionalProperties": true,
	"description":          true,
	"title":                true,
	"$schema":              true,
}

// checkSchemaShape refuses an input schema that is not a plain object
// schema (see schemaTopLevel). additionalProperties, when present, must be
// false: true or a schema admits arguments with no constraint.
func checkSchemaShape(raw json.RawMessage) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return err
	}
	for k := range top {
		if !schemaTopLevel[k] {
			return fmt.Errorf("top-level keyword %q is not allowed on a write or disclosure", k)
		}
	}
	var typ string
	if err := json.Unmarshal(top["type"], &typ); err != nil || typ != "object" {
		return errors.New(`type must be "object"`)
	}
	if ap, ok := top["additionalProperties"]; ok {
		var closed bool
		if err := json.Unmarshal(ap, &closed); err != nil || closed {
			return errors.New("additionalProperties must be false when present")
		}
	}
	return nil
}

// ErrUndeclaredArg is returned by CheckDeclaredArgs.
var ErrUndeclaredArg = errors.New("pa catalog: argument not declared by the pinned input schema")

// CheckDeclaredArgs refuses call arguments (a JSON object, the output of
// CanonicalArgs) that hold a key the pinned input schema does not list in
// its properties. The upstream schemas leave additionalProperties open, so
// the closed world a write's constraints assume is enforced here, at
// dispatch, not by the schema. No runtime code calls it yet (P2-S1).
func (t PinnedTool) CheckDeclaredArgs(args []byte) error {
	props, err := schemaProperties(t.InputSchema)
	if err != nil {
		return fmt.Errorf("%w: input_schema: %v", ErrUndeclaredArg, err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(args, &got); err != nil || got == nil {
		return fmt.Errorf("%w: arguments are not a JSON object", ErrUndeclaredArg)
	}
	for k := range got {
		if _, ok := props[k]; !ok {
			return fmt.Errorf("%w: %.40q", ErrUndeclaredArg, k)
		}
	}
	return nil
}

type schemaProperty struct {
	Type string
	Enum []string
}

// schemaProperties returns the top-level properties of an input schema
// with their type, when it is a single string, and their string enum. A
// property whose type is not a single string has Type "".
func schemaProperties(raw json.RawMessage) (map[string]schemaProperty, error) {
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	out := make(map[string]schemaProperty, len(s.Properties))
	for name, rp := range s.Properties {
		var p struct {
			Type json.RawMessage   `json:"type"`
			Enum []json.RawMessage `json:"enum"`
		}
		if err := json.Unmarshal(rp, &p); err != nil {
			return nil, fmt.Errorf("property %q: %v", name, err)
		}
		var sp schemaProperty
		_ = json.Unmarshal(p.Type, &sp.Type) // a non-string type stays ""
		for _, e := range p.Enum {
			var v string
			if err := json.Unmarshal(e, &v); err != nil {
				return nil, fmt.Errorf("property %q: enum value is not a string", name)
			}
			sp.Enum = append(sp.Enum, v)
		}
		out[name] = sp
	}
	return out, nil
}

// ServerNames returns the pinned server names, sorted.
func (p *Pin) ServerNames() []string {
	names := make([]string, 0, len(p.Servers))
	for s := range p.Servers {
		names = append(names, s)
	}
	slices.Sort(names)
	return names
}
