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

	// Derived from the server's descriptor by -update-pin.
	DescriptionSHA256 string          `json:"description_sha256"`
	InputSchema       json.RawMessage `json:"input_schema"`
	InputSchemaSHA256 string          `json:"input_schema_sha256"`
	Annotations       json.RawMessage `json:"annotations"`
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

// ParsePin decodes and validates a pin. Unknown fields are refused so a
// misspelt policy field cannot be silently ignored.
func ParsePin(raw []byte) (*Pin, error) {
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

// ServerNames returns the pinned server names, sorted.
func (p *Pin) ServerNames() []string {
	names := make([]string, 0, len(p.Servers))
	for s := range p.Servers {
		names = append(names, s)
	}
	slices.Sort(names)
	return names
}
