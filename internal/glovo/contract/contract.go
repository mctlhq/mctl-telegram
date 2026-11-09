// Package contract embeds docs/contracts/glovo-mcp-tools.json (the M0 tool
// contract) and compiles its schemas. The facade serves exactly this contract;
// scopes and descriptors are never listed a second time elsewhere.
package contract

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed glovo-mcp-tools.json
var raw []byte

// Raw returns the embedded contract bytes (a copy).
func Raw() []byte { return append([]byte(nil), raw...) }

// Tool is one contract tool with its schemas compiled.
type Tool struct {
	Name          string
	Description   string
	RequiredScope string
	Effect        string
	InputRaw      json.RawMessage
	OutputRaw     json.RawMessage

	input  *jsonschema.Schema
	output *jsonschema.Schema
}

// Contract is the parsed, compiled contract.
type Contract struct {
	Resource string
	Scopes   []string
	Tools    []*Tool
}

// ValidateInput validates arguments (exactly one JSON value) against the
// tool's input schema.
func (t *Tool) ValidateInput(b []byte) error { return validate(t.input, b) }

// ValidateOutput validates an upstream result against the output schema.
func (t *Tool) ValidateOutput(b []byte) error { return validate(t.output, b) }

func validate(s *jsonschema.Schema, b []byte) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("decode instance: %w", err)
	}
	return s.Validate(inst)
}

// Tool returns the tool by name, or nil.
func (c *Contract) Tool(name string) *Tool {
	for _, t := range c.Tools {
		if t.Name == name {
			return t
		}
	}
	return nil
}

// Load parses and compiles the embedded contract.
func Load() (*Contract, error) { return Parse(raw) }

// Parse parses and compiles contract bytes.
func Parse(b []byte) (*Contract, error) {
	var doc struct {
		PR struct {
			Resource string   `json:"resource"`
			Scopes   []string `json:"scopes_supported"`
		} `json:"protected_resource"`
		Tools []struct {
			Name          string          `json:"name"`
			Description   string          `json:"description"`
			RequiredScope string          `json:"required_scope"`
			Effect        string          `json:"effect"`
			InputSchema   json.RawMessage `json:"input_schema"`
			OutputSchema  json.RawMessage `json:"output_schema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse contract: %w", err)
	}
	if doc.PR.Resource == "" || len(doc.PR.Scopes) == 0 || len(doc.Tools) == 0 {
		return nil, fmt.Errorf("contract incomplete")
	}
	c := &Contract{Resource: doc.PR.Resource, Scopes: doc.PR.Scopes}
	for _, t := range doc.Tools {
		in, err := compile(t.Name+"/input", t.InputSchema)
		if err != nil {
			return nil, err
		}
		out, err := compile(t.Name+"/output", t.OutputSchema)
		if err != nil {
			return nil, err
		}
		c.Tools = append(c.Tools, &Tool{
			Name: t.Name, Description: t.Description, RequiredScope: t.RequiredScope,
			Effect: t.Effect, InputRaw: t.InputSchema, OutputRaw: t.OutputSchema,
			input: in, output: out,
		})
	}
	return c, nil
}

func compile(id string, schema json.RawMessage) (*jsonschema.Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schema))
	if err != nil {
		return nil, fmt.Errorf("schema %s: %w", id, err)
	}
	url := "mem://glovo/" + id + ".json"
	comp := jsonschema.NewCompiler()
	if err := comp.AddResource(url, doc); err != nil {
		return nil, fmt.Errorf("schema %s: %w", id, err)
	}
	s, err := comp.Compile(url)
	if err != nil {
		return nil, fmt.Errorf("schema %s: %w", id, err)
	}
	return s, nil
}
