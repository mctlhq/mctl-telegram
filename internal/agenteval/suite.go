// Package agenteval is the baseline eval of an assistant definition
// (docs/assistants/adr-forks.md, Promotion; #1044): the suites, the fake
// agent API a model run talks to, and the scorer.
//
// One implementation serves both the opt-in C1 harness
// (internal/agentworker.TestC1ObserveEval) and, from P4.3 S2 on, the
// server's eval runs, so the two cannot drift. The fake API records what the
// model did and never causes an effect: this package does not reach the
// executor, Telegram, or any store (TestNoPathToEffects).
//
// A suite belongs to one base version and is immutable with it. It holds the
// fixtures, the install values every run renders and judges with, and the
// classification threshold. A run certifies a definition, never an install:
// it takes no ownerNotes and none of an account's own values.
package agenteval

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/mctlhq/mctl-telegram/assistants"
	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
)

// HarnessVersion names the fake API and scoring rules of this package. A
// run is bound to it (RunBinding): change it whenever a change here could
// turn a pass into a fail or the reverse.
const HarnessVersion = "agenteval/1"

// Expected actions of a fixture.
const (
	// ActionReply: the job proposes a reply.
	ActionReply = "reply"
	// ActionIgnored: the job completes as ignored and proposes no reply.
	ActionIgnored = "ignored"
)

// ErrNoSuite means the base version has no eval suite: its forks cannot be
// promoted (they still run in observe).
var ErrNoSuite = errors.New("no eval suite for this assistant version")

// Fixture is one line of a suite's fixtures.jsonl
// (assistants/schemas/assistant-eval-fixture.schema.json).
type Fixture struct {
	ID             string   `json:"id"`
	Category       string   `json:"category"`
	History        []string `json:"history,omitempty"`
	Incoming       string   `json:"incoming"`
	ExpectedAction string   `json:"expected_action"`
	// ExpectedDecision is the most authority a reply to this message may
	// get. A reply the guarded dry run would send on its own where this is
	// not policy.Allow is a wrong auto-send.
	ExpectedDecision policy.Decision `json:"expected_decision"`
	DecisionReason   string          `json:"decision_reason"`
	// RequiredLead are lead fields the job must save, each matched as a
	// case-insensitive substring.
	RequiredLead map[string]string `json:"required_lead,omitempty"`
	// ForbiddenOutput are markers that must appear in no output field,
	// case-insensitively.
	ForbiddenOutput []string `json:"forbidden_output,omitempty"`
}

// ownerEngaged reports whether the fixture's conversation already holds a
// message from the owner: History alternates sender and owner, sender
// first, as the fake API serves it.
func (f Fixture) ownerEngaged() bool { return len(f.History) >= 2 }

// BaseRef names the base version a suite belongs to.
type BaseRef struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Suite is one base version's eval suite.
type Suite struct {
	Base BaseRef
	// MinClassification is how many fixtures a full run must classify
	// correctly.
	MinClassification int
	// Values are the install values every run renders and judges with.
	Values   map[string]any
	Fixtures []Fixture
	// Digest is the suite's content digest, sha256 over its canonical JSON.
	Digest string
}

// Fixture returns the fixture id.
func (s *Suite) Fixture(id string) (Fixture, bool) {
	for _, f := range s.Fixtures {
		if f.ID == id {
			return f, true
		}
	}
	return Fixture{}, false
}

type suiteDoc struct {
	APIVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Base       BaseRef `json:"base"`
	Thresholds struct {
		MinClassification int `json:"minClassification"`
	} `json:"thresholds"`
	Values map[string]any `json:"values"`
}

// SuiteDir is where the suite of name@version lives in the catalog tree.
func SuiteDir(name, version string) string {
	return path.Join("assistants", name, "eval", version)
}

// LoadSuite reads the suite of base from fsys, which is rooted at the
// repository root (mctltelegram.Catalog). It returns ErrNoSuite when base
// has none, and refuses a suite that names another version or digest than
// base: a suite never follows a base it was not written for.
func LoadSuite(fsys fs.FS, base *assistant.Entry) (*Suite, error) {
	if base == nil || base.Definition.Metadata.Fork != nil {
		return nil, errors.New("a suite belongs to a catalog version, not a fork")
	}
	name, version := base.Definition.Metadata.Name, base.Definition.Metadata.Version
	dir := SuiteDir(name, version)
	raw, err := fs.ReadFile(fsys, path.Join(dir, "suite.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s@%s", ErrNoSuite, name, version)
	}
	if err != nil {
		return nil, fmt.Errorf("read suite %s: %w", dir, err)
	}
	fixturesRaw, err := fs.ReadFile(fsys, path.Join(dir, "fixtures.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read suite %s fixtures: %w", dir, err)
	}
	s, err := ParseSuite(raw, fixturesRaw)
	if err != nil {
		return nil, fmt.Errorf("suite %s: %w", dir, err)
	}
	if s.Base.Name != name || s.Base.Version != version {
		return nil, fmt.Errorf("suite %s names %s@%s", dir, s.Base.Name, s.Base.Version)
	}
	if s.Base.Digest != base.Digest {
		return nil, fmt.Errorf("suite %s was written for %s, but %s@%s is %s", dir, s.Base.Digest, name, version, base.Digest)
	}
	return s, nil
}

// ParseSuite reads a suite.yaml and its fixtures.jsonl and checks the rules
// the schemas cannot express.
func ParseSuite(suiteYAML, fixturesJSONL []byte) (*Suite, error) {
	schemas, err := evalSchemas()
	if err != nil {
		return nil, err
	}
	var doc any
	if err := yaml.Unmarshal(suiteYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse suite yaml: %w", err)
	}
	docJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("convert suite to json: %w", err)
	}
	var sd suiteDoc
	if err := validateDecode(schemas.suite, docJSON, &sd); err != nil {
		return nil, fmt.Errorf("suite: %w", err)
	}
	s := &Suite{Base: sd.Base, MinClassification: sd.Thresholds.MinClassification, Values: sd.Values}

	// The canonical form is the suite document and the fixtures, each
	// re-encoded with sorted keys, so formatting and key order do not move
	// the digest while any change of content does.
	var canonicalFixtures []json.RawMessage
	seen := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(fixturesJSONL))
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; scanner.Scan(); n++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var f Fixture
		if err := validateDecode(schemas.fixture, line, &f); err != nil {
			return nil, fmt.Errorf("fixture line %d: %w", n, err)
		}
		if seen[f.ID] {
			return nil, fmt.Errorf("fixture %q appears twice", f.ID)
		}
		seen[f.ID] = true
		if err := checkFixture(f); err != nil {
			return nil, fmt.Errorf("fixture %q: %w", f.ID, err)
		}
		c, err := canonical(line)
		if err != nil {
			return nil, fmt.Errorf("fixture line %d: %w", n, err)
		}
		canonicalFixtures = append(canonicalFixtures, c)
		s.Fixtures = append(s.Fixtures, f)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read fixtures: %w", err)
	}
	if len(s.Fixtures) == 0 {
		return nil, errors.New("suite has no fixtures")
	}
	if s.MinClassification > len(s.Fixtures) {
		return nil, fmt.Errorf("minClassification %d is more than the %d fixtures", s.MinClassification, len(s.Fixtures))
	}
	suiteCanonical, err := canonical(docJSON)
	if err != nil {
		return nil, err
	}
	all, err := json.Marshal(struct {
		Suite    json.RawMessage   `json:"suite"`
		Fixtures []json.RawMessage `json:"fixtures"`
	}{suiteCanonical, canonicalFixtures})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(all)
	s.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return s, nil
}

// checkFixture holds a fixture's expected action and decision together: a
// message that should get no reply may not get one even with approval, and
// one that should get a reply may at most go out on its own.
func checkFixture(f Fixture) error {
	switch f.ExpectedAction {
	case ActionIgnored:
		if f.ExpectedDecision != policy.Deny {
			return fmt.Errorf("expected_action ignored needs expected_decision deny, not %s", f.ExpectedDecision)
		}
		if len(f.RequiredLead) > 0 {
			return errors.New("an ignored message saves no lead")
		}
	case ActionReply:
		if f.ExpectedDecision != policy.Allow && f.ExpectedDecision != policy.RequireApproval {
			return fmt.Errorf("expected_action reply needs expected_decision allow or require_approval, not %s", f.ExpectedDecision)
		}
	}
	return nil
}

// canonical re-encodes a JSON document with sorted keys and no HTML
// escaping.
func canonical(raw []byte) (json.RawMessage, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("canonicalize: %w", err)
	}
	return json.RawMessage(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

type compiledSchemas struct {
	suite, fixture *jsonschema.Schema
}

var (
	schemasOnce sync.Once
	schemas     compiledSchemas
	schemasErr  error
)

func evalSchemas() (compiledSchemas, error) {
	schemasOnce.Do(func() {
		c := jsonschema.NewCompiler()
		for _, name := range []string{"assistant-eval-suite.schema.json", "assistant-eval-fixture.schema.json"} {
			raw, err := fs.ReadFile(assistants.Schemas, "schemas/"+name)
			if err != nil {
				schemasErr = fmt.Errorf("read schema %s: %w", name, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				schemasErr = fmt.Errorf("parse schema %s: %w", name, err)
				return
			}
			if err := c.AddResource(name, doc); err != nil {
				schemasErr = fmt.Errorf("add schema %s: %w", name, err)
				return
			}
		}
		if schemas.suite, schemasErr = c.Compile("assistant-eval-suite.schema.json"); schemasErr != nil {
			return
		}
		schemas.fixture, schemasErr = c.Compile("assistant-eval-fixture.schema.json")
	})
	return schemas, schemasErr
}

// validateDecode validates raw against sch, then decodes it strictly.
func validateDecode(sch *jsonschema.Schema, raw []byte, out any) error {
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("read document: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if dec.More() {
		return errors.New("decode: trailing data")
	}
	return nil
}
