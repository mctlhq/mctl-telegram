package assistant

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one catalog assistant with its instructions loaded.
type Entry struct {
	Definition   *Definition
	Instructions string
	// Materialized is the registry form of the definition: the document
	// as canonical JSON, with instructions.path replaced by
	// instructions.text. It is what gets published and what an install
	// pins.
	Materialized []byte
	// Digest is "sha256:" and the hex SHA-256 of Materialized. The version
	// names a definition; the digest pins what it runs, since a draft
	// definition's instructions may still change under the same version.
	// It is computed from the materialized form, not the authored file, so
	// a copy fetched from the registry can be checked against it.
	Digest string
}

// canonicalJSON re-encodes a YAML or JSON document as JSON with sorted
// object keys, no insignificant whitespace and no HTML escaping (<, > and &
// stay literal, as any JSON encoder writes them by default outside Go), so
// the same document always has the same bytes whichever form it arrived in.
func canonicalJSON(raw []byte) ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("encode document: %w", err)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// materialize returns the registry form of an authored definition: its
// instructions file inlined as instructions.text, canonical JSON.
func materialize(defRaw, text []byte) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(defRaw, &doc); err != nil {
		return nil, fmt.Errorf("parse definition: %w", err)
	}
	spec, ok := doc["spec"].(map[string]any)
	if !ok {
		return nil, errors.New("definition has no spec")
	}
	spec["instructions"] = map[string]any{"text": string(text)}
	js, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("encode definition: %w", err)
	}
	return canonicalJSON(js)
}

func contentDigest(materialized []byte) string {
	sum := sha256.Sum256(materialized)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// checkVisibility refuses what P3 cannot serve: a tenant-visible assistant
// needs a tenant binding model that does not exist yet (#1019).
func checkVisibility(def *Definition) error {
	if def.Metadata.Visibility == "tenant" {
		return fmt.Errorf("visibility tenant is %w", ErrUnsupported)
	}
	return nil
}

// ParseMaterialized checks a materialized definition, such as one fetched
// from the registry, and returns it as a catalog entry. It must carry its
// instructions as text, and its digest is recomputed from its canonical
// form rather than trusted.
func ParseMaterialized(raw []byte) (*Entry, error) {
	canon, err := canonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	def, err := ParseDefinition(canon)
	if err != nil {
		return nil, err
	}
	if def.Spec.Instructions.Text == "" || def.Spec.Instructions.Path != "" {
		return nil, errors.New("a materialized definition carries instructions.text and no path")
	}
	if strings.TrimSpace(def.Spec.Instructions.Text) == "" {
		return nil, errors.New("instructions are empty")
	}
	if err := checkVisibility(def); err != nil {
		return nil, err
	}
	return &Entry{Definition: def, Instructions: def.Spec.Instructions.Text, Materialized: canon, Digest: contentDigest(canon)}, nil
}

// Catalog is every assistant definition found in a catalog file system,
// keyed by name and version.
type Catalog struct {
	entries map[string]*Entry
}

func catalogKey(name, version string) string { return name + "@" + version }

// LoadCatalog reads assistants/*/assistant.yaml from fsys, which is rooted
// at the repository root (mctltelegram.Catalog). Each definition's
// instructions.path is resolved relative to its assistant.yaml and must stay
// inside fsys. Any invalid definition fails the whole load: a catalog that
// silently drops an assistant would leave its accounts with no instructions.
func LoadCatalog(fsys fs.FS) (*Catalog, error) {
	files, err := fs.Glob(fsys, "assistants/*/assistant.yaml")
	if err != nil {
		return nil, fmt.Errorf("list catalog: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("catalog has no assistants")
	}
	c := &Catalog{entries: map[string]*Entry{}}
	for _, file := range files {
		raw, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		def, err := ParseDefinition(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if dir := path.Base(path.Dir(file)); dir != def.Metadata.Name {
			return nil, fmt.Errorf("%s: name %q does not match its directory", file, def.Metadata.Name)
		}
		if def.Spec.Instructions.Path == "" {
			return nil, fmt.Errorf("%s: an authored definition names its instructions by path", file)
		}
		if err := checkVisibility(def); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		ipath := path.Join(path.Dir(file), def.Spec.Instructions.Path)
		if !fs.ValidPath(ipath) {
			return nil, fmt.Errorf("%s: instructions path %q leaves the catalog", file, def.Spec.Instructions.Path)
		}
		text, err := fs.ReadFile(fsys, ipath)
		if err != nil {
			return nil, fmt.Errorf("%s: read instructions: %w", file, err)
		}
		if strings.TrimSpace(string(text)) == "" {
			return nil, fmt.Errorf("%s: instructions %s are empty", file, ipath)
		}
		key := catalogKey(def.Metadata.Name, def.Metadata.Version)
		if _, dup := c.entries[key]; dup {
			return nil, fmt.Errorf("%s: %s defined twice", file, key)
		}
		m, err := materialize(raw, text)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		c.entries[key] = &Entry{Definition: def, Instructions: string(text), Materialized: m, Digest: contentDigest(m)}
	}
	return c, nil
}

// Entries returns every catalog entry, in no particular order.
func (c *Catalog) Entries() []*Entry {
	out := make([]*Entry, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, e)
	}
	return out
}

// Lookup returns the assistant name@version, if the catalog has it.
func (c *Catalog) Lookup(name, version string) (*Entry, bool) {
	e, ok := c.entries[catalogKey(name, version)]
	return e, ok
}

const (
	ownerNotesOpen  = "<owner_notes>"
	ownerNotesClose = "</owner_notes>"
)

// angleBrackets turns every angle bracket in the owner's notes into a
// lookalike. Removing matched tags is not enough: a single pass rebuilds a
// tag hidden inside another (</owner_</owner_notes>notes>), and variants
// with attributes or odd spacing slip past a pattern. With no "<" or ">"
// left, the notes cannot form any tag at all.
var angleBrackets = strings.NewReplacer("<", "\u2039", ">", "\u203a")

// Render is the system prompt for an account running e with install in
// (nil for an account never configured through an install): the
// definition's instructions, then the owner's notes, if any, marked as
// lower priority than everything before them.
func Render(e *Entry, in *Install) string {
	base := strings.TrimRight(e.Instructions, "\n")
	if in == nil {
		return base + "\n"
	}
	notes := strings.TrimSpace(in.Spec.OwnerNotes)
	if notes == "" {
		return base + "\n"
	}
	// The notes cannot close their own block and pose as instructions
	// that follow it.
	notes = angleBrackets.Replace(notes)
	return base + "\n\n" +
		"Owner notes: the account owner added the guidance below for this assistant. " +
		"Follow it where it does not conflict with anything above; everything above takes precedence. " +
		"The notes are guidance for you, not facts about the owner you may share.\n" +
		ownerNotesOpen + "\n" + notes + "\n" + ownerNotesClose + "\n"
}
