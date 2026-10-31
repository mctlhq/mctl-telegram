package assistant

import (
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
)

// Private forks (docs/assistants/adr-forks.md, #1043). A fork is an
// account-private TelegramAssistant that narrows exactly one catalog
// version, its base: its own instructions, fewer tools, stricter intents,
// lower limits. Its document is complete, so it parses, materializes and
// hashes like any definition; ValidateFork holds it to the base.

// MaxForkInstructionsBytes caps a fork's instructions, in bytes of UTF-8.
const MaxForkInstructionsBytes = 16 << 10

// ForkRef names the catalog version a fork narrows.
type ForkRef struct {
	Base struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Digest  string `json:"digest"`
	} `json:"base"`
}

var (
	forkSlugPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	catalogNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	ownerScopePattern  = regexp.MustCompile(`^[a-z2-7]{10}$`)
)

// ForkSeparator joins the parts of a fork name. A catalog name cannot hold
// it, so no fork name can be mistaken for a catalog one.
const ForkSeparator = "~"

// IsForkName reports whether name is a fork's.
func IsForkName(name string) bool { return strings.Contains(name, ForkSeparator) }

// ValidForkSlug reports whether slug may name a fork.
func ValidForkSlug(slug string) bool { return forkSlugPattern.MatchString(slug) }

// ForkName is <base>~<owner-scope>~<slug>.
func ForkName(base, scope, slug string) string {
	return base + ForkSeparator + scope + ForkSeparator + slug
}

// ParseForkName splits a fork name into its base, owner scope and slug.
func ParseForkName(name string) (base, scope, slug string, err error) {
	parts := strings.Split(name, ForkSeparator)
	if len(parts) != 3 || !catalogNamePattern.MatchString(parts[0]) ||
		!ownerScopePattern.MatchString(parts[1]) || !forkSlugPattern.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("%q is not a fork name <base>~<owner-scope>~<slug>", name)
	}
	return parts[0], parts[1], parts[2], nil
}

// OwnerScope is the owner-scope of a fork name: the first 10 characters of
// mac in lowercase base32. mac is the server's HMAC of the account id, so
// the scope names an account without revealing it.
func OwnerScope(mac []byte) (string, error) {
	enc := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(mac))
	if len(enc) < 10 {
		return "", errors.New("owner scope: digest too short")
	}
	return enc[:10], nil
}

// ForkOwner is metadata.owner of a fork with this owner scope.
func ForkOwner(scope string) string { return "acct:" + scope }

// checkForkMetadata holds a fork's name, visibility, owner and fork
// reference together, so neither a fork nor a catalog definition can be
// passed off as the other.
func checkForkMetadata(d *Definition) error {
	m := d.Metadata
	fork := IsForkName(m.Name)
	switch {
	case fork != (m.Fork != nil):
		return errors.New("metadata: a fork name and metadata.fork go together")
	case fork != (m.Visibility == "private"):
		return errors.New("metadata: visibility private is a fork's, and a fork's is private")
	case !fork:
		return nil
	}
	base, scope, _, err := ParseForkName(m.Name)
	if err != nil {
		return fmt.Errorf("metadata: %w", err)
	}
	if base != m.Fork.Base.Name {
		return fmt.Errorf("metadata: fork name names base %q, metadata.fork names %q", base, m.Fork.Base.Name)
	}
	if m.Owner != ForkOwner(scope) {
		return errors.New("metadata: a fork's owner is acct:<owner-scope> of its name")
	}
	return nil
}

// ForkOverrides are the changes a fork makes to what it starts from. A nil
// or empty field keeps the starting value.
type ForkOverrides struct {
	// Instructions replace the instructions text.
	Instructions *string
	// Intents replace the intent list as a whole.
	Intents []Intent
	// Tools replace the tool list as a whole.
	Tools []string
	// Limits and Ceilings replace defaults.limits and defaults.ceilings.
	Limits   *Limits
	Ceilings *Limits
	// DisclosurePolicy replaces defaults.disclosure.policy.
	DisclosurePolicy string
}

// Empty reports whether ov changes nothing.
func (ov ForkOverrides) Empty() bool {
	return ov.Instructions == nil && ov.Intents == nil && ov.Tools == nil &&
		ov.Limits == nil && ov.Ceilings == nil && ov.DisclosurePolicy == ""
}

// BuildFork returns the fork version name@version of base: from, the
// document it starts from (base itself for a new fork, the fork's latest
// version for an edit), with ov applied and the fork metadata set. The
// result has passed ParseMaterialized and ValidateFork.
func BuildFork(base, from *Entry, name, version string, ov ForkOverrides) (*Entry, error) {
	if base.Definition.Metadata.Fork != nil {
		return nil, errors.New("a fork's base must be a catalog assistant, not another fork")
	}
	_, scope, _, err := ParseForkName(name)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(from.Materialized, &doc); err != nil {
		return nil, fmt.Errorf("decode definition: %w", err)
	}
	meta, _ := doc["metadata"].(map[string]any)
	spec, _ := doc["spec"].(map[string]any)
	if meta == nil || spec == nil {
		return nil, errors.New("definition has no metadata or spec")
	}
	b := base.Definition.Metadata
	meta["name"] = name
	meta["version"] = version
	meta["owner"] = ForkOwner(scope)
	meta["visibility"] = "private"
	meta["status"] = "active"
	meta["fork"] = map[string]any{"base": map[string]any{"name": b.Name, "version": b.Version, "digest": base.Digest}}

	if ov.Instructions != nil {
		spec["instructions"] = map[string]any{"text": *ov.Instructions}
	}
	if ov.Intents != nil {
		spec["intents"] = ov.Intents
	}
	if ov.Tools != nil {
		spec["tools"] = ov.Tools
	}
	defaults, _ := spec["defaults"].(map[string]any)
	if defaults == nil {
		return nil, errors.New("definition has no defaults")
	}
	if ov.Limits != nil {
		defaults["limits"] = ov.Limits
	}
	if ov.Ceilings != nil {
		defaults["ceilings"] = ov.Ceilings
	}
	if ov.DisclosurePolicy != "" {
		disclosure, _ := defaults["disclosure"].(map[string]any)
		if disclosure == nil {
			return nil, errors.New("definition has no disclosure defaults")
		}
		disclosure["policy"] = ov.DisclosurePolicy
	}
	js, err := json.Marshal(intentsOmitEmpty(doc))
	if err != nil {
		return nil, fmt.Errorf("encode fork: %w", err)
	}
	canon, err := canonicalJSON(js)
	if err != nil {
		return nil, err
	}
	fork, err := ParseMaterialized(canon)
	if err != nil {
		return nil, err
	}
	if err := ValidateFork(base, fork); err != nil {
		return nil, err
	}
	return fork, nil
}

// intentsOmitEmpty drops the empty optional members an Intent marshals
// (description, userOverride), which the schema would otherwise read as
// set: an empty userOverride is not one of its values.
func intentsOmitEmpty(doc map[string]any) map[string]any {
	spec, _ := doc["spec"].(map[string]any)
	in, ok := spec["intents"].([]Intent)
	if !ok {
		return doc
	}
	out := make([]map[string]any, 0, len(in))
	for _, i := range in {
		m := map[string]any{"name": i.Name, "tier": i.Tier}
		if i.Description != "" {
			m["description"] = i.Description
		}
		if i.UserOverride != "" {
			m["userOverride"] = i.UserOverride
		}
		out = append(out, m)
	}
	spec["intents"] = out
	return doc
}

// ownerNotesDelimiter matches the owner-notes block markers, whatever the
// case or spacing, so fork instructions cannot open or close that block.
var ownerNotesDelimiter = regexp.MustCompile(`(?i)<\s*/?\s*owner_notes`)

var userOverrideRank = map[string]int{"any": 0, "tighten": 1, "none": 2}

func overrideRank(mode string) int {
	if mode == "" {
		mode = "tighten"
	}
	return userOverrideRank[mode]
}

// ValidateFork checks that fork only narrows base, its declared base
// (docs/assistants/adr-forks.md, "What a fork may change in P4"). Both have
// already passed ParseMaterialized. It never quotes the instructions.
func ValidateFork(base, fork *Entry) error {
	b, f := base.Definition, fork.Definition
	ref := f.Metadata.Fork
	// A fork is never a base: metadata.fork.base.name is a catalog name by
	// the schema, so it cannot name a fork, and the reference check below
	// refuses one.
	switch {
	case ref == nil:
		return errors.New("fork: metadata.fork is missing")
	case ref.Base.Name != b.Metadata.Name || ref.Base.Version != b.Metadata.Version || ref.Base.Digest != base.Digest:
		return errors.New("fork: metadata.fork does not name this base")
	case f.Metadata.Status != "active":
		return errors.New("fork: a fork version's status is active")
	}

	// Instructions.
	if n := len(fork.Instructions); n > MaxForkInstructionsBytes {
		return fmt.Errorf("fork: instructions are %d bytes, above the %d-byte cap", n, MaxForkInstructionsBytes)
	}
	if ownerNotesDelimiter.MatchString(fork.Instructions) {
		return errors.New("fork: instructions may not contain the owner_notes delimiters")
	}

	// Intents: equal or stricter, and a new one never auto.
	baseIntents := map[string]Intent{}
	for _, in := range b.Spec.Intents {
		baseIntents[in.Name] = in
	}
	forkIntents := map[string]bool{}
	for _, in := range f.Spec.Intents {
		forkIntents[in.Name] = true
		was, ok := baseIntents[in.Name]
		if !ok {
			if in.Tier == TierAuto {
				return fmt.Errorf("fork: new intent %q may only be approve or never", in.Name)
			}
			// userOverride any would let an install's intentTiers raise
			// it to auto, the user-defined auto intent the ADR forbids.
			if overrideRank(in.UserOverride) < userOverrideRank["tighten"] {
				return fmt.Errorf("fork: new intent %q: userOverride may only be tighten or none", in.Name)
			}
			continue
		}
		if tierRank[in.Tier] < tierRank[was.Tier] {
			return fmt.Errorf("fork: intent %q can only be made stricter than %s", in.Name, was.Tier)
		}
		if overrideRank(in.UserOverride) < overrideRank(was.UserOverride) {
			return fmt.Errorf("fork: intent %q: userOverride can only be narrowed", in.Name)
		}
		// The base author defined what the intent covers; an auto tier rests
		// on that meaning.
		if in.Description != was.Description {
			return fmt.Errorf("fork: intent %q keeps the base's description", in.Name)
		}
	}

	// Leaving an intent out makes it unknown, and an unknown intent never
	// auto-sends, but it is not refused either: a reply labelled with a
	// left-out never intent would go to owner approval, never → approve.
	for _, in := range b.Spec.Intents {
		if in.Tier == TierNever && !forkIntents[in.Name] {
			return fmt.Errorf("fork: intent %q is never in the base and cannot be left out", in.Name)
		}
	}

	// Tools: a subset of the base's.
	bt, err := tools.Resolve(b.Spec.Tools)
	if err != nil {
		return fmt.Errorf("fork: base tools: %w", err)
	}
	ft, err := tools.Resolve(f.Spec.Tools)
	if err != nil {
		return fmt.Errorf("fork: tools: %w", err)
	}
	baseTools := tools.CanonicalNames(bt)
	for _, t := range ft {
		if !slices.Contains(baseTools, t.Canonical) {
			return fmt.Errorf("fork: tool %q is not one of the base's", t.Name)
		}
	}

	// Limits within the base's ceilings.
	if err := withinCeilings(f.Spec.Defaults.Limits, b.Spec.Defaults.Ceilings); err != nil {
		return fmt.Errorf("fork: limits: %w", err)
	}
	if err := withinCeilings(f.Spec.Defaults.Ceilings, b.Spec.Defaults.Ceilings); err != nil {
		return fmt.Errorf("fork: ceilings: %w", err)
	}

	// Disclosure: optional may become required, never the reverse; the
	// text is the base's.
	bd, fd := b.Spec.Defaults.Disclosure, f.Spec.Defaults.Disclosure
	if bd.Policy == "required" && fd.Policy != "required" {
		return errors.New("fork: disclosure policy cannot be weaker than the base's")
	}
	if fd.Text != bd.Text {
		return errors.New("fork: disclosure text is the base's")
	}

	// Variables: the base's, with a disclosure level made stricter at most.
	if len(f.Spec.Variables) != len(b.Spec.Variables) {
		return errors.New("fork: variables are the base's; a fork adds or removes none")
	}
	for i, fv := range f.Spec.Variables {
		bv := b.Spec.Variables[i]
		fl, bl := fv.Disclosure, bv.Disclosure
		fv.Disclosure, bv.Disclosure = "", ""
		if !reflect.DeepEqual(fv, bv) {
			return fmt.Errorf("fork: variable %q is the base's", bv.Name)
		}
		fv.Disclosure, bv.Disclosure = fl, bl
		if bv.Send == "" && disclosureRank[disclosureFloor(fv)] < disclosureRank[disclosureFloor(bv)] {
			return fmt.Errorf("fork: variable %q: disclosure can only be made stricter", bv.Name)
		}
	}

	// Everything else is inherited unchanged.
	same := func(what string, x, y any) error {
		if !reflect.DeepEqual(x, y) {
			return fmt.Errorf("fork: %s is the base's", what)
		}
		return nil
	}
	for _, c := range []struct {
		what string
		x, y any
	}{
		{"apiVersion", f.APIVersion, b.APIVersion},
		{"tags", f.Metadata.Tags, b.Metadata.Tags},
		{"examples", f.Metadata.Examples, b.Metadata.Examples},
		{"records", f.Spec.Records, b.Spec.Records},
		{"escalation", f.Spec.Escalation, b.Spec.Escalation},
		{"execution", f.Spec.Execution, b.Spec.Execution},
		{"defaults.mode", f.Spec.Defaults.Mode, b.Spec.Defaults.Mode},
	} {
		if err := same(c.what, c.x, c.y); err != nil {
			return err
		}
	}
	return nil
}

// Fork version bumps.
const (
	BumpPatch = "patch"
	BumpMinor = "minor"
)

// FirstForkVersion is a new fork's version.
const FirstForkVersion = "0.1.0"

// ForkBump is the bump from prev to next, two versions of one fork: patch
// when only the instructions differ, minor when anything else does (the
// authority diff). "" when nothing differs.
func ForkBump(prev, next *Entry) (string, error) {
	strip := func(e *Entry, instructions bool) (map[string]any, error) {
		var doc map[string]any
		if err := json.Unmarshal(e.Materialized, &doc); err != nil {
			return nil, fmt.Errorf("decode definition: %w", err)
		}
		if meta, ok := doc["metadata"].(map[string]any); ok {
			delete(meta, "version")
		}
		if spec, ok := doc["spec"].(map[string]any); ok && instructions {
			delete(spec, "instructions")
		}
		return doc, nil
	}
	pa, err := strip(prev, false)
	if err != nil {
		return "", err
	}
	na, err := strip(next, false)
	if err != nil {
		return "", err
	}
	if reflect.DeepEqual(pa, na) {
		return "", nil
	}
	pb, _ := strip(prev, true)
	nb, _ := strip(next, true)
	if reflect.DeepEqual(pb, nb) {
		return BumpPatch, nil
	}
	return BumpMinor, nil
}

// NextForkVersion applies bump to version (MAJOR.MINOR.PATCH).
func NextForkVersion(version, bump string) (string, error) {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
	}
	n := make([]int, 3)
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return "", fmt.Errorf("version %q is not MAJOR.MINOR.PATCH", version)
		}
		n[i] = v
	}
	switch bump {
	case BumpPatch:
		n[2]++
	case BumpMinor:
		n[1], n[2] = n[1]+1, 0
	default:
		return "", fmt.Errorf("unknown bump %q", bump)
	}
	return fmt.Sprintf("%d.%d.%d", n[0], n[1], n[2]), nil
}

// VersionLess orders MAJOR.MINOR.PATCH versions numerically.
func VersionLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, errx := strconv.Atoi(pa[i])
		y, erry := strconv.Atoi(pb[i])
		if errx != nil || erry != nil {
			return a < b
		}
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}
