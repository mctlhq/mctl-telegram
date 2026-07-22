// Package profile reads the owner's YAML profile — identity, public
// biography, skills, preferences, and a restricted section — from a mounted
// file (AGENT_PROFILE_PATH) and exposes the non-restricted parts to the
// agent surface via agentapi.OwnerProfileProvider.
//
// The restricted section (current compensation, references, anything the
// owner marked approval_required or never_auto_send) is parsed so the
// control/executor layer can consult it, but PublicProfile — the only
// method the agent-facing HTTP API calls — never returns it. This is the
// enforcement point for "restricted fields are NEVER returned on the agent
// surface": the omission happens here, once, rather than relying on every
// caller to remember to filter.
package profile

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// RestrictedField is one entry under the profile's restricted section. A
// field with ApprovalRequired must never be included in an autonomous
// (guarded-mode) reply — only ever surfaced via an owner-approved one.
// NeverAutoSend is the stricter marker: not even an approved reply may
// include it verbatim; the owner must have typed it themselves.
type RestrictedField struct {
	Value            any  `yaml:"value"`
	ApprovalRequired bool `yaml:"approval_required"`
	NeverAutoSend    bool `yaml:"never_auto_send"`
}

// Data is the parsed shape of the profile YAML file.
type Data struct {
	Identity      map[string]any             `yaml:"identity"`
	PublicProfile map[string]any             `yaml:"public_profile"`
	Skills        []string                   `yaml:"skills"`
	Preferences   map[string]any             `yaml:"preferences"`
	Restricted    map[string]RestrictedField `yaml:"restricted"`
}

// Provider implements agentapi.OwnerProfileProvider over a loaded Data.
// Safe for concurrent use; Reload swaps the in-memory copy under a lock so a
// config change does not require a process restart.
type Provider struct {
	path string
	mu   sync.RWMutex
	data Data
}

// Load reads and parses the profile at path. Returns an error if the file
// is missing or is not valid YAML — a communication agent deployment with
// AGENT_PROFILE_PATH set is expected to have a real profile, so failing
// loudly at startup is preferable to silently running with an empty one.
func Load(path string) (*Provider, error) {
	p := &Provider{path: path}
	if err := p.Reload(); err != nil {
		return nil, err
	}
	return p, nil
}

// Reload re-reads the profile file from disk, replacing the in-memory copy
// atomically on success. On error the previous copy is left in place.
func (p *Provider) Reload() error {
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("read profile %s: %w", p.path, err)
	}
	var d Data
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("parse profile %s: %w", p.path, err)
	}
	normalizeData(&d)
	p.mu.Lock()
	p.data = d
	p.mu.Unlock()
	return nil
}

// normalizeData recursively converts every map[interface{}]interface{} that
// yaml.v2 produces for nested YAML objects into map[string]interface{} —
// encoding/json cannot marshal the former at all, so a profile with any
// nested object under identity/public_profile/preferences (not just flat
// key: value pairs) would make GET /recruiters/{peer}'s writeJSON silently
// emit a truncated body once it hit the unmarshalable value.
func normalizeData(d *Data) {
	d.Identity = normalizeMap(d.Identity)
	d.PublicProfile = normalizeMap(d.PublicProfile)
	d.Preferences = normalizeMap(d.Preferences)
	for k, f := range d.Restricted {
		f.Value = normalizeValue(f.Value)
		d.Restricted[k] = f
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
	switch vv := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]any, len(vv))
		for k, val := range vv {
			out[fmt.Sprint(k)] = normalizeValue(val)
		}
		return out
	case map[string]interface{}:
		return normalizeMap(vv)
	case []interface{}:
		for i, val := range vv {
			vv[i] = normalizeValue(val)
		}
		return vv
	default:
		return v
	}
}

// MatchRestricted reports the first restricted-section entry (if any) whose
// value appears verbatim in text — the executor's send-time gate for
// never_auto_send/approval_required, since the DB-backed policy engine
// (internal/agent/policy) has no notion of this YAML-only concept.
//
// Non-string values (e.g. current_salary: 145000) are matched against their
// default string representation (fmt.Sprint) — this only catches the exact
// numeric literal, not every way a draft might phrase it ("$145k" won't
// match "145000"), but that's strictly better than the field never being
// enforced at all. A prior version of this function skipped non-string
// values outright on the reasoning that formatted matching would be
// "unreliable" and deferred enforcement to "any caller that checks by key" —
// no such caller existed anywhere in this codebase, which a Codex finding on
// #307 caught: it meant every non-string restricted field was silently
// unenforced, full stop, not deferred to some other gate.
func (p *Provider) MatchRestricted(text string) (key string, neverAutoSend, approvalRequired, matched bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for k, f := range p.data.Restricted {
		if f.Value == nil {
			continue
		}
		s, ok := f.Value.(string)
		if !ok {
			s = fmt.Sprint(f.Value)
		}
		if s == "" || !strings.Contains(text, s) {
			continue
		}
		return k, f.NeverAutoSend, f.ApprovalRequired, true
	}
	return "", false, false, false
}

// PublicProfile implements agentapi.OwnerProfileProvider. peerTGID is
// accepted but currently unused — kept in the interface (see #296's
// OwnerProfileProvider doc comment) for a future per-recruiter variant
// (e.g. hiding preferences from a recruiter at a company on a do-not-engage
// list) without another interface break.
func (p *Provider) PublicProfile(peerTGID int64) (map[string]any, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]any, 4)
	if len(p.data.Identity) > 0 {
		out["identity"] = p.data.Identity
	}
	if len(p.data.PublicProfile) > 0 {
		out["public_profile"] = p.data.PublicProfile
	}
	if len(p.data.Skills) > 0 {
		out["skills"] = p.data.Skills
	}
	if len(p.data.Preferences) > 0 {
		out["preferences"] = p.data.Preferences
	}
	// data.Restricted is deliberately never added to out.
	return out, nil
}

// RestrictedField returns the named restricted-section entry, for the
// executor/control layer to consult (e.g. before letting a guarded-mode
// auto-send through, or to warn if a draft appears to quote a
// never_auto_send value) — never called from the agent-facing HTTP surface.
func (p *Provider) RestrictedField(key string) (RestrictedField, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	f, ok := p.data.Restricted[key]
	return f, ok
}
