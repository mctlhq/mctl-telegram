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
	p.mu.Lock()
	p.data = d
	p.mu.Unlock()
	return nil
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
