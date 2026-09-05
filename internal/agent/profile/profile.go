// Package profile validates owner-profile documents and exposes the
// non-restricted parts to the agent surface. Runtime documents are encrypted
// per tenant in agent_profiles; the YAML reader exists only to import the
// legacy AGENT_PROFILE_PATH format once.
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// RestrictedField is one entry under the profile's restricted section. A
// field with ApprovalRequired must never be included in an autonomous
// (guarded-mode) reply — only ever surfaced via an owner-approved one.
// NeverAutoSend is the stricter marker: not even an approved reply may
// include it verbatim; the owner must have typed it themselves.
type RestrictedField struct {
	Value            any  `json:"value" yaml:"value"`
	ApprovalRequired bool `json:"approval_required" yaml:"approval_required"`
	NeverAutoSend    bool `json:"never_auto_send" yaml:"never_auto_send"`
}

// Data is the parsed shape of the profile YAML file.
type Data struct {
	Identity      map[string]any             `json:"identity,omitempty" yaml:"identity"`
	PublicProfile map[string]any             `json:"public_profile,omitempty" yaml:"public_profile"`
	Skills        []string                   `json:"skills,omitempty" yaml:"skills"`
	Preferences   map[string]any             `json:"preferences,omitempty" yaml:"preferences"`
	Restricted    map[string]RestrictedField `json:"restricted,omitempty" yaml:"restricted"`
}

// Provider reads the legacy YAML format. Runtime callers use TenantProvider;
// this type remains for validation and one-time migration.
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
	// KnownFields(true), not a plain Decode: a Codex finding on #307 caught
	// that a misspelled safety marker (never_auto_sent, approval_require,
	// ...) under a restricted-section entry silently decoded as an unknown
	// key yaml ignores — the value would still MATCH in MatchRestricted
	// (its `value` field is spelled correctly), but with both marker
	// booleans defaulting false, restrictedFieldBlocks would let it
	// auto-send with no enforcement at all, and no startup or reload error
	// would ever reveal the typo. Strict decoding fails closed on any
	// unrecognized field name instead.
	d, err := ParseYAML(raw)
	if err != nil {
		return fmt.Errorf("parse profile %s: %w", p.path, err)
	}
	p.mu.Lock()
	p.data = d
	p.mu.Unlock()
	return nil
}

// ParseYAML validates the legacy mounted-file format. It remains exported for
// the one-time database migration path; runtime reads use encrypted JSON from
// the tenant's agent_profiles row.
func ParseYAML(raw []byte) (Data, error) {
	var d Data
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return Data{}, err
	}
	normalizeData(&d)
	return d, nil
}

// ParseJSON validates the admin/API storage format. DisallowUnknownFields
// catches misspelled safety markers such as never_auto_sent instead of
// silently defaulting them to false.
func ParseJSON(raw []byte) (Data, error) {
	var d Data
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return Data{}, fmt.Errorf("profile document must be a JSON object")
	}
	if err := RejectDuplicateJSONKeys(trimmed); err != nil {
		return Data{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	// Keep the exact numeric token. Decoding into any as float64 would turn
	// 1000000 into 1e+06 and round integers above 2^53, allowing the original
	// restricted literal to evade verbatim send-time matching.
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Data{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return Data{}, fmt.Errorf("profile document must contain exactly one JSON object")
		}
		return Data{}, err
	}
	normalizeData(&d)
	return d, nil
}

// RejectDuplicateJSONKeys validates duplicate-free JSON objects recursively.
// It is also used by the admin handler on the complete request envelope before
// decoding can collapse duplicate tenant selectors or owner_profile fields.
func RejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("profile object key must be a string")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return fmt.Errorf("invalid profile object")
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return fmt.Errorf("invalid profile array")
			}
		default:
			return fmt.Errorf("unexpected profile delimiter %q", delim)
		}
		return nil
	}

	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("profile document must contain exactly one JSON object")
		}
		return err
	}
	return nil
}

// normalizeData recursively converts every map[interface{}]interface{} that
// older YAML decoders produce for nested objects into map[string]interface{}
// — encoding/json cannot marshal the former at all, so a profile with any
// nested object under identity/public_profile/preferences (not just flat
// key: value pairs) would make GET /recruiters/{peer}'s writeJSON silently
// emit a truncated body once it hit the unmarshalable value. yaml.v3
// already emits map[string]interface{}, so this is a no-op for current
// input and keeps the JSON path safe if a nested value is still a
// map[interface{}]interface{}.
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
	return matchRestricted(p.data, text)
}

func matchRestricted(data Data, text string) (key string, neverAutoSend, approvalRequired, matched bool) {
	bestRank := -1
	for k, f := range data.Restricted {
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
		// Go map iteration order is unspecified, and returning on the FIRST
		// match found a Codex finding on #307 caught: if a draft happens to
		// echo two (or more) different restricted fields at once, whichever
		// one the map iteration visits first used to win outright. Rank
		// every match — never_auto_send (2) outranks approval_required-only
		// (1) outranks a field with neither marker set (0) — and keep
		// scanning for a strictly higher rank, so the strongest applicable
		// restriction is always the one returned regardless of iteration
		// order. An earlier version of this fix only special-cased
		// never_auto_send, which a follow-up Codex finding on #307 caught
		// still lost approval_required to an unmarked entry visited first:
		// restrictedFieldBlocks only checks approvalRequired at all when
		// neverAutoSend is false, so returning an unmarked match (both
		// false) let an approval-gated value auto-send unreviewed.
		rank := 0
		if f.ApprovalRequired {
			rank = 1
		}
		if f.NeverAutoSend {
			rank = 2
		}
		if rank > bestRank {
			key, neverAutoSend, approvalRequired, matched = k, f.NeverAutoSend, f.ApprovalRequired, true
			bestRank = rank
		}
	}
	return key, neverAutoSend, approvalRequired, matched
}

// PublicProfile implements agentapi.OwnerProfileProvider. peerTGID is
// accepted but currently unused — kept in the interface (see #296's
// OwnerProfileProvider doc comment) for a future per-recruiter variant
// (e.g. hiding preferences from a recruiter at a company on a do-not-engage
// list) without another interface break.
func (p *Provider) PublicProfile(peerTGID int64) (map[string]any, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return publicProfile(p.data), nil
}

func publicProfile(data Data) map[string]any {
	out := make(map[string]any, 4)
	if len(data.Identity) > 0 {
		out["identity"] = data.Identity
	}
	if len(data.PublicProfile) > 0 {
		out["public_profile"] = data.PublicProfile
	}
	if len(data.Skills) > 0 {
		out["skills"] = data.Skills
	}
	if len(data.Preferences) > 0 {
		out["preferences"] = data.Preferences
	}
	// data.Restricted is deliberately never added to out.
	return out
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

// CanonicalJSON returns the loaded legacy profile in the strict encrypted-DB
// format. It is used only by the startup import path.
func (p *Provider) CanonicalJSON() ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return json.Marshal(p.data)
}

// TenantStore is the narrow encrypted-document storage contract implemented
// by db.Store.
type TenantStore interface {
	GetAgentOwnerProfile(ctx context.Context, userID int64) ([]byte, error)
}

// TenantProvider resolves every profile by authenticated internal user id.
// It has no process-wide owner identity and therefore cannot accidentally
// expose or enforce one tenant's data for another tenant.
type TenantProvider struct {
	store TenantStore
}

func NewTenantProvider(store TenantStore) *TenantProvider {
	return &TenantProvider{store: store}
}

func (p *TenantProvider) load(ctx context.Context, userID int64) (Data, error) {
	raw, err := p.store.GetAgentOwnerProfile(ctx, userID)
	if err != nil {
		return Data{}, err
	}
	d, err := ParseJSON(raw)
	if err != nil {
		return Data{}, fmt.Errorf("parse encrypted owner profile: %w", err)
	}
	return d, nil
}

// PublicProfile returns only safe fields for the authenticated tenant.
func (p *TenantProvider) PublicProfile(ctx context.Context, userID, peerTGID int64) (map[string]any, error) {
	d, err := p.load(ctx, userID)
	if err != nil {
		return nil, err
	}
	return publicProfile(d), nil
}

// MatchRestricted evaluates restricted values for the action's tenant. A
// storage/decryption/validation error is returned so the executor can fail
// closed before sending.
func (p *TenantProvider) MatchRestricted(ctx context.Context, userID int64, text string) (key string, neverAutoSend, approvalRequired, matched bool, err error) {
	d, err := p.load(ctx, userID)
	if err != nil {
		return "", false, false, false, err
	}
	key, neverAutoSend, approvalRequired, matched = matchRestricted(d, text)
	return key, neverAutoSend, approvalRequired, matched, nil
}
