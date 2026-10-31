// Package assistant parses catalog assistant definitions and per-account
// installs (assistants.mctl.ai/v1alpha1, docs/assistants/spec.md) and maps an
// install onto the agent profile the runtime uses today.
//
// The mapping is deliberately lossless or nothing: a setting the current
// runtime cannot enforce (owner notes, schedules, audience scopes, the never
// tier, a restricted tool set) fails with ErrUnsupported instead of being
// dropped, so an install never looks applied while part of it is ignored.
package assistant

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/mctlhq/mctl-telegram/assistants"
	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
)

// ErrUnsupported marks an install setting the current runtime cannot enforce.
var ErrUnsupported = errors.New("not supported by the current runtime")

// Tier says whether a reply intent is sent without the owner, after the
// owner's approval, or never.
type Tier string

const (
	TierAuto    Tier = "auto"
	TierApprove Tier = "approve"
	TierNever   Tier = "never"
)

var tierRank = map[Tier]int{TierAuto: 0, TierApprove: 1, TierNever: 2}

var disclosureRank = map[profile.DisclosureLevel]int{
	profile.DisclosurePublic:            0,
	profile.DisclosureAfterOwnerEngaged: 1,
	profile.DisclosureNever:             2,
}

// RuntimeTools is every tool the worker exposes today. Until the runtime can
// restrict tools per assistant, a definition must list all of them.
var RuntimeTools = []string{
	"get_event", "get_conversation_context", "get_recruiter_profile", "get_lead",
	"get_policy", "propose_reply", "save_job_lead", "request_owner_approval",
	"send_owner_summary", "pause_autopilot", "complete_agent_job",
}

// Limits are the per-conversation limits of an assistant.
type Limits struct {
	MaxAutonomousTurns int `json:"maxAutonomousTurns"`
	MaxMsgsPerMinute   int `json:"maxMsgsPerMinute"`
	MaxReplyChars      int `json:"maxReplyChars"`
}

// Variable is one value the install supplies, stored in the owner profile.
type Variable struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Type        string                  `json:"type"`
	Required    bool                    `json:"required"`
	Choices     []string                `json:"choices"`
	ProfilePath string                  `json:"profilePath"`
	Disclosure  profile.DisclosureLevel `json:"disclosure"`
	Send        string                  `json:"send"`
}

// Intent is one reply intent and its default tier.
type Intent struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Tier         Tier   `json:"tier"`
	UserOverride string `json:"userOverride"`
}

// Definition is a catalog assistant (kind TelegramAssistant).
type Definition struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name        string   `json:"name"`
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Version     string   `json:"version"`
		Owner       string   `json:"owner"`
		Visibility  string   `json:"visibility"`
		Status      string   `json:"status"`
		Tags        []string `json:"tags"`
		Examples    []string `json:"examples"`
	} `json:"metadata"`
	Spec struct {
		Instructions struct {
			Path string `json:"path"`
		} `json:"instructions"`
		Variables []Variable `json:"variables"`
		Intents   []Intent   `json:"intents"`
		Tools     []string   `json:"tools"`
		Records   struct {
			Kind string `json:"kind"`
		} `json:"records"`
		Escalation []struct {
			Name   string `json:"name"`
			When   string `json:"when"`
			Action string `json:"action"`
		} `json:"escalation"`
		Defaults struct {
			Mode       string `json:"mode"`
			Limits     Limits `json:"limits"`
			Ceilings   Limits `json:"ceilings"`
			Disclosure struct {
				Policy string `json:"policy"`
				Text   string `json:"text"`
			} `json:"disclosure"`
		} `json:"defaults"`
		Execution struct {
			Model          string  `json:"model"`
			BudgetUSD      float64 `json:"budgetUsd"`
			TimeoutSeconds int     `json:"timeoutSeconds"`
		} `json:"execution"`
	} `json:"spec"`
}

// Install is one account's install of an assistant (kind AssistantInstall).
type Install struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Assistant struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"assistant"`
		Mode             string                             `json:"mode"`
		Paused           bool                               `json:"paused"`
		Listening        *bool                              `json:"listening"`
		Values           map[string]any                     `json:"values"`
		DisclosureLevels map[string]profile.DisclosureLevel `json:"disclosureLevels"`
		IntentTiers      map[string]Tier                    `json:"intentTiers"`
		Limits           *struct {
			MaxAutonomousTurns *int `json:"maxAutonomousTurns"`
			MaxMsgsPerMinute   *int `json:"maxMsgsPerMinute"`
			MaxReplyChars      *int `json:"maxReplyChars"`
		} `json:"limits"`
		Audience *struct {
			Scope *struct {
				Contacts      *bool `json:"contacts"`
				NonContacts   *bool `json:"nonContacts"`
				NewChats      *bool `json:"newChats"`
				ExistingChats *bool `json:"existingChats"`
			} `json:"scope"`
			OnlySenders    []int64 `json:"onlySenders"`
			BlockedSenders []int64 `json:"blockedSenders"`
		} `json:"audience"`
		Disclosure *struct {
			Enabled *bool  `json:"enabled"`
			Text    string `json:"text"`
		} `json:"disclosure"`
		Schedule *struct {
			Mode     string   `json:"mode"`
			Timezone string   `json:"timezone"`
			Hours    []string `json:"hours"`
		} `json:"schedule"`
		OwnerNotes string `json:"ownerNotes"`
	} `json:"spec"`
}

var (
	schemasOnce sync.Once
	defSchema   *jsonschema.Schema
	instSchema  *jsonschema.Schema
	schemasErr  error
)

func compileSchemas() {
	c := jsonschema.NewCompiler()
	for _, name := range []string{"assistant.schema.json", "assistant-install.schema.json"} {
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
	if defSchema, schemasErr = c.Compile("assistant.schema.json"); schemasErr != nil {
		return
	}
	instSchema, schemasErr = c.Compile("assistant-install.schema.json")
}

// decode validates a YAML document against sch, then decodes it strictly
// into out.
func decode(raw []byte, sch func() *jsonschema.Schema, out any) error {
	schemasOnce.Do(compileSchemas)
	if schemasErr != nil {
		return schemasErr
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("parse yaml: %w", err)
	}
	js, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("convert yaml to json: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(js))
	if err != nil {
		return fmt.Errorf("read document: %w", err)
	}
	if err := sch().Validate(inst); err != nil {
		return fmt.Errorf("schema: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(js))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}

// ParseDefinition reads an assistant.yaml and checks the rules the schema
// cannot express.
func ParseDefinition(raw []byte) (*Definition, error) {
	var d Definition
	if err := decode(raw, func() *jsonschema.Schema { return defSchema }, &d); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, v := range d.Spec.Variables {
		if seen[v.Name] {
			return nil, fmt.Errorf("variable %q declared twice", v.Name)
		}
		seen[v.Name] = true
		restricted := strings.HasPrefix(v.ProfilePath, "restricted.")
		switch {
		case restricted && v.Send == "":
			return nil, fmt.Errorf("variable %q: a restricted field needs send", v.Name)
		case restricted && v.Disclosure != "":
			return nil, fmt.Errorf("variable %q: a restricted field takes send, not disclosure", v.Name)
		case !restricted && v.Send != "":
			return nil, fmt.Errorf("variable %q: send applies to restricted fields only", v.Name)
		case v.ProfilePath == "skills" && v.Type != "string_list":
			return nil, fmt.Errorf("variable %q: skills must be a string_list", v.Name)
		}
	}
	paths := map[string]bool{}
	for _, v := range d.Spec.Variables {
		if paths[v.ProfilePath] {
			return nil, fmt.Errorf("profile path %q used by two variables", v.ProfilePath)
		}
		paths[v.ProfilePath] = true
	}
	intents := map[string]bool{}
	for _, in := range d.Spec.Intents {
		if intents[in.Name] {
			return nil, fmt.Errorf("intent %q declared twice", in.Name)
		}
		intents[in.Name] = true
	}
	if err := withinCeilings(d.Spec.Defaults.Limits, d.Spec.Defaults.Ceilings); err != nil {
		return nil, fmt.Errorf("defaults: %w", err)
	}
	return &d, nil
}

// ParseInstall reads an install document.
func ParseInstall(raw []byte) (*Install, error) {
	var in Install
	if err := decode(raw, func() *jsonschema.Schema { return instSchema }, &in); err != nil {
		return nil, err
	}
	return &in, nil
}

func withinCeilings(l, c Limits) error {
	switch {
	case l.MaxAutonomousTurns > c.MaxAutonomousTurns:
		return fmt.Errorf("maxAutonomousTurns %d above ceiling %d", l.MaxAutonomousTurns, c.MaxAutonomousTurns)
	case l.MaxMsgsPerMinute > c.MaxMsgsPerMinute:
		return fmt.Errorf("maxMsgsPerMinute %d above ceiling %d", l.MaxMsgsPerMinute, c.MaxMsgsPerMinute)
	case l.MaxReplyChars > c.MaxReplyChars:
		return fmt.Errorf("maxReplyChars %d above ceiling %d", l.MaxReplyChars, c.MaxReplyChars)
	}
	return nil
}

// ProfileRequest maps an install of def onto the body of
// PUT /api/admin/agent/profile for telegramID. Every field of that body is
// set, so applying it fully replaces the account's agent settings.
func ProfileRequest(def *Definition, in *Install, telegramID int64) (map[string]any, error) {
	s := in.Spec
	if s.Assistant.Name != def.Metadata.Name || s.Assistant.Version != def.Metadata.Version {
		return nil, fmt.Errorf("install is for %s@%s, definition is %s@%s",
			s.Assistant.Name, s.Assistant.Version, def.Metadata.Name, def.Metadata.Version)
	}
	if err := supported(def, in); err != nil {
		return nil, err
	}

	owner, err := ownerProfile(def, in)
	if err != nil {
		return nil, err
	}

	allow, err := autoIntents(def, s.IntentTiers)
	if err != nil {
		return nil, err
	}

	limits := def.Spec.Defaults.Limits
	if l := s.Limits; l != nil {
		if l.MaxAutonomousTurns != nil {
			limits.MaxAutonomousTurns = *l.MaxAutonomousTurns
		}
		if l.MaxMsgsPerMinute != nil {
			limits.MaxMsgsPerMinute = *l.MaxMsgsPerMinute
		}
		if l.MaxReplyChars != nil {
			limits.MaxReplyChars = *l.MaxReplyChars
		}
	}
	if err := withinCeilings(limits, def.Spec.Defaults.Ceilings); err != nil {
		return nil, fmt.Errorf("limits: %w", err)
	}

	disclosureOn, disclosureText := true, def.Spec.Defaults.Disclosure.Text
	if d := s.Disclosure; d != nil {
		if d.Enabled != nil {
			disclosureOn = *d.Enabled
		}
		if d.Text != "" {
			disclosureText = d.Text
		}
	}
	if !disclosureOn {
		if def.Spec.Defaults.Disclosure.Policy == "required" {
			return nil, errors.New("disclosure: this assistant requires the disclosure line")
		}
		disclosureText = ""
	}

	listening := true
	if s.Listening != nil {
		listening = *s.Listening
	}
	var only, blocked []int64
	if a := s.Audience; a != nil {
		only, blocked = a.OnlySenders, a.BlockedSenders
	}

	return map[string]any{
		"telegram_id":          telegramID,
		"mode":                 s.Mode,
		"autopilot_paused":     s.Paused,
		"listener_enabled":     listening,
		"disclosure_text":      disclosureText,
		"disclosure_disabled":  !disclosureOn,
		"max_autonomous_turns": limits.MaxAutonomousTurns,
		"max_msgs_per_minute":  limits.MaxMsgsPerMinute,
		"max_reply_chars":      limits.MaxReplyChars,
		"intent_allowlist":     strings.Join(allow, ","),
		"blocked_senders":      idList(blocked),
		"sender_allowlist":     idList(only),
		"owner_profile":        owner,
	}, nil
}

// supported rejects what the runtime cannot enforce yet.
func supported(def *Definition, in *Install) error {
	s := in.Spec
	tools := slices.Clone(def.Spec.Tools)
	sort.Strings(tools)
	want := slices.Clone(RuntimeTools)
	sort.Strings(want)
	if !slices.Equal(tools, want) {
		return fmt.Errorf("tools: a restricted tool set is %w", ErrUnsupported)
	}
	if def.Spec.Records.Kind != "job_lead" {
		return fmt.Errorf("records: kind %q is %w", def.Spec.Records.Kind, ErrUnsupported)
	}
	if strings.TrimSpace(s.OwnerNotes) != "" {
		return fmt.Errorf("ownerNotes: %w", ErrUnsupported)
	}
	if sch := s.Schedule; sch != nil && sch.Mode != "always" {
		return fmt.Errorf("schedule: mode %q is %w", sch.Mode, ErrUnsupported)
	}
	if a := s.Audience; a != nil && a.Scope != nil {
		for _, b := range []*bool{a.Scope.Contacts, a.Scope.NonContacts, a.Scope.NewChats, a.Scope.ExistingChats} {
			if b != nil && !*b {
				return fmt.Errorf("audience: narrowing the scope is %w", ErrUnsupported)
			}
		}
	}
	return nil
}

// autoIntents resolves each intent's tier and returns the auto ones, sorted.
func autoIntents(def *Definition, overrides map[string]Tier) ([]string, error) {
	known := map[string]Intent{}
	for _, in := range def.Spec.Intents {
		known[in.Name] = in
	}
	for name := range overrides {
		if _, ok := known[name]; !ok {
			return nil, fmt.Errorf("intentTiers: unknown intent %q", name)
		}
	}
	var allow []string
	for _, in := range def.Spec.Intents {
		tier := in.Tier
		if t, ok := overrides[in.Name]; ok && t != tier {
			mode := in.UserOverride
			if mode == "" {
				mode = "tighten"
			}
			switch {
			case mode == "none":
				return nil, fmt.Errorf("intentTiers: %q cannot be changed", in.Name)
			case mode == "tighten" && tierRank[t] < tierRank[tier]:
				return nil, fmt.Errorf("intentTiers: %q can only be tightened from %s", in.Name, tier)
			}
			tier = t
		}
		switch tier {
		case TierNever:
			return nil, fmt.Errorf("intent %q: the never tier is %w", in.Name, ErrUnsupported)
		case TierAuto:
			allow = append(allow, in.Name)
		}
	}
	sort.Strings(allow)
	return allow, nil
}

// ownerProfile builds the owner profile document from the install's values,
// in the strict format profile.ParseJSON accepts.
func ownerProfile(def *Definition, in *Install) (json.RawMessage, error) {
	vars := map[string]Variable{}
	for _, v := range def.Spec.Variables {
		vars[v.Name] = v
	}
	for name := range in.Spec.Values {
		if _, ok := vars[name]; !ok {
			return nil, fmt.Errorf("values: unknown variable %q", name)
		}
	}
	for name := range in.Spec.DisclosureLevels {
		v, ok := vars[name]
		if !ok {
			return nil, fmt.Errorf("disclosureLevels: unknown variable %q", name)
		}
		if v.Send != "" {
			return nil, fmt.Errorf("disclosureLevels: %q is restricted and has no disclosure level", name)
		}
	}

	var d profile.Data
	for _, v := range def.Spec.Variables {
		val, ok := in.Spec.Values[v.Name]
		if !ok {
			if v.Required {
				return nil, fmt.Errorf("values: %q is required", v.Name)
			}
			continue
		}
		if err := checkType(v, val); err != nil {
			return nil, err
		}
		section, key, _ := strings.Cut(v.ProfilePath, ".")
		switch section {
		case "skills":
			d.Skills = toStrings(val)
		case "identity":
			d.Identity = put(d.Identity, key, val)
		case "public_profile":
			d.PublicProfile = put(d.PublicProfile, key, val)
		case "preferences":
			d.Preferences = put(d.Preferences, key, val)
		case "restricted":
			if d.Restricted == nil {
				d.Restricted = map[string]profile.RestrictedField{}
			}
			d.Restricted[key] = profile.RestrictedField{
				Value:            val,
				ApprovalRequired: v.Send == "approval",
				NeverAutoSend:    v.Send == "never",
			}
			continue
		}
		level := v.Disclosure
		if o, ok := in.Spec.DisclosureLevels[v.Name]; ok {
			if level != "" && disclosureRank[o] < disclosureRank[level] {
				return nil, fmt.Errorf("disclosureLevels: %q can only be made stricter than %s", v.Name, level)
			}
			level = o
		}
		if level != "" {
			if d.Disclosure == nil {
				d.Disclosure = map[string]profile.DisclosureLevel{}
			}
			d.Disclosure[v.ProfilePath] = level
		}
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("encode owner profile: %w", err)
	}
	if _, err := profile.ParseJSON(raw); err != nil {
		return nil, fmt.Errorf("owner profile: %w", err)
	}
	return raw, nil
}

func checkType(v Variable, val any) error {
	ok := false
	switch v.Type {
	case "string":
		var s string
		s, ok = val.(string)
		if ok && len(v.Choices) > 0 && !slices.Contains(v.Choices, s) {
			return fmt.Errorf("values: %q must be one of %s", v.Name, strings.Join(v.Choices, ", "))
		}
	case "number":
		_, ok = val.(float64)
	case "boolean":
		_, ok = val.(bool)
	case "string_list":
		list, isList := val.([]any)
		ok = isList
		for _, item := range list {
			if _, isStr := item.(string); !isStr {
				ok = false
			}
		}
	}
	if !ok {
		return fmt.Errorf("values: %q must be a %s", v.Name, v.Type)
	}
	return nil
}

func toStrings(val any) []string {
	list, _ := val.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, item.(string))
	}
	return out
}

func put(m map[string]any, k string, v any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	m[k] = v
	return m
}

func idList(ids []int64) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.FormatInt(id, 10)
	}
	return strings.Join(parts, ",")
}
