package agenteval

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// ErrNothingToPromote means the definition has no propose_reply: guarded
// mode is the same as observe for it, so a run would certify nothing.
var ErrNothingToPromote = errors.New("nothing_to_promote: the definition cannot propose a reply")

// The fake conversation every fixture runs in.
const (
	evalUserID         = 1
	evalConversationID = 1
	evalPeerTGID       = 555
)

// Adaptation is how the suite's checks follow the definition's tool set.
// It is derived from the tools alone; nobody edits fixtures for a fork.
type Adaptation struct {
	// CheckLeads is false when the definition has no save_job_lead: the
	// lead-field check is skipped, the action is still checked.
	CheckLeads bool
}

// Target is a definition prepared for a run against its base's suite: the
// prompt the worker gets, the tool set the fake API enforces, and the
// guarded profile the dry run judges replies with.
type Target struct {
	// Entry is the definition under test: a catalog version or a fork.
	Entry *assistant.Entry
	// Base is the catalog version whose suite applies: Entry itself, or
	// the fork's base.
	Base  *assistant.Entry
	Suite *Suite
	// Instructions is the system prompt, rendered from the suite's values
	// with no ownerNotes.
	Instructions string
	// JobTools names the tools as the definition calls them, for the job
	// envelope; Tools is the canonical set the fake API enforces.
	JobTools   []string
	Tools      []string
	Adaptation Adaptation

	profile db.AgentProfile
	owner   profile.Data
}

// Prepare checks that entry is base or a valid fork of it and that s is
// base's suite, and prepares the run. It returns ErrNothingToPromote for a
// definition without propose_reply.
func Prepare(entry, base *assistant.Entry, s *Suite) (*Target, error) {
	if entry == nil || base == nil || s == nil {
		return nil, errors.New("entry, base and suite are required")
	}
	if base.Definition.Metadata.Fork != nil {
		return nil, errors.New("the base must be a catalog version, not a fork")
	}
	if s.Base.Digest != base.Digest || s.Base.Name != base.Definition.Metadata.Name || s.Base.Version != base.Definition.Metadata.Version {
		return nil, fmt.Errorf("suite belongs to %s@%s (%s), not %s@%s (%s)", s.Base.Name, s.Base.Version, s.Base.Digest,
			base.Definition.Metadata.Name, base.Definition.Metadata.Version, base.Digest)
	}
	if fork := entry.Definition.Metadata.Fork; fork != nil {
		if fork.Base.Digest != base.Digest {
			return nil, fmt.Errorf("fork narrows %s, not %s", fork.Base.Digest, base.Digest)
		}
		if err := assistant.ValidateFork(base, entry); err != nil {
			return nil, fmt.Errorf("fork does not narrow its base: %w", err)
		}
	} else if entry.Digest != base.Digest {
		return nil, fmt.Errorf("%s is neither the base nor a fork of it", entry.Digest)
	}

	bindings, err := tools.ForJob(entry.Definition.Spec.Tools)
	if err != nil {
		return nil, fmt.Errorf("tools: %w", err)
	}
	canonical := tools.CanonicalNames(bindings)
	if !slices.Contains(canonical, "propose_reply") {
		return nil, ErrNothingToPromote
	}

	in, err := suiteInstall(entry, s)
	if err != nil {
		return nil, err
	}
	p, err := assistant.Resolve(entry.Definition, in)
	if err != nil {
		return nil, fmt.Errorf("resolve the suite's install: %w", err)
	}
	owner, err := profile.ParseJSON(p.OwnerProfile)
	if err != nil {
		return nil, fmt.Errorf("owner profile from the suite's values: %w", err)
	}
	return &Target{
		Entry: entry, Base: base, Suite: s,
		Instructions: assistant.Render(entry, in),
		JobTools:     entry.Definition.Spec.Tools,
		Tools:        canonical,
		Adaptation:   Adaptation{CheckLeads: slices.Contains(canonical, "save_job_lead")},
		profile: db.AgentProfile{
			UserID:             evalUserID,
			Mode:               p.Mode,
			AutopilotPaused:    p.AutopilotPaused,
			ListenerEnabled:    p.ListenerEnabled,
			DisclosureText:     p.DisclosureText,
			DisclosureDisabled: p.DisclosureDisabled,
			MaxAutonomousTurns: p.MaxAutonomousTurns,
			MaxMsgsPerMinute:   p.MaxMsgsPerMinute,
			MaxReplyChars:      p.MaxReplyChars,
			IntentAllowlist:    p.IntentAllowlist,
			IntentDenylist:     p.IntentDenylist,
			WorkingHours:       p.WorkingHours,
			AudienceExcludes:   p.AudienceExcludes,
			BlockedSenders:     p.BlockedSenders,
			SenderAllowlist:    p.SenderAllowlist,
			AssistantName:      entry.Definition.Metadata.Name,
		},
		owner: owner,
	}, nil
}

// suiteInstall is the install every run uses: entry in guarded mode,
// running, with the suite's values and nothing else. Limits, tiers,
// disclosure and audience are the definition's own defaults, which its
// ceilings already bound, and there are no ownerNotes.
func suiteInstall(entry *assistant.Entry, s *Suite) (*assistant.Install, error) {
	raw, err := json.Marshal(map[string]any{
		"apiVersion": "assistants.mctl.ai/v1alpha1",
		"kind":       "AssistantInstall",
		"spec": map[string]any{
			"assistant": map[string]any{
				"name":    entry.Definition.Metadata.Name,
				"version": entry.Definition.Metadata.Version,
			},
			"mode":      db.AgentModeGuarded,
			"paused":    false,
			"listening": true,
			"values":    s.Values,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("build the suite's install: %w", err)
	}
	in, err := assistant.ParseInstall(raw)
	if err != nil {
		return nil, fmt.Errorf("the suite's install: %w", err)
	}
	return in, nil
}
