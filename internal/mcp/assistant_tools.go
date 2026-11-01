package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// The assistant catalog tools (#1021): list_assistants, install_assistant
// and update_install. Every one acts on the caller's own account; there is
// no telegram_id argument. The install logic is assistantinstall.Service,
// the same one behind PUT /api/admin/agent/install, so the tools have no
// semantics of their own beyond self-service: only public, non-draft
// assistants, except the one the account already runs.
//
// No output of these tools carries an install's values or ownerNotes, nor
// a definition's instructions: an install is reported by the settings it
// resolved to. Neither do the audit rows, which hold only the error kind.

// WithAssistants wires the install service behind the catalog tools. nil
// (the default, and any deployment without AGENT_ENABLED) makes them
// refuse.
func (s *Server) WithAssistants(svc *assistantinstall.Service) *Server {
	s.Assistants = svc
	return s
}

// installArgKeys are the install_assistant arguments copied into the
// AssistantInstall spec as they are; their shapes are the schema's
// (assistants/schemas/assistant-install.schema.json).
var installArgKeys = []string{
	"mode", "runtime", "paused", "listening", "values", "disclosureLevels", "intentTiers",
	"limits", "audience", "disclosure", "schedule", "ownerNotes",
}

// assistantInstalled is the caller's own install, without the install.
type assistantInstalled struct {
	// Assistant and Version are "" when the account has no agent profile.
	// A profile never configured through an install still names the
	// default assistant, with Installed false.
	Assistant       string `json:"assistant"`
	Version         string `json:"version"`
	InstallRevision int64  `json:"install_revision"`
	Installed       bool   `json:"installed"`
	// Runtime is "own" or "managed" (ADR 0008); ManagedReconsentRequired is
	// true for a managed account that consented to an older consent version.
	Runtime                  string `json:"runtime"`
	ManagedReconsentRequired bool   `json:"managed_reconsent_required"`
}

type listAssistantsResult struct {
	// Source is "registry" or "embedded".
	Source     string                          `json:"source"`
	Assistants []assistantinstall.CatalogEntry `json:"assistants"`
	Mine       assistantInstalled              `json:"mine"`
	// Forks are the caller's own private forks (#1043), never anyone
	// else's, listed apart from the catalog.
	Forks []assistantinstall.ForkSummary `json:"forks"`
}

// installSettings is what an install resolved to; see
// assistantinstall.Settings.
type installSettings = assistantinstall.Settings

type installAssistantResult struct {
	Assistant       string          `json:"assistant"`
	Version         string          `json:"version"`
	InstallRevision int64           `json:"install_revision"`
	Settings        installSettings `json:"settings"`
}

func installResult(res *assistantinstall.Result) installAssistantResult {
	return installAssistantResult{
		Assistant: res.Name, Version: res.Version, InstallRevision: res.Profile.InstallRevision,
		Settings: assistantinstall.SettingsOf(res.Profile),
	}
}

// assistantErrResult answers an install service error as a JSON envelope:
// {error, message, retryable, current_revision?}. message never quotes an
// install value (assistantinstall.Error.Msg). The audit row gets only the
// error code.
func (s *Server) assistantErrResult(ctx context.Context, tool string, err error) (*mcplib.CallToolResult, error) {
	code, reason, retryable := "internal_error", ReasonStoreError, false
	msg := "internal error"
	var current *int64
	var ie *assistantinstall.Error
	if errors.As(err, &ie) {
		msg = ie.Msg
		switch ie.Kind {
		case assistantinstall.KindInvalid:
			code, reason = "invalid_install", ReasonInvalidArgument
		case assistantinstall.KindNotFound:
			code, reason = "assistant_not_found", ReasonNotFound
		case assistantinstall.KindLifecycle:
			code, reason = "lifecycle_refused", ReasonRefused
		case assistantinstall.KindRevisionConflict:
			code, reason = "revision_conflict", ReasonRefused
			current = &ie.CurrentRevision
		case assistantinstall.KindNoInstall:
			code, reason = "no_install", ReasonRefused
		case assistantinstall.KindUpstream:
			code, reason = "registry_invalid", ReasonHandlerError
		case assistantinstall.KindUnavailable:
			code, reason, retryable = "registry_unavailable", ReasonHandlerError, true
			msg = "assistant registry unavailable; nothing changed, retry in a minute"
		case assistantinstall.KindForkLimit:
			code, reason = "fork_limit", ReasonRefused
		case assistantinstall.KindForkInUse:
			code, reason = "fork_in_use", ReasonRefused
		case assistantinstall.KindForkConflict:
			code, reason, retryable = "fork_conflict", ReasonRefused, true
		case assistantinstall.KindForksDisabled:
			code, reason = "forks_disabled", ReasonCapabilityDisabled
		case assistantinstall.KindManagedConsentRequired:
			code, reason = "managed_consent_required", ReasonRefused
		case assistantinstall.KindManagedDisabled:
			code, reason = "managed_disabled", ReasonCapabilityDisabled
		case assistantinstall.KindManagedQuota:
			code, reason = "managed_quota", ReasonRefused
		}
		if ie.Err != nil {
			slog.Warn("mcp assistant tool error", "tool", tool, "code", code, "err", ie.Err)
		}
	} else {
		slog.Warn("mcp assistant tool error", "tool", tool, "err", err)
	}
	hintReason(ctx, reason)
	env := map[string]any{"error": code, "message": msg, "retryable": retryable}
	if current != nil {
		env["current_revision"] = *current
		env["action"] = "Nothing changed. Call list_assistants to see the current install, then retry with expected_revision set to current_revision."
	}
	if code == "managed_consent_required" {
		env["action"] = "Nothing changed. Show the user this text: \"" + db.ManagedConsentText + "\" If they agree, retry with consent set to \"" + db.ManagedConsentCurrent + "\"."
	}
	b, mErr := json.Marshal(env)
	if mErr != nil {
		return mcplib.NewToolResultError(msg), nil
	}
	return mcplib.NewToolResultError(string(b)), nil
}

func (s *Server) assistantsUnavailable(ctx context.Context) (*mcplib.CallToolResult, error) {
	hintReason(ctx, ReasonCapabilityDisabled)
	return mcplib.NewToolResultError("assistants are not enabled on this server"), nil
}

// toolListAssistants lists the installable catalog and the caller's own
// install reference.
func (s *Server) toolListAssistants() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("list_assistants",
		mcplib.WithTitleAnnotation("List assistants you can install"),
		mcplib.WithReadOnlyHintAnnotation(true),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[listAssistantsResult](),
		mcplib.WithDescription(`List the assistants YOUR Telegram account can install, and which one it runs now. No arguments; always about the caller's own account.

Output: {source, assistants, mine, forks}.
  source — "registry" (the mctl assistant registry) or "embedded" (the catalog built into this server).
  assistants — [{name, version, title, description, tags, examples, lifecycle, variables: [{name, type, required, default?, choices?, description}], intents: [{name, description, tier}], defaults: {mode, limits: {maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}, disclosure_policy}}], by name, highest version first.
  mine — {assistant, version, install_revision, installed, runtime, managed_reconsent_required}. installed=false means the account was never configured through an install. runtime is "own" (your own worker runs the jobs) or "managed" (a platform worker does); managed_reconsent_required is true for a managed account that consented to an older consent version. Pass install_revision as expected_revision to update_install.
  forks — your own private forks (fork_assistant), never anyone else's: [{name, base: {name, version, digest}, latest, versions: [{name, version, digest, base, promotion}]}]. Install one with install_assistant by its full name and a version.

Never returns your stored values, owner notes, an assistant's instructions or a fork's instructions. If the registry cannot be read, the call fails with error "registry_unavailable" (retryable) rather than returning an empty list.`),
	)
	handler := func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if id == nil {
			return mcplib.NewToolResultError("authentication required"), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "list_assistants", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		source, entries, err := s.Assistants.ListCatalog(ctx)
		if err != nil {
			s.audit(ctx, id, "list_assistants", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "list_assistants", err)
		}
		mine, err := s.Assistants.Current(ctx, id.UserID)
		if err != nil {
			s.audit(ctx, id, "list_assistants", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "list_assistants", err)
		}
		if entries == nil {
			entries = []assistantinstall.CatalogEntry{}
		}
		forks, err := s.Assistants.ListForks(ctx, id.UserID)
		if err != nil {
			s.audit(ctx, id, "list_assistants", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "list_assistants", err)
		}
		s.audit(ctx, id, "list_assistants", "", nil, startedAt)
		return jsonResult(listAssistantsResult{
			Source: source, Assistants: entries,
			Mine: assistantInstalled{Assistant: mine.Assistant, Version: mine.Version, InstallRevision: mine.InstallRevision, Installed: mine.Installed,
				Runtime: mine.Runtime, ManagedReconsentRequired: mine.ManagedReconsentRequired},
			Forks: forks,
		})
	}
	return tool, handler
}

// assistantErrCode is the audit text of a failed call: the error kind,
// never the message, which for a validation error names variables.
func assistantErrCode(err error) string { return assistantinstall.AuditText(err) }

// expectedRevisionArg reads expected_revision: absent is (nil, true); a
// non-integer or a value below 1 is (nil, false).
func expectedRevisionArg(args map[string]any) (*int64, bool) {
	v, ok := args["expected_revision"]
	if !ok || v == nil {
		return nil, true
	}
	var n int64
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) {
			return nil, false
		}
		n = int64(x)
	case int:
		n = int64(x)
	case int64:
		n = x
	case json.Number:
		i, err := x.Int64()
		if err != nil {
			return nil, false
		}
		n = i
	default:
		return nil, false
	}
	if n < 1 {
		return nil, false
	}
	return &n, true
}

// unknownArgs returns the arguments not in allowed, sorted.
func unknownArgs(args map[string]any, allowed ...string) []string {
	var out []string
	for k := range args {
		known := false
		for _, a := range allowed {
			if k == a {
				known = true
				break
			}
		}
		if !known {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) toolInstallAssistant() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("install_assistant",
		mcplib.WithTitleAnnotation("Install an assistant on your account"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[installAssistantResult](),
		mcplib.WithDescription(`Install a catalog assistant on YOUR OWN Telegram account, replacing the current install as a whole. Requires the account:manage scope. There is no telegram_id argument.

Inputs:
  name, version — required. The exact catalog version from list_assistants; there is no "latest". name may also be the full name of one of your own forks (list_assistants' forks), which installs that fork version; a fork runs in observe or off mode only, so mode "guarded" is refused for it.
  values — object: the assistant's variables, keyed by variable name.
  mode — "observe" | "guarded" | "off"; default the assistant's default mode.
  runtime — "own" (default) or "managed". managed means a platform worker runs the jobs and messages needed for assistant tasks are sent to MCTL's configured third-party AI provider through MCTL's AI gateway (gateway logging and caching are disabled). Switching own to managed needs consent: show the user that text and, if they agree, pass consent "managed-data-flow/v1". Switching managed back to own needs no consent.
  consent — "managed-data-flow/v1", only with runtime "managed", asserting the user agreed to the text above. It is never stored with the install.
  paused — boolean; default true. listening — boolean; default false. A new install starts paused and not listening: going live is an explicit choice.
  limits — {maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}, at most the assistant's ceilings.
  intentTiers — {intent: "auto"|"approve"|"never"}, within what the assistant allows. disclosureLevels — {variable: level}, stricter only.
  audience — {scope: {contacts, nonContacts, newChats, existingChats}, onlySenders: [user id], blockedSenders: [user id]}.
  disclosure — {enabled, text}, only where the assistant's disclosure policy is optional.
  schedule — {mode: "always"|"outside_hours", timezone, hours: ["mon-fri 09:00-18:00"]}.
  ownerNotes — string up to 2000 characters, your own guidance appended below the assistant's instructions.
  expected_revision — optional integer: apply only if the install is still at this revision (mine.install_revision from list_assistants).

Output: {assistant, version, install_revision, settings}. settings is what the install resolved to (mode, paused, listening, limits, auto and never intents, schedule, audience); values and ownerNotes are never echoed.

Errors are JSON: {error, message, retryable, current_revision?}. error is one of invalid_install, assistant_not_found, lifecycle_refused (disabled, or deprecated for an account not already running it; for a fork, its base's lifecycle), revision_conflict (with current_revision; nothing changed), forks_disabled, registry_unavailable (retryable; nothing changed), registry_invalid, managed_disabled (the managed runtime is not enabled on this server), managed_consent_required (nothing changed; the action names the consent to send), managed_quota (no managed capacity), internal_error. Work queued under the previous install is refused once this one is saved.`),
		mcplib.WithString("name", mcplib.Required(), mcplib.Description("Assistant name, as list_assistants returns it.")),
		mcplib.WithString("version", mcplib.Required(), mcplib.Description("Exact assistant version, e.g. 0.1.0.")),
		mcplib.WithObject("values", mcplib.Description("Variable values keyed by variable name.")),
		mcplib.WithString("mode", mcplib.Enum("observe", "guarded", "off"), mcplib.Description("Agent mode; default the assistant's.")),
		mcplib.WithString("runtime", mcplib.Enum("own", "managed"), mcplib.Description("Which worker runs the jobs; default own. managed needs consent.")),
		mcplib.WithString("consent", mcplib.Description("managed-data-flow/v1, to switch to managed after the user agreed to the data flow text.")),
		mcplib.WithBoolean("paused", mcplib.Description("Default true.")),
		mcplib.WithBoolean("listening", mcplib.Description("Default false.")),
		mcplib.WithObject("limits", mcplib.Description("{maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}.")),
		mcplib.WithObject("intentTiers", mcplib.Description("Per-intent tier: auto, approve or never.")),
		mcplib.WithObject("disclosureLevels", mcplib.Description("Per-variable disclosure level, stricter only.")),
		mcplib.WithObject("audience", mcplib.Description("{scope, onlySenders, blockedSenders}.")),
		mcplib.WithObject("disclosure", mcplib.Description("{enabled, text}.")),
		mcplib.WithObject("schedule", mcplib.Description("{mode, timezone, hours}.")),
		mcplib.WithString("ownerNotes", mcplib.Description("Your own guidance for the assistant, at most 2000 characters.")),
		mcplib.WithNumber("expected_revision", mcplib.Description("Apply only if the install is at this revision.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "account:manage"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "install_assistant", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		args := req.GetArguments()
		if extra := unknownArgs(args, append([]string{"name", "version", "expected_revision", "consent"}, installArgKeys...)...); len(extra) > 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("unknown arguments: " + strings.Join(extra, ", ")), nil
		}
		name, _ := args["name"].(string)
		version, _ := args["version"].(string)
		if name == "" || version == "" {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("name and version are required"), nil
		}
		expected, ok := expectedRevisionArg(args)
		if !ok {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("expected_revision must be a positive integer"), nil
		}
		spec := map[string]any{"assistant": map[string]any{"name": name, "version": version}}
		for _, k := range installArgKeys {
			// An omitted setting stays omitted, so the install's own
			// defaults apply: paused, not listening.
			if v, ok := args[k]; ok && v != nil {
				spec[k] = v
			}
		}
		if v, ok := args["consent"]; ok && v != nil {
			spec["consent"] = v
		}
		raw, err := json.Marshal(map[string]any{
			"apiVersion": "assistants.mctl.ai/v1alpha1",
			"kind":       "AssistantInstall",
			"spec":       spec,
		})
		if err != nil {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("arguments do not encode as an install"), nil
		}
		res, err := s.Assistants.Apply(ctx, id.UserID, raw, assistantinstall.CommitOptions{ExpectedRevision: expected, SelfService: true})
		if err != nil {
			s.audit(ctx, id, "install_assistant", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "install_assistant", err)
		}
		if res.CleanupErr != nil {
			slog.Warn("mcp install_assistant: deny earlier-install actions failed", "user_id", id.UserID, "err", res.CleanupErr)
		}
		s.audit(ctx, id, "install_assistant", "", nil, startedAt)
		return jsonResult(installResult(res))
	}
	return tool, handler
}

func (s *Server) toolUpdateInstall() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("update_install",
		mcplib.WithTitleAnnotation("Change your assistant install"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[installAssistantResult](),
		mcplib.WithDescription(`Change YOUR OWN assistant install with a patch, without reading back your stored values. Requires the account:manage scope. There is no telegram_id argument.

Inputs:
  patch — object, required. An RFC 7396 JSON merge patch over the install's spec (the same fields install_assistant takes, with assistant as {name, version}): a member replaces the stored one, a nested object merges, null removes a member, an array replaces the whole array. Example: {"paused": false, "values": {"headline": null}, "ownerNotes": "Reply in English."}. Changing assistant.name or assistant.version switches or upgrades the assistant like an install.
  consent — optional string: "managed-data-flow/v1", to switch runtime to "managed" after the user agreed to the text install_assistant shows. managed back to own needs none. It is never stored.
  expected_revision — integer, required: mine.install_revision from list_assistants. The change applies only if the install is still at that revision.

The server decrypts the stored install, applies the patch, validates the result as a whole install and saves it; if the result is invalid or the revision moved, nothing changes.

Output: same as install_assistant. Errors: same JSON envelope (including managed_disabled, managed_consent_required, managed_quota); also no_install when the account has nothing to patch (use install_assistant), and revision_conflict carries current_revision.`),
		mcplib.WithObject("patch", mcplib.Required(), mcplib.Description("JSON merge patch over the install spec.")),
		mcplib.WithString("consent", mcplib.Description("managed-data-flow/v1, to switch to managed after the user agreed to the data flow text.")),
		mcplib.WithNumber("expected_revision", mcplib.Required(), mcplib.Description("The install revision the patch was written against.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "account:manage"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "update_install", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		args := req.GetArguments()
		if extra := unknownArgs(args, "patch", "expected_revision", "consent"); len(extra) > 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("unknown arguments: " + strings.Join(extra, ", ")), nil
		}
		patch, ok := args["patch"].(map[string]any)
		if !ok {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("patch is required and must be an object"), nil
		}
		expected, ok := expectedRevisionArg(args)
		if !ok || expected == nil {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("expected_revision is required and must be a positive integer"), nil
		}
		raw, err := json.Marshal(patch)
		if err != nil {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("patch does not encode as JSON"), nil
		}
		consent, _ := args["consent"].(string)
		res, err := s.Assistants.PatchWithConsent(ctx, id.UserID, raw, *expected, consent)
		if err != nil {
			s.audit(ctx, id, "update_install", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "update_install", err)
		}
		if res.CleanupErr != nil {
			slog.Warn("mcp update_install: deny earlier-install actions failed", "user_id", id.UserID, "err", res.CleanupErr)
		}
		s.audit(ctx, id, "update_install", "", nil, startedAt)
		return jsonResult(installResult(res))
	}
	return tool, handler
}
