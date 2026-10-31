package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// The private fork tools (#1043, docs/assistants/adr-forks.md):
// fork_assistant, update_fork and delete_fork. Like the install tools they
// act on the caller's own account only and need account:manage; there is
// no telegram_id argument. Forks are listed by list_assistants.
//
// A fork's instructions are the owner's data: no output, error, log line
// or audit row of these tools carries them. A write is reported by name,
// version and digest; the audit row records the same reference, and the
// owner is notified in the bot chat by the store, in the write's own
// transaction. Every fork version runs in observe mode: promoting one to
// guarded (P4.3) is a human step outside MCP, so no tool here can do it.

// forkOverrideKeys are the arguments a fork write takes besides its target.
var forkOverrideKeys = []string{"instructions", "intents", "tools", "limits", "ceilings", "disclosure_policy"}

const forkOverridesDoc = `  instructions — string, at most 16 KiB of UTF-8: replaces the assistant's instructions. May not contain the owner_notes markers. Your install's ownerNotes are still added below them.
  intents — array of {name, description?, tier, userOverride?}, replacing the list as a whole. Each intent the base has keeps its description and may only get stricter (tier auto → approve → never; userOverride any → tighten → none) or be left out. A new intent may only be approve or never, never auto.
  tools — array of tool names, replacing the list as a whole: a subset of the base's tools that keeps get_event and complete_agent_job. The server refuses a job's calls to any tool left out.
  limits, ceilings — complete {maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars} objects, each value at most the base's ceiling.
  disclosure_policy — "required" makes the AI disclosure line mandatory. It can never be made optional where the base requires it.
Everything else (variables, records, escalation, defaults.mode, the disclosure text) is the base's. The platform's server-side checks of every reply apply to a fork unchanged.`

type deleteForkResult struct {
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	DeletedVersions int    `json:"deleted_versions"`
}

// forkOverridesArg reads the override arguments. Their shapes are strict:
// an unknown member of an intent or a limits object is refused.
func forkOverridesArg(args map[string]any) (assistant.ForkOverrides, error) {
	var ov assistant.ForkOverrides
	strict := func(v any, out any) error {
		raw, err := json.Marshal(v)
		if err != nil {
			return err
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		return dec.Decode(out)
	}
	if v, ok := args["instructions"]; ok && v != nil {
		text, isStr := v.(string)
		if !isStr || strings.TrimSpace(text) == "" {
			return ov, errors.New("instructions must be a non-empty string")
		}
		ov.Instructions = &text
	}
	if v, ok := args["intents"]; ok && v != nil {
		if err := strict(v, &ov.Intents); err != nil || ov.Intents == nil {
			return ov, errors.New("intents must be an array of {name, description, tier, userOverride}")
		}
	}
	if v, ok := args["tools"]; ok && v != nil {
		if err := strict(v, &ov.Tools); err != nil || ov.Tools == nil {
			return ov, errors.New("tools must be an array of tool names")
		}
	}
	for _, l := range []struct {
		key string
		dst **assistant.Limits
	}{{"limits", &ov.Limits}, {"ceilings", &ov.Ceilings}} {
		if v, ok := args[l.key]; ok && v != nil {
			var lim assistant.Limits
			if err := strict(v, &lim); err != nil {
				return ov, errors.New(l.key + " must be {maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}")
			}
			*l.dst = &lim
		}
	}
	if v, ok := args["disclosure_policy"]; ok && v != nil {
		p, isStr := v.(string)
		if !isStr || (p != "required" && p != "optional") {
			return ov, errors.New(`disclosure_policy must be "required" or "optional"`)
		}
		ov.DisclosurePolicy = p
	}
	return ov, nil
}

// forkAuditRef is the audit target of a fork write: the version and its
// digest, never the text.
func forkAuditRef(name, version, digest string) string {
	return "fork:" + name + "@" + version + " " + digest
}

func forkOverrideOptions() []mcplib.ToolOption {
	return []mcplib.ToolOption{
		mcplib.WithString("instructions", mcplib.Description("Replacement instructions, at most 16 KiB.")),
		mcplib.WithArray("intents", mcplib.Description("Replacement intent list: [{name, description?, tier, userOverride?}]."), mcplib.Items(map[string]any{"type": "object"})),
		mcplib.WithArray("tools", mcplib.Description("Replacement tool list, a subset of the base's."), mcplib.WithStringItems()),
		mcplib.WithObject("limits", mcplib.Description("{maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}.")),
		mcplib.WithObject("ceilings", mcplib.Description("{maxAutonomousTurns, maxMsgsPerMinute, maxReplyChars}.")),
		mcplib.WithString("disclosure_policy", mcplib.Enum("required", "optional"), mcplib.Description(`"required" makes the disclosure line mandatory.`)),
	}
}

func (s *Server) toolForkAssistant() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	opts := []mcplib.ToolOption{
		mcplib.WithTitleAnnotation("Fork a catalog assistant privately"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[assistantinstall.ForkWrite](),
		mcplib.WithDescription(`Create a private fork of a catalog assistant on YOUR OWN account: your own instructions, fewer tools, stricter intents, lower limits. Requires the account:manage scope. There is no telegram_id argument; nobody else can see, install or change your fork.

Inputs:
  base, base_version — required. The catalog assistant and exact version to fork, as list_assistants shows them.
  slug — required, ^[a-z0-9][a-z0-9_-]{0,31}$: your name for the fork. The fork's full name is <base>~<owner-scope>~<slug>, where owner-scope identifies your account without revealing it.
` + forkOverridesDoc + `

The fork is created at version 0.1.0 and pins the base version's digest; later changes to the catalog never reach it. Every fork version runs in observe mode only (every reply waits for your approval): installing it in guarded mode is refused. If the base is disabled in the catalog, the fork stops too. You are notified in the bot chat of every fork write. Install it with install_assistant using its full name and version.

Output: {name, version, digest, base: {name, version, digest}, promotion}. The instructions are never echoed.

Errors are JSON: {error, message, retryable}. error is one of invalid_install (a fork rule or the definition schema; the message names the rule), assistant_not_found, lifecycle_refused, fork_limit (at most 10 forks per account and 50 versions per fork; nothing changed), fork_conflict (a fork with this name exists: use update_fork), forks_disabled, registry_unavailable (retryable), registry_invalid, internal_error.`),
		mcplib.WithString("base", mcplib.Required(), mcplib.Description("Catalog assistant name.")),
		mcplib.WithString("base_version", mcplib.Required(), mcplib.Description("Exact catalog version, e.g. 0.1.0.")),
		mcplib.WithString("slug", mcplib.Required(), mcplib.Description("Your name for the fork.")),
	}
	tool := mcplib.NewTool("fork_assistant", append(opts, forkOverrideOptions()...)...)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "account:manage"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "fork_assistant", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		args := req.GetArguments()
		if extra := unknownArgs(args, append([]string{"base", "base_version", "slug"}, forkOverrideKeys...)...); len(extra) > 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("unknown arguments: " + strings.Join(extra, ", ")), nil
		}
		base, _ := args["base"].(string)
		baseVersion, _ := args["base_version"].(string)
		slug, _ := args["slug"].(string)
		if base == "" || baseVersion == "" || slug == "" {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("base, base_version and slug are required"), nil
		}
		ov, err := forkOverridesArg(args)
		if err != nil {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		res, err := s.Assistants.CreateFork(ctx, id.UserID, base, baseVersion, slug, ov)
		if err != nil {
			s.audit(ctx, id, "fork_assistant", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "fork_assistant", err)
		}
		s.audit(ctx, id, "fork_assistant", forkAuditRef(res.Name, res.Version, res.Digest), nil, startedAt)
		return jsonResult(res)
	}
	return tool, handler
}

func (s *Server) toolUpdateFork() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	opts := []mcplib.ToolOption{
		mcplib.WithTitleAnnotation("Change your private assistant fork"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(false),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[assistantinstall.ForkWrite](),
		mcplib.WithDescription(`Change one of YOUR OWN private assistant forks. Requires the account:manage scope. Each call writes a new immutable version on top of the fork's latest one; earlier versions stay as they were, and your install keeps running the version it pins until you install the new one (install_assistant, or update_install with assistant.version).

Inputs:
  name — required: the fork's full name, as fork_assistant or list_assistants returned it.
` + forkOverridesDoc + `
Give at least one change. The server numbers the version: a patch bump when only the instructions change, a minor bump when anything else does (tools, intents, limits, disclosure). An update that changes nothing is refused. The new version runs in observe mode only, like every fork version.

Output: {name, version, digest, base, promotion, bump}. The instructions are never echoed.

Errors: the same JSON envelope as fork_assistant; assistant_not_found when you have no fork of that name, and fork_conflict when the fork changed while the update was prepared (retry).`),
		mcplib.WithString("name", mcplib.Required(), mcplib.Description("The fork's full name.")),
	}
	tool := mcplib.NewTool("update_fork", append(opts, forkOverrideOptions()...)...)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "account:manage"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "update_fork", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		args := req.GetArguments()
		if extra := unknownArgs(args, append([]string{"name"}, forkOverrideKeys...)...); len(extra) > 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("unknown arguments: " + strings.Join(extra, ", ")), nil
		}
		name, _ := args["name"].(string)
		if name == "" {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("name is required"), nil
		}
		ov, err := forkOverridesArg(args)
		if err != nil {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if ov.Empty() {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("give at least one change: " + strings.Join(forkOverrideKeys, ", ")), nil
		}
		res, err := s.Assistants.UpdateFork(ctx, id.UserID, name, ov)
		if err != nil {
			s.audit(ctx, id, "update_fork", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "update_fork", err)
		}
		s.audit(ctx, id, "update_fork", forkAuditRef(res.Name, res.Version, res.Digest), nil, startedAt)
		return jsonResult(res)
	}
	return tool, handler
}

func (s *Server) toolDeleteFork() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("delete_fork",
		mcplib.WithTitleAnnotation("Delete your private assistant fork"),
		mcplib.WithReadOnlyHintAnnotation(false),
		mcplib.WithDestructiveHintAnnotation(true),
		mcplib.WithIdempotentHintAnnotation(false),
		mcplib.WithOpenWorldHintAnnotation(false),
		outputSchema[deleteForkResult](),
		mcplib.WithDescription(`Delete one version of YOUR OWN private assistant fork, or the whole fork. Requires the account:manage scope. Works even when forks are disabled on the server, so you can always remove your data.

Inputs:
  name — required: the fork's full name.
  version — optional: the version to delete. Without it, every version of the fork is deleted.

The version your install runs is never deleted: such a call is refused with fork_in_use and deletes nothing. Install another assistant or version first. Deleting frees room under the quotas (10 forks per account, 50 versions per fork).

Output: {name, version?, deleted_versions}.

Errors: the same JSON envelope as fork_assistant; assistant_not_found when there is no such fork or version, fork_in_use as above.`),
		mcplib.WithString("name", mcplib.Required(), mcplib.Description("The fork's full name.")),
		mcplib.WithString("version", mcplib.Description("One version to delete; omit to delete the whole fork.")),
	)
	handler := func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		id := auth.From(ctx)
		if err := requireScope(id, "account:manage"); err != nil {
			return mcplib.NewToolResultError(err.Error()), nil
		}
		if s.Assistants == nil {
			s.audit(ctx, id, "delete_fork", "", errors.New("not enabled"), startedAt)
			return s.assistantsUnavailable(ctx)
		}
		args := req.GetArguments()
		if extra := unknownArgs(args, "name", "version"); len(extra) > 0 {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("unknown arguments: " + strings.Join(extra, ", ")), nil
		}
		name, _ := args["name"].(string)
		version, _ := args["version"].(string)
		if name == "" || !assistant.IsForkName(name) {
			hintReason(ctx, ReasonInvalidArgument)
			return mcplib.NewToolResultError("name is required and must be a fork's full name"), nil
		}
		n, err := s.Assistants.DeleteFork(ctx, id.UserID, name, version)
		if err != nil {
			s.audit(ctx, id, "delete_fork", "", errors.New(assistantErrCode(err)), startedAt)
			return s.assistantErrResult(ctx, "delete_fork", err)
		}
		ref := "fork:" + name
		if version != "" {
			ref += "@" + version
		}
		s.audit(ctx, id, "delete_fork", ref, nil, startedAt)
		return jsonResult(deleteForkResult{Name: name, Version: version, DeletedVersions: n})
	}
	return tool, handler
}
