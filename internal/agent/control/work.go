package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/agent/actor"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

// workUsage is the reply for a missing or invalid /mctl work target — never
// followed by any mctl-api call or binding write.
const workUsage = "Usage: /mctl work https://github.com/mctlhq/<repo>/issues/<n>\nAlso: /mctl work status | /mctl work note <text> | /mctl work resume\nOne-time setup: /mctl link <code>"

// isMissingWorkArg reports whether text is a /mctl work or /mctl link
// invocation that ParseCommand rejected for a missing argument (bare
// "/mctl work", bare "/mctl link", or "/mctl work note" with no text) — the
// ParseCommand-error cases that get the work-specific usage line instead of
// the generic unknown-command reply, per requirements.md's
// explicit-runnable-target rule. workUsage documents /mctl link <code>, so
// a bare "/mctl link" must land there rather than on a reply that does not
// list the command at all.
func isMissingWorkArg(text string) bool {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) < 2 || !strings.EqualFold(fields[0], "/mctl") {
		return false
	}
	switch {
	case strings.EqualFold(fields[1], "link"):
		return len(fields) == 2 // bare "/mctl link"
	case strings.EqualFold(fields[1], "work"):
		if len(fields) == 2 {
			return true // bare "/mctl work"
		}
		return len(fields) == 3 && strings.EqualFold(fields[2], "note") // "/mctl work note" with no text
	default:
		return false
	}
}

// WorkHandler implements the five issue-443 subcommands (/mctl work
// open|status|note|resume, /mctl link) behind Router.Work. It is
// constructed and wired only when WORK_CONTEXT_ENABLED is true
// (cmd/server/main.go); Router.Work stays nil otherwise, and
// Router.HandleSavedText falls through to the pre-#443 unknown-command
// reply — see that method's doc comment.
type WorkHandler struct {
	Store    *db.Store
	Client   *workctx.Client
	Notifier *Notifier
	Metrics  *metrics.Registry
	// OnRelaySuccess, when set, is called after a successful relay call
	// (a completed /mctl link, a successful /mctl work status) for the
	// resolved actor. Used by issue-571 to enroll the user as a human-input
	// polling candidate; it is a polling hint, never an authorization.
	OnRelaySuccess func(ctx context.Context, userID, actorTGID int64)
}

// resolveActor derives the Telegram user id for the X-MCTL-Surface-Actor
// relay header. It is deliberately the ONLY source: the Saved Messages
// self-peer id the listener already authenticated (meta.SelfTGID),
// cross-checked against Store.TelegramIDByUserID for the same internal
// user. A mismatch or an unresolved id fails closed — ok=false, err=nil,
// no mctl-api call made — never falls back to a deployment allowlist such
// as TGLoginAdmins/TGLoginClients/AutoApproveClients.
func (w *WorkHandler) resolveActor(ctx context.Context, meta SavedMeta) (actorTGID int64, ok bool, err error) {
	return actor.Resolve(ctx, w.Store, meta.UserID, meta.SelfTGID)
}

const notLinkedReply = "This Telegram account is not linked to a platform identity yet. An operator needs to resolve this before /mctl work or /mctl link can be used."

// Handle dispatches a parsed CmdWork/CmdLink command. Every branch replies
// to the owner exactly once (directly, or via one of the handle* methods
// below) — see each method's own comment for its reply.
func (w *WorkHandler) Handle(ctx context.Context, meta SavedMeta, cmd Command) error {
	if cmd.Type == CmdLink {
		return w.handleLink(ctx, meta, cmd.Arg)
	}
	switch cmd.Sub {
	case SubWorkOpen:
		return w.handleOpen(ctx, meta, cmd.Arg)
	case SubWorkStatus:
		return w.handleWorkStatus(ctx, meta)
	case SubWorkNote:
		return w.handleNote(ctx, meta, cmd.Arg)
	case SubWorkResume:
		return w.handleResume(ctx, meta)
	default:
		return w.Notifier.Reply(ctx, meta.UserID, workUsage)
	}
}

func (w *WorkHandler) handleLink(ctx context.Context, meta SavedMeta, code string) error {
	actorTGID, ok, err := w.resolveActor(ctx, meta)
	if err != nil {
		return err
	}
	if !ok {
		return w.Notifier.Reply(ctx, meta.UserID, notLinkedReply)
	}
	if err := w.Client.RedeemLink(ctx, actorTGID, code); err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, "Could not link: "+w.errText(err))
	}
	if w.OnRelaySuccess != nil {
		w.OnRelaySuccess(ctx, meta.UserID, actorTGID)
	}
	return w.Notifier.Reply(ctx, meta.UserID, "Linked. /mctl work and /mctl work status now act as you.")
}

// handleOpen implements /mctl work <issue-url>. The thread key for
// idempotency purposes is THIS command's own (chat, message) pair — a
// crash-recovery redelivery of the identical command hits the same
// GetWorkItemBinding row and reuses it rather than creating a duplicate;
// see T6.
func (w *WorkHandler) handleOpen(ctx context.Context, meta SavedMeta, arg string) error {
	issueURL, err := workctx.CanonicalIssueURL(arg)
	if err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, workUsage)
	}
	actorTGID, ok, err := w.resolveActor(ctx, meta)
	if err != nil {
		return err
	}
	if !ok {
		return w.Notifier.Reply(ctx, meta.UserID, notLinkedReply)
	}

	existing, found, err := w.Store.GetWorkItemBinding(ctx, meta.UserID, meta.ChatTGID, meta.TGMessageID)
	if err != nil {
		return fmt.Errorf("get work item binding: %w", err)
	}
	if found && isOpenWorkItemState(existing.LastState) {
		if existing.ExternalKey != issueURL {
			w.Metrics.CountWorkContextBinding("refused")
			return w.Notifier.Reply(ctx, meta.UserID, fmt.Sprintf(
				"This thread is already bound to %s. Start a new thread to work a different issue.", existing.ExternalKey))
		}
		if existing.LastRequestID != "" {
			w.Metrics.CountWorkContextBinding("reused")
			return w.Notifier.Reply(ctx, meta.UserID, fmt.Sprintf(
				"Already bound to work item %s (%s).", existing.WorkItemID, existing.LastState))
		}
		// Bound, but no start request was ever recorded: a crash (or a
		// failed start) between UpsertWorkItemBinding and
		// SetWorkItemBindingRequest below. Answering "already bound" here
		// would leave the item with no start request forever, so fall
		// through and redo the create + start: both carry this command's
		// deterministic Idempotency-Keys, so the platform replays whatever
		// it already accepted instead of doing it twice.
	}

	idemKey := workctx.IdempotencyKey(meta.ChatTGID, meta.TGMessageID, "open", 0)
	item, err := w.Client.CreateWorkItem(ctx, actorTGID, workctx.CreateRequest{ExternalKey: issueURL, IdempotencyKey: idemKey})
	if err != nil {
		if errors.Is(err, workctx.ErrExternalKeyInUse) {
			return w.Notifier.Reply(ctx, meta.UserID, "That issue already has work you don't have access to.")
		}
		return w.Notifier.Reply(ctx, meta.UserID, "Could not open work item: "+w.errText(err))
	}

	binding := db.WorkItemBinding{
		UserID: meta.UserID, ChatTGID: meta.ChatTGID, RootTGMessageID: meta.TGMessageID,
		WorkItemID: item.WorkItem.ID, ExternalKey: issueURL,
		LastState: item.WorkItem.State, LastStateVersion: item.StateVersion,
	}
	if item.LatestExecution != nil {
		binding.LastExecutionID = item.LatestExecution.ExecutionID
	}
	if err := w.Store.UpsertWorkItemBinding(ctx, binding); err != nil {
		return fmt.Errorf("upsert work item binding: %w", err)
	}
	if found {
		w.Metrics.CountWorkContextBinding("reused")
	} else {
		w.Metrics.CountWorkContextBinding("created")
	}

	// Correlation metadata only — best-effort in the sense that a failure
	// here must not stop the start request below, but it is still reported
	// as a real error (not silently dropped) since a Codex-caught defect
	// here would otherwise be invisible.
	var surfaceRefWarning string
	if err := w.Client.AddSurfaceRef(ctx, actorTGID, item.WorkItem.ID, workctx.SurfaceRefRequest{
		ChatTGID: meta.ChatTGID, RootTGMessageID: meta.TGMessageID,
	}); err != nil {
		surfaceRefWarning = fmt.Sprintf(
			"Work item %s created, but registering this thread failed: %s\n", item.WorkItem.ID, w.errText(err))
	}

	startKey := workctx.IdempotencyKey(meta.ChatTGID, meta.TGMessageID, "start", 0)
	req, err := w.Client.RequestExecution(ctx, actorTGID, item.WorkItem.ID, workctx.ExecutionRequest{
		Kind: workctx.ExecutionKindStart, ExpectedStateVersion: item.StateVersion, IdempotencyKey: startKey,
	})
	if err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, surfaceRefWarning+fmt.Sprintf(
			"Work item %s bound, but the start request failed: %s", item.WorkItem.ID, w.errText(err)))
	}
	if err := w.Store.SetWorkItemBindingRequest(ctx, meta.UserID, meta.ChatTGID, meta.TGMessageID, req.ID); err != nil {
		return fmt.Errorf("set work item binding request: %w", err)
	}
	return w.Notifier.Reply(ctx, meta.UserID, surfaceRefWarning+fmt.Sprintf(
		"Bound to work item %s.\nRequest %s\n/mctl work status to check progress.",
		item.WorkItem.ID, formatRequestState(*req)))
}

func isOpenWorkItemState(state string) bool {
	return state == workctx.ItemStateActive || state == workctx.ItemStateWaiting
}

func (w *WorkHandler) handleNote(ctx context.Context, meta SavedMeta, text string) error {
	actorTGID, ok, err := w.resolveActor(ctx, meta)
	if err != nil {
		return err
	}
	if !ok {
		return w.Notifier.Reply(ctx, meta.UserID, notLinkedReply)
	}
	binding, found, err := w.Store.LatestWorkItemBinding(ctx, meta.UserID, meta.ChatTGID)
	if err != nil {
		return fmt.Errorf("get latest work item binding: %w", err)
	}
	if !found {
		return w.Notifier.Reply(ctx, meta.UserID, "No work item bound yet. Run /mctl work <issue-url> first.")
	}
	// Scoped to this note command's own message id (not the binding's root
	// message) — each note is a distinct intent, and reusing the binding's
	// root-message key here would make every note after the first collide
	// on the same Idempotency-Key and be dropped as a duplicate.
	idemKey := workctx.IdempotencyKey(meta.ChatTGID, meta.TGMessageID, "note", 0)
	if err := w.Client.AppendIntent(ctx, actorTGID, binding.WorkItemID, workctx.IntentRequest{Text: text, IdempotencyKey: idemKey}); err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, "Could not record note: "+w.errText(err))
	}
	return w.Notifier.Reply(ctx, meta.UserID, fmt.Sprintf("Noted on work item %s.", binding.WorkItemID))
}

func (w *WorkHandler) handleResume(ctx context.Context, meta SavedMeta) error {
	actorTGID, ok, err := w.resolveActor(ctx, meta)
	if err != nil {
		return err
	}
	if !ok {
		return w.Notifier.Reply(ctx, meta.UserID, notLinkedReply)
	}
	binding, found, err := w.Store.LatestWorkItemBinding(ctx, meta.UserID, meta.ChatTGID)
	if err != nil {
		return fmt.Errorf("get latest work item binding: %w", err)
	}
	if !found {
		return w.Notifier.Reply(ctx, meta.UserID, "No work item bound yet. Run /mctl work <issue-url> first.")
	}

	item, err := w.Client.GetWorkItem(ctx, actorTGID, binding.WorkItemID)
	if err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, "Could not read work item: "+w.errText(err))
	}
	req, err := w.requestResumeWithRetry(ctx, actorTGID, binding, meta.TGMessageID, item.StateVersion)
	if err != nil {
		if errors.Is(err, workctx.ErrStateVersionConflict) {
			return w.Notifier.Reply(ctx, meta.UserID, "The work item changed while resuming — please try /mctl work resume again.")
		}
		return w.Notifier.Reply(ctx, meta.UserID, "Could not resume: "+w.errText(err))
	}
	if err := w.Store.SetWorkItemBindingRequest(ctx, meta.UserID, binding.ChatTGID, binding.RootTGMessageID, req.ID); err != nil {
		return fmt.Errorf("set work item binding request: %w", err)
	}
	return w.Notifier.Reply(ctx, meta.UserID, "Request "+formatRequestState(*req)+"\n/mctl work status to check progress.")
}

// requestResumeWithRetry submits a resume execution request at
// stateVersion. On a single 409 state-version conflict it re-reads the item
// and retries EXACTLY once; a second conflict is returned to the caller
// rather than looping — matching the bounded re-read-and-retry rule.
//
// The idempotency key is scoped to cmdMsgID — THIS /mctl work resume
// command's own message id — not the binding's root message id. A rejected
// (refused) resume does not advance the work item's state_version, so
// keying on the thread root plus state_version alone would make every
// subsequent resume attempt recompute the exact same key as the refused one
// and be answered from the platform's idempotency cache with that same
// stale rejection forever — a permanent no-op from Telegram (P2). Each
// distinct /mctl work resume the owner sends is a distinct Telegram
// message, so scoping to cmdMsgID guarantees a fresh key per attempt while
// still keying on stateVersion to give the in-function 409-conflict retry
// below its own, correctly distinct key.
func (w *WorkHandler) requestResumeWithRetry(ctx context.Context, actorTGID int64, binding db.WorkItemBinding, cmdMsgID, stateVersion int64) (*workctx.ExecutionRequestView, error) {
	key := workctx.IdempotencyKey(binding.ChatTGID, cmdMsgID, "resume", stateVersion)
	req, err := w.Client.RequestExecution(ctx, actorTGID, binding.WorkItemID, workctx.ExecutionRequest{
		Kind: workctx.ExecutionKindResume, ExpectedStateVersion: stateVersion, IdempotencyKey: key,
	})
	if err == nil {
		return req, nil
	}
	if !errors.Is(err, workctx.ErrStateVersionConflict) {
		return nil, err
	}
	item, gerr := w.Client.GetWorkItem(ctx, actorTGID, binding.WorkItemID)
	if gerr != nil {
		return nil, gerr
	}
	retryKey := workctx.IdempotencyKey(binding.ChatTGID, cmdMsgID, "resume", item.StateVersion)
	req, err = w.Client.RequestExecution(ctx, actorTGID, binding.WorkItemID, workctx.ExecutionRequest{
		Kind: workctx.ExecutionKindResume, ExpectedStateVersion: item.StateVersion, IdempotencyKey: retryKey,
	})
	return req, err
}

// requestReasonExplanations is the fixed, closed table of owner-facing
// one-line explanations for a rejected execution request's typed reason.
// Any code not in this table is shown verbatim, labelled unrecognised —
// mctl-api's free-text message is never shown (see workctxErrText's
// analogous rule for relay errors).
var requestReasonExplanations = map[string]string{
	"no_runnable_target": "the work item has no runnable GitHub issue target",
	"loop_active":        "the issue's DevLoop is already running",
	"unsupported_kind":   "the platform does not support that request kind",
}

func explainRequestReason(reason string) string {
	if strings.HasPrefix(reason, "resume_refused:") {
		return "the platform refused to resume (" + strings.TrimPrefix(reason, "resume_refused:") + ")"
	}
	if strings.HasPrefix(reason, "fulfil_refused:") {
		return "the platform refused to fulfil the request (" + strings.TrimPrefix(reason, "fulfil_refused:") + ")"
	}
	if reason == "engine_run_ended" {
		return "the run ended before the request could be fulfilled"
	}
	if exp, ok := requestReasonExplanations[reason]; ok {
		return exp
	}
	return "unrecognised reason"
}

func (w *WorkHandler) handleWorkStatus(ctx context.Context, meta SavedMeta) error {
	actorTGID, ok, err := w.resolveActor(ctx, meta)
	if err != nil {
		return err
	}
	if !ok {
		return w.Notifier.Reply(ctx, meta.UserID, notLinkedReply)
	}
	binding, found, err := w.Store.LatestWorkItemBinding(ctx, meta.UserID, meta.ChatTGID)
	if err != nil {
		return fmt.Errorf("get latest work item binding: %w", err)
	}
	if !found {
		return w.Notifier.Reply(ctx, meta.UserID, "No work item bound yet. Run /mctl work <issue-url> first.")
	}

	item, err := w.Client.GetWorkItem(ctx, actorTGID, binding.WorkItemID)
	if err != nil {
		return w.Notifier.Reply(ctx, meta.UserID, "Could not read work item: "+w.errText(err))
	}
	if w.OnRelaySuccess != nil {
		w.OnRelaySuccess(ctx, meta.UserID, actorTGID)
	}
	execID := ""
	if item.LatestExecution != nil {
		execID = item.LatestExecution.ExecutionID
	}
	if err := w.Store.TouchWorkItemBindingState(ctx, meta.UserID, binding.WorkItemID, item.WorkItem.State, item.StateVersion, execID); err != nil {
		return fmt.Errorf("touch work item binding state: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Work item %s\nIssue: %s\nState: %s\n", item.WorkItem.ID, binding.ExternalKey, item.WorkItem.State)
	if item.LatestExecution != nil && item.LatestExecution.ExecutionID != "" {
		fmt.Fprintf(&sb, "Latest execution: %s\n", item.LatestExecution.ExecutionID)
	}
	if item.PendingApproval != nil {
		fmt.Fprintf(&sb, "Pending approval: %s\n", item.PendingApproval.ID)
	}
	if item.LatestSnapshot != nil {
		fmt.Fprintf(&sb, "Latest snapshot: %s\n", item.LatestSnapshot.SnapshotID)
	}

	sb.WriteString(w.renderRequestLine(ctx, actorTGID, binding))
	return w.Notifier.Reply(ctx, meta.UserID, sb.String())
}

// renderRequestLine implements the request-state rendering rule from
// design.md: read the binding's last request id (or, missing one, the
// newest from the list), and render its state — never mctl-api's free-text
// message for a rejected request. A failed read degrades to "request state
// unavailable" rather than failing the whole /mctl work status reply.
func (w *WorkHandler) renderRequestLine(ctx context.Context, actorTGID int64, binding db.WorkItemBinding) string {
	var req *workctx.ExecutionRequestView
	var err error
	if binding.LastRequestID != "" {
		req, err = w.Client.GetExecutionRequest(ctx, actorTGID, binding.WorkItemID, binding.LastRequestID)
	} else {
		var list []workctx.ExecutionRequestView
		list, err = w.Client.ListExecutionRequests(ctx, actorTGID, binding.WorkItemID)
		if err == nil {
			if len(list) == 0 {
				return "Request: none submitted yet."
			}
			req = &list[0]
		}
	}
	if err != nil {
		return "Request state unavailable."
	}
	return "Request " + formatRequestState(*req)
}

func formatRequestState(req workctx.ExecutionRequestView) string {
	switch req.State {
	case workctx.RequestStatePending:
		return fmt.Sprintf("%s (%s): pending — waiting for the platform to pick it up.", req.ID, req.Kind)
	case workctx.RequestStateClaimed:
		return fmt.Sprintf("%s (%s): claimed — the platform is starting it.", req.ID, req.Kind)
	case workctx.RequestStateFulfilled:
		return fmt.Sprintf("%s (%s): fulfilled, execution %s.", req.ID, req.Kind, req.ExecutionID)
	case workctx.RequestStateRejected:
		return fmt.Sprintf("%s (%s): failed: %s (%s).", req.ID, req.Kind, req.Reason, explainRequestReason(req.Reason))
	default:
		return fmt.Sprintf("%s (%s): %s.", req.ID, req.Kind, req.State)
	}
}

// errText renders a workctx error for an owner-facing reply via
// workctxErrText, naming the configured work-item tenant, and logs any
// platform error that has no fixed phrase together with its code, so an
// unmapped refusal is diagnosable from the logs instead of looking like a
// bot bug.
func (w *WorkHandler) errText(err error) string {
	tenant := ""
	if w.Client != nil {
		tenant = w.Client.Tenant()
	}
	text, mapped := workctxErrText(err, tenant)
	if !mapped {
		var apiErr *workctx.APIError
		if errors.As(err, &apiErr) {
			slog.Warn("work: unmapped platform error", "status", apiErr.StatusCode,
				"code", apiErr.Code, "correlation_id", apiErr.CorrelationID)
		} else {
			slog.Warn("work: platform call failed", "err", err)
		}
	}
	return text
}

// workctxErrText renders a workctx error as owner-facing text, following
// the approverErrText precedent above — it never leaks mctl-api's free-text
// message, only a fixed phrase per known sentinel. mapped is false when no
// fixed phrase applies: a typed code mctl-api returned that has no sentinel
// is rendered with that code (a machine identifier, never free text), and
// anything else as an internal error.
func workctxErrText(err error, tenant string) (text string, mapped bool) {
	switch {
	case errors.Is(err, workctx.ErrLinkNotFound), errors.Is(err, workctx.ErrLinkRevoked), errors.Is(err, workctx.ErrLinkExpired), errors.Is(err, workctx.ErrRelayRequired):
		return "your Telegram account is not linked — run /mctl link <code> (get a code from the platform first)", true
	case errors.Is(err, workctx.ErrChallengeInvalid):
		return "that link code is invalid or already used", true
	case errors.Is(err, workctx.ErrLinkConflict):
		return "this Telegram account is already linked", true
	case errors.Is(err, workctx.ErrActorNotAccepted):
		return "rejected by the platform", true
	case errors.Is(err, workctx.ErrStateVersionConflict):
		return "the work item changed — try again", true
	case errors.Is(err, workctx.ErrExternalKeyInUse):
		return "that issue already has work you don't have access to", true
	case errors.Is(err, workctx.ErrIncompatibleSchema):
		return "the platform returned an incompatible response — try again later", true
	case errors.Is(err, workctx.ErrExecutionRequestOpen):
		return "a request for this work item is already open — /mctl work status to check it", true
	case errors.Is(err, workctx.ErrExecutionActive):
		return "an execution for this work item is already running — /mctl work status to check it", true
	case errors.Is(err, workctx.ErrInvalidTransition):
		return "the work item cannot take that request in its current state — /mctl work status to check it", true
	case errors.Is(err, workctx.ErrTenantForbidden):
		return fmt.Sprintf("you have no access to the work-item tenant %q on the platform — ask an operator to grant it or to change MCTL_WORK_ITEM_TENANT", tenant), true
	case errors.Is(err, workctx.ErrWorkItemsUnavailable):
		return "work items are unavailable on the platform right now — try again later", true
	case errors.Is(err, workctx.ErrWorkItemNotFound):
		return "the work item was not found, or you no longer have access to it", true
	case errors.Is(err, workctx.ErrIdempotencyKeyReused):
		return "this command was already used for a different request — send it again as a new message", true
	case errors.Is(err, workctx.ErrSecretInText):
		return "the text looks like it contains a secret, so the platform refused it — remove it and try again", true
	}
	var apiErr *workctx.APIError
	if errors.As(err, &apiErr) && isTypedErrorCode(apiErr.Code) {
		return fmt.Sprintf("rejected by the platform (%d %s)", apiErr.StatusCode, apiErr.Code), false
	}
	return "an internal error occurred", false
}

// isTypedErrorCode reports whether code has the shape of one of mctl-api's
// typed error codes (snake_case, bounded). The client falls back to the
// body's "error" field when no "code" is present, and on mctl-api's
// untyped writeError path that field is free text — which must never be
// echoed to the owner.
func isTypedErrorCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for i, r := range code {
		switch {
		case r >= 'a' && r <= 'z':
		case (r >= '0' && r <= '9') || r == '_':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}
