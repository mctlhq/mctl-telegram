package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/edgectx"
)

// callRecord is one Server.audit outcome, either staged for a later flush
// (Server.recordToolCall is installed) or written through immediately
// (Server.writeAuditRow). elapsed/hasElapsed mirror startedAt.IsZero()'s
// role in the pre-#696 Server.audit: some auditDetached callers pass a zero
// startedAt when there is nothing meaningful to time.
type callRecord struct {
	tool, peer, status, reason, errMsg, callPath string
	elapsed                                      time.Duration
	hasElapsed                                   bool
	// synthesized is set on every record Server.flushRecordedCall creates
	// itself (Rule 1's appended error record, Rule 2, Rule 3) and on a refusal
	// staged by Server.auditRefusal, as opposed to a record staged by
	// Server.audit. A synthesized record never reached
	// Server.audit, so before mctl-telegram#696 it touched neither
	// ToolInvocationsTotal nor ToolInvocationDuration. Those two series are
	// the tool-availability SLO's input (deploy/alerts/mctl-telegram.rules.yaml),
	// and synthesized failures are overwhelmingly client-caused
	// (invalid_argument, scope_denied, ...) — counting them would let a
	// looping bad client page on-call for a healthy server. writeAuditRow
	// still writes the audit_logs row and (via Rule 5) ToolCallErrorsTotal
	// for it; only the SLO pair is skipped, keeping the SLO's input set
	// exactly what it was before #696. Server faults are surfaced by the
	// MctlToolHandlerFaults alert and mctl_tool_call_errors_total instead.
	synthesized bool
	id          *auth.Identity
}

// feedsSLO reports whether this record may sample the two series the
// tool-availability SLO reads. Only records staged by Server.audit do
// (pre-#696 behaviour); a synthesized record never does, whatever its reason.
func (r callRecord) feedsSLO() bool {
	return !r.synthesized
}

// callRecorder buffers every callRecord staged during one tools/call
// dispatch, in the order Server.audit produced them. A real handler
// invocation stages at most one record (every tool has at most one audited
// branch actually taken per call); the slice exists so
// Server.flushRecordedCall never has to assume that invariant.
type callRecorder struct {
	mu     sync.Mutex
	staged []callRecord
	// hint is the reason the failing code path named for itself (see
	// hintReason). Last writer wins.
	hint string
}

func (r *callRecorder) setHint(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hint = reason
}

func (r *callRecorder) snapshotHint() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hint
}

// hintReason lets the failing code path name its own Reason* constant. A
// hint outranks classifyToolResultReason's text guess (which stays as the
// fallback for paths that name nothing) but never the panic / handler_error
// reasons recordToolCall knows with certainty. With no recorder in ctx it is
// a no-op, like Server.audit's write-through branch.
func hintReason(ctx context.Context, reason string) {
	if rec := recorderFrom(ctx); rec != nil {
		rec.setHint(reason)
	}
}

func (r *callRecorder) stage(rec callRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.staged = append(r.staged, rec)
}

// snapshot returns a copy of the staged records so the caller can mutate
// its own copy (reconciling the last one's status/reason) without a data
// race against a concurrent stage — not expected within one call, but the
// lock makes it safe by construction rather than by convention.
func (r *callRecorder) snapshot() []callRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]callRecord, len(r.staged))
	copy(out, r.staged)
	return out
}

// recorderCtxKey is the ctx key Server.recordToolCall installs a
// *callRecorder under. Unexported so only this package can stage into or
// read one.
type recorderCtxKey struct{}

// withRecorder returns a ctx carrying rec, so every Server.audit call made
// while handling this tools/call dispatch stages into it instead of
// writing through.
func withRecorder(ctx context.Context, rec *callRecorder) context.Context {
	return context.WithValue(ctx, recorderCtxKey{}, rec)
}

// recorderFrom returns the *callRecorder installed in ctx, or nil when
// none is present (every call path that predates mctl-telegram#696, and
// every direct-handler test).
func recorderFrom(ctx context.Context) *callRecorder {
	rec, _ := ctx.Value(recorderCtxKey{}).(*callRecorder)
	return rec
}

// auditExemptOnSuccess lists the tools whose successful calls
// flushRecordedCall must NOT synthesize an audit row for, because their
// handlers deliberately do not audit their own successes today. The
// exemption is success-only: a failing call from any of the three is still
// recorded, staged or synthesized like any other tool's failure.
var auditExemptOnSuccess = map[string]bool{
	// get_my_audit_log intentionally does not audit-log this call itself --
	// it would create a recursive audit-of-audit row on every page fetch
	// (see toolGetMyAuditLog).
	"get_my_audit_log": true,
	// get_my_identity / get_my_send_status do not audit their successes
	// today either; success volume unchanged is a deliberate decision, not
	// an oversight (requirements.md Open questions, resolved at review
	// 2026-09-27).
	"get_my_identity":    true,
	"get_my_send_status": true,
}

// recordToolCall is the mcpserver.ToolHandlerMiddleware registered by
// newMCPServer (mctl-telegram#696). It is the single place every tools/call
// dispatch to a resolved handler passes through, so a tool added later
// cannot reintroduce the blind spots this proposal fixes: it installs a
// *callRecorder in ctx before calling next, and on the way out — success,
// an IsError result, a non-nil Go error, or a recovered panic — flushes
// exactly the rows design.md section B specifies.
//
// A non-nil Go error or a recovered panic is absorbed here into an
// IsError=true tool result: handleToolCall (mcp-go@v1.0.0) turns any error
// a middleware-wrapped handler returns into a JSON-RPC INTERNAL_ERROR, which
// would both hide the failure from the model's context window and fire
// jsonrpcHooks' onError — the "disjoint by construction" property design.md
// relies on requires that this middleware never lets that happen for a
// registered tool.
func (s *Server) recordToolCall(next mcpserver.ToolHandlerFunc) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (result *mcplib.CallToolResult, err error) {
		startedAt := time.Now()
		rec := &callRecorder{}
		ctx = withRecorder(ctx, rec)

		var explicitReason string
		defer func() {
			if p := recover(); p != nil {
				// The recovered value can carry request-scoped material (a
				// session token, peer id, ...) baked into a panic message
				// upstream; log it (with a stack trace) for debugging but
				// never echo it back into the client response or the audit
				// row, both of which the flush persists.
				slog.Error("panic recovered in tool handler",
					"tool", req.Params.Name,
					"panic", fmt.Sprintf("%v", p),
					"stack", string(debug.Stack()),
				)
				result = mcplib.NewToolResultError(fmt.Sprintf("internal error in %s tool handler", req.Params.Name))
				err = nil
				explicitReason = ReasonPanic
			}
			s.flushRecordedCall(ctx, rec, req, startedAt, result, explicitReason)
		}()

		result, err = next(ctx, req)
		if err != nil {
			result = mcplib.NewToolResultError(err.Error())
			err = nil
			explicitReason = ReasonHandlerError
		}
		return result, err
	}
}

// flushRecordedCall applies the four flush rules from design.md section B
// and writes every resulting record through Server.writeAuditRow, on a
// context.WithoutCancel + auditWriteTimeout-bounded context so a client
// disconnect can no longer drop the row (mirroring auditDetached).
//
// explicitReason overrides classification for the two cases
// recordToolCall already knows with certainty — a handler-returned error or
// a recovered panic — where classifying the wrapper's own synthesized
// result text would be meaningless. It is empty for every other outcome.
func (s *Server) flushRecordedCall(ctx context.Context, rec *callRecorder, req mcplib.CallToolRequest, startedAt time.Time, final *mcplib.CallToolResult, explicitReason string) {
	records := rec.snapshot()
	isError := explicitReason != "" || (final != nil && final.IsError)

	switch {
	case len(records) > 0 && isError:
		// Rule 1: the call failed after staging at least one record.
		reason := explicitReason
		if reason == "" {
			reason = rec.snapshotHint()
		}
		if reason == "" {
			reason = classifyToolResultReason(final)
		}
		last := &records[len(records)-1]
		if last.status == "error" {
			// The handler already staged its own error: reconcile in place.
			last.reason = reason
			if last.errMsg == "" {
				last.errMsg = firstResultText(final)
			}
		} else {
			// A staged success (e.g. send_message:sent) records an action that
			// really completed; a later failure (jsonResult encode) must not
			// rewrite it. Keep it and append a separate error record carrying
			// the same peer and route. This relies on every handler staging
			// "ok" only for a completed action: a refusal goes through
			// Server.auditRefusal instead.
			records = append(records, callRecord{
				tool:        req.Params.Name,
				peer:        last.peer,
				callPath:    last.callPath,
				status:      "error",
				reason:      reason,
				errMsg:      firstResultText(final),
				id:          auth.From(ctx),
				elapsed:     time.Since(startedAt),
				hasElapsed:  true,
				synthesized: true,
			})
		}
	case len(records) == 0 && isError:
		// Rule 2: nothing reached Server.audit at all — every early-return
		// blind spot design.md documents.
		reason := explicitReason
		if reason == "" {
			reason = rec.snapshotHint()
		}
		if reason == "" {
			reason = classifyToolResultReason(final)
		}
		records = append(records, callRecord{
			tool:        req.Params.Name,
			status:      "error",
			reason:      reason,
			errMsg:      firstResultText(final),
			id:          auth.From(ctx),
			elapsed:     time.Since(startedAt),
			hasElapsed:  true,
			synthesized: true,
		})
	case len(records) == 0 && !isError:
		// Rule 3: a successful call whose handler never calls Server.audit
		// on success gets exactly one synthesized "ok" row, unless the tool
		// is exempt.
		if !auditExemptOnSuccess[req.Params.Name] {
			records = append(records, callRecord{
				tool:        req.Params.Name,
				status:      "ok",
				id:          auth.From(ctx),
				elapsed:     time.Since(startedAt),
				hasElapsed:  true,
				synthesized: true,
			})
		}
	}
	// The remaining case — records staged, success — needs no rule: the
	// handler's own audit call(s) already carry the right status/reason and
	// are flushed as-is below.

	if len(records) == 0 {
		return
	}

	// Rule 4: write every record through the existing path, detached so a
	// client that has already disconnected cannot drop the row.
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	for _, r := range records {
		s.writeAuditRow(detached, r)
	}

	// Rule 5: exactly one counter increment per erroring call, keyed by the
	// canonical tool name mctl_tool_invocations_total already uses — not a
	// per-branch suffixed audit name such as "send_message:draft".
	if isError && s.Metrics != nil {
		s.Metrics.ToolCallErrorsTotal.WithLabelValues(req.Params.Name, records[len(records)-1].reason).Inc()
	}
}

// classifyJSONRPCReason derives a Reason* constant for a JSON-RPC
// tools/call dispatch error from its sentinel/type identity — never from
// its message text, which mcp-go composes with request.Params.Name. The
// three cases design.md documents (server.go:2026-2117 in
// mark3labs/mcp-go@v1.0.0): an unregistered/filtered tool name
// (ErrToolNotFound), the tools capability disabled (ErrUnsupported), and an
// unparsable tools/call body (*UnparsableMessageError). Anything else falls
// back to the honest ReasonJSONRPCError.
func classifyJSONRPCReason(err error) string {
	switch {
	case errors.Is(err, mcpserver.ErrToolNotFound):
		return ReasonToolNotFound
	case errors.Is(err, mcpserver.ErrUnsupported):
		return ReasonCapabilityDisabled
	}
	var unparsable *mcpserver.UnparsableMessageError
	if errors.As(err, &unparsable) {
		return ReasonUnparsableMessage
	}
	return ReasonJSONRPCError
}

// jsonrpcCoder is satisfied by mcp-go's unexported requestError via its one
// exported method (server/server.go, mark3labs/mcp-go@v1.0.0). Asserting on
// this local interface — rather than the unexported concrete type — is the
// only way to read the real JSON-RPC error code for a tools/call rejection
// from outside the server package.
type jsonrpcCoder interface {
	ToJSONRPCError() mcplib.JSONRPCError
}

// jsonrpcHooks builds the mcp-go server hooks that make a JSON-RPC-level
// tools/call rejection visible: an unknown tool name, a ToolFilter
// exclusion, an unparsable tools/call body, or the tools capability itself
// disabled (mctl-telegram#696). None of these ever resolve a handler, so
// Server.recordToolCall — which wraps only resolved handlers — cannot see
// them; this hook is the only place they are observable at all. Scoped to
// tools/call, per requirements.md Out of scope (tools/list, initialize,
// resources/read, ping keep their current, unobserved behaviour).
func (s *Server) jsonrpcHooks(registered *atomic.Pointer[map[string]struct{}]) *mcpserver.Hooks {
	hooks := &mcpserver.Hooks{}
	hooks.AddOnError(func(ctx context.Context, _ any, method mcplib.MCPMethod, message any, err error) {
		if method != mcplib.MethodToolsCall {
			return
		}
		code := 0
		var coder jsonrpcCoder
		if errors.As(err, &coder) {
			code = coder.ToJSONRPCError().Error.Code
		}
		toolName := ""
		if req, ok := message.(*mcplib.CallToolRequest); ok {
			toolName = req.Params.Name
		}
		reason := classifyJSONRPCReason(err)

		uid := int64(0)
		if identity := auth.From(ctx); identity != nil {
			uid = identity.UserID
		}
		attrs := []any{
			"mcp_method", string(mcplib.MethodToolsCall),
			"tool", toolName,
			"jsonrpc_code", code,
			"reason", reason,
			"user_id", uid,
		}
		ec := edgectx.From(ctx)
		if ec.RequestID != "" {
			attrs = append(attrs, "edge_request_id", ec.RequestID)
		}
		if ec.Route != "" {
			attrs = append(attrs, "edge_route", ec.Route)
		}
		slog.Warn("mcp jsonrpc error", attrs...)
		if s.Metrics != nil {
			// The metric label must stay bounded: toolName is a client-supplied
			// string (unlike the registered-tool path, this request never
			// resolved a handler), so any name outside the registered set is
			// collapsed to a fixed sentinel here. The log line above still
			// carries the verbatim name for debugging.
			// Only a name in the registered-tool set is emitted verbatim; a nil
			// set (hook fired before construction finished) fails closed.
			labelTool := "unregistered"
			if registered != nil {
				if names := registered.Load(); names != nil {
					if _, ok := (*names)[toolName]; ok {
						labelTool = toolName
					}
				}
			}
			s.Metrics.ToolCallErrorsTotal.WithLabelValues(labelTool, reason).Inc()
		}
	})
	return hooks
}
