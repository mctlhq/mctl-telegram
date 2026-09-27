package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
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
	id                                           *auth.Identity
}

// callRecorder buffers every callRecord staged during one tools/call
// dispatch, in the order Server.audit produced them. A real handler
// invocation stages at most one record (every tool has at most one audited
// branch actually taken per call); the slice exists so
// Server.flushRecordedCall never has to assume that invariant.
type callRecorder struct {
	mu     sync.Mutex
	staged []callRecord
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

// classifyReason turns a staged/synthesized record's callPath plus the
// call's final tool result into one of the Reason* constants.
// callPath=="local" is the existing marker for a Local Bridge relay call
// (see bridgeResultErr and its callers); a call that reached the bridge and
// failed is classified bridge_error regardless of what its result text
// happens to say, since the daemon's own error text is not one this
// package controls or can enumerate. Every other case falls through to the
// text classifier.
func classifyReason(callPath string, final *mcplib.CallToolResult) string {
	if callPath == "local" {
		return ReasonBridgeError
	}
	return classifyToolResultReason(final)
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
				result = mcplib.NewToolResultError(fmt.Sprintf("panic recovered in %s tool handler: %v", req.Params.Name, p))
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
		// Rule 1: reconcile the last staged record — this is what fixes the
		// jsonResult encode-after-ok-audit bug, and also the normal case
		// where a handler already staged its own error.
		last := &records[len(records)-1]
		last.status = "error"
		if explicitReason != "" {
			last.reason = explicitReason
		} else {
			last.reason = classifyReason(last.callPath, final)
		}
		if last.errMsg == "" {
			last.errMsg = firstResultText(final)
		}
	case len(records) == 0 && isError:
		// Rule 2: nothing reached Server.audit at all — every early-return
		// blind spot design.md documents.
		reason := explicitReason
		if reason == "" {
			reason = classifyReason("", final)
		}
		records = append(records, callRecord{
			tool:       req.Params.Name,
			status:     "error",
			reason:     reason,
			errMsg:     firstResultText(final),
			id:         auth.From(ctx),
			elapsed:    time.Since(startedAt),
			hasElapsed: true,
		})
	case len(records) == 0 && !isError:
		// Rule 3: a successful call whose handler never calls Server.audit
		// on success gets exactly one synthesized "ok" row, unless the tool
		// is exempt.
		if !auditExemptOnSuccess[req.Params.Name] {
			records = append(records, callRecord{
				tool:       req.Params.Name,
				status:     "ok",
				id:         auth.From(ctx),
				elapsed:    time.Since(startedAt),
				hasElapsed: true,
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
func (s *Server) jsonrpcHooks() *mcpserver.Hooks {
	hooks := &mcpserver.Hooks{}
	hooks.AddOnError(func(ctx context.Context, _ any, method mcplib.MCPMethod, message any, err error) {
		if method != mcplib.MethodToolsCall {
			return
		}
		code := 0
		if coder, ok := err.(jsonrpcCoder); ok {
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
			s.Metrics.ToolCallErrorsTotal.WithLabelValues(toolName, reason).Inc()
		}
	})
	return hooks
}
