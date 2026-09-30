package mcp

import (
	"strings"

	mcplib "github.com/mark3labs/mcp-go/mcp"
)

// Reason* is the closed set of tool-call-failure classifications this
// package ever writes to audit_logs.reason, the "mcp tool call" / "mcp
// jsonrpc error" slog lines, and the mctl_tool_call_errors_total{reason}
// label (mctl-telegram#696). Every value here is a compile-time constant;
// no client-supplied string is ever used as a reason, which is what keeps
// the counter's label cardinality bounded.
const (
	// ReasonAuthRequired is raised by requireScope / requireAnyScope when
	// ctx carries no identity at all.
	ReasonAuthRequired = "auth_required"
	// ReasonScopeDenied is raised by requireScope / requireAnyScope when an
	// identity is present but lacks the required OAuth scope.
	ReasonScopeDenied = "scope_denied"
	// ReasonInvalidArgument is raised by empty/malformed tool-argument
	// checks (missing required field, wrong enum value, out-of-range
	// number, mutually-exclusive fields both set, ...).
	ReasonInvalidArgument = "invalid_argument"
	// ReasonModeUnsupported is raised when a tool refuses a Local-Bridge
	// (mode="local") account because it has no bridge-side implementation.
	ReasonModeUnsupported = "mode_unsupported"
	// ReasonRefused is raised by policy refusals that are neither a scope
	// nor an argument problem — the demo-reviewer account-management guard,
	// a dry-run "blocked:" preview, a generic mint-policy rejection.
	ReasonRefused = "refused"
	// ReasonRateLimited is raised when audit.RateLimiter blocks a
	// destructive send/write action.
	ReasonRateLimited = "rate_limited"
	// ReasonNotFound is raised when a referenced resource — an unknown
	// Local Bridge device, an expired media reference, an unrecognized
	// confirmation_id, a session with no linked identity — cannot be
	// located.
	ReasonNotFound = "not_found"
	// ReasonConfirmationRejected is raised by internal/mcp/confirm.go when a
	// confirmation_id was issued for a different call, or belongs to
	// another identity.
	ReasonConfirmationRejected = "confirmation_rejected"
	// ReasonTelegramError is raised by borrowWithRetry / MTProto failures:
	// pool exhaustion, a broken/expired session, or an tgerr.Error the
	// catalog in errorcatalog.go already classifies.
	ReasonTelegramError = "telegram_error"
	// ReasonBridgeError is raised when a Local Bridge daemon call
	// (bridgeResultErr) fails.
	ReasonBridgeError = "bridge_error"
	// ReasonStoreError is raised by *db.Store failures unrelated to the
	// audit log itself (a lookup or write against another table failing).
	// Emitted by Server.storeErr.
	ReasonStoreError = "store_error"
	// ReasonEncodeFailed is raised by jsonResult's json.MarshalIndent
	// failure path (and the inline equivalent in toolSearchMessages).
	ReasonEncodeFailed = "encode_failed"
	// ReasonHandlerError is raised by the recording middleware when a tool
	// handler returns a non-nil Go error instead of an IsError result.
	ReasonHandlerError = "handler_error"
	// ReasonPanic is raised by the recording middleware when it recovers a
	// panic from a tool handler.
	ReasonPanic = "panic"
	// ReasonUnknown is the classifier's fallback: an IsError result whose
	// text matched none of the literals below. Deliberately honest rather
	// than a guessed label.
	ReasonUnknown = "unknown"
	// ReasonToolNotFound is raised by the JSON-RPC error hook when mcp-go
	// rejects a tools/call for an unregistered or filtered-out tool name
	// (server.ErrToolNotFound).
	ReasonToolNotFound = "tool_not_found"
	// ReasonUnparsableMessage is raised by the JSON-RPC error hook when the
	// tools/call params could not be unmarshaled into mcp.CallToolRequest
	// (server.UnparsableMessageError).
	ReasonUnparsableMessage = "unparsable_message"
	// ReasonCapabilityDisabled is raised by the JSON-RPC error hook when the
	// tools capability itself is not enabled on the server
	// (server.ErrUnsupported).
	ReasonCapabilityDisabled = "capability_disabled"
	// ReasonJSONRPCError is the JSON-RPC error hook's fallback for any other
	// tools/call dispatch error mcp-go returns.
	ReasonJSONRPCError = "jsonrpc_error"
	// ReasonMediaCapacity (issue #705) is raised when the media admission
	// gate refuses a fetch_media=true bulk fetch or a get_media download
	// because MEDIA_MAX_CONCURRENT operations are already in flight and no
	// slot freed within the gate's admission wait.
	ReasonMediaCapacity = "media_capacity"
)

// classifyToolResultReason infers a Reason* constant from the text of a
// tool's final *mcplib.CallToolResult. It is a best-effort narrowing of an
// otherwise-unlabelled bucket, never an authorization input: the literals it
// matches are copied verbatim from the handlers that produce them (see
// reasons_test.go), and anything unrecognized — including any text an MCP
// client could ever supply — falls back to ReasonUnknown rather than a
// guessed label.
//
// Only the first text content block is inspected, matching how every
// handler in this package builds its error result via
// mcplib.NewToolResultError, which sets exactly one text block.
func classifyToolResultReason(res *mcplib.CallToolResult) string {
	if res == nil {
		return ReasonUnknown
	}
	text := firstResultText(res)
	if text == "" {
		return ReasonUnknown
	}

	switch {
	case text == "authentication required":
		return ReasonAuthRequired
	case strings.HasPrefix(text, "identity missing scope "):
		return ReasonScopeDenied
	case strings.HasPrefix(text, "encode: "):
		return ReasonEncodeFailed
	case strings.HasSuffix(text, " is not yet supported for local-bridge accounts"),
		strings.Contains(text, "is not supported in Local Bridge mode"):
		return ReasonModeUnsupported
	case text == errMediaBusy.Error():
		return ReasonMediaCapacity
	}

	// Fallback only: an explicit hintReason (borrowErrResult) outranks this
	// text match. Catalog messages must not be prefixes of one another, or
	// the result would depend on map iteration order (see reasons_test.go).
	// Telegram permanent-error catalog (errorcatalog.go's mtprotoErrCatalog),
	// rendered by mtprotoErrResult as "<entry.message>[ <entry.action>]".
	// Checked before argument validation below: CHANNEL_PRIVATE's message
	// contains "must be " (via its action text), which would otherwise be
	// misclassified as ReasonInvalidArgument.
	for _, entry := range mtprotoErrCatalog {
		if strings.HasPrefix(text, entry.message) {
			return ReasonTelegramError
		}
	}

	// Argument validation: the handlers in tools.go / media_tools.go /
	// apps.go phrase every "you gave me something I can't use" refusal with
	// one of these fragments. Order matters only in that each case below is
	// independent, not overlapping with another bucket.
	switch {
	case strings.Contains(text, " is required"),
		strings.Contains(text, " are required"),
		strings.Contains(text, "confirmation_id required"),
		strings.Contains(text, "must be "),
		strings.Contains(text, "must be one of"),
		strings.Contains(text, "mutually exclusive"),
		strings.Contains(text, "exactly one of"):
		return ReasonInvalidArgument
	}

	// Confirmation-flow mismatches (internal/mcp/confirm.go and the inline
	// equivalents in tools.go / media_tools.go).
	switch {
	case strings.Contains(text, "confirmation_id was issued for a different"),
		strings.Contains(text, "confirmation_id belongs to another identity"):
		return ReasonConfirmationRejected
	case strings.Contains(text, "confirmation_id not found, expired, or already used"):
		return ReasonNotFound
	}

	// Telegram-side failures: the friendly session-sentinel messages
	// (sessionErrText), pool exhaustion, and the MTProto risk-gated /
	// flood-wait JSON envelopes emitted by errorcatalog.go. Checked before
	// the generic rate-limit substring below: a flood-wait envelope's
	// message field says "Telegram rate limit reached", which would
	// otherwise be misclassified as the per-peer send limiter.
	switch {
	case strings.Contains(text, "Telegram setup is incomplete"),
		strings.Contains(text, "Your Telegram session is no longer valid"),
		strings.Contains(text, "Your Telegram session has expired"),
		strings.Contains(text, "No Telegram account is connected"),
		strings.Contains(text, "server at session capacity"),
		strings.Contains(text, `"error":"flood_wait"`),
		strings.Contains(text, `"error":"slowmode_wait"`),
		strings.Contains(text, `"error":"RISK_GATED"`):
		return ReasonTelegramError
	}

	// Rate limiting (audit.RateLimiter's per-peer send cap).
	if strings.Contains(text, "rate limit reached") {
		return ReasonRateLimited
	}

	// Policy refusals: dry-run/"blocked:" previews and the demo-reviewer
	// account-management guard.
	switch {
	case strings.Contains(text, " blocked: "),
		text == demoReviewerAccountMgmtRefusal:
		return ReasonRefused
	}

	// "<tool> not found" style lookups (unknown device, no identity on this
	// session, ...).
	if strings.Contains(text, "not found") || strings.Contains(text, "no Telegram identity on this session") {
		return ReasonNotFound
	}

	return ReasonUnknown
}

// firstResultText returns the text of the first mcplib.TextContent block in
// res, or "" if res carries none. classifyToolResultReason never inspects
// anything beyond this: no arguments, no structured content, no other
// content blocks.
func firstResultText(res *mcplib.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := mcplib.AsTextContent(c); ok {
			return tc.Text
		}
	}
	return ""
}
