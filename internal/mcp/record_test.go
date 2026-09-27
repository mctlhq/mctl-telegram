package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/bridge"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// --- shared test helpers --------------------------------------------------

// countAuditRows returns the number of audit_logs rows for uid.
func countAuditRows(t *testing.T, store *db.Store, uid int64) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_logs WHERE user_id = $1`, uid,
	).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// totalAuditRows returns the number of audit_logs rows across every user —
// used by the JSON-RPC-hook tests (T6/T7), where no handler ever ran and so
// no user-scoped call exists to count.
func totalAuditRows(t *testing.T, store *db.Store) int {
	t.Helper()
	var n int
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT count(*) FROM audit_logs`,
	).Scan(&n); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// latestAuditReason returns the reason column of the newest audit_logs row
// for uid ("" when NULL).
func latestAuditReason(t *testing.T, store *db.Store, uid int64) string {
	t.Helper()
	var reason sql.NullString
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT reason FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, uid,
	).Scan(&reason); err != nil {
		t.Fatalf("read latest audit reason: %v", err)
	}
	return reason.String
}

// captureSlog swaps slog.Default for a JSON handler writing to buf, restored
// on test cleanup — the same pattern audit_edge_test.go uses.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// countSlogRecords counts JSON slog lines in buf matching level and msg.
func countSlogRecords(t *testing.T, buf string, level, msg string) int {
	t.Helper()
	n := 0
	for _, line := range strings.Split(strings.TrimSpace(buf), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("slog line is not JSON: %v (%q)", err, line)
		}
		if rec["level"] == level && rec["msg"] == msg {
			n++
		}
	}
	return n
}

// callTool drives one tools/call through srv via the in-process callRPC
// harness (apps_surface_test.go) and decodes the result. It fails the test
// on a JSON-RPC-level error — use rawCallTool below for the two hook tests
// that expect one.
func callTool(t *testing.T, ctx context.Context, srv *mcpserver.MCPServer, name string, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	env := callRPC(t, ctx, srv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      name,
		"arguments": args,
	})
	if env.Error != nil {
		t.Fatalf("unexpected JSON-RPC error calling %s: %+v", name, env.Error)
	}
	var result mcplib.CallToolResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode %s result: %v", name, err)
	}
	return &result
}

// --- T3-T5: early-return blind spots (search_messages) -------------------

// TestRecordToolCall_ScopeDenied is T3: search_messages with an identity
// missing telegram:messages:read must produce exactly one audit row
// (status=error, reason=scope_denied), one WARN "mcp tool call" line, and
// one ToolCallErrorsTotal{search_messages,scope_denied} sample — even
// though requireScope's early return (tools.go) never reaches Server.audit.
// This must fail if the middleware registration in newMCPServer is
// reverted, because with no recorder in ctx and no staged record, nothing
// would ever be written.
func TestRecordToolCall_ScopeDenied(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()
	buf := captureSlog(t)

	const uid int64 = 4201
	id := &auth.Identity{UserID: uid, Scopes: []string{}}
	ctx := auth.With(context.Background(), id)

	result := callTool(t, ctx, mcpSrv, "search_messages", map[string]any{"query": "hello"})
	if !result.IsError {
		t.Fatalf("expected an error result for a missing-scope identity, got %+v", result)
	}

	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	tool, status, _ := latestAudit(t, store, uid)
	if tool != "search_messages" || status != "error" {
		t.Fatalf("audit = (%q, %q), want (search_messages, error)", tool, status)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonScopeDenied {
		t.Fatalf("reason = %q, want %q", reason, ReasonScopeDenied)
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp tool call"); n != 1 {
		t.Fatalf("WARN mcp tool call lines = %d, want 1: %s", n, buf.String())
	}
	if got := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("search_messages", ReasonScopeDenied)); got != 1 {
		t.Fatalf("ToolCallErrorsTotal{search_messages,scope_denied} = %v, want 1", got)
	}
}

// TestRecordToolCall_InvalidArgument is T4: search_messages with an empty
// query (a valid scope) must produce one error row with
// reason=invalid_argument.
func TestRecordToolCall_InvalidArgument(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()

	const uid int64 = 4202
	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	result := callTool(t, ctx, mcpSrv, "search_messages", map[string]any{"query": ""})
	if !result.IsError {
		t.Fatalf("expected an error result for an empty query, got %+v", result)
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonInvalidArgument {
		t.Fatalf("reason = %q, want %q", reason, ReasonInvalidArgument)
	}
}

// TestRecordToolCall_ModeUnsupported is T5: search_messages for an account
// whose GetAccountMode returns "local" with a non-nil Hub must produce one
// error row with reason=mode_unsupported.
func TestRecordToolCall_ModeUnsupported(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	uid := seedAccountWithSession(t, store, 4203, false)
	if _, err := store.SetAccountMode(context.Background(), uid, db.ModeLocal); err != nil {
		t.Fatalf("SetAccountMode: %v", err)
	}
	mcpSrv := (&Server{Store: store, Metrics: reg, Hub: bridge.NewHub()}).newMCPServer()

	id := &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}}
	ctx := auth.With(context.Background(), id)

	result := callTool(t, ctx, mcpSrv, "search_messages", map[string]any{"query": "hello"})
	if !result.IsError {
		t.Fatalf("expected an error result for a local-bridge account, got %+v", result)
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonModeUnsupported {
		t.Fatalf("reason = %q, want %q", reason, ReasonModeUnsupported)
	}
}

// --- T6-T7: JSON-RPC-level rejections (jsonrpcHooks) ----------------------

// TestJSONRPCHook_ToolNotFound is T6: an unknown tool name never resolves a
// handler, so recordToolCall cannot see it — only jsonrpcHooks can. No
// audit row is written (there is no user-scoped call to record), one WARN
// "mcp jsonrpc error" line is emitted, and the counter is incremented once.
func TestJSONRPCHook_ToolNotFound(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()
	buf := captureSlog(t)

	before := totalAuditRows(t, store)
	env := callRPC(t, context.Background(), mcpSrv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "no_such_tool",
		"arguments": map[string]any{},
	})
	if env.Error == nil {
		t.Fatal("expected a JSON-RPC error for an unknown tool")
	}
	if env.Error.Code != mcplib.INVALID_PARAMS {
		t.Errorf("code = %d, want %d (INVALID_PARAMS)", env.Error.Code, mcplib.INVALID_PARAMS)
	}
	if after := totalAuditRows(t, store); after != before {
		t.Fatalf("audit rows changed from %d to %d; an unresolved tool call must never write one", before, after)
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp jsonrpc error"); n != 1 {
		t.Fatalf("WARN mcp jsonrpc error lines = %d, want 1: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), `"tool":"no_such_tool"`) {
		t.Errorf("expected the requested tool name in the log line: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `"reason":"tool_not_found"`) {
		t.Errorf("expected reason=tool_not_found: %s", buf.String())
	}
	if got := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("no_such_tool", ReasonToolNotFound)); got != 1 {
		t.Fatalf("ToolCallErrorsTotal{no_such_tool,tool_not_found} = %v, want 1", got)
	}
}

// TestJSONRPCHook_UnparsableMessage is T7: a tools/call whose params cannot
// unmarshal into mcp.CallToolRequest (here, a non-object params value) must
// produce a WARN with reason=unparsable_message and the INVALID_REQUEST
// code.
func TestJSONRPCHook_UnparsableMessage(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()
	buf := captureSlog(t)

	env := callRPC(t, context.Background(), mcpSrv, string(mcplib.MethodToolsCall), 123)
	if env.Error == nil {
		t.Fatal("expected a JSON-RPC error for an unparsable tools/call body")
	}
	if env.Error.Code != mcplib.INVALID_REQUEST {
		t.Errorf("code = %d, want %d (INVALID_REQUEST)", env.Error.Code, mcplib.INVALID_REQUEST)
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp jsonrpc error"); n != 1 {
		t.Fatalf("WARN mcp jsonrpc error lines = %d, want 1: %s", n, buf.String())
	}
	if !strings.Contains(buf.String(), `"reason":"unparsable_message"`) {
		t.Errorf("expected reason=unparsable_message: %s", buf.String())
	}
}

// --- T8: encode-after-ok-audit reconciliation -----------------------------

// TestFlushRecordedCall_ReconcilesEncodeFailureAfterOKAudit is T8: a test
// tool whose handler calls Server.audit with err=nil (staging an "ok"
// record) and then hits jsonResult's json.MarshalIndent failure path must
// end up with exactly one row, status=error, reason=encode_failed — never
// the "ok" row the handler already staged. This is the exact bug design.md
// documents: jsonResult (tools.go) returning an IsError result *after* the
// handler already audited success.
func TestFlushRecordedCall_ReconcilesEncodeFailureAfterOKAudit(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}

	const uid int64 = 4204
	id := &auth.Identity{UserID: uid}

	mcpSrv := mcpserver.NewMCPServer("record-test", "0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithToolHandlerMiddleware(srv.recordToolCall),
	)
	mcpSrv.AddTool(mcplib.NewTool("encode_boom"), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		startedAt := time.Now()
		srv.audit(ctx, id, "encode_boom", "", nil, startedAt) // stages an "ok" record
		return jsonResult(math.Inf(1))                        // json.MarshalIndent fails on +Inf
	})

	ctx := auth.With(context.Background(), id)
	result := callTool(t, ctx, mcpSrv, "encode_boom", map[string]any{})
	if !result.IsError {
		t.Fatalf("expected an error result from the encode failure, got %+v", result)
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want exactly 1 (never both an ok and an error row)", n)
	}
	tool, status, _ := latestAudit(t, store, uid)
	if tool != "encode_boom" || status != "error" {
		t.Fatalf("audit = (%q, %q), want (encode_boom, error) — the pre-existing ok audit must be reconciled, not left standing", tool, status)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonEncodeFailed {
		t.Fatalf("reason = %q, want %q", reason, ReasonEncodeFailed)
	}
}

// --- T9: success path unchanged -------------------------------------------

// TestRecordToolCall_SuccessPathUnchanged is a T9 variant. list_dialogs
// itself needs a live Telegram round trip (Pool.Borrow), which nothing in
// this unit-test suite fakes; get_user_audit_log exercises the exact same
// property — a handler that already calls Server.audit on success, driven
// through the real middleware — without needing one. A successful call
// must produce exactly one "ok" row with an empty reason, one INFO line, no
// WARN, no error-counter sample, and one ToolInvocationsTotal{tool,ok}
// increment.
func TestRecordToolCall_SuccessPathUnchanged(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()
	buf := captureSlog(t)

	const adminUID int64 = 4205
	const targetTGID int64 = 4206
	_ = seedAccountWithSession(t, store, targetTGID, false)
	id := &auth.Identity{UserID: adminUID, Scopes: []string{"admin:users"}}
	ctx := auth.With(context.Background(), id)

	result := callTool(t, ctx, mcpSrv, "get_user_audit_log", map[string]any{"telegram_id": float64(targetTGID)})
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result)
	}

	if n := countAuditRows(t, store, adminUID); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	tool, status, errMsg := latestAudit(t, store, adminUID)
	if tool != "get_user_audit_log" || status != "ok" || errMsg != "" {
		t.Fatalf("audit = (%q, %q, %q), want (get_user_audit_log, ok, \"\")", tool, status, errMsg)
	}
	if reason := latestAuditReason(t, store, adminUID); reason != "" {
		t.Fatalf("reason = %q, want empty on success", reason)
	}
	if n := countSlogRecords(t, buf.String(), "INFO", "mcp tool call"); n != 1 {
		t.Fatalf("INFO mcp tool call lines = %d, want 1: %s", n, buf.String())
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp tool call"); n != 0 {
		t.Fatalf("WARN mcp tool call lines = %d, want 0: %s", n, buf.String())
	}
	if got := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("get_user_audit_log", ReasonUnknown)); got != 0 {
		t.Fatalf("ToolCallErrorsTotal must stay at 0 on success, got %v", got)
	}
	if got := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues("get_user_audit_log", "ok")); got != 1 {
		t.Fatalf("ToolInvocationsTotal{get_user_audit_log,ok} = %v, want 1", got)
	}
}

// --- T10: audit-exempt tools -----------------------------------------------

// TestRecordToolCall_AuditExemptTools is T10: a successful get_my_identity,
// get_my_send_status or get_my_audit_log adds no row (matching their
// existing behaviour); a failing get_my_audit_log (an invalid "before"
// timestamp) still adds exactly one row with reason=invalid_argument.
func TestRecordToolCall_AuditExemptTools(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	mcpSrv := (&Server{Store: store, Metrics: reg}).newMCPServer()

	uid := seedAccountWithSession(t, store, 4207, false)
	id := &auth.Identity{UserID: uid, TelegramID: 4207, Scopes: []string{"telegram:account:read"}}
	ctx := auth.With(context.Background(), id)

	for _, name := range []string{"get_my_identity", "get_my_send_status", "get_my_audit_log"} {
		result := callTool(t, ctx, mcpSrv, name, map[string]any{})
		if result.IsError {
			t.Fatalf("%s: expected success, got %+v", name, result)
		}
		if n := countAuditRows(t, store, uid); n != 0 {
			t.Fatalf("%s: audit rows = %d, want 0 on a successful exempt call", name, n)
		}
	}

	result := callTool(t, ctx, mcpSrv, "get_my_audit_log", map[string]any{"before": "not-a-timestamp"})
	if !result.IsError {
		t.Fatalf("expected an error result for an invalid before timestamp, got %+v", result)
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want exactly 1 for the failing call", n)
	}
	tool, status, _ := latestAudit(t, store, uid)
	if tool != "get_my_audit_log" || status != "error" {
		t.Fatalf("audit = (%q, %q), want (get_my_audit_log, error)", tool, status)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonInvalidArgument {
		t.Fatalf("reason = %q, want %q", reason, ReasonInvalidArgument)
	}

	// The reason column must never surface in the tool's own JSON output —
	// it is operator-only (requirements.md: get_my_audit_log's output schema
	// is unchanged by this proposal).
	for _, c := range result.Content {
		if tc, ok := mcplib.AsTextContent(c); ok && strings.Contains(tc.Text, "reason") {
			t.Errorf("get_my_audit_log result text must never mention reason: %s", tc.Text)
		}
	}
}

// --- T11: handler error / panic absorption --------------------------------

// TestRecordToolCall_HandlerErrorAbsorbed is T11's error half: a tool
// handler returning a non-nil Go error must be absorbed into an
// IsError=true result (never a JSON-RPC INTERNAL_ERROR), recorded with
// reason=handler_error, with no jsonrpcHooks WARN line firing alongside it
// — the no-double-recording invariant.
func TestRecordToolCall_HandlerErrorAbsorbed(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	buf := captureSlog(t)

	const uid int64 = 4208
	id := &auth.Identity{UserID: uid}

	mcpSrv := mcpserver.NewMCPServer("record-test", "0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithToolHandlerMiddleware(srv.recordToolCall),
		mcpserver.WithHooks(srv.jsonrpcHooks()),
	)
	mcpSrv.AddTool(mcplib.NewTool("boom"), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return nil, errors.New("boom")
	})

	ctx := auth.With(context.Background(), id)
	env := callRPC(t, ctx, mcpSrv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "boom",
		"arguments": map[string]any{},
	})
	if env.Error != nil {
		t.Fatalf("a handler error must be absorbed into a tool result, not a JSON-RPC error: %+v", env.Error)
	}
	var result mcplib.CallToolResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an IsError tool result")
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonHandlerError {
		t.Fatalf("reason = %q, want %q", reason, ReasonHandlerError)
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp jsonrpc error"); n != 0 {
		t.Fatalf("the onError hook must not also fire for an absorbed handler error: %d WARN jsonrpc lines: %s", n, buf.String())
	}
}

// TestRecordToolCall_PanicAbsorbed is T11's panic half: a panicking handler
// must be recovered inside the middleware, recorded with reason=panic, and
// converted into an IsError result rather than unwinding into the
// transport.
func TestRecordToolCall_PanicAbsorbed(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	buf := captureSlog(t)

	const uid int64 = 4209
	id := &auth.Identity{UserID: uid}

	mcpSrv := mcpserver.NewMCPServer("record-test", "0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithToolHandlerMiddleware(srv.recordToolCall),
		mcpserver.WithHooks(srv.jsonrpcHooks()),
	)
	mcpSrv.AddTool(mcplib.NewTool("panics"), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		panic("kaboom")
	})

	ctx := auth.With(context.Background(), id)
	env := callRPC(t, ctx, mcpSrv, string(mcplib.MethodToolsCall), map[string]any{
		"name":      "panics",
		"arguments": map[string]any{},
	})
	if env.Error != nil {
		t.Fatalf("a recovered panic must never unwind into a JSON-RPC error: %+v", env.Error)
	}
	var result mcplib.CallToolResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected an IsError tool result")
	}
	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1", n)
	}
	if reason := latestAuditReason(t, store, uid); reason != ReasonPanic {
		t.Fatalf("reason = %q, want %q", reason, ReasonPanic)
	}
	if n := countSlogRecords(t, buf.String(), "WARN", "mcp jsonrpc error"); n != 0 {
		t.Fatalf("the onError hook must not also fire for a recovered panic: %d WARN jsonrpc lines: %s", n, buf.String())
	}
}

// --- T2 (extra): write-through with no recorder in ctx --------------------

// TestAudit_WriteThroughWithNoRecorderIsSynchronous pins the write-through
// branch design.md relies on to keep every direct-handler test green: with
// no *callRecorder installed in ctx, Server.audit writes the row before it
// returns, exactly as it always has.
func TestAudit_WriteThroughWithNoRecorderIsSynchronous(t *testing.T) {
	store := newToolsTestStore(t)
	srv := &Server{Store: store}
	const uid int64 = 4210

	srv.audit(context.Background(), &auth.Identity{UserID: uid}, "list_dialogs", "", nil, time.Time{})

	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1 written synchronously", n)
	}
	tool, status, _ := latestAudit(t, store, uid)
	if tool != "list_dialogs" || status != "ok" {
		t.Fatalf("audit = (%q, %q), want (list_dialogs, ok)", tool, status)
	}
	if reason := latestAuditReason(t, store, uid); reason != "" {
		t.Fatalf("reason = %q, want empty on the write-through path", reason)
	}
}
