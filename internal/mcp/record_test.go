package mcp

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotd/td/tgerr"
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
	// The Rule 2 synthesized error record must not feed the SLO-input pair:
	// callRecord.synthesized gates it (feedsSLO), and counting it in
	// ToolInvocationsTotal would inflate mctl_tool_availability's error
	// numerator on every scope-denied/invalid-argument call, which can
	// false-page an on-call via MctlToolAvailabilityFastBurn.
	if got := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues("search_messages", "error")); got != 0 {
		t.Fatalf("ToolInvocationsTotal{search_messages,error} = %v, want 0 (Rule 2 records must not feed the availability SLO)", got)
	}
	if got := histogramSampleCount(t, reg, "search_messages"); got != 0 {
		t.Fatalf("ToolInvocationDuration sample count for search_messages = %d, want 0", got)
	}
}

// histogramSampleCount returns the total sample count observed under
// ToolInvocationDuration for the given tool label (its only label), by
// gathering the raw Prometheus metric family.
func histogramSampleCount(t *testing.T, m *metrics.Registry, tool string) uint64 {
	t.Helper()
	mfs, err := m.Prometheus.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "mctl_tool_invocation_duration_seconds" {
			continue
		}
		var total uint64
		for _, metric := range mf.GetMetric() {
			for _, l := range metric.GetLabel() {
				if l.GetName() == "tool" && l.GetValue() == tool {
					total += metric.GetHistogram().GetSampleCount()
				}
			}
		}
		return total
	}
	return 0
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
	if got := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("unregistered", ReasonToolNotFound)); got != 1 {
		t.Fatalf("ToolCallErrorsTotal{unregistered,tool_not_found} = %v, want 1", got)
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

// TestFlushRecordedCall_KeepsCompletedActionRow is T6/T8: a test tool whose
// handler calls Server.audit with err=nil (staging an "ok" record, like
// send_message:sent after a real send) and then hits jsonResult's
// json.MarshalIndent failure path must keep the staged "ok" row untouched and
// append a separate error row (reason=encode_failed) — the audit log must
// never deny an action that completed. Exactly one ToolCallErrorsTotal sample.
func TestFlushRecordedCall_KeepsCompletedActionRow(t *testing.T) {
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
		srv.audit(ctx, id, "encode_boom:sent", "", nil, startedAt) // stages an "ok" record
		return jsonResult(math.Inf(1))                             // json.MarshalIndent fails on +Inf
	})

	ctx := auth.With(context.Background(), id)
	result := callTool(t, ctx, mcpSrv, "encode_boom", map[string]any{})
	if !result.IsError {
		t.Fatalf("expected an error result from the encode failure, got %+v", result)
	}
	rows, err := store.DB.QueryContext(context.Background(),
		`SELECT tool_name, status, COALESCE(reason, '') FROM audit_logs WHERE user_id = $1 ORDER BY id`, uid)
	if err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	defer rows.Close()
	type row struct{ tool, status, reason string }
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tool, &r.status, &r.reason); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	want := []row{
		{"encode_boom:sent", "ok", ""},
		{"encode_boom", "error", ReasonEncodeFailed},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("audit rows = %+v, want %+v", got, want)
	}
	if n := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("encode_boom", ReasonEncodeFailed)); n != 1 {
		t.Fatalf("ToolCallErrorsTotal{encode_boom,encode_failed} = %v, want 1", n)
	}
	// The appended record is synthesized; only the staged ok record feeds the SLO.
	if n := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues("encode_boom", "error")); n != 0 {
		t.Fatalf("ToolInvocationsTotal{encode_boom,error} = %v, want 0", n)
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
		mcpserver.WithHooks(srv.jsonrpcHooks(nil)),
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
		mcpserver.WithHooks(srv.jsonrpcHooks(nil)),
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

// --- T12: Rule 3 synthesis for a handler that never audits its success ----

// TestFlushRecordedCall_SynthesizesOKRowOnUnauditedSuccess pins Rule 3: a
// successful call whose handler stages no records at all (it never calls
// Server.audit) still gets exactly one synthesized "ok" row, one INFO log
// line, a ToolInvocationsTotal{tool,ok} increment, and no
// ToolCallErrorsTotal sample — unless the tool is in auditExemptOnSuccess
// (covered separately by T10).
func TestFlushRecordedCall_SynthesizesOKRowOnUnauditedSuccess(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	buf := captureSlog(t)

	const uid int64 = 4211
	id := &auth.Identity{UserID: uid}

	mcpSrv := mcpserver.NewMCPServer("record-test", "0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithToolHandlerMiddleware(srv.recordToolCall),
		mcpserver.WithHooks(srv.jsonrpcHooks(nil)),
	)
	mcpSrv.AddTool(mcplib.NewTool("quiet_success"), func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return jsonResult(map[string]any{"ok": true})
	})

	ctx := auth.With(context.Background(), id)
	result := callTool(t, ctx, mcpSrv, "quiet_success", map[string]any{})
	if result.IsError {
		t.Fatalf("expected success, got error result: %+v", result)
	}

	if n := countAuditRows(t, store, uid); n != 1 {
		t.Fatalf("audit rows = %d, want 1 synthesized", n)
	}
	tool, status, errMsg := latestAudit(t, store, uid)
	if tool != "quiet_success" || status != "ok" || errMsg != "" {
		t.Fatalf("audit = (%q, %q, %q), want (quiet_success, ok, \"\")", tool, status, errMsg)
	}
	if reason := latestAuditReason(t, store, uid); reason != "" {
		t.Fatalf("reason = %q, want empty on success", reason)
	}
	if n := countSlogRecords(t, buf.String(), "INFO", "mcp tool call"); n != 1 {
		t.Fatalf("INFO mcp tool call lines = %d, want 1: %s", n, buf.String())
	}
	if got := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("quiet_success", ReasonUnknown)); got != 0 {
		t.Fatalf("ToolCallErrorsTotal must stay at 0 on success, got %v", got)
	}
	// A Rule 3 record is synthesized, so it never feeds the SLO pair.
	if got := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues("quiet_success", "ok")); got != 0 {
		t.Fatalf("ToolInvocationsTotal{quiet_success,ok} = %v, want 0 (synthesized records never feed the SLO)", got)
	}
}

// --- #703 follow-ups -------------------------------------------------------

// hintTestServer builds a server with one tool running handler behind the
// recording middleware.
func hintTestServer(t *testing.T, srv *Server, name string, h mcpserver.ToolHandlerFunc) *mcpserver.MCPServer {
	t.Helper()
	m := mcpserver.NewMCPServer("record-test", "0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithToolHandlerMiddleware(srv.recordToolCall),
	)
	m.AddTool(mcplib.NewTool(name), h)
	return m
}

// TestHintReason_BeatsTextClassification: a hinted reason beats a
// contradicting result text, in both the audit row and the error counter.
func TestHintReason_BeatsTextClassification(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	const uid int64 = 4220
	m := hintTestServer(t, srv, "hinting", func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		hintReason(ctx, ReasonStoreError)
		return mcplib.NewToolResultError("thing not found"), nil // classifies as not_found
	})
	callTool(t, auth.With(context.Background(), &auth.Identity{UserID: uid}), m, "hinting", map[string]any{})
	if r := latestAuditReason(t, store, uid); r != ReasonStoreError {
		t.Fatalf("reason = %q, want %q", r, ReasonStoreError)
	}
	if n := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("hinting", ReasonStoreError)); n != 1 {
		t.Fatalf("ToolCallErrorsTotal{hinting,store_error} = %v, want 1", n)
	}
}

// TestHintReason_LosesToPanicAndHandlerError: the wrapper's certain knowledge
// outranks any hint.
func TestHintReason_LosesToPanicAndHandlerError(t *testing.T) {
	store := newToolsTestStore(t)
	srv := &Server{Store: store, Metrics: metrics.New()}
	for i, tc := range []struct {
		name string
		h    mcpserver.ToolHandlerFunc
		want string
	}{
		{"hint_panic", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			hintReason(ctx, ReasonStoreError)
			panic("kaboom")
		}, ReasonPanic},
		{"hint_err", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			hintReason(ctx, ReasonStoreError)
			return nil, errors.New("boom")
		}, ReasonHandlerError},
		// Rule 1: a staged record exists, so precedence is resolved on the
		// reconcile-in-place and append paths, not Rule 2's.
		{"staged_ok_hint_panic", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			srv.audit(ctx, auth.From(ctx), "staged_ok_hint_panic", "", nil, time.Now())
			hintReason(ctx, ReasonStoreError)
			panic("kaboom")
		}, ReasonPanic},
		{"staged_err_hint_err", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			srv.audit(ctx, auth.From(ctx), "staged_err_hint_err", "", errors.New("staged"), time.Now())
			hintReason(ctx, ReasonStoreError)
			return nil, errors.New("boom")
		}, ReasonHandlerError},
	} {
		uid := int64(4230 + i)
		m := hintTestServer(t, srv, tc.name, tc.h)
		callTool(t, auth.With(context.Background(), &auth.Identity{UserID: uid}), m, tc.name, map[string]any{})
		if r := latestAuditReason(t, store, uid); r != tc.want {
			t.Fatalf("%s: reason = %q, want %q", tc.name, r, tc.want)
		}
	}
}

// TestStoreErr_RecordsStoreError: storeErr keeps the tool-prefixed text and
// hints store_error.
func TestStoreErr_RecordsStoreError(t *testing.T) {
	store := newToolsTestStore(t)
	srv := &Server{Store: store, Metrics: metrics.New()}
	const uid int64 = 4240
	m := hintTestServer(t, srv, "store_tool", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return srv.storeErr(ctx, "store_tool", errors.New("row not found")), nil
	})
	res := callTool(t, auth.With(context.Background(), &auth.Identity{UserID: uid}), m, "store_tool", map[string]any{})
	if got := firstResultText(res); got != "store_tool: row not found" {
		t.Fatalf("text = %q", got)
	}
	if r := latestAuditReason(t, store, uid); r != ReasonStoreError {
		t.Fatalf("reason = %q, want %q", r, ReasonStoreError)
	}
}

// TestBorrowErrResult_UnenumeratedMTProtoIsTelegramError: an MTProto code in
// neither catalog records telegram_error rather than unknown.
func TestBorrowErrResult_UnenumeratedMTProtoIsTelegramError(t *testing.T) {
	store := newToolsTestStore(t)
	srv := &Server{Store: store, Metrics: metrics.New()}
	const uid int64 = 4241
	m := hintTestServer(t, srv, "tg_tool", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		return borrowErrResult(ctx, "tg_tool", tgerr.New(500, "SOME_UNLISTED_ERROR_XYZ")), nil
	})
	callTool(t, auth.With(context.Background(), &auth.Identity{UserID: uid}), m, "tg_tool", map[string]any{})
	if r := latestAuditReason(t, store, uid); r != ReasonTelegramError {
		t.Fatalf("reason = %q, want %q", r, ReasonTelegramError)
	}
}

// TestRecordToolCall_LocalRefusalIsNotBridgeError: fetch_media=true on a local
// account is refused without ever calling the bridge.
func TestRecordToolCall_LocalRefusalIsNotBridgeError(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 4242, false)
	if _, err := store.SetAccountMode(context.Background(), uid, db.ModeLocal); err != nil {
		t.Fatalf("SetAccountMode: %v", err)
	}
	mcpSrv := (&Server{Store: store, Metrics: metrics.New(), Hub: bridge.NewHub()}).newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: []string{"telegram:messages:read"}})
	res := callTool(t, ctx, mcpSrv, "get_unread_messages", map[string]any{"fetch_media": true})
	if !res.IsError {
		t.Fatalf("expected error result, got %+v", res)
	}
	if r := latestAuditReason(t, store, uid); r != ReasonModeUnsupported {
		t.Fatalf("reason = %q, want %q", r, ReasonModeUnsupported)
	}
	var cp sql.NullString
	if err := store.DB.QueryRowContext(context.Background(),
		`SELECT call_path FROM audit_logs WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, uid).Scan(&cp); err != nil {
		t.Fatalf("read call_path: %v", err)
	}
	if cp.String != "local" {
		t.Fatalf("call_path = %q, want local", cp.String)
	}
}

// TestRecordToolCall_BridgeFailureIsBridgeError: a relay to an absent daemon
// fails and is recorded as bridge_error.
func TestRecordToolCall_BridgeFailureIsBridgeError(t *testing.T) {
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 4243, false)
	if _, err := store.SetAccountMode(context.Background(), uid, db.ModeLocal); err != nil {
		t.Fatalf("SetAccountMode: %v", err)
	}
	mcpSrv := (&Server{Store: store, Metrics: metrics.New(), Hub: bridge.NewHub()}).newMCPServer()
	ctx := auth.With(context.Background(), &auth.Identity{UserID: uid, Scopes: []string{"telegram:dialogs:read"}})
	res := callTool(t, ctx, mcpSrv, "list_dialogs", map[string]any{})
	if !res.IsError {
		t.Fatalf("expected error result, got %+v", res)
	}
	if r := latestAuditReason(t, store, uid); r != ReasonBridgeError {
		t.Fatalf("reason = %q, want %q", r, ReasonBridgeError)
	}
}

// TestFeedsSLO_SynthesizedNeverFeedsSLO: no synthesized record samples the SLO
// pair, whatever its reason; a record staged by Server.audit still does.
func TestFeedsSLO_SynthesizedNeverFeedsSLO(t *testing.T) {
	if (callRecord{synthesized: true, reason: ReasonPanic}).feedsSLO() {
		t.Fatal("a synthesized panic record must not feed the SLO")
	}
	if !(callRecord{}).feedsSLO() {
		t.Fatal("a staged record must feed the SLO")
	}
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	id := &auth.Identity{UserID: 4250}
	ctx := auth.With(context.Background(), id)
	for _, tc := range []struct {
		name string
		h    mcpserver.ToolHandlerFunc
	}{
		{"t_panic", func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) { panic("x") }},
		{"t_herr", func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			return nil, errors.New("x")
		}},
		{"t_invalid", func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
			return mcplib.NewToolResultError("peer is required"), nil
		}},
		{"t_ok", func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) { return jsonResult(1) }},
	} {
		callTool(t, ctx, hintTestServer(t, srv, tc.name, tc.h), tc.name, map[string]any{})
		for _, st := range []string{"ok", "error"} {
			if n := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues(tc.name, st)); n != 0 {
				t.Fatalf("%s: ToolInvocationsTotal{%s} = %v, want 0", tc.name, st, n)
			}
		}
		if n := histogramSampleCount(t, reg, tc.name); n != 0 {
			t.Fatalf("%s: duration samples = %d, want 0", tc.name, n)
		}
	}
	// A record staged by Server.audit still feeds the pair.
	m := hintTestServer(t, srv, "t_staged", func(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		srv.audit(ctx, id, "t_staged", "", nil, time.Now())
		return jsonResult(1)
	})
	callTool(t, ctx, m, "t_staged", map[string]any{})
	if n := testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues("t_staged", "ok")); n != 1 {
		t.Fatalf("staged record: ToolInvocationsTotal = %v, want 1", n)
	}
}

// wrappedCodeErr satisfies jsonrpcCoder, like mcp-go's unexported requestError.
type wrappedCodeErr struct{}

func (wrappedCodeErr) Error() string { return "coded" }
func (wrappedCodeErr) ToJSONRPCError() mcplib.JSONRPCError {
	var e mcplib.JSONRPCError
	e.Error.Code = mcplib.INVALID_PARAMS
	return e
}

// TestJSONRPCHook_WrappedErrorKeepsCode: errors.As finds the code through a wrap.
func TestJSONRPCHook_WrappedErrorKeepsCode(t *testing.T) {
	srv := &Server{Metrics: metrics.New()}
	buf := captureSlog(t)
	hooks := srv.jsonrpcHooks(nil)
	for _, f := range hooks.OnError {
		f(context.Background(), 1, mcplib.MethodToolsCall, &mcplib.CallToolRequest{}, fmt.Errorf("wrap: %w", wrappedCodeErr{}))
	}
	if !strings.Contains(buf.String(), `"jsonrpc_code":-32602`) {
		t.Fatalf("expected the wrapped error's real code in the log line: %s", buf.String())
	}
}

// TestJSONRPCHook_UnregisteredLabelIsAllowlisted: the metric tool label is
// verbatim only for a registered name.
func TestJSONRPCHook_UnregisteredLabelIsAllowlisted(t *testing.T) {
	reg := metrics.New()
	srv := &Server{Metrics: reg}
	captureSlog(t)
	registered := map[string]struct{}{"list_dialogs": {}}
	var ptr atomic.Pointer[map[string]struct{}]
	fire := func(p *atomic.Pointer[map[string]struct{}], name string) {
		for _, f := range srv.jsonrpcHooks(p).OnError {
			f(context.Background(), 1, mcplib.MethodToolsCall, &mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: name}}, mcpserver.ErrUnsupported)
		}
	}
	fire(&ptr, "list_dialogs") // set not yet stored: fail closed
	ptr.Store(&registered)
	fire(&ptr, "list_dialogs")
	fire(&ptr, "attacker_chosen_name")
	if n := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("list_dialogs", ReasonCapabilityDisabled)); n != 1 {
		t.Fatalf("registered name label = %v, want 1", n)
	}
	if n := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("unregistered", ReasonCapabilityDisabled)); n != 2 {
		t.Fatalf("unregistered label = %v, want 2 (nil set + unknown name)", n)
	}
	if n := testutil.ToFloat64(reg.ToolCallErrorsTotal.WithLabelValues("attacker_chosen_name", ReasonCapabilityDisabled)); n != 0 {
		t.Fatalf("client-supplied name leaked into the label: %v", n)
	}
}
