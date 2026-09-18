package mcp

import (
	"context"
	"reflect"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/mctlhq/mctl-telegram/internal/edgectx"
)

// recordingSpan is a trace.Span that reports itself as recording and
// captures the attributes it is given. It embeds the OpenTelemetry API's
// no-op span, not the SDK: mctl-telegram has no tracer wired, and
// mctlhq/.github#55 owns installing one. This type exists only to prove what
// the adapter writes onto a span that already exists in ctx.
type recordingSpan struct {
	noop.Span
	attrs []attribute.KeyValue
}

func (s *recordingSpan) IsRecording() bool { return true }

func (s *recordingSpan) SetAttributes(kv ...attribute.KeyValue) {
	s.attrs = append(s.attrs, kv...)
}

func fullEdgeContext() edgectx.Context {
	return edgectx.Context{
		RequestID:       "a39ad476896f4649-IAD",
		Route:           edgectx.RoutePortal,
		MCPMethod:       "tools/call",
		MCPName:         "get_my_identity",
		ProtocolVersion: "2026-07-28",
	}
}

func attrMap(attrs []attribute.KeyValue) map[string]attribute.Value {
	m := make(map[string]attribute.Value, len(attrs))
	for _, kv := range attrs {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

// T1: every existing edgectx.Context correlation field populated must
// produce the eight canonical keys with the expected values.
func TestAuditSpanAttributes_MapsAllCanonicalFields(t *testing.T) {
	got := attrMap(auditSpanAttributes(fullEdgeContext(), "get_my_identity", "ok", 7))

	want := map[string]string{
		"mctl.edge.request_id": "a39ad476896f4649-IAD",
		"mctl.edge.route":      edgectx.RoutePortal,
		"mcp.method":           "tools/call",
		"mcp.name":             "get_my_identity",
		"mcp.protocol_version": "2026-07-28",
		"mctl.tool.name":       "get_my_identity",
		"mctl.tool.status":     "ok",
	}
	for k, w := range want {
		v, ok := got[k]
		if !ok {
			t.Errorf("missing attribute %s", k)
			continue
		}
		if v.AsString() != w {
			t.Errorf("%s = %q, want %q", k, v.AsString(), w)
		}
	}
	if v, ok := got["mctl.user.id"]; !ok || v.AsInt64() != 7 {
		t.Errorf("mctl.user.id = %v, want 7", got["mctl.user.id"])
	}
	if len(got) != 8 {
		t.Errorf("got %d attributes, want exactly 8: %v", len(got), got)
	}
}

// T2: empty optional edge/MCP fields must not produce empty attributes, but
// the tool name, status and user id are always present -- they come from the
// audit call itself, not from the edge, so they are never optional.
func TestAuditSpanAttributes_OmitsEmptyOptionalFields(t *testing.T) {
	got := attrMap(auditSpanAttributes(edgectx.Context{}, "list_dialogs", "error", 0))

	for _, k := range []string{
		"mctl.edge.request_id",
		"mctl.edge.route",
		"mcp.method",
		"mcp.name",
		"mcp.protocol_version",
	} {
		if _, ok := got[k]; ok {
			t.Errorf("attribute %s must be omitted when the edge value is empty, got %v", k, got[k])
		}
	}
	if v, ok := got["mctl.tool.name"]; !ok || v.AsString() != "list_dialogs" {
		t.Errorf("mctl.tool.name = %v, want %q", got["mctl.tool.name"], "list_dialogs")
	}
	if v, ok := got["mctl.tool.status"]; !ok || v.AsString() != "error" {
		t.Errorf("mctl.tool.status = %v, want %q", got["mctl.tool.status"], "error")
	}
	if v, ok := got["mctl.user.id"]; !ok || v.AsInt64() != 0 {
		t.Errorf("mctl.user.id = %v, want 0", got["mctl.user.id"])
	}
	if len(got) != 3 {
		t.Errorf("got %d attributes, want exactly 3: %v", len(got), got)
	}
}

// T3: the helper's signature is the entire sensitive-data surface of this
// adapter. It must stay (edgectx.Context, tool string, status string,
// userID int64) with no slot for tool arguments, peer, handle, message body,
// authorization or arbitrary headers -- widening it would silently open a
// path for private payload data to reach a span.
func TestAuditSpanAttributes_SignatureHasNoSensitiveDataSurface(t *testing.T) {
	fn := reflect.TypeOf(auditSpanAttributes)
	wantIn := []reflect.Type{
		reflect.TypeOf(edgectx.Context{}),
		reflect.TypeOf(""),
		reflect.TypeOf(""),
		reflect.TypeOf(int64(0)),
	}
	if fn.NumIn() != len(wantIn) {
		t.Fatalf("auditSpanAttributes takes %d arguments, want %d: %v", fn.NumIn(), len(wantIn), fn)
	}
	for i, want := range wantIn {
		if got := fn.In(i); got != want {
			t.Errorf("argument %d is %v, want %v", i, got, want)
		}
	}
}

// T4: with no recording span in ctx, the adapter must perform no tracing
// side effect and must not panic. context.Background() carries no span at
// all, which trace.SpanFromContext resolves to a non-recording no-op span.
func TestSetAuditSpanAttributes_NoRecordingSpanIsNoOp(t *testing.T) {
	setAuditSpanAttributes(context.Background(), fullEdgeContext(), "get_my_identity", "ok", 7)
}

// Companion to T4/T1: when ctx does carry a recording span, the adapter must
// write exactly the attributes auditSpanAttributes computes -- proving the
// two are actually wired together, not just independently correct.
func TestSetAuditSpanAttributes_WritesToARecordingSpan(t *testing.T) {
	span := &recordingSpan{}
	ctx := trace.ContextWithSpan(context.Background(), span)

	setAuditSpanAttributes(ctx, fullEdgeContext(), "get_my_identity", "ok", 7)

	got := attrMap(span.attrs)
	want := attrMap(auditSpanAttributes(fullEdgeContext(), "get_my_identity", "ok", 7))
	if len(got) != len(want) {
		t.Fatalf("span got %d attributes, want %d: %v", len(got), len(want), got)
	}
	for k, w := range want {
		if v, ok := got[k]; !ok || v.Emit() != w.Emit() {
			t.Errorf("span attribute %s = %v, want %v", k, v, w)
		}
	}
}

// T5: the detached-audit path strips cancellation with context.WithoutCancel
// but must keep carrying whatever span was already in ctx -- it does not
// create a second span, and the adapter must still be able to reach the
// original one through the stripped context.
func TestSetAuditSpanAttributes_SurvivesDetachedContext(t *testing.T) {
	span := &recordingSpan{}
	ctx, cancel := context.WithCancel(trace.ContextWithSpan(context.Background(), span))
	cancel() // simulate the caller having already disconnected

	detached := context.WithoutCancel(ctx)
	if got := trace.SpanFromContext(detached); got != trace.Span(span) {
		t.Fatalf("context.WithoutCancel lost the original span: got %v, want %v", got, span)
	}

	setAuditSpanAttributes(detached, fullEdgeContext(), "fetch_media", "ok", 7)

	if len(span.attrs) == 0 {
		t.Fatal("adapter did not write to the span carried through context.WithoutCancel")
	}
}
