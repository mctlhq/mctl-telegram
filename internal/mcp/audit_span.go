package mcp

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/mctlhq/mctl-telegram/internal/edgectx"
)

// auditSpanAttributes builds the OpenTelemetry attributes for an MCP tool
// call's audit record, from the same values already written to the
// audit_logs row and mirrored to slog (mctl-telegram#617). An optional
// edge/MCP field that was not captured is omitted rather than written as an
// empty string: an absent attribute is itself information, a mangled or
// empty one is not.
//
// This is the entire sensitive-data surface of the adapter: no tool
// arguments, peer values, handles, message text or authorization values are
// accepted here, or anywhere else this helper is called from.
func auditSpanAttributes(ec edgectx.Context, tool, status string, userID int64) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, 8)
	if ec.RequestID != "" {
		attrs = append(attrs, attribute.String("mctl.edge.request_id", ec.RequestID))
	}
	if ec.Route != "" {
		attrs = append(attrs, attribute.String("mctl.edge.route", ec.Route))
	}
	if ec.MCPMethod != "" {
		attrs = append(attrs, attribute.String("mcp.method", ec.MCPMethod))
	}
	if ec.MCPName != "" {
		attrs = append(attrs, attribute.String("mcp.name", ec.MCPName))
	}
	if ec.ProtocolVersion != "" {
		attrs = append(attrs, attribute.String("mcp.protocol_version", ec.ProtocolVersion))
	}
	attrs = append(attrs,
		attribute.String("mctl.tool.name", tool),
		attribute.String("mctl.tool.status", status),
		attribute.Int64("mctl.user.id", userID),
	)
	return attrs
}

// setAuditSpanAttributes copies the audit correlation facts onto ctx's
// recording span, if one exists. mctl-telegram has no tracer wired --
// installing a provider, exporter, propagator or sampling policy is owned by
// mctlhq/.github#55, the vendor-neutral observability epic -- so this only
// ever writes attributes to a span that already exists in ctx. With no
// recording span this is a no-op: no tracing side effect, and current audit,
// DB and slog behavior is unchanged.
func setAuditSpanAttributes(ctx context.Context, ec edgectx.Context, tool, status string, userID int64) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}
	span.SetAttributes(auditSpanAttributes(ec, tool, status, userID)...)
}
