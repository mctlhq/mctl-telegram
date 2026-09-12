package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/edgectx"
)

// The audit row and the log line are read by different people with different
// tools; a correlation that exists only in the database cannot be joined to
// Loki, which is where the operator actually looks first.
func TestAudit_MirrorsCorrelationFactsToTheLogLine(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := &Server{Store: newToolsTestStore(t)}
	ctx := edgectx.With(context.Background(), edgectx.Context{
		RequestID:       "a39ad476896f4649-IAD",
		Route:           edgectx.RoutePortal,
		MCPMethod:       "tools/call",
		MCPName:         "get_my_identity",
		ProtocolVersion: "2026-07-28",
	})

	s.audit(ctx, &auth.Identity{UserID: 7}, "get_my_identity", "", nil, time.Time{})

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("log line is not JSON: %v (%q)", err, buf.String())
	}
	for k, want := range map[string]string{
		"edge_route":       edgectx.RoutePortal,
		"edge_request_id":  "a39ad476896f4649-IAD",
		"mcp_method":       "tools/call",
		"mcp_name":         "get_my_identity",
		"protocol_version": "2026-07-28",
	} {
		if got, _ := rec[k].(string); got != want {
			t.Errorf("log %s = %q, want %q", k, got, want)
		}
	}
}

// Without an HTTP request behind the call there is nothing to report, and the
// line must not gain empty keys that a query would then have to filter out.
func TestAudit_OmitsCorrelationKeysWhenThereIsNoEdgeContext(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s := &Server{Store: newToolsTestStore(t)}
	s.audit(context.Background(), &auth.Identity{UserID: 7}, "list_dialogs", "", nil, time.Time{})

	out := buf.String()
	for _, k := range []string{"edge_route", "edge_request_id", "mcp_method", "mcp_name", "protocol_version"} {
		if strings.Contains(out, k) {
			t.Errorf("line must not carry %s when nothing was captured: %s", k, out)
		}
	}
}

// The capture has to happen where every tool call's context is built. Without
// it the audit row is written with empty correlation columns and the trail
// cannot be joined to anything, with nothing failing loudly to say so.
func TestHTTPContext_CapturesTheArrivingRequestFacts(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Cf-Ray", "a39ad476896f4649-IAD")
	r.Header.Set("Cf-Worker", "gateway.agents.cloudflare.com")
	r.Header.Set("Mcp-Method", "tools/call")
	r.Header.Set("Mcp-Name", "get_my_identity")

	got := edgectx.From(httpContext(context.Background(), r))
	if got.Route != edgectx.RoutePortal || got.RequestID != "a39ad476896f4649-IAD" {
		t.Fatalf("captured %+v", got)
	}
	if got.MCPMethod != "tools/call" || got.MCPName != "get_my_identity" {
		t.Errorf("MCP routing headers not captured: %+v", got)
	}
}

// Both audit tools return db.AuditEntry, so a field added there appears in
// their output whether or not anyone updated the description. The gap this
// closes was real: Slice 2 added five fields and documented them on
// get_my_audit_log only, leaving the admin tool -- the cross-principal read,
// where the values were chosen by the user being queried -- describing an
// output it no longer had.
func TestAuditToolDescriptions_DocumentEveryReturnedField(t *testing.T) {
	var fields []string
	for i := 0; i < reflect.TypeOf(db.AuditEntry{}).NumField(); i++ {
		tag := reflect.TypeOf(db.AuditEntry{}).Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name != "" && name != "-" {
			fields = append(fields, name)
		}
	}
	if len(fields) == 0 {
		t.Fatal("no json tags found on db.AuditEntry; this guard would pass vacuously")
	}

	s := &Server{Store: newToolsTestStore(t)}
	mine, _ := s.toolGetMyAuditLog()
	theirs, _ := s.toolGetUserAuditLog()
	for _, tool := range []struct {
		name string
		desc string
	}{
		{"get_my_audit_log", mine.Description},
		{"get_user_audit_log", theirs.Description},
	} {
		for _, f := range fields {
			if !strings.Contains(tool.desc, f) {
				t.Errorf("%s: description does not mention the returned field %q", tool.name, f)
			}
		}
	}

	// The warning is load-bearing on the admin path specifically: there the
	// header values were chosen by the subject of the query.
	if !strings.Contains(theirs.Description, "EVIDENCE, NOT AS IDENTITY") {
		t.Error("get_user_audit_log must warn that the correlation fields are headers as received, not identity")
	}
}
