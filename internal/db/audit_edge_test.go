package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/edgectx"
)

// The correlation fields are the deliverable of mctl-telegram#617 Slice 2:
// an audit row has to say how the call arrived, or the trail cannot be joined
// to anything.
func TestLogToolCall_RecordsHowTheCallArrived(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")

	called := edgectx.With(ctx, edgectx.Context{
		RequestID:       "a39ad476896f4649-IAD",
		Route:           edgectx.RoutePortal,
		MCPMethod:       "tools/call",
		MCPName:         "get_my_identity",
		ProtocolVersion: "2026-07-28",
	})
	s.LogToolCall(called, uid, "get_my_identity", "", "ok", "", "")

	entries, err := s.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got.EdgeRequestID != "a39ad476896f4649-IAD" {
		t.Errorf("edge_request_id = %q", got.EdgeRequestID)
	}
	if got.EdgeRoute != edgectx.RoutePortal {
		t.Errorf("edge_route = %q", got.EdgeRoute)
	}
	if got.MCPMethod != "tools/call" || got.MCPName != "get_my_identity" {
		t.Errorf("mcp method/name = %q/%q", got.MCPMethod, got.MCPName)
	}
	if got.ProtocolVersion != "2026-07-28" {
		t.Errorf("protocol_version = %q", got.ProtocolVersion)
	}
}

// A call with no HTTP request behind it must leave the fields empty rather
// than invent a route: "no edge context" is itself a fact about the call.
func TestLogToolCall_LeavesCorrelationEmptyWithoutAnEdgeContext(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "bob", "", "test")

	s.LogToolCall(ctx, uid, "list_dialogs", "", "ok", "", "")

	entries, err := s.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	got := entries[0]
	if got.EdgeRequestID != "" || got.EdgeRoute != "" || got.MCPMethod != "" || got.MCPName != "" || got.ProtocolVersion != "" {
		t.Errorf("correlation fields must stay empty, got %+v", got)
	}
	if v, err := s.VerifyAuditChain(ctx, uid); err != nil || !v.OK {
		t.Errorf("chain must verify: ok=%v err=%v", v.OK, err)
	}
}

// The hash chain has to cover the new fields, or an audit row's account of
// how a call arrived could be rewritten without detection - which is the one
// property that makes it evidence rather than a hint.
func TestVerifyAuditChain_DetectsARewrittenEdgeRequestID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "carol", "", "test")

	s.LogToolCall(edgectx.With(ctx, edgectx.Context{
		RequestID: "a39ad476896f4649-IAD",
		Route:     edgectx.RoutePortal,
	}), uid, "get_my_identity", "", "ok", "", "")

	if v, err := s.VerifyAuditChain(ctx, uid); err != nil || !v.OK {
		t.Fatalf("precondition: chain should verify, ok=%v err=%v", v.OK, err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE audit_logs SET edge_request_id = $1 WHERE user_id = $2`,
		"0000000000000000-XXX", uid,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	v, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if v.OK {
		t.Error("a rewritten edge_request_id must break the chain")
	}
}

// Rows written before these columns existed must keep verifying. A row whose
// correlation columns are NULL has to hash exactly as it did then - the same
// rule call_path follows - or every user's history reports as tampered the
// moment this ships.
func TestVerifyAuditChain_PreSlice2NullCorrelationVerifies(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "dana", "", "test")

	createdAt := time.Now().UTC()
	prev := make([]byte, sha256.Size)
	// Hashed the way the pre-Slice-2 code did: call_path present, no
	// correlation block at all.
	entry := hashAuditEntry(prev, uid, "legacy_tool", "", "ok", "", sql.NullString{String: "", Valid: true}, createdAt, auditEdge{})
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, peer_redacted, status, error, created_at, prev_hash, entry_hash, call_path)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,'')`,
		uid, "legacy_tool", nil, "ok", nil, createdAt, prev, entry,
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	// A Slice 2 row chains on top of it.
	s.LogToolCall(edgectx.With(ctx, edgectx.Context{RequestID: "ray", Route: edgectx.RouteDirect}),
		uid, "list_dialogs", "", "ok", "", "")

	v, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !v.OK {
		t.Fatalf("pre-Slice-2 history must still verify: %+v", v)
	}
	if v.Verified != 2 {
		t.Errorf("verified %d rows, want 2", v.Verified)
	}
}
