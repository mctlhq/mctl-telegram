package db

import (
	"context"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestListAuditFor_FiltersByUserAndOrdersNewestFirst(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, _ := s.EnsureUser(ctx, "alice", "", "test")
	bob, _ := s.EnsureUser(ctx, "bob", "", "test")

	// Two rows for alice, one for bob; insert order matters for the
	// "newest first" assertion.
	s.LogToolCall(ctx, alice, "list_dialogs", "", "ok", "")
	time.Sleep(5 * time.Millisecond)
	s.LogToolCall(ctx, alice, "get_messages", "user:hash", "ok", "")
	time.Sleep(5 * time.Millisecond)
	s.LogToolCall(ctx, bob, "list_dialogs", "", "ok", "")

	got, err := s.ListAuditFor(ctx, alice, 50, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows for alice, got %d", len(got))
	}
	if got[0].ToolName != "get_messages" || got[1].ToolName != "list_dialogs" {
		t.Fatalf("expected newest-first, got %+v", got)
	}
	if got[0].PeerRedacted != "user:hash" {
		t.Fatalf("expected peer_redacted preserved, got %q", got[0].PeerRedacted)
	}
}

func TestListAuditFor_CrossTenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, _ := s.EnsureUser(ctx, "alice", "", "test")
	bob, _ := s.EnsureUser(ctx, "bob", "", "test")

	s.LogToolCall(ctx, alice, "list_dialogs", "", "ok", "")
	s.LogToolCall(ctx, bob, "list_dialogs", "", "ok", "")

	// alice must NOT see bob's rows.
	got, err := s.ListAuditFor(ctx, alice, 50, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row for alice (cross-tenant filter), got %d", len(got))
	}
}

func TestListAuditFor_LimitClamp(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "u", "", "test")
	for i := 0; i < 5; i++ {
		s.LogToolCall(ctx, uid, "x", "", "ok", "")
	}

	// limit=0 → clamps to 50 (returns all 5)
	got, _ := s.ListAuditFor(ctx, uid, 0, time.Time{})
	if len(got) != 5 {
		t.Fatalf("limit=0 should return all 5, got %d", len(got))
	}
	// limit=2 → returns 2
	got, _ = s.ListAuditFor(ctx, uid, 2, time.Time{})
	if len(got) != 2 {
		t.Fatalf("limit=2 should return 2, got %d", len(got))
	}
	// limit=999 → clamped to 500 (we only have 5 rows so 5)
	got, _ = s.ListAuditFor(ctx, uid, 999, time.Time{})
	if len(got) != 5 {
		t.Fatalf("limit=999 with 5 rows should return 5, got %d", len(got))
	}
}

func TestListAuditFor_BeforeFiltersOlderEntries(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "u", "", "test")

	// SQLite's CURRENT_TIMESTAMP has second-level precision so we insert
	// rows with explicit timestamps to make the cutoff unambiguous.
	old := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	fresh := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
		uid, "first", "ok", old,
	); err != nil {
		t.Fatalf("seed first: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
		uid, "second", "ok", fresh,
	); err != nil {
		t.Fatalf("seed second: %v", err)
	}

	cutoff := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	got, err := s.ListAuditFor(ctx, uid, 50, cutoff)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("before=cutoff should return only 'first', got %d rows", len(got))
	}
	if got[0].ToolName != "first" {
		t.Fatalf("expected 'first', got %q", got[0].ToolName)
	}
}
