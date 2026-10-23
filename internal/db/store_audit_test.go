package db

import (
	"context"
	"strings"
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
	s.LogToolCall(ctx, ToolCall{UserID: alice, Tool: "list_dialogs", Status: "ok"})
	time.Sleep(5 * time.Millisecond)
	s.LogToolCall(ctx, ToolCall{UserID: alice, Tool: "get_messages", PeerRedacted: "user:hash", Status: "ok"})
	time.Sleep(5 * time.Millisecond)
	s.LogToolCall(ctx, ToolCall{UserID: bob, Tool: "list_dialogs", Status: "ok"})

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

	s.LogToolCall(ctx, ToolCall{UserID: alice, Tool: "list_dialogs", Status: "ok"})
	s.LogToolCall(ctx, ToolCall{UserID: bob, Tool: "list_dialogs", Status: "ok"})

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
		s.LogToolCall(ctx, ToolCall{UserID: uid, Tool: "x", Status: "ok"})
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

func TestSweepAuditLog_DeletesOlderThanRetention(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "u", "", "test")
	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	fresh := time.Now().UTC().Add(-1 * time.Hour)
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
		uid, "ancient", "ok", old,
	); err != nil {
		t.Fatalf("seed old: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
		uid, "recent", "ok", fresh,
	); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}
	rows, err := s.SweepAuditLog(ctx, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rows != 1 {
		t.Fatalf("expected 1 row deleted, got %d", rows)
	}
	// And the recent row survives.
	var tool string
	if err := s.DB.QueryRowContext(ctx,
		`SELECT tool_name FROM audit_logs WHERE user_id=$1`, uid,
	).Scan(&tool); err != nil {
		t.Fatalf("query survivor: %v", err)
	}
	if tool != "recent" {
		t.Fatalf("expected 'recent' to survive, got %q", tool)
	}
}

func TestSweepAuditLog_ZeroRetentionIsNoop(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "u", "", "test")
	s.LogToolCall(ctx, ToolCall{UserID: uid, Tool: "x", Status: "ok"})
	rows, err := s.SweepAuditLog(ctx, 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if rows != 0 {
		t.Fatalf("retention=0 must be no-op, got rows=%d", rows)
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

// The error column is free text that peer-resolution failures fill with the
// caller's peer verbatim. peer_redacted was masked but error was not, so the
// raw identifier came back out through get_my_audit_log. LogToolCall must
// scrub it before the row is written -- and before it is hashed, so the
// chain still verifies over the stored value.
func TestLogToolCall_ScrubsPeerIdentifiersInError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "carol", "", "test")

	s.LogToolCall(ctx, ToolCall{UserID: uid, Tool: "get_messages", PeerRedacted: "channel:<id>", Status: "error", ErrMsg: `peer "channel:9876543210" could not be accessed`})
	s.LogToolCall(ctx, ToolCall{UserID: uid, Tool: "get_messages", PeerRedacted: "user:<id>", Status: "error", ErrMsg: `peer "@alice_handle" not found`})

	entries, err := s.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	for _, e := range entries {
		for _, raw := range []string{"9876543210", "@alice_handle"} {
			if strings.Contains(e.ErrorRedacted, raw) {
				t.Errorf("error column leaks %q: %q", raw, e.ErrorRedacted)
			}
		}
		if !strings.Contains(e.ErrorRedacted, "[redacted]") {
			t.Errorf("error column not scrubbed: %q", e.ErrorRedacted)
		}
	}

	// The stored column itself, not just what ListAuditFor returns: the read
	// path scrubs too, so only a raw query proves the write path does.
	rows, err := s.DB.QueryContext(ctx, `SELECT error FROM audit_logs WHERE user_id = $1`, uid)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var stored string
		if err := rows.Scan(&stored); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if strings.Contains(stored, "9876543210") || strings.Contains(stored, "@alice_handle") {
			t.Errorf("stored error column leaks a peer: %q", stored)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}

	v, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if !v.OK {
		t.Fatalf("audit chain broken after scrub: %+v", v)
	}
}

// Rows written before the write-path scrub still hold the raw peer. The read
// path must mask them so history stops leaking through get_my_audit_log.
func TestListAuditFor_ScrubsLegacyUnmaskedError(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "dana", "", "test")

	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO audit_logs(user_id, tool_name, status, error, created_at, call_path)
		 VALUES($1, 'get_messages', 'error', $2, $3, '')`,
		uid, `peer "channel:9876543210" could not be accessed`, time.Now().UTC(),
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	entries, err := s.ListAuditFor(ctx, uid, 10, time.Time{})
	if err != nil {
		t.Fatalf("ListAuditFor: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	if strings.Contains(entries[0].ErrorRedacted, "9876543210") {
		t.Errorf("legacy error leaks the peer: %q", entries[0].ErrorRedacted)
	}
}
