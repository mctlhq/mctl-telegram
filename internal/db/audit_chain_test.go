package db

import (
	"context"
	"testing"
)

func TestVerifyAuditChain_EmptyChainIsOK(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")
	res, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK || res.Verified != 0 {
		t.Fatalf("empty chain must be OK with Verified=0, got %+v", res)
	}
}

func TestVerifyAuditChain_FreshChainVerifies(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")

	s.LogToolCall(ctx, uid, "list_dialogs", "", "ok", "")
	s.LogToolCall(ctx, uid, "get_messages", "user:hash", "ok", "")
	s.LogToolCall(ctx, uid, "send_message:draft", "user:hash", "ok", "")

	res, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected OK chain, got %+v", res)
	}
	if res.Verified != 3 {
		t.Fatalf("expected Verified=3, got %d", res.Verified)
	}
}

func TestVerifyAuditChain_DetectsTamperedRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")
	s.LogToolCall(ctx, uid, "list_dialogs", "", "ok", "")
	s.LogToolCall(ctx, uid, "get_messages", "user:hash", "ok", "")
	s.LogToolCall(ctx, uid, "send_message:sent", "user:hash", "ok", "")

	// Tamper: rewrite the middle row's tool_name without touching its hash.
	var middleID int64
	if err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM audit_logs WHERE tool_name='get_messages'`,
	).Scan(&middleID); err != nil {
		t.Fatalf("find middle: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE audit_logs SET tool_name = 'tampered' WHERE id = $1`,
		middleID,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	res, err := s.VerifyAuditChain(ctx, uid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.OK {
		t.Fatal("tampered row must fail verification")
	}
	if res.FirstBadID != middleID {
		t.Fatalf("expected FirstBadID=%d, got %d", middleID, res.FirstBadID)
	}
}

func TestLogToolCall_ChainsAcrossEntries(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, _ := s.EnsureUser(ctx, "alice", "", "test")
	s.LogToolCall(ctx, uid, "a", "", "ok", "")
	s.LogToolCall(ctx, uid, "b", "", "ok", "")

	rows, err := s.DB.QueryContext(ctx,
		`SELECT entry_hash, prev_hash FROM audit_logs WHERE user_id=$1 ORDER BY id ASC`,
		uid,
	)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	type row struct{ entry, prev []byte }
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.entry, &r.prev); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(got))
	}
	// First row's prev_hash is zero (genesis).
	for _, b := range got[0].prev {
		if b != 0 {
			t.Fatal("first row prev_hash should be all-zero (genesis)")
		}
	}
	// Second row's prev_hash equals first row's entry_hash.
	if !bytesEqual(got[1].prev, got[0].entry) {
		t.Fatal("second row prev_hash must equal first row entry_hash")
	}
}

func TestVerifyAuditChain_IsolatedPerUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	alice, _ := s.EnsureUser(ctx, "alice", "", "test")
	bob, _ := s.EnsureUser(ctx, "bob", "", "test")
	s.LogToolCall(ctx, alice, "a", "", "ok", "")
	s.LogToolCall(ctx, bob, "b", "", "ok", "")
	s.LogToolCall(ctx, alice, "c", "", "ok", "")

	// alice's chain doesn't include bob's row, so alice's chain is
	// a→c (verified). bob's chain has one row (verified). Tamper bob
	// — alice's verification must still pass.
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE audit_logs SET tool_name = 'tampered' WHERE user_id = $1`, bob,
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err := s.VerifyAuditChain(ctx, alice)
	if err != nil {
		t.Fatalf("verify alice: %v", err)
	}
	if !res.OK {
		t.Fatalf("tampering bob's row must not affect alice's chain, got %+v", res)
	}
}
