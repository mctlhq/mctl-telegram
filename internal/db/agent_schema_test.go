package db

import (
	"context"
	"testing"
)

// TestMigrate_UpgradesPreExistingJobLeadsWithoutJobIDColumn guards against
// the P1 found in round-4 review: on a database that already has job_leads
// from before A-PR6 (#296) — i.e. without a job_id column — the agent
// migration's CREATE INDEX ON job_leads(job_id) statement used to run in the
// same pass as the CREATE TABLE statements, ahead of the addColumnIfMissing
// ALTER that would have added the column, so the whole migration failed on
// upgrade. Simulated here by hand-creating job_leads in its pre-A-PR6 shape
// before calling Migrate.
func TestMigrate_UpgradesPreExistingJobLeadsWithoutJobIDColumn(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Pre-A-PR6 shape: no job_id column at all.
	if _, err := conn.ExecContext(ctx, `CREATE TABLE job_leads (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		conversation_id INTEGER,
		company TEXT,
		role TEXT,
		recruiter_name TEXT,
		recruiter_tg_id INTEGER,
		compensation TEXT,
		status TEXT NOT NULL DEFAULT 'new',
		detail TEXT NOT NULL DEFAULT '{}',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("seed pre-existing job_leads: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var count int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('job_leads') WHERE name = 'job_id'`,
	).Scan(&count); err != nil {
		t.Fatalf("check job_id column: %v", err)
	}
	if count == 0 {
		t.Fatal("job_leads.job_id column not added by migration")
	}

	var indexCount int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = 'idx_job_leads_job'`,
	).Scan(&indexCount); err != nil {
		t.Fatalf("check idx_job_leads_job: %v", err)
	}
	if indexCount == 0 {
		t.Fatal("idx_job_leads_job index not created by migration")
	}
}

// TestMigrate_UpgradesPreExistingConversationsWithoutPeerAccessHash guards
// against the P1 found in a later A-PR7 review round: addColumnIfMissing for
// conversations.peer_access_hash added the column with no DEFAULT, so an
// existing row on an already-deployed database got a NULL there — and
// getConversation scans peer_access_hash into a plain int64 (not
// sql.NullInt64), so GetConversation broke on any upgraded deployment that
// already had conversation rows. Simulated by hand-creating conversations in
// its pre-round-4 shape (no peer_access_hash) with an existing row before
// calling Migrate, then exercising the real GetConversation path.
func TestMigrate_UpgradesPreExistingConversationsWithoutPeerAccessHash(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Pre-round-4 shape: no peer_access_hash column at all.
	if _, err := conn.ExecContext(ctx, `CREATE TABLE conversations (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		peer_tg_id INTEGER NOT NULL,
		peer_username TEXT,
		peer_display_name TEXT,
		state TEXT NOT NULL DEFAULT 'active',
		autonomous_turns INTEGER NOT NULL DEFAULT 0,
		last_incoming_at DATETIME,
		last_agent_reply_at DATETIME,
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("seed pre-existing conversations table: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO conversations (user_id, peer_tg_id) VALUES (7, 555)`,
	); err != nil {
		t.Fatalf("seed pre-existing conversation row: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store := &Store{DB: conn}
	conv, err := store.GetConversation(ctx, 7, 1)
	if err != nil {
		t.Fatalf("GetConversation on upgraded row: %v", err)
	}
	if conv.PeerAccessHash != 0 {
		t.Fatalf("PeerAccessHash = %d, want 0 (backfilled default)", conv.PeerAccessHash)
	}
}
