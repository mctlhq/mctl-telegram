package db

import (
	"context"
	"database/sql"
	"testing"
)

func TestMigrate_UpgradesPreExistingProfilesWithoutSenderAllowlist(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.ExecContext(ctx, `CREATE TABLE agent_profiles (
		user_id INTEGER PRIMARY KEY,
		mode TEXT NOT NULL DEFAULT 'observe',
		autopilot_paused INTEGER NOT NULL DEFAULT 0,
		listener_enabled INTEGER NOT NULL DEFAULT 0,
		disclosure_text TEXT NOT NULL DEFAULT '',
		max_autonomous_turns INTEGER NOT NULL DEFAULT 6,
		max_msgs_per_minute INTEGER NOT NULL DEFAULT 2,
		max_reply_chars INTEGER NOT NULL DEFAULT 1200,
		intent_allowlist TEXT NOT NULL DEFAULT '',
		blocked_senders TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatalf("seed pre-existing profiles: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO agent_profiles(user_id) VALUES(7)`); err != nil {
		t.Fatalf("seed pre-existing profile row: %v", err)
	}

	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var allowlist string
	var ownerProfileColumnCount, ownerProfileImportColumnCount int
	if err := conn.QueryRowContext(ctx,
		`SELECT sender_allowlist FROM agent_profiles WHERE user_id=7`,
	).Scan(&allowlist); err != nil {
		t.Fatalf("read upgraded sender allowlist: %v", err)
	}
	if allowlist != "" {
		t.Fatalf("sender_allowlist = %q, want empty compatibility default", allowlist)
	}
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('agent_profiles') WHERE name = 'owner_profile_encrypted'`,
	).Scan(&ownerProfileColumnCount); err != nil {
		t.Fatalf("check owner_profile_encrypted column: %v", err)
	}
	if ownerProfileColumnCount != 1 {
		t.Fatal("agent_profiles.owner_profile_encrypted column not added")
	}
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM pragma_table_info('agent_profiles') WHERE name = 'owner_profile_imported_at'`,
	).Scan(&ownerProfileImportColumnCount); err != nil {
		t.Fatalf("check owner_profile_imported_at column: %v", err)
	}
	if ownerProfileImportColumnCount != 1 {
		t.Fatal("agent_profiles.owner_profile_imported_at column not added")
	}
}

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

func TestMigrate_CreatesPendingNotificationSweepIndex(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var count int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master
		  WHERE type = 'index' AND name = 'idx_owner_notifications_pending'`,
	).Scan(&count); err != nil {
		t.Fatalf("check pending notification index: %v", err)
	}
	if count != 1 {
		t.Fatalf("pending notification indexes=%d, want 1", count)
	}
}

func TestRetirePlaintextApprovalCodes_ExpiresLegacyCapabilities(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "legacy-code-owner")

	// Seed the pre-hardening row shape to simulate upgrading a live database.
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO agent_actions
		   (approval_code, user_id, action_type, policy_decision, status)
		 VALUES($1,$2,$3,$4,$5)`,
		"LEGACY", uid, ActionTypeReply, PolicyRequireApproval, ActionPendingApproval,
	)
	if err != nil {
		t.Fatalf("seed legacy approval: %v", err)
	}
	legacyID, _ := res.LastInsertId()

	if err := retirePlaintextApprovalCodes(ctx, s.DB); err != nil {
		t.Fatalf("retire plaintext approvals: %v", err)
	}
	var (
		status string
		code   sql.NullString
	)
	if err := s.DB.QueryRowContext(ctx,
		`SELECT status, approval_code FROM agent_actions WHERE id = $1`,
		legacyID,
	).Scan(&status, &code); err != nil {
		t.Fatalf("read retired approval: %v", err)
	}
	if status != ActionExpired || code.Valid {
		t.Fatalf("retired approval status/code = %q/%v, want expired/nil", status, code)
	}

	freshID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ActionType: ActionTypeReply, ApprovalCode: "FRESH1",
		PolicyDecision: PolicyRequireApproval, Status: ActionPendingApproval,
	})
	if err != nil {
		t.Fatalf("insert protected approval: %v", err)
	}
	if err := retirePlaintextApprovalCodes(ctx, s.DB); err != nil {
		t.Fatalf("rerun retirement: %v", err)
	}
	fresh, err := s.GetAgentAction(ctx, uid, freshID)
	if err != nil {
		t.Fatalf("get protected approval after rerun: %v", err)
	}
	if fresh.Status != ActionPendingApproval || fresh.ApprovalCode != "FRESH1" {
		t.Fatalf("fresh approval changed on rerun: %+v", fresh)
	}
}

func TestRetirePreExecutorApprovedActions_RunsOnce(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "rollout-owner")
	conv, err := s.EnsureConversation(ctx, uid, 9001, "peer", "Peer")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	// Fresh migrations install the marker with no rows to retire. Remove it
	// to simulate the first deployment over a database created by an older
	// release.
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM agent_migrations WHERE name = $1`,
		"retire_pre_executor_approved_v1",
	); err != nil {
		t.Fatalf("remove marker: %v", err)
	}
	oldID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ConversationID: conv.ID, ActionType: ActionTypeReply,
		Payload: "stale", PolicyDecision: PolicyAllow, Status: ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert stale action: %v", err)
	}
	ambiguousID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ConversationID: conv.ID, ActionType: ActionTypeReply,
		Payload: "possibly sent", PolicyDecision: PolicyAllow, Status: ActionExecuting,
	})
	if err != nil {
		t.Fatalf("insert legacy executing action: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions SET send_random_id = $1 WHERE id = $2`,
		12345, ambiguousID,
	); err != nil {
		t.Fatalf("seed legacy random id: %v", err)
	}
	if err := retirePreExecutorApprovedActions(ctx, s.DB); err != nil {
		t.Fatalf("retire old actions: %v", err)
	}
	old, err := s.GetAgentAction(ctx, uid, oldID)
	if err != nil {
		t.Fatalf("get retired action: %v", err)
	}
	if old.Status != ActionDenied {
		t.Fatalf("old action status=%q, want denied", old.Status)
	}
	ambiguous, err := s.GetAgentAction(ctx, uid, ambiguousID)
	if err != nil {
		t.Fatalf("get legacy executing action: %v", err)
	}
	if ambiguous.Status != ActionDenied {
		t.Fatalf("legacy executing status=%q, want denied", ambiguous.Status)
	}
	gotConv, err := s.GetConversation(ctx, uid, conv.ID)
	if err != nil {
		t.Fatalf("get conversation after retirement: %v", err)
	}
	if gotConv.AutonomousTurns != 1 {
		t.Fatalf("autonomous_turns=%d, want one conservative legacy reservation", gotConv.AutonomousTurns)
	}

	newID, err := s.InsertAgentAction(ctx, AgentAction{
		UserID: uid, ConversationID: conv.ID, ActionType: ActionTypeReply,
		Payload: "fresh", PolicyDecision: PolicyAllow, Status: ActionApproved,
	})
	if err != nil {
		t.Fatalf("insert fresh action: %v", err)
	}
	if err := retirePreExecutorApprovedActions(ctx, s.DB); err != nil {
		t.Fatalf("rerun retirement: %v", err)
	}
	fresh, err := s.GetAgentAction(ctx, uid, newID)
	if err != nil {
		t.Fatalf("get fresh action: %v", err)
	}
	if fresh.Status != ActionApproved {
		t.Fatalf("fresh action status=%q, want approved after marker exists", fresh.Status)
	}
}
