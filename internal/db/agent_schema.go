package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Agent domain schema (communication agent, M6). These tables back the
// autonomous communication agent: incoming Telegram updates become durable
// incoming_events rows, the agent's proposed actions and their approval
// lifecycle live in agent_actions, and recruiter conversations are modelled
// independently of Telegram in conversations/conversation_messages.
//
// Message bodies and action payloads are AES-GCM encrypted with the owning
// user's derived key (crypto.SealForUser), mirroring session_encrypted
// handling — plaintext message content never reaches the DB or logs.
//
// tg_update_state / tg_channel_state persist gotd's updates.Manager pts/qts
// watermark so a restarted listener can recover missed updates via
// getDifference instead of silently dropping them.
func migrateAgent(ctx context.Context, dbConn *sql.DB, pg bool) error {
	var stmts []string
	if pg {
		stmts = agentSchemaPG()
	} else {
		stmts = agentSchemaSQLite()
	}
	for _, s := range stmts {
		if _, err := dbConn.ExecContext(ctx, s); err != nil {
			return fmt.Errorf("migrate agent: %w\nstmt: %s", err, s)
		}
	}

	// Idempotent ALTER passes for columns added after the tables above first
	// shipped — CREATE TABLE IF NOT EXISTS is a no-op against a deployment
	// that already has the table, so a column added later needs the same
	// addColumnIfMissing treatment db.go's Migrate uses for the core
	// tables, or it silently never appears on an existing database. None of
	// these three have a CREATE INDEX anywhere in this file that references
	// them, so — unlike job_leads.job_id below — they can safely run after
	// the whole stmts list above with no ordering dependency.
	//
	// agent_actions.send_random_id: added in A-PR7 (#297) — see
	// internal/agent/executor's package doc for why the executor needs a
	// persisted MTProto random_id.
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_actions", "send_random_id", "BIGINT", "INTEGER"); err != nil {
		return err
	}
	// agent_actions.send_body_encrypted: the exact final body paired with
	// send_random_id. Recovery must never rebuild it from mutable profile
	// configuration (notably disclosure_text), because Telegram deduplicates
	// retries by random_id and therefore requires every retry to be identical.
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_actions", "send_body_encrypted", "BYTEA", "BLOB"); err != nil {
		return err
	}
	// Approval codes are looked up by a tenant-scoped keyed blind index and
	// retained reversibly only as per-user AES-GCM ciphertext so notification
	// retries can reproduce the original command without leaving a live
	// capability in plaintext.
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_actions", "approval_code_hash", "BYTEA", "BLOB"); err != nil {
		return err
	}
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_actions", "approval_code_encrypted", "BYTEA", "BLOB"); err != nil {
		return err
	}
	if _, err := dbConn.ExecContext(ctx, `DROP INDEX IF EXISTS idx_agent_actions_code`); err != nil {
		return fmt.Errorf("drop plaintext approval-code index: %w", err)
	}
	if _, err := dbConn.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_code_hash
		   ON agent_actions(user_id, approval_code_hash)
		 WHERE approval_code_hash IS NOT NULL`,
	); err != nil {
		return fmt.Errorf("create approval-code hash index: %w", err)
	}
	// Existing plaintext codes cannot be encrypted here because schema
	// migration intentionally has no access to the application encryption
	// key. Expire those drafts and require a fresh proposal rather than
	// retaining a readable approval capability. This converges on every boot
	// so a temporary rollback cannot reintroduce persistent plaintext.
	//
	// This is intentionally not dual-write compatible with the old binary:
	// production and preview use Recreate deployments, documented in the
	// runbook, so every old pod is gone before this migration starts.
	if err := retirePlaintextApprovalCodes(ctx, dbConn); err != nil {
		return err
	}
	// owner_notifications.claimed_until: added in A-PR7 round-3 review fixes —
	// see Store.ClaimOwnerNotification's doc comment for why delivery needs a
	// lease.
	if err := addColumnIfMissing(ctx, dbConn, pg, "owner_notifications", "claimed_until", "TIMESTAMPTZ", "DATETIME"); err != nil {
		return err
	}
	// conversations.peer_access_hash: added in A-PR7 round-4 review fixes —
	// see Store.SetConversationPeerAccessHash's doc comment for why the
	// executor needs it to send at all (MTProto rejects a zero-access-hash
	// InputPeerUser with PEER_ID_INVALID).
	if err := addColumnIfMissing(ctx, dbConn, pg, "conversations", "peer_access_hash", "BIGINT DEFAULT 0", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	// owner_notifications.random_id: added in a later A-PR7 review round —
	// see Store.ClaimOwnerNotification's doc comment for why notification
	// delivery needs the executor's persisted-random-id pattern to be
	// crash-safe against Telegram-side duplicates, not just claim-safe
	// against concurrent replicas.
	if err := addColumnIfMissing(ctx, dbConn, pg, "owner_notifications", "random_id", "BIGINT", "INTEGER"); err != nil {
		return err
	}
	// agent_profiles.sender_allowlist: an optional CSV of Telegram peer ids
	// whose incoming private messages may enter the agent queue. Empty keeps
	// the historical allow-all behavior; a configured list is enforced by
	// the listener before it creates a conversation, event, or job.
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_profiles", "sender_allowlist",
		"TEXT NOT NULL DEFAULT ''", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// agent_profiles.owner_profile_encrypted holds the account-specific
	// identity, public biography, skills, preferences, and restricted fields.
	// Keeping it on the tenant row removes the process-wide mounted-profile
	// singleton and lets every lookup derive the encryption key from user_id.
	if err := addColumnIfMissing(ctx, dbConn, pg, "agent_profiles", "owner_profile_encrypted",
		"BYTEA", "BLOB"); err != nil {
		return err
	}

	// job_leads.job_id: added alongside A-PR6 (#296) so POST
	// /jobs/{id}/complete can recognize a lead-only result — see
	// HasJobLeadForJob. Unlike the three columns above, its index is NOT
	// inline in the job_leads CREATE TABLE stmts list above (see #310):
	// on a pre-A-PR6 database, job_leads exists without job_id, and a
	// CREATE INDEX ... ON job_leads(job_id) run in the same pass as that
	// CREATE TABLE would fail outright with a missing-column error before
	// this ALTER ever got a chance to run. Kept as its own ALTER-then-INDEX
	// pair, strictly after the stmts loop, so the column always exists
	// first. No FK to agent_jobs: job_leads precedes agent_jobs in the
	// CREATE TABLE sequence, matching agent_actions.job_id's existing
	// no-FK precedent rather than reordering the whole schema.
	if err := addColumnIfMissing(ctx, dbConn, pg, "job_leads", "job_id", "BIGINT", "INTEGER"); err != nil {
		return fmt.Errorf("migrate agent: %w", err)
	}
	idxStmt := `CREATE INDEX IF NOT EXISTS idx_job_leads_job ON job_leads(job_id) WHERE job_id IS NOT NULL`
	if _, err := dbConn.ExecContext(ctx, idxStmt); err != nil {
		return fmt.Errorf("migrate agent: %w\nstmt: %s", err, idxStmt)
	}
	if err := retirePreExecutorApprovedActions(ctx, dbConn); err != nil {
		return err
	}
	return nil
}

func retirePlaintextApprovalCodes(ctx context.Context, dbConn *sql.DB) error {
	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin plaintext approval-code retirement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, updated_at = $2
		  WHERE approval_code IS NOT NULL AND status = $3`,
		ActionExpired, now, ActionPendingApproval,
	); err != nil {
		return fmt.Errorf("expire plaintext approval actions: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE agent_actions SET approval_code = NULL
		  WHERE approval_code IS NOT NULL`,
	); err != nil {
		return fmt.Errorf("clear plaintext approval codes: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit plaintext approval-code retirement: %w", err)
	}
	return nil
}

// retirePreExecutorApprovedActions is a one-shot rollout boundary for A-PR7.
// Older releases persisted guarded-mode actions as approved but had no
// production executor, so they may be arbitrarily stale. The migration marker
// and status update share one transaction: exactly one replica retires those
// rows, while later restarts leave newly-approved work untouched.
func retirePreExecutorApprovedActions(ctx context.Context, dbConn *sql.DB) error {
	tx, err := dbConn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin pre-executor action retirement: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx,
		`INSERT INTO agent_migrations(name) VALUES($1) ON CONFLICT (name) DO NOTHING`,
		"retire_pre_executor_approved_v1",
	)
	if err != nil {
		return fmt.Errorf("record pre-executor action retirement: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		// Legacy executing rows predate the exact-body/turn reservation. Their
		// RPC may already have landed, but retrying is unsafe because the body
		// paired with random_id was never snapshotted. Account them
		// conservatively before terminalizing: one turn per ambiguous send;
		// the retained random_id makes the denied row count in the short rate
		// window as well.
		if _, err := tx.ExecContext(ctx,
			`UPDATE conversations
			    SET autonomous_turns = autonomous_turns + (
			          SELECT COUNT(*) FROM agent_actions a
			           WHERE a.conversation_id = conversations.id
			             AND a.status = $1
			             AND a.send_body_encrypted IS NULL
			        ),
			        updated_at = $2
			  WHERE EXISTS (
			        SELECT 1 FROM agent_actions a
			         WHERE a.conversation_id = conversations.id
			           AND a.status = $1
			           AND a.send_body_encrypted IS NULL
			  )`,
			ActionExecuting, time.Now().UTC(),
		); err != nil {
			return fmt.Errorf("reserve accounting for legacy executing actions: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_actions
			    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
			        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
			  WHERE status = $4 AND send_body_encrypted IS NULL`,
			ActionDenied, "retired ambiguous execution at rollout boundary", time.Now().UTC(), ActionExecuting,
		); err != nil {
			return fmt.Errorf("retire legacy executing actions: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`UPDATE agent_actions
			    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
			        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
			  WHERE status = $4`,
			ActionDenied, "retired at executor rollout boundary", time.Now().UTC(), ActionApproved,
		); err != nil {
			return fmt.Errorf("retire pre-executor approved actions: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit pre-executor action retirement: %w", err)
	}
	return nil
}

func agentSchemaSQLite() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS agent_profiles (
			user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			mode TEXT NOT NULL DEFAULT 'observe',
			autopilot_paused INTEGER NOT NULL DEFAULT 0,
			listener_enabled INTEGER NOT NULL DEFAULT 0,
			disclosure_text TEXT NOT NULL DEFAULT '',
			max_autonomous_turns INTEGER NOT NULL DEFAULT 6,
			max_msgs_per_minute INTEGER NOT NULL DEFAULT 2,
			max_reply_chars INTEGER NOT NULL DEFAULT 1200,
			intent_allowlist TEXT NOT NULL DEFAULT '',
			blocked_senders TEXT NOT NULL DEFAULT '',
			sender_allowlist TEXT NOT NULL DEFAULT '',
			owner_profile_encrypted BLOB,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS incoming_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id TEXT NOT NULL,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			chat_tg_id INTEGER NOT NULL,
			sender_tg_id INTEGER NOT NULL,
			message_id INTEGER NOT NULL,
			body_encrypted BLOB,
			meta TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_incoming_events_event_id ON incoming_events(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_incoming_events_created_at ON incoming_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS agent_sent_messages (
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			tg_message_id INTEGER NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY(user_id, tg_message_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_sent_messages_created ON agent_sent_messages(created_at)`,
		`CREATE TABLE IF NOT EXISTS conversations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			peer_tg_id INTEGER NOT NULL,
			peer_username TEXT,
			peer_display_name TEXT,
			peer_access_hash INTEGER NOT NULL DEFAULT 0,
			state TEXT NOT NULL DEFAULT 'active',
			autonomous_turns INTEGER NOT NULL DEFAULT 0,
			last_incoming_at DATETIME,
			last_agent_reply_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_user_peer ON conversations(user_id, peer_tg_id)`,
		`CREATE TABLE IF NOT EXISTS conversation_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			direction TEXT NOT NULL,
			tg_message_id INTEGER,
			event_id TEXT,
			body_encrypted BLOB,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_conv ON conversation_messages(conversation_id, id)`,
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_created_at ON conversation_messages(created_at)`,
		// Serves ListRecentAgentOutgoingTimestamps, a hot per-send path (every
		// executor send and propose_reply call): without conversation_id as
		// the leading column, the (conversation_id, direction, created_at >
		// since) filter would fall back to idx_conv_messages_conv and scan
		// every row for the conversation regardless of direction.
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_direction_created ON conversation_messages(conversation_id, direction, created_at)`,
		`CREATE TABLE IF NOT EXISTS agent_actions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			approval_code TEXT,
			approval_code_hash BLOB,
			approval_code_encrypted BLOB,
			job_id INTEGER,
			conversation_id INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			action_type TEXT NOT NULL,
			intent TEXT NOT NULL DEFAULT '',
			payload_encrypted BLOB,
			policy_decision TEXT NOT NULL,
			policy_reasons TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'proposed',
			executed_tg_message_id INTEGER,
			-- send_random_id is generated and persisted BEFORE the executor issues
			-- the MTProto send RPC (approved -> executing), not after. A crash
			-- between the persist and the RPC, or between the RPC and recording
			-- executed, is recovered by retrying messages.sendMessage with this
			-- SAME random_id: Telegram dedups on it server-side, so the retry is a
			-- safe no-op if the original send actually landed. This is what makes
			-- the executing status a self-healing transient state instead of the
			-- original design's permanent crash trap.
			send_random_id INTEGER,
			send_body_encrypted BLOB,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// The queue is at-least-once: a redelivered job proposing again must
		// dedupe onto its existing action row (keeping the original
		// approval_code) instead of minting a second live approval.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_job_type ON agent_actions(job_id, action_type) WHERE job_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_user_status ON agent_actions(user_id, status)`,
		// The approval-expiry sweep runs a GLOBAL (tenant-less) scan every
		// minute on every replica: WHERE status = 'pending_approval' AND
		// updated_at < cutoff. The (user_id, status) index above cannot serve
		// it — its leading column is absent from the predicate — so without
		// this index the sweep degrades to a full-table scan as terminal
		// action rows accumulate.
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_status_updated ON agent_actions(status, updated_at)`,
		`CREATE TABLE IF NOT EXISTS agent_migrations (
			name TEXT PRIMARY KEY,
			applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS job_leads (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			conversation_id INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
			company TEXT,
			role TEXT,
			recruiter_name TEXT,
			recruiter_tg_id INTEGER,
			compensation TEXT,
			status TEXT NOT NULL DEFAULT 'new',
			detail TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_job_leads_conversation ON job_leads(conversation_id)`,
		`CREATE TABLE IF NOT EXISTS owner_notifications (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			action_id INTEGER REFERENCES agent_actions(id) ON DELETE SET NULL,
			body_encrypted BLOB,
			status TEXT NOT NULL DEFAULT 'pending',
			tg_message_id INTEGER,
			sent_at DATETIME,
			claimed_until DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		// One notification per action: a redelivered job whose action insert
		// resolved via the (job_id, action_type) idempotency conflict must not
		// be allowed to queue a second copy of the same owner summary/approval.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_owner_notifications_action ON owner_notifications(action_id) WHERE action_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_owner_notifications_pending ON owner_notifications(status, created_at) WHERE status = 'pending'`,
		`CREATE TABLE IF NOT EXISTS agent_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event_id TEXT NOT NULL,
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			conversation_id INTEGER REFERENCES conversations(id) ON DELETE SET NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			max_attempts INTEGER NOT NULL DEFAULT 5,
			next_run_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			claimed_by TEXT,
			claimed_at DATETIME,
			last_error TEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_jobs_event ON agent_jobs(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_jobs_claim ON agent_jobs(status, next_run_at)`,
		// Serves the claim's correlated NOT EXISTS (per-conversation
		// predecessor lookup): without a conversation_id-leading index every
		// claim candidate would scan the queue.
		`CREATE INDEX IF NOT EXISTS idx_agent_jobs_conversation ON agent_jobs(conversation_id, status, id)`,
		`CREATE TABLE IF NOT EXISTS agent_job_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			job_id INTEGER NOT NULL REFERENCES agent_jobs(id) ON DELETE CASCADE,
			attempt INTEGER NOT NULL,
			started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			finished_at DATETIME,
			status TEXT NOT NULL DEFAULT 'running',
			error TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_job_attempts_job ON agent_job_attempts(job_id)`,
		`CREATE TABLE IF NOT EXISTS tg_update_state (
			user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			pts INTEGER NOT NULL DEFAULT 0,
			qts INTEGER NOT NULL DEFAULT 0,
			date INTEGER NOT NULL DEFAULT 0,
			seq INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS tg_channel_state (
			user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			channel_id INTEGER NOT NULL,
			pts INTEGER NOT NULL DEFAULT 0,
			access_hash INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, channel_id)
		)`,
		`CREATE TABLE IF NOT EXISTS agent_saved_command_cursors (
			user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			last_message_id INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
	}
}

func agentSchemaPG() []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS agent_profiles (
			user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			mode TEXT NOT NULL DEFAULT 'observe',
			autopilot_paused BOOLEAN NOT NULL DEFAULT FALSE,
			listener_enabled BOOLEAN NOT NULL DEFAULT FALSE,
			disclosure_text TEXT NOT NULL DEFAULT '',
			max_autonomous_turns INT NOT NULL DEFAULT 6,
			max_msgs_per_minute INT NOT NULL DEFAULT 2,
			max_reply_chars INT NOT NULL DEFAULT 1200,
			intent_allowlist TEXT NOT NULL DEFAULT '',
			blocked_senders TEXT NOT NULL DEFAULT '',
			sender_allowlist TEXT NOT NULL DEFAULT '',
			owner_profile_encrypted BYTEA,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS incoming_events (
			id BIGSERIAL PRIMARY KEY,
			event_id TEXT NOT NULL,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			chat_tg_id BIGINT NOT NULL,
			sender_tg_id BIGINT NOT NULL,
			message_id BIGINT NOT NULL,
			body_encrypted BYTEA,
			meta TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_incoming_events_event_id ON incoming_events(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_incoming_events_created_at ON incoming_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS agent_sent_messages (
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			tg_message_id BIGINT NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY(user_id, tg_message_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_sent_messages_created ON agent_sent_messages(created_at)`,
		`CREATE TABLE IF NOT EXISTS conversations (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			peer_tg_id BIGINT NOT NULL,
			peer_username TEXT,
			peer_display_name TEXT,
			peer_access_hash BIGINT NOT NULL DEFAULT 0,
			state TEXT NOT NULL DEFAULT 'active',
			autonomous_turns INT NOT NULL DEFAULT 0,
			last_incoming_at TIMESTAMPTZ,
			last_agent_reply_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_user_peer ON conversations(user_id, peer_tg_id)`,
		`CREATE TABLE IF NOT EXISTS conversation_messages (
			id BIGSERIAL PRIMARY KEY,
			conversation_id BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
			direction TEXT NOT NULL,
			tg_message_id BIGINT,
			event_id TEXT,
			body_encrypted BYTEA,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_conv ON conversation_messages(conversation_id, id)`,
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_created_at ON conversation_messages(created_at)`,
		// Serves ListRecentAgentOutgoingTimestamps, a hot per-send path (every
		// executor send and propose_reply call): without conversation_id as
		// the leading column, the (conversation_id, direction, created_at >
		// since) filter would fall back to idx_conv_messages_conv and scan
		// every row for the conversation regardless of direction.
		`CREATE INDEX IF NOT EXISTS idx_conv_messages_direction_created ON conversation_messages(conversation_id, direction, created_at)`,
		`CREATE TABLE IF NOT EXISTS agent_actions (
			id BIGSERIAL PRIMARY KEY,
			approval_code TEXT,
			approval_code_hash BYTEA,
			approval_code_encrypted BYTEA,
			job_id BIGINT,
			conversation_id BIGINT REFERENCES conversations(id) ON DELETE SET NULL,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			action_type TEXT NOT NULL,
			intent TEXT NOT NULL DEFAULT '',
			payload_encrypted BYTEA,
			policy_decision TEXT NOT NULL,
			policy_reasons TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'proposed',
			executed_tg_message_id BIGINT,
			-- see the SQLite copy of this table for send_random_id's role in
			-- crash-safe recovery of the executing state.
			send_random_id BIGINT,
			send_body_encrypted BYTEA,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		// The queue is at-least-once: a redelivered job proposing again must
		// dedupe onto its existing action row (keeping the original
		// approval_code) instead of minting a second live approval.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_job_type ON agent_actions(job_id, action_type) WHERE job_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_user_status ON agent_actions(user_id, status)`,
		// The approval-expiry sweep runs a GLOBAL (tenant-less) scan every
		// minute on every replica: WHERE status = 'pending_approval' AND
		// updated_at < cutoff. The (user_id, status) index above cannot serve
		// it — its leading column is absent from the predicate — so without
		// this index the sweep degrades to a full-table scan as terminal
		// action rows accumulate.
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_status_updated ON agent_actions(status, updated_at)`,
		`CREATE TABLE IF NOT EXISTS agent_migrations (
			name TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE TABLE IF NOT EXISTS job_leads (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			conversation_id BIGINT REFERENCES conversations(id) ON DELETE SET NULL,
			company TEXT,
			role TEXT,
			recruiter_name TEXT,
			recruiter_tg_id BIGINT,
			compensation TEXT,
			status TEXT NOT NULL DEFAULT 'new',
			detail TEXT NOT NULL DEFAULT '{}',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_job_leads_conversation ON job_leads(conversation_id)`,
		`CREATE TABLE IF NOT EXISTS owner_notifications (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			action_id BIGINT REFERENCES agent_actions(id) ON DELETE SET NULL,
			body_encrypted BYTEA,
			status TEXT NOT NULL DEFAULT 'pending',
			tg_message_id BIGINT,
			sent_at TIMESTAMPTZ,
			claimed_until TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		// One notification per action: a redelivered job whose action insert
		// resolved via the (job_id, action_type) idempotency conflict must not
		// be allowed to queue a second copy of the same owner summary/approval.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_owner_notifications_action ON owner_notifications(action_id) WHERE action_id IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_owner_notifications_pending ON owner_notifications(status, created_at) WHERE status = 'pending'`,
		`CREATE TABLE IF NOT EXISTS agent_jobs (
			id BIGSERIAL PRIMARY KEY,
			event_id TEXT NOT NULL,
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			conversation_id BIGINT REFERENCES conversations(id) ON DELETE SET NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			attempts INT NOT NULL DEFAULT 0,
			max_attempts INT NOT NULL DEFAULT 5,
			next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			claimed_by TEXT,
			claimed_at TIMESTAMPTZ,
			last_error TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_jobs_event ON agent_jobs(event_id)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_jobs_claim ON agent_jobs(status, next_run_at)`,
		// Serves the claim's correlated NOT EXISTS (per-conversation
		// predecessor lookup): without a conversation_id-leading index every
		// claim candidate would scan the queue.
		`CREATE INDEX IF NOT EXISTS idx_agent_jobs_conversation ON agent_jobs(conversation_id, status, id)`,
		`CREATE TABLE IF NOT EXISTS agent_job_attempts (
			id BIGSERIAL PRIMARY KEY,
			job_id BIGINT NOT NULL REFERENCES agent_jobs(id) ON DELETE CASCADE,
			attempt INT NOT NULL,
			started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			finished_at TIMESTAMPTZ,
			status TEXT NOT NULL DEFAULT 'running',
			error TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_agent_job_attempts_job ON agent_job_attempts(job_id)`,
		`CREATE TABLE IF NOT EXISTS tg_update_state (
			user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			pts INT NOT NULL DEFAULT 0,
			qts INT NOT NULL DEFAULT 0,
			date INT NOT NULL DEFAULT 0,
			seq INT NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS tg_channel_state (
			user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			channel_id BIGINT NOT NULL,
			pts INT NOT NULL DEFAULT 0,
			access_hash BIGINT NOT NULL DEFAULT 0,
			PRIMARY KEY (user_id, channel_id)
		)`,
		`CREATE TABLE IF NOT EXISTS agent_saved_command_cursors (
			user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
			last_message_id BIGINT NOT NULL DEFAULT 0,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}
}
