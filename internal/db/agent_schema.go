package db

import (
	"context"
	"database/sql"
	"fmt"
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
		`CREATE TABLE IF NOT EXISTS agent_actions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			approval_code TEXT,
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
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_code ON agent_actions(user_id, approval_code) WHERE approval_code IS NOT NULL`,
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
		`CREATE TABLE IF NOT EXISTS agent_actions (
			id BIGSERIAL PRIMARY KEY,
			approval_code TEXT,
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
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_code ON agent_actions(user_id, approval_code) WHERE approval_code IS NOT NULL`,
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
	}
}
