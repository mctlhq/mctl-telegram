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
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_code ON agent_actions(user_id, approval_code) WHERE approval_code IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_user_status ON agent_actions(user_id, status)`,
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
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
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
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_actions_code ON agent_actions(user_id, approval_code) WHERE approval_code IS NOT NULL`,
		`CREATE INDEX IF NOT EXISTS idx_agent_actions_user_status ON agent_actions(user_id, status)`,
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
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
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
