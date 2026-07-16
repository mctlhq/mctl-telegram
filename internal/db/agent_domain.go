package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrAgentProfileNotFound is returned by GetAgentProfile when the user has no
// agent profile row — i.e. the communication agent has never been enabled for
// that account.
var ErrAgentProfileNotFound = errors.New("agent profile not found")

// ErrConversationNotFound is returned by the conversation getters when no row
// matches.
var ErrConversationNotFound = errors.New("conversation not found")

// Agent operating modes. The mode is evaluated server-side by the policy
// engine on every proposed action; the agent process itself never enforces it.
const (
	AgentModeObserve = "observe" // never auto-send; every reply requires owner approval
	AgentModeGuarded = "guarded" // allowlisted discovery intents may auto-send
	AgentModeOff     = "off"     // deny everything
)

// Conversation states.
const (
	ConversationActive    = "active"
	ConversationPaused    = "paused"
	ConversationTakenOver = "taken_over" // owner replied in-thread; agent must stay silent
	ConversationClosed    = "closed"
)

// Message directions in conversation_messages.
const (
	DirectionIncoming      = "incoming"
	DirectionAgentOutgoing = "agent_outgoing"
	DirectionOwnerOutgoing = "owner_outgoing"
)

// AgentProfile is the per-user configuration of the communication agent. All
// limits are enforced server-side by the policy engine; the profile row is the
// single source of truth an operator edits to tune or kill the agent for one
// account (the global kill switch lives in env, not here).
type AgentProfile struct {
	UserID             int64
	Mode               string
	AutopilotPaused    bool
	ListenerEnabled    bool
	DisclosureText     string
	MaxAutonomousTurns int
	MaxMsgsPerMinute   int
	MaxReplyChars      int
	IntentAllowlist    string // csv of intents allowed to auto-send in guarded mode
	BlockedSenders     string // csv of telegram user ids the agent must ignore
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// UpsertAgentProfile inserts or fully replaces the user's agent profile.
// Zero-valued limits are replaced with the documented defaults so a partially
// filled profile cannot accidentally disable a guardrail (e.g. a zero
// MaxReplyChars would otherwise mean "no length limit" to a careless reader —
// here it means "default 1200").
func (s *Store) UpsertAgentProfile(ctx context.Context, p AgentProfile) error {
	if p.UserID <= 0 {
		return errors.New("user id required")
	}
	if p.Mode == "" {
		p.Mode = AgentModeObserve
	}
	if p.MaxAutonomousTurns <= 0 {
		p.MaxAutonomousTurns = 6
	}
	if p.MaxMsgsPerMinute <= 0 {
		p.MaxMsgsPerMinute = 2
	}
	if p.MaxReplyChars <= 0 {
		p.MaxReplyChars = 1200
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO agent_profiles
		   (user_id, mode, autopilot_paused, listener_enabled, disclosure_text,
		    max_autonomous_turns, max_msgs_per_minute, max_reply_chars,
		    intent_allowlist, blocked_senders, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		 ON CONFLICT (user_id) DO UPDATE SET
		   mode = EXCLUDED.mode,
		   autopilot_paused = EXCLUDED.autopilot_paused,
		   listener_enabled = EXCLUDED.listener_enabled,
		   disclosure_text = EXCLUDED.disclosure_text,
		   max_autonomous_turns = EXCLUDED.max_autonomous_turns,
		   max_msgs_per_minute = EXCLUDED.max_msgs_per_minute,
		   max_reply_chars = EXCLUDED.max_reply_chars,
		   intent_allowlist = EXCLUDED.intent_allowlist,
		   blocked_senders = EXCLUDED.blocked_senders,
		   updated_at = EXCLUDED.updated_at`,
		p.UserID, p.Mode, p.AutopilotPaused, p.ListenerEnabled, p.DisclosureText,
		p.MaxAutonomousTurns, p.MaxMsgsPerMinute, p.MaxReplyChars,
		p.IntentAllowlist, p.BlockedSenders, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("upsert agent profile: %w", err)
	}
	return nil
}

// GetAgentProfile returns the user's agent profile or ErrAgentProfileNotFound.
func (s *Store) GetAgentProfile(ctx context.Context, userID int64) (*AgentProfile, error) {
	var p AgentProfile
	err := s.DB.QueryRowContext(ctx,
		`SELECT user_id, mode, autopilot_paused, listener_enabled, disclosure_text,
		        max_autonomous_turns, max_msgs_per_minute, max_reply_chars,
		        intent_allowlist, blocked_senders, created_at, updated_at
		   FROM agent_profiles WHERE user_id = $1`,
		userID,
	).Scan(&p.UserID, &p.Mode, &p.AutopilotPaused, &p.ListenerEnabled, &p.DisclosureText,
		&p.MaxAutonomousTurns, &p.MaxMsgsPerMinute, &p.MaxReplyChars,
		&p.IntentAllowlist, &p.BlockedSenders, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get agent profile: %w", err)
	}
	return &p, nil
}

// SetAgentAutopilotPaused flips the per-account pause flag. Used by the
// pause_autopilot agent tool and the /mctl pause | continue owner commands.
func (s *Store) SetAgentAutopilotPaused(ctx context.Context, userID int64, paused bool) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_profiles SET autopilot_paused = $1, updated_at = $2 WHERE user_id = $3`,
		paused, time.Now().UTC(), userID,
	)
	if err != nil {
		return fmt.Errorf("set autopilot paused: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentProfileNotFound
	}
	return nil
}

// purgeAgentData deletes every communication-agent row owned by a user within
// the caller's transaction. Called by HardDeleteAccount so account deletion
// takes the agent's stored (encrypted) recruiter data with it. Order respects
// FKs: children before parents, though ON DELETE CASCADE on conversations
// would also cover messages/leads — the explicit deletes keep it robust to
// schema changes and readable. tg_update_state / tg_channel_state and
// agent_profiles cascade on users(id), but the users row survives account
// deletion, so they are purged here too.
func purgeAgentData(ctx context.Context, ex execer, userID int64) error {
	stmts := []string{
		`DELETE FROM owner_notifications WHERE user_id = $1`,
		`DELETE FROM agent_actions WHERE user_id = $1`,
		`DELETE FROM job_leads WHERE user_id = $1`,
		`DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = $1)`,
		`DELETE FROM conversations WHERE user_id = $1`,
		`DELETE FROM incoming_events WHERE user_id = $1`,
		`DELETE FROM tg_channel_state WHERE user_id = $1`,
		`DELETE FROM tg_update_state WHERE user_id = $1`,
		`DELETE FROM agent_profiles WHERE user_id = $1`,
	}
	for _, q := range stmts {
		if _, err := ex.ExecContext(ctx, q, userID); err != nil {
			return fmt.Errorf("purge agent data: %w", err)
		}
	}
	return nil
}

// GetTelegramID returns the account's active Telegram user id, or 0 when the
// account has no finalised session yet (telegram_user_id NULL / all sessions
// revoked). The listener supervisor uses it to namespace event ids and detect
// the self peer; 0 means "skip pinning until the session establishes".
func (s *Store) GetTelegramID(ctx context.Context, userID int64) (int64, error) {
	var tgID sql.NullInt64
	err := s.DB.QueryRowContext(ctx,
		`SELECT telegram_user_id FROM telegram_accounts
		  WHERE user_id = $1 AND revoked_at IS NULL AND telegram_user_id IS NOT NULL
		  ORDER BY connected_at DESC LIMIT 1`,
		userID,
	).Scan(&tgID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get telegram id: %w", err)
	}
	return tgID.Int64, nil
}

// ListListenerEnabledProfiles returns every profile with listener_enabled set.
// The listener supervisor polls this to know which accounts need a pinned,
// update-handling MTProto client.
func (s *Store) ListListenerEnabledProfiles(ctx context.Context) ([]AgentProfile, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT user_id, mode, autopilot_paused, listener_enabled, disclosure_text,
		        max_autonomous_turns, max_msgs_per_minute, max_reply_chars,
		        intent_allowlist, blocked_senders, created_at, updated_at
		   FROM agent_profiles WHERE listener_enabled = $1`,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("list listener profiles: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AgentProfile
	for rows.Next() {
		var p AgentProfile
		if err := rows.Scan(&p.UserID, &p.Mode, &p.AutopilotPaused, &p.ListenerEnabled, &p.DisclosureText,
			&p.MaxAutonomousTurns, &p.MaxMsgsPerMinute, &p.MaxReplyChars,
			&p.IntentAllowlist, &p.BlockedSenders, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan listener profile: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Conversation models one agent-visible dialog with a Telegram peer,
// independent of Telegram's own dialog list. The (user_id, peer_tg_id) pair is
// unique; peers are only ever private users in v1.
type Conversation struct {
	UserID           int64
	ID               int64
	PeerTGID         int64
	PeerUsername     string
	PeerDisplayName  string
	State            string
	AutonomousTurns  int
	LastIncomingAt   time.Time // zero value ⇒ never
	LastAgentReplyAt time.Time // zero value ⇒ never
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// EnsureConversation returns the conversation for (userID, peerTGID),
// creating it in the active state if absent. Username/display name are
// refreshed on every call so the row tracks Telegram's current values.
// Uses the same INSERT ... ON CONFLICT + SELECT shape as EnsureUserByTelegramID
// for race safety.
func (s *Store) EnsureConversation(ctx context.Context, userID, peerTGID int64, username, displayName string) (*Conversation, error) {
	if userID <= 0 || peerTGID == 0 {
		return nil, errors.New("user id and peer id required")
	}
	// COALESCE keeps a previously stored handle/name when this call arrives
	// with empty metadata (e.g. the listener saw only a numeric peer): a
	// later richer update fills them, but an emptier one must not erase them.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO conversations(user_id, peer_tg_id, peer_username, peer_display_name)
		 VALUES($1,$2,$3,$4)
		 ON CONFLICT (user_id, peer_tg_id) DO UPDATE SET
		   peer_username = COALESCE(EXCLUDED.peer_username, conversations.peer_username),
		   peer_display_name = COALESCE(EXCLUDED.peer_display_name, conversations.peer_display_name),
		   updated_at = $5`,
		userID, peerTGID, nullable(username), nullable(displayName), time.Now().UTC(),
	); err != nil {
		return nil, fmt.Errorf("ensure conversation: %w", err)
	}
	return s.GetConversationByPeer(ctx, userID, peerTGID)
}

// GetConversation returns a conversation by id, scoped to the owning user.
func (s *Store) GetConversation(ctx context.Context, userID, id int64) (*Conversation, error) {
	return s.getConversation(ctx, `id = $1 AND user_id = $2`, id, userID)
}

// GetConversationByPeer returns the conversation for a (user, peer) pair.
func (s *Store) GetConversationByPeer(ctx context.Context, userID, peerTGID int64) (*Conversation, error) {
	return s.getConversation(ctx, `user_id = $1 AND peer_tg_id = $2`, userID, peerTGID)
}

func (s *Store) getConversation(ctx context.Context, where string, args ...any) (*Conversation, error) {
	var (
		c                 Conversation
		username, display sql.NullString
		lastIn, lastOut   sql.NullTime
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, peer_tg_id, peer_username, peer_display_name, state,
		        autonomous_turns, last_incoming_at, last_agent_reply_at, created_at, updated_at
		   FROM conversations WHERE `+where,
		args...,
	).Scan(&c.ID, &c.UserID, &c.PeerTGID, &username, &display, &c.State,
		&c.AutonomousTurns, &lastIn, &lastOut, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrConversationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get conversation: %w", err)
	}
	c.PeerUsername = username.String
	c.PeerDisplayName = display.String
	if lastIn.Valid {
		c.LastIncomingAt = lastIn.Time
	}
	if lastOut.Valid {
		c.LastAgentReplyAt = lastOut.Time
	}
	return &c, nil
}

// SetConversationState transitions a conversation to the given state.
func (s *Store) SetConversationState(ctx context.Context, userID, id int64, state string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE conversations SET state = $1, updated_at = $2 WHERE id = $3 AND user_id = $4`,
		state, time.Now().UTC(), id, userID,
	)
	if err != nil {
		return fmt.Errorf("set conversation state: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConversationNotFound
	}
	return nil
}

// IncrementAutonomousTurns bumps the autonomous reply counter and stamps
// last_agent_reply_at. Called by the executor after a successful agent send;
// the policy engine reads the counter to enforce max_autonomous_turns.
func (s *Store) IncrementAutonomousTurns(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE conversations
		    SET autonomous_turns = autonomous_turns + 1,
		        last_agent_reply_at = $1, updated_at = $1
		  WHERE id = $2 AND user_id = $3`,
		time.Now().UTC(), id, userID,
	)
	if err != nil {
		return fmt.Errorf("increment autonomous turns: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConversationNotFound
	}
	return nil
}

// ResetAutonomousTurns zeroes the counter — called when the owner takes over
// or explicitly continues a conversation, granting the agent a fresh budget.
func (s *Store) ResetAutonomousTurns(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE conversations SET autonomous_turns = 0, updated_at = $1 WHERE id = $2 AND user_id = $3`,
		time.Now().UTC(), id, userID,
	)
	if err != nil {
		return fmt.Errorf("reset autonomous turns: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConversationNotFound
	}
	return nil
}

// TouchConversationIncoming stamps last_incoming_at. Called by the listener
// for every persisted incoming event on the conversation.
func (s *Store) TouchConversationIncoming(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE conversations SET last_incoming_at = $1, updated_at = $1 WHERE id = $2 AND user_id = $3`,
		time.Now().UTC(), id, userID,
	)
	if err != nil {
		return fmt.Errorf("touch conversation: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConversationNotFound
	}
	return nil
}

// ConversationMessage is one message in an agent-visible conversation. Body is
// plaintext in memory only — sealed with the owner's derived key at rest.
type ConversationMessage struct {
	ID             int64
	ConversationID int64
	Direction      string
	TGMessageID    int64 // 0 ⇒ unknown (e.g. not yet sent)
	EventID        string
	Body           string
	CreatedAt      time.Time
}

// InsertConversationMessage appends a message to a conversation. userID must
// be the conversation owner's id — it selects the encryption subkey and is
// verified against the conversation row so a mismatched caller cannot write
// (or later read) another user's thread.
func (s *Store) InsertConversationMessage(ctx context.Context, userID int64, m ConversationMessage) (int64, error) {
	if m.ConversationID <= 0 {
		return 0, errors.New("conversation id required")
	}
	if m.Direction == "" {
		return 0, errors.New("direction required")
	}
	conv, err := s.GetConversation(ctx, userID, m.ConversationID)
	if err != nil {
		return 0, err
	}
	var body []byte
	if m.Body != "" {
		body, err = s.Crypt.SealForUser([]byte(m.Body), conv.UserID)
		if err != nil {
			return 0, fmt.Errorf("seal message body: %w", err)
		}
	}
	var tgMsgID any
	if m.TGMessageID != 0 {
		tgMsgID = m.TGMessageID
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`INSERT INTO conversation_messages(conversation_id, direction, tg_message_id, event_id, body_encrypted)
		 VALUES($1,$2,$3,$4,$5)
		 RETURNING id`,
		m.ConversationID, m.Direction, tgMsgID, nullable(m.EventID), body,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert conversation message: %w", err)
	}
	return id, nil
}

// ListConversationMessages returns the newest `limit` messages of a
// conversation in chronological order, bodies decrypted. userID scopes the
// read to the conversation owner.
func (s *Store) ListConversationMessages(ctx context.Context, userID, conversationID int64, limit int) ([]ConversationMessage, error) {
	conv, err := s.GetConversation(ctx, userID, conversationID)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, conversation_id, direction, tg_message_id, event_id, body_encrypted, created_at
		   FROM conversation_messages
		  WHERE conversation_id = $1
		  ORDER BY id DESC LIMIT $2`,
		conversationID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list conversation messages: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []ConversationMessage
	for rows.Next() {
		var (
			m       ConversationMessage
			tgMsgID sql.NullInt64
			eventID sql.NullString
			body    []byte
		)
		if err := rows.Scan(&m.ID, &m.ConversationID, &m.Direction, &tgMsgID, &eventID, &body, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan conversation message: %w", err)
		}
		m.TGMessageID = tgMsgID.Int64
		m.EventID = eventID.String
		if len(body) > 0 {
			pt, err := s.Crypt.OpenForUser(body, conv.UserID)
			if err != nil {
				return nil, fmt.Errorf("open message body: %w", err)
			}
			m.Body = string(pt)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse into chronological order (query fetched newest-first).
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}
