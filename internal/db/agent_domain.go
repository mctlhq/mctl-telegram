package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAgentProfileNotFound is returned by GetAgentProfile when the user has no
// agent profile row — i.e. the communication agent has never been enabled for
// that account.
var ErrAgentProfileNotFound = errors.New("agent profile not found")

// ErrAgentOwnerProfileNotFound means the account has an agent policy row but
// has not configured the encrypted identity/profile document used by the
// communication worker.
var ErrAgentOwnerProfileNotFound = errors.New("agent owner profile not found")

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
	SenderAllowlist    string // csv of telegram user ids allowed into the listener; empty allows all
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
		    intent_allowlist, blocked_senders, sender_allowlist, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
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
		   sender_allowlist = EXCLUDED.sender_allowlist,
		   updated_at = EXCLUDED.updated_at`,
		p.UserID, p.Mode, p.AutopilotPaused, p.ListenerEnabled, p.DisclosureText,
		p.MaxAutonomousTurns, p.MaxMsgsPerMinute, p.MaxReplyChars,
		p.IntentAllowlist, p.BlockedSenders, p.SenderAllowlist, time.Now().UTC(),
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
		        intent_allowlist, blocked_senders, sender_allowlist, created_at, updated_at
		   FROM agent_profiles WHERE user_id = $1`,
		userID,
	).Scan(&p.UserID, &p.Mode, &p.AutopilotPaused, &p.ListenerEnabled, &p.DisclosureText,
		&p.MaxAutonomousTurns, &p.MaxMsgsPerMinute, &p.MaxReplyChars,
		&p.IntentAllowlist, &p.BlockedSenders, &p.SenderAllowlist, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get agent profile: %w", err)
	}
	return &p, nil
}

// EnsureAgentProfile inserts a profile row with the safe C1 defaults
// (observe, autopilot paused, listener off) if none exists yet -- a no-op
// otherwise. Explicit column values rather than the table's own DEFAULTs
// (autopilot_paused DEFAULT FALSE) because a brand-new profile created
// through the admin bootstrap flow should start paused even though the
// schema-level default does not require it. The INSERT ... ON CONFLICT DO
// NOTHING is a single atomic statement -- there is no read-then-write window
// for a concurrent EnsureAgentProfile or UpdateAgentProfileFields call to
// race against.
func (s *Store) EnsureAgentProfile(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO agent_profiles
		   (user_id, mode, autopilot_paused, listener_enabled,
		    max_autonomous_turns, max_msgs_per_minute, max_reply_chars)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 ON CONFLICT (user_id) DO NOTHING`,
		userID, AgentModeObserve, true, false, 6, 2, 1200,
	); err != nil {
		return fmt.Errorf("ensure agent profile: %w", err)
	}
	return nil
}

// SetAgentOwnerProfile encrypts and replaces one account's owner-profile
// document. The caller validates and canonicalizes the document before this
// storage boundary; the store's responsibility is tenant-key encryption and
// an update scoped by user_id.
func (s *Store) SetAgentOwnerProfile(ctx context.Context, userID int64, document []byte) error {
	if len(document) == 0 {
		return errors.New("owner profile document required")
	}
	return s.UpdateAgentProfileFields(ctx, userID, AgentProfileUpdate{
		OwnerProfileDocument: &document,
	})
}

// SetAgentOwnerProfileIfMissing is the atomic legacy-YAML migration path.
// It never overwrites a profile already managed through the admin API.
// inserted reports whether this call populated the previously-empty column.
func (s *Store) SetAgentOwnerProfileIfMissing(ctx context.Context, userID int64, document []byte) (inserted bool, err error) {
	if userID <= 0 {
		return false, errors.New("user id required")
	}
	if len(document) == 0 {
		return false, errors.New("owner profile document required")
	}
	if s.Crypt == nil {
		return false, errors.New("owner profile encryption is not configured")
	}
	encrypted, err := s.Crypt.SealForUser(document, userID)
	if err != nil {
		return false, fmt.Errorf("encrypt agent owner profile: %w", err)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_profiles
		    SET owner_profile_encrypted = $1, updated_at = $2
		  WHERE user_id = $3 AND owner_profile_encrypted IS NULL`,
		encrypted, time.Now().UTC(), userID,
	)
	if err != nil {
		return false, fmt.Errorf("import agent owner profile: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("import agent owner profile rows affected: %w", err)
	}
	return n == 1, nil
}

// GetAgentOwnerProfile decrypts one account's owner-profile document. A blob
// copied to another tenant row cannot decrypt because OpenForUser derives a
// different subkey for each user_id.
func (s *Store) GetAgentOwnerProfile(ctx context.Context, userID int64) ([]byte, error) {
	if userID <= 0 {
		return nil, errors.New("user id required")
	}
	var encrypted []byte
	err := s.DB.QueryRowContext(ctx,
		`SELECT owner_profile_encrypted FROM agent_profiles WHERE user_id = $1`,
		userID,
	).Scan(&encrypted)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && len(encrypted) == 0) {
		return nil, ErrAgentOwnerProfileNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get agent owner profile: %w", err)
	}
	if s.Crypt == nil {
		return nil, errors.New("owner profile encryption is not configured")
	}
	document, err := s.Crypt.OpenForUser(encrypted, userID)
	if err != nil {
		return nil, fmt.Errorf("decrypt agent owner profile: %w", err)
	}
	return document, nil
}

// ClearAgentOwnerProfile removes the profile document without changing the
// account's policy/listener settings.
func (s *Store) ClearAgentOwnerProfile(ctx context.Context, userID int64) error {
	empty := []byte(nil)
	return s.UpdateAgentProfileFields(ctx, userID, AgentProfileUpdate{
		OwnerProfileDocument: &empty,
	})
}

// AgentProfileUpdate carries only the fields to change; a nil pointer means
// "leave this column alone". This is the type UpdateAgentProfileFields
// consumes -- see its doc comment for why this shape exists.
type AgentProfileUpdate struct {
	Mode               *string
	AutopilotPaused    *bool
	ListenerEnabled    *bool
	DisclosureText     *string
	MaxAutonomousTurns *int
	MaxMsgsPerMinute   *int
	MaxReplyChars      *int
	IntentAllowlist    *string
	BlockedSenders     *string
	SenderAllowlist    *string
	// OwnerProfileDocument is plaintext canonical JSON at this boundary.
	// nil leaves it unchanged; a pointer to an empty slice clears it; a
	// non-empty document is tenant-key encrypted in the same UPDATE as all
	// other requested fields.
	OwnerProfileDocument *[]byte
}

// UpdateAgentProfileFields applies only the non-nil fields in u, leaving
// every other column untouched -- including ones a concurrent single-field
// writer (SetAgentAutopilotPaused, called by POST /autopilot/pause and the
// owner's /mctl pause command) might be changing at the same instant. This
// is what makes a partial admin update safe against that race: a
// read-modify-write (read the whole row, mutate a local copy, write the
// whole row back) has a window where the local copy's untouched fields go
// stale; a single UPDATE statement naming only the columns actually being
// set has no such window because the columns it doesn't mention are never
// read here at all. Returns ErrAgentProfileNotFound if no row exists yet --
// call EnsureAgentProfile first. A no-op call (every field nil) is a no-op
// query too, not an error.
func (s *Store) UpdateAgentProfileFields(ctx context.Context, userID int64, u AgentProfileUpdate) error {
	if userID <= 0 {
		return errors.New("user id required")
	}
	var sets []string
	var args []any
	set := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if u.Mode != nil {
		set("mode", *u.Mode)
	}
	if u.AutopilotPaused != nil {
		set("autopilot_paused", *u.AutopilotPaused)
	}
	if u.ListenerEnabled != nil {
		set("listener_enabled", *u.ListenerEnabled)
	}
	if u.DisclosureText != nil {
		set("disclosure_text", *u.DisclosureText)
	}
	if u.MaxAutonomousTurns != nil {
		set("max_autonomous_turns", *u.MaxAutonomousTurns)
	}
	if u.MaxMsgsPerMinute != nil {
		set("max_msgs_per_minute", *u.MaxMsgsPerMinute)
	}
	if u.MaxReplyChars != nil {
		set("max_reply_chars", *u.MaxReplyChars)
	}
	if u.IntentAllowlist != nil {
		set("intent_allowlist", *u.IntentAllowlist)
	}
	if u.BlockedSenders != nil {
		set("blocked_senders", *u.BlockedSenders)
	}
	if u.SenderAllowlist != nil {
		set("sender_allowlist", *u.SenderAllowlist)
	}
	if u.OwnerProfileDocument != nil {
		if len(*u.OwnerProfileDocument) == 0 {
			set("owner_profile_encrypted", nil)
		} else {
			if s.Crypt == nil {
				return errors.New("owner profile encryption is not configured")
			}
			encrypted, err := s.Crypt.SealForUser(*u.OwnerProfileDocument, userID)
			if err != nil {
				return fmt.Errorf("encrypt agent owner profile: %w", err)
			}
			set("owner_profile_encrypted", encrypted)
		}
	}
	if len(sets) == 0 {
		return nil
	}
	set("updated_at", time.Now().UTC())
	args = append(args, userID)
	query := fmt.Sprintf(`UPDATE agent_profiles SET %s WHERE user_id = $%d`,
		strings.Join(sets, ", "), len(args))
	res, err := s.DB.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update agent profile fields: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentProfileNotFound
	}
	return nil
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
// schema changes and readable. tg_update_state / tg_channel_state,
// agent_saved_command_cursors, and agent_profiles cascade on users(id), but
// the users row survives account deletion, so they are purged here too.
//
// purgeAgentJobsHook is set by the queue package's init (agent_jobs.go) to
// also drop the queue tables, which are introduced in a later change than
// this base schema; nil until that code is present.
var purgeAgentJobsHook func(ctx context.Context, ex execer, userID int64) error

func purgeAgentData(ctx context.Context, ex execer, userID int64) error {
	if purgeAgentJobsHook != nil {
		if err := purgeAgentJobsHook(ctx, ex, userID); err != nil {
			return err
		}
	}
	stmts := []string{
		`DELETE FROM owner_notifications WHERE user_id = $1`,
		`DELETE FROM agent_actions WHERE user_id = $1`,
		`DELETE FROM agent_sent_messages WHERE user_id = $1`,
		`DELETE FROM job_leads WHERE user_id = $1`,
		`DELETE FROM conversation_messages WHERE conversation_id IN (SELECT id FROM conversations WHERE user_id = $1)`,
		`DELETE FROM conversations WHERE user_id = $1`,
		`DELETE FROM incoming_events WHERE user_id = $1`,
		`DELETE FROM agent_saved_command_cursors WHERE user_id = $1`,
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
		        intent_allowlist, blocked_senders, sender_allowlist, created_at, updated_at
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
			&p.IntentAllowlist, &p.BlockedSenders, &p.SenderAllowlist, &p.CreatedAt, &p.UpdatedAt); err != nil {
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
	UserID   int64
	ID       int64
	PeerTGID int64
	// PeerAccessHash is the MTProto access_hash Telegram returned for this
	// peer, captured from an incoming update's entity data (see
	// SetConversationPeerAccessHash). 0 ⇒ unknown — messages.* RPCs reject a
	// zero-access-hash InputPeerUser with PEER_ID_INVALID, so the executor
	// must have a nonzero value here before it can send at all.
	PeerAccessHash   int64
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
		`SELECT id, user_id, peer_tg_id, peer_username, peer_display_name, peer_access_hash, state,
		        autonomous_turns, last_incoming_at, last_agent_reply_at, created_at, updated_at
		   FROM conversations WHERE `+where,
		args...,
	).Scan(&c.ID, &c.UserID, &c.PeerTGID, &username, &display, &c.PeerAccessHash, &c.State,
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

// SetConversationPeerAccessHash persists the MTProto access_hash Telegram
// returned for this peer, captured from an incoming update's entity data
// (internal/agent/listener.ExtractMessage). messages.* RPCs reject an
// InputPeerUser carrying a zero access_hash with PEER_ID_INVALID — see
// internal/telegram/messages.go's seedPeerCache doc comment for the
// underlying MTProto rule — so the executor cannot send at all until this
// has run at least once for a conversation. accessHash == 0 is a no-op: the
// listener does not always have a usable one (e.g. a Telegram "min" user's
// hash works only for limited contexts, never for messages.*), and a zero
// value must never overwrite an already-known good hash.
func (s *Store) SetConversationPeerAccessHash(ctx context.Context, userID, peerTGID, accessHash int64) error {
	if accessHash == 0 {
		return nil
	}
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE conversations SET peer_access_hash = $1, updated_at = $2 WHERE user_id = $3 AND peer_tg_id = $4`,
		accessHash, time.Now().UTC(), userID, peerTGID,
	); err != nil {
		return fmt.Errorf("set conversation peer access hash: %w", err)
	}
	return nil
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

// ListRecentAgentOutgoingTimestamps returns timestamps for completed sends
// plus durable execution reservations newer than `since` —
// policy.Input.RecentAgentSends' MaxMsgsPerMinute input. Executing rows count
// because the RPC may already have reached Telegram; denied rows with a
// random_id count because a recovery-time policy change cannot prove that the
// original RPC did not land. This fail-closed accounting survives crashes and
// prevents another replica from spending the same rate budget.
//
// A dedicated,
// correctly-scoped query rather than callers fetching
// ListConversationMessages' top-N-of-any-direction page and filtering: a
// Codex finding on #307 caught that both internal/agentapi's and
// internal/agent/executor's recentAgentSends helpers did exactly that
// filter-after-fetch, so 50+ newer messages of ANY direction (inbound,
// owner takeover, another agent reply) arriving after a real agent send
// could push it out of that fixed-size page entirely — RecentAgentSends
// would then silently miss it, undercounting the rate limit and letting
// another action send when MaxMsgsPerMinute should have blocked it.
func (s *Store) ListRecentAgentOutgoingTimestamps(ctx context.Context, userID, conversationID int64, since time.Time) ([]time.Time, error) {
	return s.listRecentAgentOutgoingTimestamps(ctx, userID, conversationID, since, 0)
}

// ListRecentAgentOutgoingTimestampsExcludingAction is the crash-recovery
// variant: the action being retried already owns one execution reservation
// and must not count itself as a newer competing send during policy
// re-evaluation.
func (s *Store) ListRecentAgentOutgoingTimestampsExcludingAction(
	ctx context.Context,
	userID, conversationID int64,
	since time.Time,
	excludeActionID int64,
) ([]time.Time, error) {
	return s.listRecentAgentOutgoingTimestamps(ctx, userID, conversationID, since, excludeActionID)
}

func (s *Store) listRecentAgentOutgoingTimestamps(
	ctx context.Context,
	userID, conversationID int64,
	since time.Time,
	excludeActionID int64,
) ([]time.Time, error) {
	if _, err := s.GetConversation(ctx, userID, conversationID); err != nil {
		return nil, err
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT sent_at FROM (
		    SELECT created_at AS sent_at
		      FROM conversation_messages
		     WHERE conversation_id = $1 AND direction = $2 AND created_at > $3
		    UNION ALL
		    SELECT updated_at AS sent_at
		      FROM agent_actions
		     WHERE conversation_id = $1 AND status IN ($4, $5)
		       AND send_random_id IS NOT NULL AND updated_at > $3
		       AND ($6 = 0 OR id <> $6)
		  ) reserved_and_sent
		  ORDER BY sent_at`,
		conversationID, DirectionAgentOutgoing, since, ActionExecuting, ActionDenied, excludeActionID,
	)
	if err != nil {
		return nil, fmt.Errorf("list recent agent outgoing timestamps: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []time.Time
	for rows.Next() {
		var t time.Time
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("scan agent outgoing timestamp: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
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
