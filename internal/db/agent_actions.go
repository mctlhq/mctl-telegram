package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrAgentActionNotFound is returned by the agent-action getters when no row
// matches.
var ErrAgentActionNotFound = errors.New("agent action not found")

// ErrJobLeadNotFound is returned by GetJobLead when no row matches.
var ErrJobLeadNotFound = errors.New("job lead not found")

// ErrOwnerNotificationNotFound is returned by the notification status setters
// when no (id, user) row matches.
var ErrOwnerNotificationNotFound = errors.New("owner notification not found")

// Agent action types.
const (
	ActionTypeReply         = "propose_reply"
	ActionTypeOwnerSummary  = "send_owner_summary"
	ActionTypeOwnerApproval = "request_owner_approval"
)

// Agent action statuses. The lifecycle is a one-way state machine enforced by
// UpdateAgentActionStatus's compare-and-set:
//
//	proposed → pending_approval → approved → executing → executed
//	                            ↘ rejected            ↘ (stuck: manual retry only)
//	proposed → denied | executed (guarded-mode auto-send)
//	pending_approval → expired (approval TTL sweep)
//
// `executing` is deliberately a trap state on crash: the executor moves a row
// to executing *before* the Telegram send and to executed after it, and
// nothing auto-retries from executing — double-messaging a human is worse
// than not sending.
const (
	ActionProposed        = "proposed"
	ActionPendingApproval = "pending_approval"
	ActionApproved        = "approved"
	ActionExecuting       = "executing"
	ActionExecuted        = "executed"
	ActionRejected        = "rejected"
	ActionExpired         = "expired"
	ActionDenied          = "denied"
)

// Policy decisions recorded on an action.
const (
	PolicyAllow           = "allow"
	PolicyRequireApproval = "require_approval"
	PolicyDeny            = "deny"
)

// AgentAction is one proposed (and possibly executed) agent action. Payload is
// the action content — for replies, the proposed message text — plaintext in
// memory only, sealed with the owner's derived key at rest. ApprovalCode is a
// short code the owner types in Saved Messages (/mctl approve <code>); unique
// per user among rows that still carry one.
type AgentAction struct {
	ID                  int64
	ApprovalCode        string
	JobID               int64 // agent_jobs.id; 0 ⇒ not tied to a queue job
	ConversationID      int64 // 0 ⇒ not tied to a conversation
	UserID              int64
	ActionType          string
	Intent              string
	Payload             string
	PolicyDecision      string
	PolicyReasons       string
	Status              string
	ExecutedTGMessageID int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// InsertAgentAction persists a proposed action and returns its id. The payload
// is encrypted with the owner's derived key before storage.
func (s *Store) InsertAgentAction(ctx context.Context, a AgentAction) (int64, error) {
	if a.UserID <= 0 {
		return 0, errors.New("user id required")
	}
	if a.ActionType == "" {
		return 0, errors.New("action type required")
	}
	if a.PolicyDecision == "" {
		return 0, errors.New("policy decision required")
	}
	if a.Status == "" {
		a.Status = ActionProposed
	}
	// A non-zero conversation must belong to the same user — otherwise an
	// action for one account could reference (and later act on) another
	// account's conversation.
	if a.ConversationID != 0 {
		if _, err := s.GetConversation(ctx, a.UserID, a.ConversationID); err != nil {
			return 0, err
		}
	}
	var payload []byte
	if a.Payload != "" {
		var err error
		payload, err = s.Crypt.SealForUser([]byte(a.Payload), a.UserID)
		if err != nil {
			return 0, fmt.Errorf("seal action payload: %w", err)
		}
	}
	var jobID, convID any
	if a.JobID != 0 {
		jobID = a.JobID
	}
	if a.ConversationID != 0 {
		convID = a.ConversationID
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`INSERT INTO agent_actions
		   (approval_code, job_id, conversation_id, user_id, action_type, intent,
		    payload_encrypted, policy_decision, policy_reasons, status)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		 RETURNING id`,
		nullable(a.ApprovalCode), jobID, convID, a.UserID, a.ActionType, a.Intent,
		payload, a.PolicyDecision, a.PolicyReasons, a.Status,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert agent action: %w", err)
	}
	return id, nil
}

// GetAgentAction returns an action by id, scoped to the owning user, payload
// decrypted.
func (s *Store) GetAgentAction(ctx context.Context, userID, id int64) (*AgentAction, error) {
	return s.getAgentAction(ctx, `id = $1 AND user_id = $2`, id, userID)
}

// GetAgentActionByCode returns the action carrying the given approval code
// for the user. Codes are matched case-sensitively; the caller normalizes.
func (s *Store) GetAgentActionByCode(ctx context.Context, userID int64, code string) (*AgentAction, error) {
	if code == "" {
		return nil, ErrAgentActionNotFound
	}
	return s.getAgentAction(ctx, `user_id = $1 AND approval_code = $2`, userID, code)
}

func (s *Store) getAgentAction(ctx context.Context, where string, args ...any) (*AgentAction, error) {
	var (
		a             AgentAction
		code          sql.NullString
		jobID, convID sql.NullInt64
		execMsgID     sql.NullInt64
		payload       []byte
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, approval_code, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, created_at, updated_at
		   FROM agent_actions WHERE `+where,
		args...,
	).Scan(&a.ID, &code, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
		&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
		&execMsgID, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentActionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get agent action: %w", err)
	}
	a.ApprovalCode = code.String
	a.JobID = jobID.Int64
	a.ConversationID = convID.Int64
	a.ExecutedTGMessageID = execMsgID.Int64
	if len(payload) > 0 {
		pt, err := s.Crypt.OpenForUser(payload, a.UserID)
		if err != nil {
			return nil, fmt.Errorf("open action payload: %w", err)
		}
		a.Payload = string(pt)
	}
	return &a, nil
}

// terminalActionStatuses are the end states of the action lifecycle. Reaching
// one releases the approval code (nulled) so its short string can be reused by
// a future action without colliding on the (user_id, approval_code) unique
// index.
var terminalActionStatuses = map[string]struct{}{
	ActionExecuted: {}, ActionRejected: {}, ActionExpired: {}, ActionDenied: {},
}

func isTerminalActionStatus(s string) bool {
	_, ok := terminalActionStatuses[s]
	return ok
}

// allowedActionTransitions is the state machine enforced by
// UpdateAgentActionStatus. It intentionally covers only the transitions driven
// through that method; executing→executed and pending_approval→expired have
// dedicated methods (SetAgentActionExecuted, ExpireStaleAgentActions) with
// their own preconditions. A caller passing a (from, to) pair not listed here
// is a programming error, reported as ErrInvalidActionTransition rather than
// silently applied.
var allowedActionTransitions = map[string]map[string]struct{}{
	ActionProposed:        {ActionPendingApproval: {}, ActionDenied: {}, ActionApproved: {}},
	ActionPendingApproval: {ActionApproved: {}, ActionRejected: {}},
	ActionApproved:        {ActionExecuting: {}},
}

// ErrInvalidActionTransition is returned by UpdateAgentActionStatus when the
// (from, to) pair is not a permitted step in the action state machine.
var ErrInvalidActionTransition = errors.New("invalid agent action state transition")

// UpdateAgentActionStatus transitions an action from one status to another
// atomically (compare-and-set). Returns false when the row was not in `from` —
// a lost race (e.g. owner approved and rejected in quick succession) that the
// caller must treat as "someone else already decided". Transitioning into a
// terminal status releases the approval code. Returns
// ErrInvalidActionTransition for a (from, to) pair outside the state machine.
func (s *Store) UpdateAgentActionStatus(ctx context.Context, userID, id int64, from, to string) (bool, error) {
	if tos, ok := allowedActionTransitions[from]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, to)
	} else if _, ok := tos[to]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, to)
	}
	var res sql.Result
	var err error
	if isTerminalActionStatus(to) {
		res, err = s.DB.ExecContext(ctx,
			`UPDATE agent_actions SET status = $1, approval_code = NULL, updated_at = $2
			  WHERE id = $3 AND user_id = $4 AND status = $5`,
			to, time.Now().UTC(), id, userID, from,
		)
	} else {
		res, err = s.DB.ExecContext(ctx,
			`UPDATE agent_actions SET status = $1, updated_at = $2
			  WHERE id = $3 AND user_id = $4 AND status = $5`,
			to, time.Now().UTC(), id, userID, from,
		)
	}
	if err != nil {
		return false, fmt.Errorf("update action status: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// SetAgentActionExecuted records the Telegram message id of the sent reply and
// flips the row from executing to executed. Returns false when the row was not
// in executing (crash-recovery double call).
func (s *Store) SetAgentActionExecuted(ctx context.Context, userID, id, tgMessageID int64) (bool, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, executed_tg_message_id = $2, approval_code = NULL, updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		ActionExecuted, tgMessageID, time.Now().UTC(), id, userID, ActionExecuting,
	)
	if err != nil {
		return false, fmt.Errorf("set action executed: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ExpireStaleAgentActions moves pending_approval rows older than ttl to
// expired. The age is measured from updated_at, not created_at: an action can
// be inserted as `proposed` and only later transition to pending_approval, so
// created_at would start the clock before the owner was ever asked. updated_at
// on a pending_approval row is stamped by the transition into that state (or
// the direct insert), i.e. the approval-request time. Returns the number of
// rows flipped so the sweeper can log and the notifier can tell owners their
// drafts lapsed.
func (s *Store) ExpireStaleAgentActions(ctx context.Context, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().Add(-ttl)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions SET status = $1, approval_code = NULL, updated_at = $2
		  WHERE status = $3 AND updated_at < $4`,
		ActionExpired, time.Now().UTC(), ActionPendingApproval, cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("expire agent actions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// JobLead is the structured vacancy record the agent extracts from a
// recruiter conversation. Detail is a free-form JSON blob for fields that do
// not warrant their own column (stack, interview process, remote policy, …);
// the typed columns exist for listing and matching. One lead per conversation
// (unique index), so saves are upserts keyed on ConversationID.
type JobLead struct {
	ID             int64
	UserID         int64
	ConversationID int64
	Company        string
	Role           string
	RecruiterName  string
	RecruiterTGID  int64
	Compensation   string
	Status         string
	Detail         string // JSON
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// UpsertJobLead inserts or updates the lead for a conversation and returns its
// id. Only non-empty incoming fields overwrite existing values so the agent
// can save partial extractions incrementally without erasing earlier answers —
// including Status: an empty status means "leave as is" ("new" on first
// insert), so a metadata-only save can never reset a progressed lead.
//
// The conversation must belong to l.UserID (verified upfront, and belt-and-
// braces re-checked by the DO UPDATE's WHERE guard) so a caller can never
// write into another user's lead row via a foreign conversation id.
func (s *Store) UpsertJobLead(ctx context.Context, l JobLead) (int64, error) {
	if l.UserID <= 0 {
		return 0, errors.New("user id required")
	}
	if l.ConversationID <= 0 {
		return 0, errors.New("conversation id required")
	}
	if _, err := s.GetConversation(ctx, l.UserID, l.ConversationID); err != nil {
		return 0, err
	}
	if l.Detail == "" {
		l.Detail = "{}"
	}
	var id int64
	err := s.DB.QueryRowContext(ctx,
		`INSERT INTO job_leads
		   (user_id, conversation_id, company, role, recruiter_name, recruiter_tg_id,
		    compensation, status, detail, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,COALESCE($8,'new'),$9,$10)
		 ON CONFLICT (conversation_id) DO UPDATE SET
		   company = CASE WHEN EXCLUDED.company IS NOT NULL THEN EXCLUDED.company ELSE job_leads.company END,
		   role = CASE WHEN EXCLUDED.role IS NOT NULL THEN EXCLUDED.role ELSE job_leads.role END,
		   recruiter_name = CASE WHEN EXCLUDED.recruiter_name IS NOT NULL THEN EXCLUDED.recruiter_name ELSE job_leads.recruiter_name END,
		   recruiter_tg_id = CASE WHEN EXCLUDED.recruiter_tg_id IS NOT NULL THEN EXCLUDED.recruiter_tg_id ELSE job_leads.recruiter_tg_id END,
		   compensation = CASE WHEN EXCLUDED.compensation IS NOT NULL THEN EXCLUDED.compensation ELSE job_leads.compensation END,
		   status = COALESCE($8, job_leads.status),
		   detail = CASE WHEN EXCLUDED.detail <> '{}' THEN EXCLUDED.detail ELSE job_leads.detail END,
		   updated_at = EXCLUDED.updated_at
		 WHERE job_leads.user_id = EXCLUDED.user_id
		 RETURNING id`,
		l.UserID, l.ConversationID, nullable(l.Company), nullable(l.Role),
		nullable(l.RecruiterName), nullableInt(l.RecruiterTGID),
		nullable(l.Compensation), nullable(l.Status), l.Detail, time.Now().UTC(),
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		// The WHERE guard rejected the update: the conflicting lead row is
		// owned by a different user. Should be unreachable given the upfront
		// ownership check, but must not silently succeed.
		return 0, ErrJobLeadNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("upsert job lead: %w", err)
	}
	return id, nil
}

// GetJobLead returns a lead by id, scoped to the owning user.
func (s *Store) GetJobLead(ctx context.Context, userID, id int64) (*JobLead, error) {
	return s.getJobLead(ctx, `id = $1 AND user_id = $2`, id, userID)
}

// GetJobLeadByConversation returns the lead for a conversation, if any.
func (s *Store) GetJobLeadByConversation(ctx context.Context, userID, conversationID int64) (*JobLead, error) {
	return s.getJobLead(ctx, `conversation_id = $1 AND user_id = $2`, conversationID, userID)
}

func (s *Store) getJobLead(ctx context.Context, where string, args ...any) (*JobLead, error) {
	var (
		l                              JobLead
		convID, recruiterTGID          sql.NullInt64
		company, role, recruiter, comp sql.NullString
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, user_id, conversation_id, company, role, recruiter_name, recruiter_tg_id,
		        compensation, status, detail, created_at, updated_at
		   FROM job_leads WHERE `+where,
		args...,
	).Scan(&l.ID, &l.UserID, &convID, &company, &role, &recruiter, &recruiterTGID,
		&comp, &l.Status, &l.Detail, &l.CreatedAt, &l.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrJobLeadNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get job lead: %w", err)
	}
	l.ConversationID = convID.Int64
	l.Company = company.String
	l.Role = role.String
	l.RecruiterName = recruiter.String
	l.RecruiterTGID = recruiterTGID.Int64
	l.Compensation = comp.String
	return &l, nil
}

// ListJobLeads returns the user's newest leads, most recent first.
func (s *Store) ListJobLeads(ctx context.Context, userID int64, limit int) ([]JobLead, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, user_id, conversation_id, company, role, recruiter_name, recruiter_tg_id,
		        compensation, status, detail, created_at, updated_at
		   FROM job_leads WHERE user_id = $1
		  ORDER BY updated_at DESC LIMIT $2`,
		userID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list job leads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []JobLead
	for rows.Next() {
		var (
			l                              JobLead
			convID, recruiterTGID          sql.NullInt64
			company, role, recruiter, comp sql.NullString
		)
		if err := rows.Scan(&l.ID, &l.UserID, &convID, &company, &role, &recruiter, &recruiterTGID,
			&comp, &l.Status, &l.Detail, &l.CreatedAt, &l.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan job lead: %w", err)
		}
		l.ConversationID = convID.Int64
		l.Company = company.String
		l.Role = role.String
		l.RecruiterName = recruiter.String
		l.RecruiterTGID = recruiterTGID.Int64
		l.Compensation = comp.String
		out = append(out, l)
	}
	return out, rows.Err()
}

// Owner notification kinds and statuses.
const (
	NotificationSummary  = "summary"
	NotificationApproval = "approval_request"
	NotificationAlert    = "alert"

	NotificationPending = "pending"
	NotificationSent    = "sent"
	NotificationFailed  = "failed"
)

// OwnerNotification is one message queued for (or already delivered to) the
// owner's Saved Messages. Body is sealed with the owner's derived key at rest.
type OwnerNotification struct {
	ID          int64
	UserID      int64
	Kind        string
	ActionID    int64 // 0 ⇒ not tied to an action
	Body        string
	Status      string
	TGMessageID int64
	SentAt      time.Time // zero value ⇒ not sent
	CreatedAt   time.Time
}

// InsertOwnerNotification persists a pending notification and returns its id.
func (s *Store) InsertOwnerNotification(ctx context.Context, n OwnerNotification) (int64, error) {
	if n.UserID <= 0 {
		return 0, errors.New("user id required")
	}
	if n.Kind == "" {
		return 0, errors.New("notification kind required")
	}
	// A non-zero action must belong to the same user, so a notification can
	// never be linked to another account's action.
	if n.ActionID != 0 {
		if _, err := s.GetAgentAction(ctx, n.UserID, n.ActionID); err != nil {
			return 0, err
		}
	}
	var body []byte
	if n.Body != "" {
		var err error
		body, err = s.Crypt.SealForUser([]byte(n.Body), n.UserID)
		if err != nil {
			return 0, fmt.Errorf("seal notification body: %w", err)
		}
	}
	var actionID any
	if n.ActionID != 0 {
		actionID = n.ActionID
	}
	var id int64
	if err := s.DB.QueryRowContext(ctx,
		`INSERT INTO owner_notifications(user_id, kind, action_id, body_encrypted, status)
		 VALUES($1,$2,$3,$4,$5)
		 RETURNING id`,
		n.UserID, n.Kind, actionID, body, NotificationPending,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert owner notification: %w", err)
	}
	return id, nil
}

// MarkOwnerNotificationSent records a successful Saved Messages delivery.
func (s *Store) MarkOwnerNotificationSent(ctx context.Context, userID, id, tgMessageID int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET status = $1, tg_message_id = $2, sent_at = $3
		  WHERE id = $4 AND user_id = $5`,
		NotificationSent, tgMessageID, time.Now().UTC(), id, userID,
	)
	if err != nil {
		return fmt.Errorf("mark notification sent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOwnerNotificationNotFound
	}
	return nil
}

// MarkOwnerNotificationFailed records a delivery failure so the control plane
// can surface undelivered drafts (e.g. when the owner's session is revoked).
func (s *Store) MarkOwnerNotificationFailed(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET status = $1 WHERE id = $2 AND user_id = $3`,
		NotificationFailed, id, userID,
	)
	if err != nil {
		return fmt.Errorf("mark notification failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrOwnerNotificationNotFound
	}
	return nil
}

// nullableInt mirrors nullable() for int64 columns: 0 becomes NULL.
func nullableInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}
