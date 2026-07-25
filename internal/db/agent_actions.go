package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// ErrAgentActionNotFound is returned by the agent-action getters when no row
// matches.
var ErrAgentActionNotFound = errors.New("agent action not found")

// ErrAgentSendBudgetExhausted means another execution reservation consumed
// the conversation's autonomous-turn or per-minute budget before this action
// could claim it. The executor must fail closed instead of sending.
var ErrAgentSendBudgetExhausted = errors.New("agent send budget exhausted")

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
//	                            ↘ rejected            ↘ (self-heals — see below)
//	proposed → denied | executed (guarded-mode auto-send)
//	pending_approval → expired (approval TTL sweep)
//
// `executing` was originally a permanent crash trap (nothing auto-retried out
// of it — double-messaging a human seemed worse than not sending). Revised in
// A-PR7 (mctlhq/mctl-telegram#297): the executor now persists a Telegram
// send_random_id on the row BEFORE issuing the RPC, so a crash-recovery sweep
// can safely retry the SAME send with the SAME random_id — MTProto dedups on
// it server-side, so the retry is a no-op if the original send actually
// landed and a real (idempotent) send if it didn't. See
// Store.ListStuckExecutingActions and internal/agent/executor.
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
	SendRandomID        int64  // 0 ⇒ not yet allocated; persisted before the send RPC, see BeginExecutingAgentAction
	SendBody            string // exact final outbound body paired with SendRandomID; encrypted at rest
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// InsertAgentAction persists a proposed action and returns its id. The payload
// is encrypted with the owner's derived key before storage.
//
// Idempotent per (job_id, action_type): the queue is at-least-once, so a
// worker that persisted an action and crashed before completing its job will
// re-run the job and propose again. The unique index makes the second insert
// a no-op and the EXISTING row's id is returned — critically keeping the
// original approval_code, so a redelivered job cannot mint a second live
// approval for the same reply. Actions without a job (JobID == 0) are
// exempt.
//
// A job-tied action also requires its job to still exist (returns
// ErrAgentJobNotFound otherwise), which keeps a racing worker from recreating
// encrypted action data after HardDeleteAccount's purge — see the insert
// statement's comment.
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
	var convID any
	if a.ConversationID != 0 {
		convID = a.ConversationID
	}
	var id int64
	var err error
	if a.JobID != 0 {
		// Source the insert from the job row so a job-tied action can only be
		// created while its job still exists. This closes a purge race:
		// HardDeleteAccount's purge locks the user's job rows first
		// (purgeAgentJobs' no-op UPDATE) and only then deletes agent_actions,
		// so a worker that claimed the job before the purge began must not be
		// able to slip a fresh (encrypted) action row in after that DELETE. On
		// Postgres FOR SHARE makes this statement block on the purge's row
		// lock and re-evaluate once it commits: the job is gone, the SELECT is
		// empty, nothing is inserted. SQLite has no FOR SHARE, but its
		// single-writer transactions serialize the two paths anyway — the
		// action either lands before the purge (and is deleted by it) or the
		// job is already gone and the SELECT is empty.
		lock := ""
		if s.isPostgres(ctx) {
			lock = " FOR SHARE"
		}
		err = s.DB.QueryRowContext(ctx,
			`INSERT INTO agent_actions
			   (approval_code, job_id, conversation_id, user_id, action_type, intent,
			    payload_encrypted, policy_decision, policy_reasons, status)
			 SELECT $1, j.id, $3, $4, $5, $6, $7, $8, $9, $10
			   FROM agent_jobs j WHERE j.id = $2 AND j.user_id = $4`+lock+`
			 ON CONFLICT (job_id, action_type) WHERE job_id IS NOT NULL DO NOTHING
			 RETURNING id`,
			nullable(a.ApprovalCode), a.JobID, convID, a.UserID, a.ActionType, a.Intent,
			payload, a.PolicyDecision, a.PolicyReasons, a.Status,
		).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			// Two ways to land here: a redelivery hit the (job_id, action_type)
			// unique index — the action exists, return it with its ORIGINAL
			// approval_code — or the source SELECT found no job (purged account
			// or foreign/bogus id) and the job must be reported gone.
			lookupErr := s.DB.QueryRowContext(ctx,
				`SELECT id FROM agent_actions
				  WHERE job_id = $1 AND action_type = $2 AND user_id = $3`,
				a.JobID, a.ActionType, a.UserID,
			).Scan(&id)
			if errors.Is(lookupErr, sql.ErrNoRows) {
				return 0, ErrAgentJobNotFound
			}
			if lookupErr != nil {
				return 0, fmt.Errorf("load existing agent action: %w", lookupErr)
			}
			return id, nil
		}
	} else {
		err = s.DB.QueryRowContext(ctx,
			`INSERT INTO agent_actions
			   (approval_code, job_id, conversation_id, user_id, action_type, intent,
			    payload_encrypted, policy_decision, policy_reasons, status)
			 VALUES($1,NULL,$2,$3,$4,$5,$6,$7,$8,$9)
			 RETURNING id`,
			nullable(a.ApprovalCode), convID, a.UserID, a.ActionType, a.Intent,
			payload, a.PolicyDecision, a.PolicyReasons, a.Status,
		).Scan(&id)
	}
	if err != nil {
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
		a                 AgentAction
		code              sql.NullString
		jobID, convID     sql.NullInt64
		execMsgID         sql.NullInt64
		sendRandomID      sql.NullInt64
		payload, sendBody []byte
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, approval_code, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at
		   FROM agent_actions WHERE `+where,
		args...,
	).Scan(&a.ID, &code, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
		&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
		&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt)
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
	a.SendRandomID = sendRandomID.Int64
	if len(payload) > 0 {
		pt, err := s.Crypt.OpenForUser(payload, a.UserID)
		if err != nil {
			return nil, fmt.Errorf("open action payload: %w", err)
		}
		a.Payload = string(pt)
	}
	if len(sendBody) > 0 {
		pt, err := s.Crypt.OpenForUser(sendBody, a.UserID)
		if err != nil {
			return nil, fmt.Errorf("open action send body: %w", err)
		}
		a.SendBody = string(pt)
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
	// approved -> denied (added in A-PR7, internal/agent/executor): approval
	// and send are not atomic, and policy is re-checked immediately before
	// the send RPC fires (owner takeover, autopilot pause, kill switch flip,
	// or a rate limit newly exceeded since approval). A stale approval must
	// not bypass a deny condition that has since become true — this is the
	// state that re-check lands on instead of proceeding to executing.
	ActionApproved: {ActionExecuting: {}, ActionDenied: {}},
	// executing -> denied: recoverOne's re-check (added in the same round as
	// the approved->denied transition above) can find policy now denies a
	// send that crashed before completing — e.g. the owner took over or hit
	// the kill switch during the crash-recovery grace window. Recording that
	// as denied rather than leaving the row stuck in executing forever, or
	// silently retrying a send policy no longer allows.
	ActionExecuting: {ActionDenied: {}},
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

// BeginExecutingAgentAction transitions an action from approved to executing
// and persists the Telegram send_random_id in the SAME atomic UPDATE, before
// the executor issues the actual send RPC — never after. That ordering is
// what makes crash recovery safe: if the process dies between this call and
// the RPC, or between the RPC and SetAgentActionExecuted, the row is left in
// executing WITH a random_id already on it, so ListStuckExecutingActions +
// a retry of the same send is always possible. Returns false on a lost CAS
// race (concurrent reject, or a second executor goroutine).
func (s *Store) BeginExecutingAgentAction(ctx context.Context, userID, id, randomID int64) (bool, error) {
	action, err := s.GetAgentAction(ctx, userID, id)
	if err != nil {
		return false, err
	}
	return s.ReserveAgentActionSend(ctx, *action, randomID, "", 0, 0, time.Time{}, false)
}

// ReserveAgentActionSend atomically claims an approved action, persists the
// random_id and exact final body, and reserves one autonomous turn. When
// enforceBudget is true it serializes on the conversation row and checks both
// the turn budget and the complete one-minute send window before making the
// reservation. This closes the cross-replica race where two different action
// rows could both pass policy against the same pre-send history.
//
// Executing actions are themselves durable rate reservations. A subsequent
// claim counts them alongside completed conversation_messages, so the budget
// remains consumed across process crashes and until RecordAgentActionSent
// atomically replaces the executing reservation with a durable history row.
func (s *Store) ReserveAgentActionSend(
	ctx context.Context,
	action AgentAction,
	randomID int64,
	finalBody string,
	maxAutonomousTurns, maxMsgsPerMinute int,
	rateWindowStart time.Time,
	enforceBudget bool,
) (bool, error) {
	if randomID == 0 {
		return false, errors.New("send random id required")
	}
	if action.UserID <= 0 || action.ID <= 0 || action.ConversationID <= 0 {
		return false, errors.New("action user, id, and conversation required")
	}
	var sendBody []byte
	if finalBody != "" {
		var err error
		sendBody, err = s.Crypt.SealForUser([]byte(finalBody), action.UserID)
		if err != nil {
			return false, fmt.Errorf("seal action send body: %w", err)
		}
	}

	pg := s.isPostgres(ctx)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin reserve-send tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	var autonomousTurns int
	if err := tx.QueryRowContext(ctx,
		`SELECT autonomous_turns FROM conversations
		  WHERE id = $1 AND user_id = $2`+lock,
		action.ConversationID, action.UserID,
	).Scan(&autonomousTurns); errors.Is(err, sql.ErrNoRows) {
		return false, ErrConversationNotFound
	} else if err != nil {
		return false, fmt.Errorf("lock conversation for send reservation: %w", err)
	}

	if enforceBudget && maxAutonomousTurns > 0 && autonomousTurns >= maxAutonomousTurns {
		return false, fmt.Errorf("%w: autonomous turns %d/%d", ErrAgentSendBudgetExhausted, autonomousTurns, maxAutonomousTurns)
	}
	if enforceBudget && maxMsgsPerMinute > 0 {
		var recent int
		if err := tx.QueryRowContext(ctx,
			`SELECT
			   (SELECT COUNT(*) FROM conversation_messages
			     WHERE conversation_id = $1 AND direction = $2 AND created_at > $3)
			 + (SELECT COUNT(*) FROM agent_actions
			     WHERE conversation_id = $1 AND status IN ($4, $5)
			       AND send_random_id IS NOT NULL AND updated_at > $3)`,
			action.ConversationID, DirectionAgentOutgoing, rateWindowStart, ActionExecuting, ActionDenied,
		).Scan(&recent); err != nil {
			return false, fmt.Errorf("count reserved agent sends: %w", err)
		}
		if recent >= maxMsgsPerMinute {
			return false, fmt.Errorf("%w: messages per minute %d/%d", ErrAgentSendBudgetExhausted, recent, maxMsgsPerMinute)
		}
	}

	now := time.Now().UTC()
	res, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, send_random_id = $2, send_body_encrypted = $3, updated_at = $4
		  WHERE id = $5 AND user_id = $6 AND conversation_id = $7 AND status = $8`,
		ActionExecuting, randomID, sendBody, now, action.ID, action.UserID, action.ConversationID, ActionApproved,
	)
	if err != nil {
		return false, fmt.Errorf("claim agent action send: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE conversations
		    SET autonomous_turns = autonomous_turns + 1, updated_at = $1
		  WHERE id = $2 AND user_id = $3`,
		now, action.ConversationID, action.UserID,
	); err != nil {
		return false, fmt.Errorf("reserve autonomous turn: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit send reservation: %w", err)
	}
	return true, nil
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

// RecordAgentActionSent atomically does everything a successful executor
// send needs recorded: flips the action executing -> executed (the same CAS
// SetAgentActionExecuted performs), updates the conversation's last-send
// timestamp, and inserts the outgoing conversation_messages row — all in ONE
// transaction. The autonomous turn was already reserved by
// ReserveAgentActionSend before the RPC. Returns ok=false, exactly like
// SetAgentActionExecuted, when the CAS finds the row already out of
// `executing` (a concurrent sweep/call already recorded it); in that case
// no other write in this function happens either, matching the executor's
// existing "don't double-count a completion someone else already recorded"
// rule.
//
// The conversation row is locked before the action transition. Reservation
// claims use the same lock order, so there is no visibility gap where a new
// claim can observe neither the executing reservation nor the completed
// history row.
func (s *Store) RecordAgentActionSent(ctx context.Context, userID, actionID, conversationID, tgMessageID int64, sentText string) (bool, error) {
	pg := s.isPostgres(ctx)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin record-sent tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	lock := ""
	if pg {
		lock = " FOR UPDATE"
	}
	if err := tx.QueryRowContext(ctx,
		`SELECT id FROM conversations WHERE id = $1 AND user_id = $2`+lock,
		conversationID, userID,
	).Scan(new(int64)); errors.Is(err, sql.ErrNoRows) {
		return false, ErrConversationNotFound
	} else if err != nil {
		return false, fmt.Errorf("lock conversation for send completion: %w", err)
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, executed_tg_message_id = $2, approval_code = NULL,
		        send_body_encrypted = NULL, updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		ActionExecuted, tgMessageID, time.Now().UTC(), actionID, userID, ActionExecuting,
	)
	if err != nil {
		return false, fmt.Errorf("set action executed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return false, nil
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx,
		`UPDATE conversations
		    SET last_agent_reply_at = $1, updated_at = $1
		  WHERE id = $2 AND user_id = $3`,
		now, conversationID, userID,
	); err != nil {
		return false, fmt.Errorf("record last agent reply: %w", err)
	}

	var body []byte
	if sentText != "" {
		body, err = s.Crypt.SealForUser([]byte(sentText), userID)
		if err != nil {
			return false, fmt.Errorf("seal message body: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO conversation_messages(conversation_id, direction, tg_message_id, body_encrypted)
		 VALUES($1,$2,$3,$4)`,
		conversationID, DirectionAgentOutgoing, tgMessageID, body,
	); err != nil {
		return false, fmt.Errorf("insert conversation message: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit record-sent tx: %w", err)
	}
	return true, nil
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

// ExpireAgentActionIfStale is ExpireStaleAgentActions' single-row
// counterpart: the same pending_approval -> expired transition and cutoff
// logic, scoped by id/user instead of a bulk time-based scan. Returns
// ok=true when this call is what actually expired the row.
//
// A Codex finding on #307 caught that Executor.Approve had no TTL check of
// its own at all — the bulk sweeper runs on its own minute-scale interval
// (or could simply be failing), so an owner typing /mctl approve on a code
// that is already past AGENT_APPROVAL_TTL but hasn't been swept YET would
// still succeed, sending an already-stale draft. pending_approval->expired
// is deliberately absent from allowedActionTransitions (see its own doc
// comment) — this is the dedicated method that transition needs, mirroring
// SetAgentActionExecuted/BeginExecutingAgentAction's precedent for
// transitions with their own preconditions beyond a bare status match.
func (s *Store) ExpireAgentActionIfStale(ctx context.Context, userID, id int64, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, nil
	}
	cutoff := time.Now().UTC().Add(-ttl)
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions SET status = $1, approval_code = NULL, updated_at = $2
		  WHERE id = $3 AND user_id = $4 AND status = $5 AND updated_at < $6`,
		ActionExpired, time.Now().UTC(), id, userID, ActionPendingApproval, cutoff,
	)
	if err != nil {
		return false, fmt.Errorf("expire agent action if stale: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListStuckExecutingActions returns actions stuck in executing whose
// updated_at is older than grace, for the executor's crash-recovery sweep.
// System-wide (no user scoping) and unordered beyond updated_at, matching
// RequeueStaleAgentJobs' sweep pattern — grace exists so the sweep never
// races a send that is still genuinely in flight in the current process
// (BeginExecutingAgentAction stamps updated_at right before the RPC).
func (s *Store) ListStuckExecutingActions(ctx context.Context, grace time.Duration) ([]AgentAction, error) {
	cutoff := time.Now().UTC().Add(-grace)
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, approval_code, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at
		   FROM agent_actions WHERE status = $1 AND updated_at < $2`,
		ActionExecuting, cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("list stuck executing actions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AgentAction
	for rows.Next() {
		var (
			a                 AgentAction
			code              sql.NullString
			jobID, convID     sql.NullInt64
			execMsgID         sql.NullInt64
			sendRandomID      sql.NullInt64
			payload, sendBody []byte
		)
		if err := rows.Scan(&a.ID, &code, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
			&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
			&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan stuck action: %w", err)
		}
		a.ApprovalCode = code.String
		a.JobID = jobID.Int64
		a.ConversationID = convID.Int64
		a.ExecutedTGMessageID = execMsgID.Int64
		a.SendRandomID = sendRandomID.Int64
		if len(payload) > 0 {
			pt, err := s.Crypt.OpenForUser(payload, a.UserID)
			if err != nil {
				// Same isolation reasoning as ListActionsByStatus: one
				// undecryptable stuck row must not block RecoverStuck's sweep
				// from retrying every other tenant's genuinely-crashed send.
				slog.Warn("agent_actions: skipping stuck row with undecryptable payload", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.Payload = string(pt)
		}
		if len(sendBody) > 0 {
			pt, err := s.Crypt.OpenForUser(sendBody, a.UserID)
			if err != nil {
				slog.Warn("agent_actions: skipping stuck row with undecryptable send body", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.SendBody = string(pt)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DenyPendingActionsForConversation transitions every non-terminal,
// non-executing action of a conversation to denied. Used when the source
// message an action was derived from is edited — a draft built from text the
// sender has since changed must not go out unchanged. Actions already
// `executing` are deliberately left alone: the send may already be in
// flight and cannot be safely recalled. Returns the number of rows flipped.
func (s *Store) DenyPendingActionsForConversation(ctx context.Context, userID, conversationID int64, reason string) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, policy_reasons = $2, updated_at = $3
		  WHERE user_id = $4 AND conversation_id = $5
		    AND status IN ($6, $7, $8)`,
		ActionDenied, reason, time.Now().UTC(), userID, conversationID,
		ActionProposed, ActionPendingApproval, ActionApproved,
	)
	if err != nil {
		return 0, fmt.Errorf("deny pending actions for conversation: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListActionsByStatus returns up to limit actions in the given status,
// oldest first, system-wide (no user scoping) — the executor's
// ProcessApproved sweep uses it to pick up guarded-mode auto-approved
// actions the same way RequeueStaleAgentJobs/ExpireStaleAgentActions sweep
// other tables.
func (s *Store) ListActionsByStatus(ctx context.Context, status string, limit int) ([]AgentAction, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, approval_code, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at
		   FROM agent_actions WHERE status = $1 ORDER BY updated_at LIMIT $2`,
		status, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list actions by status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AgentAction
	for rows.Next() {
		var (
			a                 AgentAction
			code              sql.NullString
			jobID, convID     sql.NullInt64
			execMsgID         sql.NullInt64
			sendRandomID      sql.NullInt64
			payload, sendBody []byte
		)
		if err := rows.Scan(&a.ID, &code, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
			&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
			&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan action: %w", err)
		}
		a.ApprovalCode = code.String
		a.JobID = jobID.Int64
		a.ConversationID = convID.Int64
		a.ExecutedTGMessageID = execMsgID.Int64
		a.SendRandomID = sendRandomID.Int64
		if len(payload) > 0 {
			pt, err := s.Crypt.OpenForUser(payload, a.UserID)
			if err != nil {
				// A single row's ciphertext failing to open (corruption, a key
				// rotation gap) must not block every other tenant's approved
				// action behind it — ProcessApproved always re-queries this
				// same oldest-first list, so an unskipped bad row would sit at
				// the front of every sweep forever. Quarantine just this row;
				// it stays in `approved`/`executing` untouched and can be
				// investigated separately.
				slog.Warn("agent_actions: skipping row with undecryptable payload", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.Payload = string(pt)
		}
		if len(sendBody) > 0 {
			pt, err := s.Crypt.OpenForUser(sendBody, a.UserID)
			if err != nil {
				slog.Warn("agent_actions: skipping row with undecryptable send body", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.SendBody = string(pt)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// HasAgentActionForJob reports whether at least one agent_actions row exists
// for the given job, scoped to the owning user. Used by the agent API's
// POST /jobs/{id}/complete to enforce that a job can only be marked
// completed once its result has actually been persisted — completion is not
// a bare acknowledgement from the worker's local invocation.
func (s *Store) HasAgentActionForJob(ctx context.Context, userID, jobID int64) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM agent_actions WHERE job_id = $1 AND user_id = $2)`,
		jobID, userID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check agent action for job: %w", err)
	}
	return exists, nil
}

// HasJobLeadForJob reports whether a job_leads row is tagged with the given
// job, scoped to the owning user — the job_leads-side counterpart to
// HasAgentActionForJob. A job whose only durable output was a lead save
// (rather than a proposed reply or owner notification) must still be
// completable; POST /jobs/{id}/complete checks both before accepting
// status=completed.
func (s *Store) HasJobLeadForJob(ctx context.Context, userID, jobID int64) (bool, error) {
	var exists bool
	err := s.DB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM job_leads WHERE job_id = $1 AND user_id = $2)`,
		jobID, userID,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check job lead for job: %w", err)
	}
	return exists, nil
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
	JobID          int64 // 0 ⇒ not tied to a specific queue job (e.g. a manual/backfilled save)
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
		   (user_id, conversation_id, job_id, company, role, recruiter_name, recruiter_tg_id,
		    compensation, status, detail, updated_at)
		 VALUES($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,'new'),$10,$11)
		 ON CONFLICT (conversation_id) DO UPDATE SET
		   job_id = CASE WHEN EXCLUDED.job_id IS NOT NULL THEN EXCLUDED.job_id ELSE job_leads.job_id END,
		   company = CASE WHEN EXCLUDED.company IS NOT NULL THEN EXCLUDED.company ELSE job_leads.company END,
		   role = CASE WHEN EXCLUDED.role IS NOT NULL THEN EXCLUDED.role ELSE job_leads.role END,
		   recruiter_name = CASE WHEN EXCLUDED.recruiter_name IS NOT NULL THEN EXCLUDED.recruiter_name ELSE job_leads.recruiter_name END,
		   recruiter_tg_id = CASE WHEN EXCLUDED.recruiter_tg_id IS NOT NULL THEN EXCLUDED.recruiter_tg_id ELSE job_leads.recruiter_tg_id END,
		   compensation = CASE WHEN EXCLUDED.compensation IS NOT NULL THEN EXCLUDED.compensation ELSE job_leads.compensation END,
		   status = COALESCE($9, job_leads.status),
		   detail = CASE WHEN EXCLUDED.detail <> '{}' THEN EXCLUDED.detail ELSE job_leads.detail END,
		   updated_at = EXCLUDED.updated_at
		 WHERE job_leads.user_id = EXCLUDED.user_id
		 RETURNING id`,
		l.UserID, l.ConversationID, nullableInt(l.JobID), nullable(l.Company), nullable(l.Role),
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

// ListPendingOwnerNotifications returns up to limit pending notifications,
// oldest first, system-wide (no user scoping) — the control.Notifier's
// delivery sweep uses it the same way other background loops in this
// codebase scan across accounts (RequeueStaleAgentJobs,
// ExpireStaleAgentActions), since the caller already has to resolve a
// per-user Telegram client to actually deliver each one regardless.
//
// Currently-leased rows (claimed_until in the future — see
// ClaimOwnerNotification) are excluded: a Codex finding on #307 caught that
// without this, a batch of permanently-failing notifications (e.g. all
// belonging to one account with a revoked session) would occupy the same
// oldest-50 slots on every sweep even while their claim was active and
// therefore certain to be skipped again, wasting the whole batch on rows
// DeliverPending cannot act on instead of reaching healthy accounts' newer,
// deliverable notifications ranked just past position 50.
func (s *Store) ListPendingOwnerNotifications(ctx context.Context, limit int) ([]OwnerNotification, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, user_id, kind, action_id, body_encrypted, status, tg_message_id, sent_at, created_at
		   FROM owner_notifications
		  WHERE status = $1 AND (claimed_until IS NULL OR claimed_until < $2)
		  ORDER BY created_at LIMIT $3`,
		NotificationPending, time.Now().UTC(), limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list pending owner notifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []OwnerNotification
	for rows.Next() {
		var (
			n           OwnerNotification
			actionID    sql.NullInt64
			body        []byte
			tgMessageID sql.NullInt64
			sentAt      sql.NullTime
		)
		if err := rows.Scan(&n.ID, &n.UserID, &n.Kind, &actionID, &body, &n.Status, &tgMessageID, &sentAt, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan owner notification: %w", err)
		}
		n.ActionID = actionID.Int64
		n.TGMessageID = tgMessageID.Int64
		if sentAt.Valid {
			n.SentAt = sentAt.Time
		}
		if len(body) > 0 {
			pt, err := s.Crypt.OpenForUser(body, n.UserID)
			if err != nil {
				// Same isolation reasoning as ListActionsByStatus: one
				// undecryptable notification must not block DeliverPending's
				// sweep from reaching every other tenant's deliverable
				// summaries/approval requests behind it.
				slog.Warn("owner_notifications: skipping row with undecryptable body", "notification_id", n.ID, "user_id", n.UserID, "err", err)
				continue
			}
			n.Body = string(pt)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// InsertOwnerNotification persists a pending notification and returns its
// id. Idempotent per action_id (when non-zero): a job that redelivers after
// its action insert already resolved via the (job_id, action_type)
// idempotency conflict must not queue a second copy of the same owner
// summary/approval on this call too — the unique partial index on
// (action_id) WHERE action_id IS NOT NULL makes the second insert a no-op
// that returns the EXISTING row's id, mirroring InsertAgentAction's own
// (job_id, action_type) conflict handling. Standalone notifications
// (ActionID == 0) are unaffected — they always insert a new row.
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
	err := s.DB.QueryRowContext(ctx,
		`INSERT INTO owner_notifications(user_id, kind, action_id, body_encrypted, status)
		 VALUES($1,$2,$3,$4,$5)
		 ON CONFLICT (action_id) WHERE action_id IS NOT NULL DO NOTHING
		 RETURNING id`,
		n.UserID, n.Kind, actionID, body, NotificationPending,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		if n.ActionID == 0 {
			// Should be unreachable (no index on NULL action_id to conflict
			// against), but never silently swallow an unexpected empty result.
			return 0, fmt.Errorf("insert owner notification: unexpected empty result for standalone notification")
		}
		lookupErr := s.DB.QueryRowContext(ctx,
			`SELECT id FROM owner_notifications WHERE user_id = $1 AND action_id = $2`,
			n.UserID, n.ActionID,
		).Scan(&id)
		if lookupErr != nil {
			return 0, fmt.Errorf("load existing owner notification: %w", lookupErr)
		}
		return id, nil
	}
	if err != nil {
		return 0, fmt.Errorf("insert owner notification: %w", err)
	}
	return id, nil
}

// ClaimOwnerNotification atomically leases a pending notification for
// delivery, so two replicas (or two overlapping sweep ticks in the same
// process) racing on the same row returned by ListPendingOwnerNotifications
// cannot both call SendToSelf for it — only the caller whose UPDATE actually
// matches a row wins the lease and should proceed to send.
//
// A lease (claimed_until), not a status transition: a claim that is never
// released (the process crashes between winning it and calling
// MarkOwnerNotificationSent/Failed) simply expires and becomes claimable
// again on a later sweep, rather than leaving the row permanently invisible
// to every future ListPendingOwnerNotifications scan the way moving it to a
// dedicated "sending" status would without a separate stuck-row sweep. This
// mirrors the visibility-timeout pattern ClaimAgentJobs already uses.
//
// Also persists (or, on a retry, reuses) a Telegram send random_id in the
// SAME atomic UPDATE, mirroring BeginExecutingAgentAction's crash-safety
// pattern for executor sends — a Codex finding on #307 caught that the
// claim lease alone only protects against two REPLICAS racing the same row
// concurrently; it does nothing for a single replica that crashes AFTER
// SendToSelf reaches Telegram but BEFORE MarkOwnerNotificationSent commits.
// Without a persisted id, the retry (once the lease expires) would call
// SendToSelf again with a FRESH random_id — Telegram has no way to dedup
// that against the first, genuinely-delivered send. candidateRandomID is a
// freshly-generated id the caller offers for THIS attempt; COALESCE only
// applies it when the row has no random_id yet, so a retry that finds one
// already persisted reuses that exact same value instead.
func (s *Store) ClaimOwnerNotification(ctx context.Context, userID, id, candidateRandomID int64, lease time.Duration) (randomID int64, claimed bool, err error) {
	if candidateRandomID == 0 {
		return 0, false, errors.New("candidate random id required")
	}
	now := time.Now().UTC()
	err = s.DB.QueryRowContext(ctx,
		`UPDATE owner_notifications
		    SET claimed_until = $1, random_id = COALESCE(random_id, $2)
		  WHERE id = $3 AND user_id = $4 AND status = $5
		    AND (claimed_until IS NULL OR claimed_until < $6)
		RETURNING random_id`,
		now.Add(lease), candidateRandomID, id, userID, NotificationPending, now,
	).Scan(&randomID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("claim owner notification: %w", err)
	}
	return randomID, true, nil
}

// MarkOwnerNotificationSent records a successful Saved Messages delivery.
// Compare-and-set from pending: a notification is delivered at most once, so
// only a still-pending row transitions. Returns ErrOwnerNotificationNotFound
// when no pending (id, user) row matches — including the case where a
// concurrent attempt already marked it sent or failed, so a late/duplicate
// call can never overwrite a terminal delivery state.
func (s *Store) MarkOwnerNotificationSent(ctx context.Context, userID, id, tgMessageID int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET status = $1, tg_message_id = $2, sent_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		NotificationSent, tgMessageID, time.Now().UTC(), id, userID, NotificationPending,
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
// Compare-and-set from pending, matching MarkOwnerNotificationSent: a row that
// another attempt already marked sent must NOT be flipped to failed by a
// racing/late failure report.
func (s *Store) MarkOwnerNotificationFailed(ctx context.Context, userID, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE owner_notifications SET status = $1 WHERE id = $2 AND user_id = $3 AND status = $4`,
		NotificationFailed, id, userID, NotificationPending,
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
