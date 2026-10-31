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
//	executing → delivery_unknown → (executed, once the echo proves delivery)
//
// delivery_unknown (#1029) is where a send ends when its outcome cannot be
// observed: recovery retries ran out, or recovery was refused by policy
// after at least one RPC had already been attempted. It is neither success
// nor failure. Nothing retries it, the owner is told once, and the only way
// out is the listener seeing the send's own echo, which proves delivery.
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
	// ActionDeliveryUnknown: the send may or may not have reached Telegram
	// and will not be retried. See the lifecycle comment above.
	ActionDeliveryUnknown = "delivery_unknown"
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
// short code the owner types in Saved Messages (/mctl approve <code>). At
// rest it is stored as a lookup hash plus per-user ciphertext, never plaintext.
type AgentAction struct {
	ID           int64
	ApprovalCode string
	JobID        int64 // agent_jobs.id; 0 ⇒ not tied to a queue job
	// Attempt must match the job's currently claimed attempt when JobID != 0
	// — see InsertAgentAction's doc comment. Ignored when JobID == 0.
	Attempt             int
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
	// SendAttempts counts the send RPCs issued for this action, stamped
	// before each RPC (#1029). Zero on an executing row means no RPC was
	// ever attempted, so a refusal at recovery is a plain denial; above zero
	// the outcome of an earlier attempt is unknown.
	SendAttempts int
	CreatedAt    time.Time
	UpdatedAt    time.Time
	// InstallRevision is the install revision the action was created under:
	// its job's, or the profile's for an action without a job (#1018).
	InstallRevision int64
}

const approvalCodeBlindIndexPurpose = "agent-approval-code"

func (s *Store) approvalCodeHash(code string, userID int64) ([]byte, error) {
	if code == "" {
		return nil, nil
	}
	return s.Crypt.BlindIndexForUser(approvalCodeBlindIndexPurpose, []byte(code), userID)
}

func (s *Store) protectApprovalCode(code string, userID int64) (hash, encrypted []byte, err error) {
	if code == "" {
		return nil, nil, nil
	}
	hash, err = s.approvalCodeHash(code, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("hash approval code: %w", err)
	}
	encrypted, err = s.Crypt.SealForUser([]byte(code), userID)
	if err != nil {
		return nil, nil, fmt.Errorf("seal approval code: %w", err)
	}
	return hash, encrypted, nil
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
// A job-tied action also requires its job to still exist AND still be
// processing under a.Attempt (returns ErrAgentJobNotFound otherwise), which
// keeps a racing worker from recreating encrypted action data after
// HardDeleteAccount's purge — see the insert statement's comment — and closes
// a second race: if CompleteJob commits on the server but its HTTP response
// never reaches the caller, the caller's local completed-guard never fires,
// so it can still issue another action call afterward. Gating the INSERT's
// source SELECT on the job's live status/attempt (the same compare-and-set
// shape CompleteAgentJob/RetryAgentJob already use) means that later call
// finds no matching job row and is rejected, even though the caller believes
// the job is still open.
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
	codeHash, codeEncrypted, err := s.protectApprovalCode(a.ApprovalCode, a.UserID)
	if err != nil {
		return 0, err
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
		tx, txErr := s.DB.BeginTx(ctx, nil)
		if txErr != nil {
			return 0, fmt.Errorf("begin agent action tx: %w", txErr)
		}
		defer func() { _ = tx.Rollback() }()
		err = tx.QueryRowContext(ctx,
			`INSERT INTO agent_actions
			   (approval_code_hash, approval_code_encrypted, job_id, conversation_id,
			    user_id, action_type, intent, payload_encrypted, policy_decision,
			    policy_reasons, status, install_revision)
			 SELECT $1, $2, j.id, $4, $5, $6, $7, $8, $9, $10, $11, j.install_revision
			   FROM agent_jobs j
			  WHERE j.id = $3 AND j.user_id = $5 AND j.status = $12 AND j.attempts = $13`+lock+`
			 ON CONFLICT (job_id, action_type) WHERE job_id IS NOT NULL DO NOTHING
			 RETURNING id`,
			codeHash, codeEncrypted, a.JobID, convID, a.UserID, a.ActionType, a.Intent,
			payload, a.PolicyDecision, a.PolicyReasons, a.Status, JobProcessing, a.Attempt,
		).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			// Two ways to land here: a redelivery hit the (job_id, action_type)
			// unique index — the action exists, return it with its ORIGINAL
			// approval_code (looked up without an attempt filter: idempotent
			// redelivery after a crash re-claims the job under a NEW attempt,
			// and the existing row from the original attempt must still be
			// returned, not treated as missing) — or the source SELECT found no
			// job matching both id/user AND the live status+attempt gate (purged
			// account, foreign/bogus id, or a stale/completed attempt) and the
			// job must be reported gone.
			lookupErr := tx.QueryRowContext(ctx,
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
		if err == nil {
			// Operator routing: a job-tied propose_reply that the policy
			// denied or parked for approval is forwarded to the operator in
			// the same transaction that records the decision.
			var reason string
			if a.ActionType == ActionTypeReply {
				switch a.Status {
				case ActionDenied:
					reason = RoutePolicyDeny
				case ActionPendingApproval:
					reason = RoutePolicyRequireApproval
				}
			}
			var routed bool
			if reason != "" {
				if routed, err = s.routeJobEventTx(ctx, tx, a.JobID, reason); err != nil {
					return 0, err
				}
			}
			if err := tx.Commit(); err != nil {
				return 0, fmt.Errorf("commit agent action: %w", err)
			}
			s.notifyOutbox(routed)
		}
	} else {
		err = s.DB.QueryRowContext(ctx,
			`INSERT INTO agent_actions
			   (approval_code_hash, approval_code_encrypted, job_id, conversation_id,
			    user_id, action_type, intent, payload_encrypted, policy_decision,
			    policy_reasons, status, install_revision)
			 VALUES($1,$2,NULL,$3,$4,$5,$6,$7,$8,$9,$10,
			        COALESCE((SELECT install_revision FROM agent_profiles WHERE user_id = $4), 1))
			 RETURNING id`,
			codeHash, codeEncrypted, convID, a.UserID, a.ActionType, a.Intent,
			payload, a.PolicyDecision, a.PolicyReasons, a.Status,
		).Scan(&id)
	}
	if err != nil {
		return 0, fmt.Errorf("insert agent action: %w", err)
	}
	return id, nil
}

// InsertStandaloneApprovalWithNotification atomically creates a jobless
// pending-approval action and the Saved Messages notification that carries
// its approval code. A standalone proposal has no idempotency key, so
// inserting these rows separately cannot safely return an error after only
// the action commits: a caller retry would mint a second action/code. The
// transaction makes the pair all-or-nothing.
func (s *Store) InsertStandaloneApprovalWithNotification(ctx context.Context, a AgentAction, notificationBody string) (int64, error) {
	if a.JobID != 0 {
		return 0, errors.New("standalone approval action must not have a job id")
	}
	if a.UserID <= 0 || a.ConversationID <= 0 {
		return 0, errors.New("user id and conversation id required")
	}
	if a.ActionType == "" || a.PolicyDecision == "" {
		return 0, errors.New("action type and policy decision required")
	}
	if a.Status != ActionPendingApproval || a.ApprovalCode == "" {
		return 0, errors.New("pending approval status and approval code required")
	}
	if _, err := s.GetConversation(ctx, a.UserID, a.ConversationID); err != nil {
		return 0, err
	}
	payload, err := s.Crypt.SealForUser([]byte(a.Payload), a.UserID)
	if err != nil {
		return 0, fmt.Errorf("seal action payload: %w", err)
	}
	body, err := s.Crypt.SealForUser([]byte(notificationBody), a.UserID)
	if err != nil {
		return 0, fmt.Errorf("seal notification body: %w", err)
	}
	codeHash, codeEncrypted, err := s.protectApprovalCode(a.ApprovalCode, a.UserID)
	if err != nil {
		return 0, err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin standalone approval tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var id int64
	if err := tx.QueryRowContext(ctx,
		`INSERT INTO agent_actions
		   (approval_code_hash, approval_code_encrypted, job_id, conversation_id,
		    user_id, action_type, intent, payload_encrypted, policy_decision,
		    policy_reasons, status, install_revision)
		 VALUES($1,$2,NULL,$3,$4,$5,$6,$7,$8,$9,$10,
		        COALESCE((SELECT install_revision FROM agent_profiles WHERE user_id = $4), 1))
		 RETURNING id`,
		codeHash, codeEncrypted, a.ConversationID, a.UserID, a.ActionType, a.Intent,
		payload, a.PolicyDecision, a.PolicyReasons, a.Status,
	).Scan(&id); err != nil {
		return 0, fmt.Errorf("insert standalone approval action: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO owner_notifications(user_id, kind, action_id, body_encrypted, status)
		 VALUES($1,$2,$3,$4,$5)`,
		a.UserID, NotificationApproval, id, body, NotificationPending,
	); err != nil {
		return 0, fmt.Errorf("insert standalone approval notification: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit standalone approval: %w", err)
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
	hash, err := s.approvalCodeHash(code, userID)
	if err != nil {
		return nil, fmt.Errorf("hash approval code: %w", err)
	}
	return s.getAgentAction(ctx, `user_id = $1 AND approval_code_hash = $2`, userID, hash)
}

func (s *Store) getAgentAction(ctx context.Context, where string, args ...any) (*AgentAction, error) {
	var (
		a                 AgentAction
		jobID, convID     sql.NullInt64
		execMsgID         sql.NullInt64
		sendRandomID      sql.NullInt64
		codeEncrypted     []byte
		payload, sendBody []byte
	)
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, approval_code_encrypted, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at, install_revision,
		        send_attempts
		   FROM agent_actions WHERE `+where,
		args...,
	).Scan(&a.ID, &codeEncrypted, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
		&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
		&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt, &a.InstallRevision,
		&a.SendAttempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentActionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get agent action: %w", err)
	}
	a.JobID = jobID.Int64
	a.ConversationID = convID.Int64
	a.ExecutedTGMessageID = execMsgID.Int64
	a.SendRandomID = sendRandomID.Int64
	if len(codeEncrypted) > 0 {
		pt, err := s.Crypt.OpenForUser(codeEncrypted, a.UserID)
		if err != nil {
			return nil, fmt.Errorf("open approval code: %w", err)
		}
		a.ApprovalCode = string(pt)
	}
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
// a future action without colliding on the (user_id, approval_code_hash) unique
// index.
var terminalActionStatuses = map[string]struct{}{
	ActionExecuted: {}, ActionRejected: {}, ActionExpired: {}, ActionDenied: {},
	ActionDeliveryUnknown: {},
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
	ActionProposed: {ActionPendingApproval: {}, ActionDenied: {}, ActionApproved: {}},
	// pending_approval -> denied: a draft written under an earlier install
	// revision, refused at /mctl approve (#1018). The bulk deny sweeps
	// (DenyPendingActionsFor*) already move rows along this edge.
	ActionPendingApproval: {ActionApproved: {}, ActionRejected: {}, ActionDenied: {}},
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
			`UPDATE agent_actions
			    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
			        approval_code_encrypted = NULL, updated_at = $2
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

// DenyAgentAction moves an action from `from` to denied and records reason
// as its policy_reasons, compare-and-set like UpdateAgentActionStatus, so
// the audit row says why it was refused rather than keeping the reasons it
// was proposed with.
func (s *Store) DenyAgentAction(ctx context.Context, userID, id int64, from, reason string) (bool, error) {
	if tos, ok := allowedActionTransitions[from]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, ActionDenied)
	} else if _, ok := tos[ActionDenied]; !ok {
		return false, fmt.Errorf("%w: %s -> %s", ErrInvalidActionTransition, from, ActionDenied)
	}
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		ActionDenied, reason, time.Now().UTC(), id, userID, from,
	)
	if err != nil {
		return false, fmt.Errorf("deny action: %w", err)
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
			     WHERE conversation_id = $1 AND status IN ($4, $5, $6)
			       AND send_random_id IS NOT NULL AND updated_at > $3)`,
			action.ConversationID, DirectionAgentOutgoing, rateWindowStart, ActionExecuting, ActionDenied, ActionDeliveryUnknown,
		).Scan(&recent); err != nil {
			return false, fmt.Errorf("count reserved agent sends: %w", err)
		}
		if recent >= maxMsgsPerMinute {
			return false, fmt.Errorf("%w: messages per minute %d/%d", ErrAgentSendBudgetExhausted, recent, maxMsgsPerMinute)
		}
	}

	// Checked under the conversation lock, as the last step before the row
	// becomes executing: a source message edited or deleted at any point up
	// to here withdraws the draft, including one the owner approved (#949,
	// #950). Once the row is executing the send goes out; the window that
	// remains is the one between this commit and the Telegram RPC.
	if action.JobID != 0 {
		kind, err := jobSourceSuperseded(ctx, tx, action.UserID, action.JobID)
		if err != nil {
			return false, err
		}
		if kind != "" {
			return false, &SourceSupersededError{Kind: kind}
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
		    SET status = $1, executed_tg_message_id = $2, approval_code = NULL,
		        approval_code_hash = NULL, approval_code_encrypted = NULL, updated_at = $3
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
	return s.recordAgentActionSent(ctx, ActionExecuting, userID, actionID, conversationID, tgMessageID, sentText)
}

// recordAgentActionSent is RecordAgentActionSent with the status the action
// must leave from: executing for a send that returned, delivery_unknown for
// a send whose echo later proved it was delivered (#1029).
func (s *Store) recordAgentActionSent(ctx context.Context, from string, userID, actionID, conversationID, tgMessageID int64, sentText string) (bool, error) {
	// tgMessageID 0 means delivered with an unknown message id (a recovery
	// retry answered RANDOM_ID_DUPLICATE, #1029). Store NULL, never a fake 0.
	// The exact send body is then kept: it is the only way the listener can
	// still recognise the send's echo and fill in the id
	// (MatchUnconfirmedAgentSend). The retention sweep clears it later.
	msgID := sql.NullInt64{Int64: tgMessageID, Valid: tgMessageID != 0}
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
	if !msgID.Valid {
		// The listener may already have matched the send's echo while the
		// row was still executing and noted the id there.
		var noted sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT executed_tg_message_id FROM agent_actions WHERE id = $1 AND user_id = $2 AND status = $3`,
			actionID, userID, from,
		).Scan(&noted); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("read noted message id: %w", err)
		}
		if noted.Valid && noted.Int64 != 0 {
			msgID = noted
		}
	}
	clearSendBody := "send_body_encrypted = NULL, "
	if !msgID.Valid {
		clearSendBody = ""
	}

	res, err := tx.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, executed_tg_message_id = $2, approval_code = NULL,
		        approval_code_hash = NULL, approval_code_encrypted = NULL,
		        `+clearSendBody+`updated_at = $3
		  WHERE id = $4 AND user_id = $5 AND status = $6`,
		ActionExecuted, msgID, time.Now().UTC(), actionID, userID, from,
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
	// An owner-approved reply that reached Telegram is an owner engagement
	// event (#953). Only the executed transition counts, and it commits
	// with it: an approval whose send fails never engages the conversation.
	var decision string
	if err := tx.QueryRowContext(ctx,
		`SELECT policy_decision FROM agent_actions WHERE id = $1 AND user_id = $2`,
		actionID, userID,
	).Scan(&decision); err != nil {
		return false, fmt.Errorf("read executed action decision: %w", err)
	}
	if decision == PolicyRequireApproval {
		if _, err := tx.ExecContext(ctx,
			`UPDATE conversations SET owner_engaged_at = $1
			  WHERE id = $2 AND user_id = $3
			    AND (owner_engaged_at IS NULL OR owner_engaged_at < $1)`,
			now, conversationID, userID,
		); err != nil {
			return false, fmt.Errorf("record owner engagement: %w", err)
		}
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
		conversationID, DirectionAgentOutgoing, msgID, body,
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
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, updated_at = $2
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
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, updated_at = $2
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
		`SELECT id, approval_code_encrypted, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at, install_revision,
		        send_attempts
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
			jobID, convID     sql.NullInt64
			execMsgID         sql.NullInt64
			sendRandomID      sql.NullInt64
			codeEncrypted     []byte
			payload, sendBody []byte
		)
		if err := rows.Scan(&a.ID, &codeEncrypted, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
			&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
			&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt, &a.InstallRevision,
			&a.SendAttempts); err != nil {
			return nil, fmt.Errorf("scan stuck action: %w", err)
		}
		a.JobID = jobID.Int64
		a.ConversationID = convID.Int64
		a.ExecutedTGMessageID = execMsgID.Int64
		a.SendRandomID = sendRandomID.Int64
		if len(codeEncrypted) > 0 {
			pt, err := s.Crypt.OpenForUser(codeEncrypted, a.UserID)
			if err != nil {
				slog.Warn("agent_actions: skipping stuck row with undecryptable approval code", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.ApprovalCode = string(pt)
		}
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
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
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

// DenyPendingActionsForSourceMessage invalidates only drafts derived from a
// particular Telegram message (including drafts produced from earlier edits
// of that same message id). Other messages in the conversation may have
// independent, still-current drafts and must not be cancelled. A message
// coalesced into another job's turn denies the head job's drafts, since
// actions are written under the head (#950).
func (s *Store) DenyPendingActionsForSourceMessage(ctx context.Context, userID, conversationID, sourceMessageID int64, reason string) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
		  WHERE user_id = $4 AND conversation_id = $5
		    AND status IN ($6, $7, $8)
		    AND job_id IN (
		        SELECT `+jobHeadExpr+`
		          FROM agent_jobs j
		          JOIN incoming_events e
		            ON e.event_id = j.event_id AND e.user_id = j.user_id
		         WHERE j.user_id = $4 AND j.conversation_id = $5
		           AND e.message_id = $9
		    )`,
		ActionDenied, reason, time.Now().UTC(), userID, conversationID,
		ActionProposed, ActionPendingApproval, ActionApproved, sourceMessageID,
	)
	if err != nil {
		return 0, fmt.Errorf("deny pending actions for source message: %w", err)
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
		`SELECT id, approval_code_encrypted, job_id, conversation_id, user_id, action_type, intent,
		        payload_encrypted, policy_decision, policy_reasons, status,
		        executed_tg_message_id, send_random_id, send_body_encrypted, created_at, updated_at, install_revision
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
			jobID, convID     sql.NullInt64
			execMsgID         sql.NullInt64
			sendRandomID      sql.NullInt64
			codeEncrypted     []byte
			payload, sendBody []byte
		)
		if err := rows.Scan(&a.ID, &codeEncrypted, &jobID, &convID, &a.UserID, &a.ActionType, &a.Intent,
			&payload, &a.PolicyDecision, &a.PolicyReasons, &a.Status,
			&execMsgID, &sendRandomID, &sendBody, &a.CreatedAt, &a.UpdatedAt, &a.InstallRevision); err != nil {
			return nil, fmt.Errorf("scan action: %w", err)
		}
		a.JobID = jobID.Int64
		a.ConversationID = convID.Int64
		a.ExecutedTGMessageID = execMsgID.Int64
		a.SendRandomID = sendRandomID.Int64
		if len(codeEncrypted) > 0 {
			pt, err := s.Crypt.OpenForUser(codeEncrypted, a.UserID)
			if err != nil {
				slog.Warn("agent_actions: skipping row with undecryptable approval code", "action_id", a.ID, "user_id", a.UserID, "err", err)
				continue
			}
			a.ApprovalCode = string(pt)
		}
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
	Attempt        int   // required live claim attempt when JobID != 0
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

// UpsertJobLead creates a lead or updates one and returns its id. A
// conversation holds any number of leads (#951): l.ID == 0 always inserts a
// new lead, and l.ID > 0 updates that lead, which must belong to l.UserID
// and to l.ConversationID (ErrJobLeadNotFound otherwise, so a caller can
// never write into a lead of another conversation or user). On an update
// only non-empty incoming fields overwrite existing values, so the agent can
// save partial extractions incrementally without erasing earlier answers —
// including Status: an empty status means "leave as is" ("new" on insert),
// so a metadata-only save can never reset a progressed lead.
//
// With l.JobID set, the job must be the caller's currently claimed attempt
// for this conversation (ErrAgentJobNotFound otherwise).
func (s *Store) UpsertJobLead(ctx context.Context, l JobLead) (int64, error) {
	if l.UserID <= 0 {
		return 0, errors.New("user id required")
	}
	if l.ConversationID <= 0 {
		return 0, errors.New("conversation id required")
	}
	if l.ID < 0 {
		return 0, ErrJobLeadNotFound
	}
	if _, err := s.GetConversation(ctx, l.UserID, l.ConversationID); err != nil {
		return 0, err
	}
	if l.Detail == "" {
		l.Detail = "{}"
	}
	var (
		id  int64
		err error
	)
	if l.ID == 0 {
		id, err = s.insertJobLead(ctx, l)
	} else {
		id, err = s.updateJobLead(ctx, l)
	}
	if err != nil {
		return 0, err
	}
	if l.JobID != 0 {
		// Preserve an immutable per-job association so a later save for
		// the same conversation cannot rewrite the historical result of
		// this job. A job that saves several leads keeps the last one, the
		// same lead the worker reports as the job's result.
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO agent_job_lead_results(job_id, user_id, lead_id)
			 VALUES($1,$2,$3)
			 ON CONFLICT (job_id) DO UPDATE SET lead_id = EXCLUDED.lead_id
			 WHERE agent_job_lead_results.user_id = EXCLUDED.user_id`,
			l.JobID, l.UserID, id,
		); err != nil {
			return 0, fmt.Errorf("bind job lead result: %w", err)
		}
	}
	return id, nil
}

func (s *Store) insertJobLead(ctx context.Context, l JobLead) (int64, error) {
	const insertLead = `INSERT INTO job_leads
	   (user_id, conversation_id, job_id, company, role, recruiter_name, recruiter_tg_id,
	    compensation, status, detail, updated_at)
	`
	args := []any{
		l.UserID, l.ConversationID, nullableInt(l.JobID), nullable(l.Company), nullable(l.Role),
		nullable(l.RecruiterName), nullableInt(l.RecruiterTGID),
		nullable(l.Compensation), nullable(l.Status), l.Detail, time.Now().UTC(),
	}
	var (
		id  int64
		err error
	)
	if l.JobID != 0 {
		lock, lockErr := s.leadJobLock(ctx)
		if lockErr != nil {
			return 0, lockErr
		}
		err = s.DB.QueryRowContext(ctx,
			insertLead+`
			 SELECT $1,$2,j.id,$4,$5,$6,$7,$8,COALESCE($9,'new'),$10,$11
			   FROM agent_jobs j
			  WHERE j.id=$3 AND j.user_id=$1 AND j.conversation_id=$2
			    AND j.status=$12 AND j.attempts=$13`+lock+`
			 RETURNING id`,
			append(args, JobProcessing, l.Attempt)...,
		).Scan(&id)
	} else {
		err = s.DB.QueryRowContext(ctx,
			insertLead+` VALUES($1,$2,$3,$4,$5,$6,$7,$8,COALESCE($9,'new'),$10,$11) RETURNING id`,
			args...,
		).Scan(&id)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrAgentJobNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("insert job lead: %w", err)
	}
	return id, nil
}

func (s *Store) updateJobLead(ctx context.Context, l JobLead) (int64, error) {
	// Resolve the lock before BeginTx: an uncached dialect probe goes through
	// s.DB, and on SQLite (one connection) it would wait on this transaction.
	var lock string
	if l.JobID != 0 {
		var err error
		if lock, err = s.leadJobLock(ctx); err != nil {
			return 0, err
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin lead update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if l.JobID != 0 {
		var one int
		err := tx.QueryRowContext(ctx,
			`SELECT 1 FROM agent_jobs
			  WHERE id=$1 AND user_id=$2 AND conversation_id=$3
			    AND status=$4 AND attempts=$5`+lock,
			l.JobID, l.UserID, l.ConversationID, JobProcessing, l.Attempt,
		).Scan(&one)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrAgentJobNotFound
		}
		if err != nil {
			return 0, fmt.Errorf("check lead job: %w", err)
		}
	}
	var id int64
	err = tx.QueryRowContext(ctx,
		`UPDATE job_leads SET
		   job_id = COALESCE($4, job_id),
		   company = COALESCE($5, company),
		   role = COALESCE($6, role),
		   recruiter_name = COALESCE($7, recruiter_name),
		   recruiter_tg_id = COALESCE($8, recruiter_tg_id),
		   compensation = COALESCE($9, compensation),
		   status = COALESCE($10, status),
		   detail = CASE WHEN $11 <> '{}' THEN $11 ELSE detail END,
		   updated_at = $12
		 WHERE id = $1 AND user_id = $2 AND conversation_id = $3
		 RETURNING id`,
		l.ID, l.UserID, l.ConversationID, nullableInt(l.JobID), nullable(l.Company), nullable(l.Role),
		nullable(l.RecruiterName), nullableInt(l.RecruiterTGID), nullable(l.Compensation),
		nullable(l.Status), l.Detail, time.Now().UTC(),
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrJobLeadNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("update job lead: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit lead update: %w", err)
	}
	return id, nil
}

// leadJobLock is the row lock a lead save takes on its job on Postgres, so
// the job cannot finish between the check and the write. SQLite serializes
// writers and has no FOR SHARE. An inconclusive dialect probe is an error,
// not "SQLite": that would silently drop the lock on a live Postgres.
func (s *Store) leadJobLock(ctx context.Context) (string, error) {
	pg, err := s.postgresDialect(ctx)
	if err != nil {
		return "", fmt.Errorf("lead job lock: %w", err)
	}
	if pg {
		return " FOR SHARE", nil
	}
	return "", nil
}

// GetJobLead returns a lead by id, scoped to the owning user.
func (s *Store) GetJobLead(ctx context.Context, userID, id int64) (*JobLead, error) {
	return s.getJobLead(ctx, `id = $1 AND user_id = $2`, id, userID)
}

// GetJobLeadByConversation returns the conversation's most recently updated
// lead, if any. A conversation can hold several (#951); see
// ListJobLeadsByConversation for all of them.
func (s *Store) GetJobLeadByConversation(ctx context.Context, userID, conversationID int64) (*JobLead, error) {
	return s.getJobLead(ctx, `conversation_id = $1 AND user_id = $2 ORDER BY updated_at DESC, id DESC LIMIT 1`, conversationID, userID)
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
	return s.listJobLeads(ctx, `user_id = $1 ORDER BY updated_at DESC, id DESC LIMIT $2`, userID, limit)
}

// ListJobLeadsByConversation returns a conversation's leads, most recently
// updated first (#951).
func (s *Store) ListJobLeadsByConversation(ctx context.Context, userID, conversationID int64, limit int) ([]JobLead, error) {
	if limit <= 0 {
		limit = 10
	}
	return s.listJobLeads(ctx,
		`user_id = $1 AND conversation_id = $2 ORDER BY updated_at DESC, id DESC LIMIT $3`,
		userID, conversationID, limit)
}

func (s *Store) listJobLeads(ctx context.Context, where string, args ...any) ([]JobLead, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, user_id, conversation_id, company, role, recruiter_name, recruiter_tg_id,
		        compensation, status, detail, created_at, updated_at
		   FROM job_leads WHERE `+where,
		args...,
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
	// NotificationHumanInput is issue-571's agent clarification request (and
	// its "no longer active" follow-up). Its body is pre-rendered at enqueue
	// time and passed through unchanged by the notifier.
	NotificationHumanInput = "human_input"

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

// HasOwnerNotificationSince reports whether userID already has a
// notification of the given kind created at or after `since`.
//
// It exists to bound a producer that is otherwise unbounded: an account left
// paused with its listener on is denied one reply per inbound message, and
// one alert per denial would queue rows without limit. That is not merely a
// nuisance for the owner — ListPendingOwnerNotifications drains the oldest
// 50 pending rows SYSTEM-WIDE, so one chatty paused account can push other
// accounts' approval-code notifications past position 50 and delay them.
// See that function's own doc comment for the earlier starvation finding of
// exactly this shape (agy/claude review on PR #582).
//
// Deliberately ignores status: pending, sent and failed rows all count. A
// row that failed delivery means the channel to that owner is down, so
// re-queueing sooner would not reach them either — and counting failures is
// what keeps the bound honest during exactly the outage it exists to
// protect against. Omitting the status filter is a choice, not an oversight.
func (s *Store) HasOwnerNotificationSince(ctx context.Context, userID int64, kind string, since time.Time) (bool, error) {
	if userID <= 0 {
		return false, errors.New("user id required")
	}
	var one int
	err := s.DB.QueryRowContext(ctx,
		`SELECT 1 FROM owner_notifications
		  WHERE user_id = $1 AND kind = $2 AND created_at >= $3
		  LIMIT 1`,
		userID, kind, since.UTC(),
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("has owner notification since: %w", err)
	}
	return true, nil
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

// HasExecutedOwnerSummarySince reports whether userID already has an
// executed send_owner_summary action with intent for conversationID (0 means
// one with no conversation) created at or after since. It throttles
// assistant-manipulation alerts (#953); suppressed alerts are never inserted
// as actions, so only alerts the owner was actually sent count.
func (s *Store) HasExecutedOwnerSummarySince(ctx context.Context, userID, conversationID int64, intent string, since time.Time) (bool, error) {
	if userID <= 0 {
		return false, errors.New("user id required")
	}
	convCond := `conversation_id = $5`
	args := []any{userID, ActionTypeOwnerSummary, intent, since.UTC(), conversationID, ActionExecuted}
	if conversationID == 0 {
		convCond = `conversation_id IS NULL AND $5 = 0`
	}
	var one int
	err := s.DB.QueryRowContext(ctx,
		`SELECT 1 FROM agent_actions
		  WHERE user_id = $1 AND action_type = $2 AND intent = $3 AND created_at >= $4
		    AND `+convCond+` AND status = $6
		  LIMIT 1`,
		args...,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("has executed owner summary since: %w", err)
	}
	return true, nil
}

// DenyActionsFromEarlierInstalls denies the proposed and approved actions
// of userID created under an install revision older than the account's
// current one (#1018). It is cleanup after an install change: the revision
// check at propose, approve and send is what keeps such work from acting,
// so a race with this sweep is harmless. Drafts awaiting the owner's
// approval are left alone on purpose: denying them here would release
// their codes, and /mctl approve would then answer "code not found"
// instead of saying the assistant changed. The approve-time check denies
// them with that explanation, and approval expiry clears the rest.
func (s *Store) DenyActionsFromEarlierInstalls(ctx context.Context, userID int64, reason string) (int64, error) {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE agent_actions
		    SET status = $1, approval_code = NULL, approval_code_hash = NULL,
		        approval_code_encrypted = NULL, policy_reasons = $2, updated_at = $3
		  WHERE user_id = $4
		    AND status IN ($5, $6)
		    AND install_revision < (SELECT install_revision FROM agent_profiles WHERE user_id = $4)`,
		ActionDenied, reason, time.Now().UTC(), userID,
		ActionProposed, ActionApproved,
	)
	if err != nil {
		return 0, fmt.Errorf("deny actions from earlier installs: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
