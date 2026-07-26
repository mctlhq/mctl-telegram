package agentapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// maxApprovalCodeAttempts bounds the retry loop on the astronomically rare
// (user_id, approval_code) unique-index collision (see approvalcode.go).
const maxApprovalCodeAttempts = 3

// loadProfile fetches the caller's agent profile or writes a 404. Every
// action-proposing endpoint requires one: a missing profile means the
// communication agent has never been enabled for this account, and there is
// no sane policy default to fall back to (in particular no Mode to evaluate
// against) — better to fail loudly here than to silently deny or allow.
func (s *Server) loadProfile(w http.ResponseWriter, ctx context.Context, userID int64) (*db.AgentProfile, bool) {
	p, err := s.Store.GetAgentProfile(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		writeJSONError(w, http.StatusNotFound, "agent profile not configured for this account")
		return nil, false
	}
	if err != nil {
		logHandlerErr("load_profile", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return nil, false
	}
	return p, true
}

// recentAgentSends returns the timestamps of this conversation's recent
// agent-sent messages, for the policy engine's per-minute rate check.
// Deliberately scoped to ONE conversation rather than the whole account: a
// per-conversation rate is a defensible product choice on its own (a burst
// answering one dialog vs. bursting across many are different risk
// profiles) — revisit if request_owner_approval/propose_reply need a true
// account-wide limit. Delegates to db.Store.ListRecentAgentOutgoingTimestamps
// (a Codex finding on #307 caught this used to fetch
// ListConversationMessages' top-50-of-any-direction page and filter it
// locally — 50+ newer messages of ANY direction could push a real agent
// send out of that fixed-size page entirely, silently undercounting the
// rate limit).
func (s *Server) recentAgentSends(ctx context.Context, userID, conversationID int64, since time.Time) ([]time.Time, error) {
	return s.Store.ListRecentAgentOutgoingTimestamps(ctx, userID, conversationID, since)
}

// isApprovalCodeCollision reports whether err looks like a violation of the
// (user_id, approval_code) unique index specifically — narrower than a bare
// "unique" substring match, which would also match the unrelated
// (job_id, action_type) index on the same table and mask its real error
// behind three pointless retries. Matches by driver-reported name rather
// than an errors.As type check against pgx/modernc so this package does not
// need to import either driver: Postgres names the index itself
// ("idx_agent_actions_code") in its error text; SQLite instead lists the
// column pair ("agent_actions.approval_code").
func isApprovalCodeCollision(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "idx_agent_actions_code") || strings.Contains(msg, "approval_code")
}

// insertActionWithApprovalCode wraps InsertAgentAction with the approval-code
// retry loop, used only for the pending_approval path (the other statuses
// carry no code).
func (s *Server) insertActionWithApprovalCode(ctx context.Context, a db.AgentAction) (int64, string, error) {
	for attempt := 0; attempt < maxApprovalCodeAttempts; attempt++ {
		code, err := newApprovalCode()
		if err != nil {
			return 0, "", err
		}
		a.ApprovalCode = code
		id, err := s.Store.InsertAgentAction(ctx, a)
		if err == nil {
			if a.JobID != 0 {
				// Job-tied inserts are idempotent on (job_id, action_type): a
				// redelivered job (worker crashed after propose_reply but
				// before completing it) hits that conflict and InsertAgentAction
				// silently returns the PRE-EXISTING row's id — with its
				// ORIGINAL approval_code, not the fresh `code` generated above.
				// Returning `code` here would tell the owner to type a string
				// that was never actually written to the row.
				existing, err := s.Store.GetAgentAction(ctx, a.UserID, id)
				if err != nil {
					return 0, "", err
				}
				return id, existing.ApprovalCode, nil
			}
			return id, code, nil
		}
		if isApprovalCodeCollision(err) {
			continue
		}
		return 0, "", err
	}
	return 0, "", errors.New("failed to allocate a unique approval code")
}

func (s *Server) insertStandaloneApprovalWithNotification(ctx context.Context, a db.AgentAction) (int64, string, error) {
	for attempt := 0; attempt < maxApprovalCodeAttempts; attempt++ {
		code, err := newApprovalCode()
		if err != nil {
			return 0, "", err
		}
		a.ApprovalCode = code
		id, err := s.Store.InsertStandaloneApprovalWithNotification(ctx, a, a.Payload)
		if err == nil {
			return id, code, nil
		}
		if isApprovalCodeCollision(err) {
			continue
		}
		return 0, "", err
	}
	return 0, "", errors.New("failed to allocate a unique approval code")
}

type proposeReplyRequest struct {
	ConversationID int64 `json:"conversation_id"`
	JobID          int64 `json:"job_id,omitempty"`
	// Attempt must match the job's currently claimed attempt (as returned by
	// POST /jobs/claim) when JobID is set; see InsertAgentAction's doc comment.
	Attempt int    `json:"attempt,omitempty"`
	Intent  string `json:"intent"`
	Text    string `json:"text"`
}

type actionResponse struct {
	ActionID     int64    `json:"action_id"`
	Decision     string   `json:"decision"`
	Reasons      []string `json:"reasons,omitempty"`
	Status       string   `json:"status"`
	ApprovalCode string   `json:"approval_code,omitempty"`
}

// handleProposeReply is POST /actions/propose_reply. There is deliberately no
// peer parameter in the request: the peer is derived server-side from the
// conversation row, so a caller can never direct a send anywhere the
// listener didn't already establish a conversation.
func (s *Server) handleProposeReply(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var req proposeReplyRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ConversationID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "conversation_id required")
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeJSONError(w, http.StatusBadRequest, "text required")
		return
	}

	ctx := r.Context()
	profile, ok := s.loadProfile(w, ctx, id.UserID)
	if !ok {
		return
	}
	conv, err := s.Store.GetConversation(ctx, id.UserID, req.ConversationID)
	if errors.Is(err, db.ErrConversationNotFound) {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if req.JobID != 0 {
		// The job and the conversation the caller pairs it with must actually
		// match — otherwise policy evaluates against the wrong conversation's
		// state/peer while HasAgentActionForJob still lets the (unrelated)
		// job complete, since the action row it checks is keyed on job_id
		// alone. GetAgentJob already scopes to id.UserID, so a foreign job_id
		// is rejected before this check ever runs.
		job, err := s.Store.GetAgentJob(ctx, id.UserID, req.JobID)
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusBadRequest, "job_id does not exist for this account")
			return
		}
		if err != nil {
			logHandlerErr("propose_reply", err)
			writeJSONError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		if job.ConversationID != req.ConversationID {
			writeJSONError(w, http.StatusBadRequest, "job_id does not belong to conversation_id")
			return
		}
	}
	sends, err := s.recentAgentSends(ctx, id.UserID, req.ConversationID, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	result := policy.Evaluate(policy.Input{
		Profile:      *profile,
		Conversation: *conv,
		Action: policy.Action{
			Type: db.ActionTypeReply, Intent: req.Intent, Text: req.Text, PeerTGID: conv.PeerTGID,
		},
		RecentAgentSends: sends,
		GlobalKill:       s.globalKill(),
		Now:              time.Now(),
	})

	base := db.AgentAction{
		JobID: req.JobID, Attempt: req.Attempt, ConversationID: req.ConversationID, UserID: id.UserID,
		ActionType: db.ActionTypeReply, Intent: req.Intent, Payload: req.Text,
		PolicyDecision: string(result.Decision), PolicyReasons: strings.Join(result.Reasons, "; "),
	}

	var actionID int64
	var approvalCode string
	notificationQueued := false
	switch result.Decision {
	case policy.Deny:
		base.Status = db.ActionDenied
		actionID, err = s.Store.InsertAgentAction(ctx, base)
	case policy.RequireApproval:
		base.Status = db.ActionPendingApproval
		if base.JobID == 0 {
			actionID, approvalCode, err = s.insertStandaloneApprovalWithNotification(ctx, base)
			notificationQueued = err == nil
		} else {
			actionID, approvalCode, err = s.insertActionWithApprovalCode(ctx, base)
		}
	default: // policy.Allow
		base.Status = db.ActionApproved
		actionID, err = s.Store.InsertAgentAction(ctx, base)
	}
	if errors.Is(err, db.ErrAgentJobNotFound) {
		if req.JobID != 0 {
			// req.JobID's existence/ownership was already confirmed above
			// (the GetAgentJob check ~30 lines up) — reaching this with
			// ErrAgentJobNotFound means InsertAgentAction's own live
			// status/attempt gate lost the race: the job completed (or was
			// reclaimed under a new attempt) between that check and this
			// insert. Same "too late" shape as handleJobComplete's own CAS
			// loss, so it gets the same 409, not the 400 a truly bogus
			// job_id gets.
			writeJSONError(w, http.StatusConflict, "job is no longer the active attempt for this account")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "job_id does not exist for this account")
		return
	}
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "propose failed")
		return
	}
	// InsertAgentAction is idempotent for job-tied actions and may have
	// returned a row created by an earlier attempt under a different policy
	// result. Drive notification and response handling from durable state,
	// not from this replay's freshly-evaluated `base`.
	persisted, err := s.Store.GetAgentAction(ctx, id.UserID, actionID)
	if err != nil {
		logHandlerErr("propose_reply", fmt.Errorf("reload persisted action: %w", err))
		writeJSONError(w, http.StatusInternalServerError, "propose failed")
		return
	}
	approvalCode = persisted.ApprovalCode
	if persisted.Status == db.ActionPendingApproval && !notificationQueued {
		// Idempotent per action_id (see InsertOwnerNotification's doc
		// comment) — a redelivered job that lands on the same existing
		// action via InsertAgentAction's (job_id, action_type) conflict
		// must not queue a second approval-request notification.
		// internal/agent/control.Notifier (A-PR7) delivers this to Saved
		// Messages.
		if _, nerr := s.Store.InsertOwnerNotification(ctx, db.OwnerNotification{
			UserID: id.UserID, Kind: db.NotificationApproval, ActionID: actionID, Body: req.Text,
		}); nerr != nil {
			logHandlerErr("propose_reply", fmt.Errorf("queue approval notification: %w", nerr))
			// A Codex finding on #307 caught that this used to be swallowed
			// as best-effort on the theory that "the owner can still
			// /mctl leads`/`/mctl show` to find it" — false: neither
			// command surfaces a pending action or its approval code (see
			// control.Router.handleLeads/handleShow), so a lost
			// notification was the ONLY path to ever deliver ApprovalCode
			// to the owner, and the draft would silently expire unapprovable.
			// Job-tied actions are safe to retry through their
			// (job_id, action_type) idempotency key. Standalone approval
			// actions never reach this branch: their action+notification pair
			// is committed atomically above.
			writeJSONError(w, http.StatusInternalServerError, "propose failed: could not queue approval notification")
			return
		}
	}
	s.audit(ctx, id.UserID, "propose_reply", "ok", "")
	responseReasons := result.Reasons
	if persisted.PolicyReasons != "" {
		responseReasons = strings.Split(persisted.PolicyReasons, "; ")
	}
	writeJSON(w, http.StatusOK, actionResponse{
		ActionID: actionID, Decision: persisted.PolicyDecision, Reasons: responseReasons,
		Status: persisted.Status, ApprovalCode: approvalCode,
	})
}

type saveLeadRequest struct {
	ConversationID int64  `json:"conversation_id"`
	JobID          int64  `json:"job_id,omitempty"`
	Attempt        int    `json:"attempt,omitempty"`
	Company        string `json:"company"`
	Role           string `json:"role"`
	RecruiterName  string `json:"recruiter_name"`
	RecruiterTGID  int64  `json:"recruiter_tg_id"`
	Compensation   string `json:"compensation"`
	Status         string `json:"status"`
	Detail         string `json:"detail"`
}

// handleSaveLead is POST /leads (save_job_lead). Upserts — the agent can save
// a partial extraction on every turn without erasing earlier answers, see
// UpsertJobLead's doc comment.
func (s *Server) handleSaveLead(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var req saveLeadRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.ConversationID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "conversation_id required")
		return
	}
	leadID, err := s.Store.UpsertJobLead(r.Context(), db.JobLead{
		UserID: id.UserID, ConversationID: req.ConversationID, JobID: req.JobID, Attempt: req.Attempt,
		Company: req.Company, Role: req.Role,
		RecruiterName: req.RecruiterName, RecruiterTGID: req.RecruiterTGID, Compensation: req.Compensation,
		Status: req.Status, Detail: req.Detail,
	})
	if errors.Is(err, db.ErrConversationNotFound) {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if errors.Is(err, db.ErrAgentJobNotFound) {
		writeJSONError(w, http.StatusConflict, "job is no longer the active attempt for this account")
		return
	}
	if err != nil {
		logHandlerErr("save_job_lead", err)
		writeJSONError(w, http.StatusInternalServerError, "save failed")
		return
	}
	s.audit(r.Context(), id.UserID, "save_job_lead", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"lead_id": leadID})
}

type ownerNotifyRequest struct {
	ConversationID int64 `json:"conversation_id,omitempty"`
	JobID          int64 `json:"job_id,omitempty"`
	// Attempt must match the job's currently claimed attempt when JobID is
	// set — see InsertAgentAction's doc comment.
	Attempt int    `json:"attempt,omitempty"`
	Intent  string `json:"intent,omitempty"`
	Text    string `json:"text"`
}

// handleRequestOwnerApproval is POST /actions/request_owner_approval. Unlike
// propose_reply, owner-facing action types always evaluate to Allow in the
// policy engine (they ask a human, they do not send anything themselves) —
// Evaluate still runs so the decision/reasons are recorded on the action row
// for audit, but the outcome is not in question.
func (s *Server) handleRequestOwnerApproval(w http.ResponseWriter, r *http.Request) {
	s.handleOwnerFacing(w, r, db.ActionTypeOwnerApproval, db.NotificationApproval, "request_owner_approval")
}

// handleNotifySummary is POST /notify/summary (send_owner_summary).
func (s *Server) handleNotifySummary(w http.ResponseWriter, r *http.Request) {
	s.handleOwnerFacing(w, r, db.ActionTypeOwnerSummary, db.NotificationSummary, "send_owner_summary")
}

func (s *Server) handleOwnerFacing(w http.ResponseWriter, r *http.Request, actionType, notificationKind, tool string) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var req ownerNotifyRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.Text) == "" {
		writeJSONError(w, http.StatusBadRequest, "text required")
		return
	}

	ctx := r.Context()
	profile, ok := s.loadProfile(w, ctx, id.UserID)
	if !ok {
		return
	}
	// Conversation.State is checked by Evaluate BEFORE the owner-facing
	// short-circuit (policy.go's switch on in.Conversation.State runs ahead
	// of the ActionTypeOwnerSummary/OwnerApproval branch), and its default
	// case denies any unrecognized state — including the empty string a
	// zero-value Conversation carries. A conversation-less owner-facing call
	// (req.ConversationID == 0, e.g. a general daily summary) must therefore
	// still present State: Active so it reaches that short-circuit at all;
	// policy_test.go's TestEvaluate_OwnerActionsAndPeerZero documents this
	// exact contract.
	conv := db.Conversation{State: db.ConversationActive}
	if req.ConversationID != 0 {
		c, err := s.Store.GetConversation(ctx, id.UserID, req.ConversationID)
		if errors.Is(err, db.ErrConversationNotFound) {
			writeJSONError(w, http.StatusNotFound, "conversation not found")
			return
		}
		if err != nil {
			logHandlerErr(tool, err)
			writeJSONError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		conv = *c
	}

	result := policy.Evaluate(policy.Input{
		Profile: *profile, Conversation: conv,
		Action:     policy.Action{Type: actionType, Intent: req.Intent, Text: req.Text},
		GlobalKill: s.globalKill(), Now: time.Now(),
	})

	// Owner-facing action types short-circuit to Allow inside Evaluate, but
	// ONLY after the global gates (kill switch, mode==off, autopilot paused)
	// have already had a chance to deny — see policy.go's ordering. A Deny
	// here means one of those gates fired, and it must actually stop the
	// notification from going out: the emergency kill switch exists
	// precisely to silence every owner-facing message too, not just replies.
	status := db.ActionExecuted
	if result.Decision != policy.Allow {
		status = db.ActionDenied
	}
	actionID, err := s.Store.InsertAgentAction(ctx, db.AgentAction{
		JobID: req.JobID, Attempt: req.Attempt, ConversationID: req.ConversationID, UserID: id.UserID,
		ActionType: actionType, Intent: req.Intent, Payload: req.Text,
		PolicyDecision: string(result.Decision), PolicyReasons: strings.Join(result.Reasons, "; "),
		Status: status,
	})
	if errors.Is(err, db.ErrAgentJobNotFound) {
		// Covers both a truly bogus/foreign job_id and InsertAgentAction's
		// live status/attempt gate losing the race (the job completed or was
		// reclaimed under a new attempt since the caller last saw it) — this
		// handler has no earlier pre-check to tell the two apart, unlike
		// handleProposeReply.
		writeJSONError(w, http.StatusBadRequest, "job_id does not exist for this account, or is no longer the active attempt")
		return
	}
	if err != nil {
		logHandlerErr(tool, err)
		writeJSONError(w, http.StatusInternalServerError, "request failed")
		return
	}
	// A job redelivery may resolve the insert through the
	// (job_id, action_type) idempotency key after policy or request text has
	// changed. As with propose_reply above, durable state is authoritative:
	// never turn a previously denied action into a notification merely
	// because a kill switch was lifted before the replay, and never report a
	// previously executed action as freshly denied.
	persisted, err := s.Store.GetAgentAction(ctx, id.UserID, actionID)
	if err != nil {
		logHandlerErr(tool, fmt.Errorf("reload persisted owner-facing action: %w", err))
		writeJSONError(w, http.StatusInternalServerError, "request failed")
		return
	}
	persistedReasons := result.Reasons
	if persisted.PolicyReasons != "" {
		persistedReasons = strings.Split(persisted.PolicyReasons, "; ")
	}
	if persisted.Status == db.ActionDenied {
		s.audit(ctx, id.UserID, tool, "denied", persisted.PolicyReasons)
		writeJSON(w, http.StatusOK, map[string]any{
			"action_id": actionID, "decision": persisted.PolicyDecision, "reasons": persistedReasons,
		})
		return
	}
	if persisted.Status != db.ActionExecuted {
		logHandlerErr(tool, fmt.Errorf("unexpected persisted owner-facing action status %q", persisted.Status))
		writeJSONError(w, http.StatusInternalServerError, "request failed")
		return
	}
	// InsertOwnerNotification is idempotent per action_id (see its doc
	// comment): a redelivered job that reaches this point again after
	// InsertAgentAction resolved via the (job_id, action_type) conflict must
	// not queue a second copy of the same summary/approval request.
	notifID, err := s.Store.InsertOwnerNotification(ctx, db.OwnerNotification{
		UserID: id.UserID, Kind: notificationKind, ActionID: actionID, Body: persisted.Payload,
	})
	if err != nil {
		logHandlerErr(tool, err)
		writeJSONError(w, http.StatusInternalServerError, "notification enqueue failed")
		return
	}
	s.audit(ctx, id.UserID, tool, "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"action_id": actionID, "notification_id": notifID})
}

// globalKill reports the process-wide kill switch. A tiny indirection so
// tests can construct a Server without wiring cmd/server/config through this
// package — see server_test.go.
func (s *Server) globalKill() bool {
	return s.GlobalKill
}
