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
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// maxApprovalCodeAttempts bounds the retry loop on the astronomically rare
// (user_id, approval_code_hash) unique-index collision (see approvalcode.go).
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
// (user_id, approval_code_hash) unique index specifically — narrower than a bare
// "unique" substring match, which would also match the unrelated
// (job_id, action_type) index on the same table and mask its real error
// behind three pointless retries. Matches by driver-reported name rather
// than an errors.As type check against pgx/modernc so this package does not
// need to import either driver: Postgres names the index itself
// ("idx_agent_actions_code") in its error text; SQLite instead lists the
// column pair ("agent_actions.approval_code_hash").
func isApprovalCodeCollision(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "idx_agent_actions_code_hash") || strings.Contains(msg, "approval_code_hash")
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

// pauseAlertWindow bounds how often an account is told that autopilot pause
// withheld a reply. See the throttle in handleProposeReply for why an
// unbounded stream is unsafe.
const pauseAlertWindow = 6 * time.Hour

// pauseAlertWindowText is pauseAlertWindow written for a human. time.Duration
// renders as "6h0m0s", which has no place in a message the owner reads in
// Saved Messages; keep the two in step by hand rather than pulling in a
// formatter for one string.
const pauseAlertWindowText = "6 hours"

// hasReason reports whether the persisted "; "-joined reason list contains
// want as a whole element. Deliberately not an equality check on the joined
// string: a future change that appends a second reason to the pause denial
// would silently stop matching, and the owner alert would quietly stop
// firing with no test failing (claude review P3 on PR #582).
func hasReason(joined, want string) bool {
	for _, r := range strings.Split(joined, "; ") {
		if r == want {
			return true
		}
	}
	return false
}

// protectedField runs the owner_profile disclosure match (#953) on a draft
// reply against the conversation's engagement state. Nil means no match, no
// provider, or no owner profile for this tenant; the executor runs the same
// check again before sending.
func (s *Server) protectedField(ctx context.Context, userID int64, conv db.Conversation, jobID int64, text string) (*policy.ProtectedField, error) {
	if s.Profile == nil {
		return nil, nil
	}
	inbound, err := s.Store.TurnInboundText(ctx, userID, jobID)
	if err != nil {
		return nil, fmt.Errorf("load turn inbound text: %w", err)
	}
	key, never, matched, err := s.Profile.MatchProtected(ctx, userID, text, inbound, conv.OwnerEngaged(time.Now()))
	if errors.Is(err, db.ErrAgentOwnerProfileNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("match protected profile fields: %w", err)
	}
	if !matched {
		return nil, nil
	}
	return &policy.ProtectedField{Key: key, Never: never}, nil
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
	if jobBound(id) && req.ConversationID == 0 {
		req.ConversationID = id.ConversationID
	}
	if !s.enforceBinding(w, r, id, "propose_reply", req.ConversationID, req.JobID, req.Attempt) {
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
		// state/peer and persists a result that cannot validly belong to this
		// job. GetAgentJob already scopes to id.UserID, so a foreign job_id is
		// rejected before this check ever runs.
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
	// A draft for a turn whose source message the sender has since edited
	// or deleted is stored as denied rather than queued (#949, #950). The
	// send reservation repeats the check for edits that land later.
	superseded, err := s.Store.JobSourceSuperseded(ctx, id.UserID, req.JobID)
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	sends, err := s.recentAgentSends(ctx, id.UserID, req.ConversationID, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	protected, err := s.protectedField(ctx, id.UserID, *conv, req.JobID, req.Text)
	if err != nil {
		logHandlerErr("propose_reply", err)
		writeJSONError(w, http.StatusInternalServerError, "profile lookup failed")
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
		ProtectedField:   protected,
		SourceSuperseded: superseded,
	})
	// Counted from THIS evaluation, deliberately unlike the notification and
	// response handling below, which read the persisted row so a redelivered
	// job is not re-judged. The two want different things: the response must
	// tell the worker what was actually decided for that action, while this
	// series is an anomaly signal — "how often is policy refusing calls at
	// this surface". A worker hammering a paused account through repeated
	// redeliveries is exactly the shape the signal exists to expose, and
	// counting only newly-persisted denials would hide it behind the
	// idempotency key.
	if result.Decision == policy.Deny {
		s.m.CountPolicyDenial(string(result.DenyCode()), metrics.PolicySurfaceProposeReply)
	}

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
	// Driven by the PERSISTED row, not by this replay's freshly-evaluated
	// `result` — the same rule the reload comment above states and the
	// approval notification above already follows. InsertAgentAction is
	// idempotent for job-tied actions: a redelivered job whose action was
	// first persisted as `approved` (account active at the time) must not
	// produce a "reply withheld" alert just because the owner paused the
	// account in between, while the response returned to the worker still
	// says allow off that same durable row (agy P2 on PR #582).
	if persisted.Status == db.ActionDenied && hasReason(persisted.PolicyReasons, policy.ReasonAutopilotPaused) {
		// Deliberately best-effort, unlike the approval-code notification
		// above: that notification carries the only copy of ApprovalCode, so
		// losing it strands an otherwise-approvable draft forever. This alert
		// is purely informational — the denied action row above already
		// records the pause reason for audit — so a lost enqueue costs the
		// owner a heads-up, not data, and must not fail an otherwise-
		// successful propose_reply call (issue #581).
		//
		// Throttled per account, not merely deduped per action. The
		// per-action_id uniqueness inside InsertOwnerNotification only collapses
		// redeliveries of the SAME draft; every new inbound message is a
		// distinct action, and ingestion is gated on listener_enabled, never on
		// autopilot_paused (internal/agent/listener). An account sitting in the
		// documented bootstrap default (paused, listener on) would therefore
		// queue one alert per inbound DM forever — and owner_notifications is
		// drained oldest-50 SYSTEM-WIDE, so that backlog delays other accounts'
		// approval codes. The proposal's open question 3 asked whether to
		// throttle and answered no on the grounds that Saved Messages is not a
		// scarce channel; the scarce resource is the shared delivery batch, not
		// the channel (claude review on PR #582).
		//
		// Check-then-insert, deliberately not transactional: two concurrent
		// propose_reply calls for the same paused account can both observe
		// recent==false and both insert, since their action_ids differ and
		// the per-action_id unique index does not collapse them. The bound
		// is therefore "one per window per in-flight request", not exactly
		// one — which still converts an unbounded stream (one per inbound
		// message, forever) into something bounded by request concurrency.
		// Serialising it would need a lock on a path that must not fail the
		// propose call; not worth it for an informational notice.
		recent, rerr := s.Store.HasOwnerNotificationSince(ctx, id.UserID, db.NotificationAlert, time.Now().UTC().Add(-pauseAlertWindow))
		switch {
		case rerr != nil:
			// Fail closed on the throttle check: skipping the alert costs the
			// owner one heads-up, queueing an unbounded stream costs every
			// account's approval delivery.
			logHandlerErr("propose_reply", fmt.Errorf("pause-alert throttle check (user_id=%d): %w", id.UserID, rerr))
		case recent:
			// Already told within the window; stay quiet.
		default:
			peerLabel := "a conversation"
			switch {
			case strings.TrimSpace(conv.PeerDisplayName) != "":
				peerLabel = conv.PeerDisplayName
			case strings.TrimSpace(conv.PeerUsername) != "":
				peerLabel = "@" + conv.PeerUsername
			}
			// Names both ways out: /mctl continue for this conversation and
			// /mctl unpause for the whole account.
			// Addressed to the owner and accurate about the throttle: only
			// this alert is held back for the window, owner summaries are
			// not (#994).
			alertBody := fmt.Sprintf("Autopilot is paused, so the agent did not reply to %s. /mctl continue %d lets it reply in that conversation. /mctl unpause lifts the pause for the whole account. You will not get this alert again for %s.", peerLabel, conv.ID, pauseAlertWindowText)
			if _, nerr := s.Store.InsertOwnerNotification(ctx, db.OwnerNotification{
				UserID: id.UserID, Kind: db.NotificationAlert, ActionID: actionID, Body: alertBody,
			}); nerr != nil {
				logHandlerErr("propose_reply", fmt.Errorf("queue autopilot-pause alert (action_id=%d user_id=%d): %w", actionID, id.UserID, nerr))
			}
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
	ConversationID int64 `json:"conversation_id"`
	// LeadID selects the lead to update (#951). Zero creates a new lead; a
	// conversation can hold several. The lead must belong to ConversationID.
	LeadID        int64  `json:"lead_id,omitempty"`
	JobID         int64  `json:"job_id,omitempty"`
	Attempt       int    `json:"attempt,omitempty"`
	Company       string `json:"company"`
	Role          string `json:"role"`
	RecruiterName string `json:"recruiter_name"`
	RecruiterTGID int64  `json:"recruiter_tg_id"`
	Compensation  string `json:"compensation"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
}

// handleSaveLead is POST /leads (save_job_lead). Without lead_id it creates a
// new lead; with lead_id it updates that lead of this conversation, merging
// partial data without erasing earlier answers (#951, see UpsertJobLead).
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
	if jobBound(id) && req.ConversationID == 0 {
		req.ConversationID = id.ConversationID
	}
	if !s.enforceBinding(w, r, id, "save_lead", req.ConversationID, req.JobID, req.Attempt) {
		return
	}
	if req.ConversationID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "conversation_id required")
		return
	}
	leadID, err := s.Store.UpsertJobLead(r.Context(), db.JobLead{
		ID:     req.LeadID,
		UserID: id.UserID, ConversationID: req.ConversationID, JobID: req.JobID, Attempt: req.Attempt,
		Company: req.Company, Role: req.Role,
		RecruiterName: req.RecruiterName, RecruiterTGID: req.RecruiterTGID, Compensation: req.Compensation,
		Status: req.Status, Detail: req.Detail,
	})
	if errors.Is(err, db.ErrConversationNotFound) {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if errors.Is(err, db.ErrJobLeadNotFound) {
		writeJSONError(w, http.StatusNotFound, "lead not found in this conversation")
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

// policySurfaceForOwnerTool maps handleOwnerFacing's tool name onto its own
// denial surface. The handler is shared by two tools, so a single surface
// value would merge their denials into one series; the mapping keeps the
// label a compile-time-fixed set rather than passing the tool name through.
//
// Both tools are matched explicitly and an unknown name falls back to
// metrics.PolicySurfaceUnknown rather than to one of the real surfaces. The
// two call sites pass literals, so an unknown name can only arrive via a
// third caller or a rename — and silently attributing its denials to
// request_owner_approval would corrupt that series instead of showing up as
// something to fix.
func policySurfaceForOwnerTool(tool string) string {
	switch tool {
	case "send_owner_summary":
		return metrics.PolicySurfaceOwnerSummary
	case "request_owner_approval":
		return metrics.PolicySurfaceOwnerApproval
	default:
		return metrics.PolicySurfaceUnknown
	}
}

// IntentAssistantManipulation marks a send_owner_summary that reports a
// message trying to instruct the assistant (prompt injection, jailbreak,
// requests for its instructions). The server owns the wording and the rate
// of these alerts (#953): see manipulationAlertBody and
// manipulationAlertWindow. Other intents, including OTP or credential
// phishing alerts, are delivered as the agent wrote them and never
// throttled.
const IntentAssistantManipulation = "assistant_manipulation"

// manipulationAlertWindow bounds assistant-manipulation alerts to one per
// conversation per window. A sender probing the assistant tends to send
// many such messages; the owner needs to know once, not each time.
const manipulationAlertWindow = 6 * time.Hour

// ManipulationAlertText is the whole substance of an assistant-manipulation
// alert. It never quotes or paraphrases the sender's text: an alert that
// carries the attacker's words delivers the injection to the owner's Saved
// Messages, where another assistant with access to them may read it.
const ManipulationAlertText = "A message contained instructions directed at the assistant. They were not followed."

// manipulationAlertBody replaces whatever text the agent sent with the
// canonical alert. Only the conversation id and the peer's @username are
// added, for the owner to find the chat: a username is limited to
// [A-Za-z0-9_], while a display name is free text the sender controls and is
// deliberately left out.
func manipulationAlertBody(conv db.Conversation) string {
	if conv.ID == 0 {
		return ManipulationAlertText
	}
	who := ""
	if u := strings.TrimSpace(conv.PeerUsername); u != "" && validUsername(u) {
		who = " (@" + u + ")"
	}
	return fmt.Sprintf("Conversation %d%s: %s\n\n/mctl show %d", conv.ID, who, ManipulationAlertText, conv.ID)
}

// validUsername reports whether u has only the characters a Telegram
// username can, so a stored value can never smuggle text into the alert.
func validUsername(u string) bool {
	for _, r := range u {
		switch {
		case r == '_', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
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
	if jobBound(id) && req.ConversationID == 0 {
		req.ConversationID = id.ConversationID
	}
	if !s.enforceBinding(w, r, id, tool, req.ConversationID, req.JobID, req.Attempt) {
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
	// Owner-facing actions bypass conversation state entirely in Evaluate
	// (its short-circuit runs before the in.Conversation.State switch), so
	// no synthetic conversation is needed here: a conversation-less call
	// (req.ConversationID == 0, e.g. a general daily summary) can pass the
	// zero-value Conversation as-is.
	var conv db.Conversation
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

	if actionType == db.ActionTypeOwnerSummary && strings.EqualFold(strings.TrimSpace(req.Intent), IntentAssistantManipulation) {
		req.Intent = IntentAssistantManipulation
		req.Text = manipulationAlertBody(conv)
		// Check-then-insert is not atomic. Accepted: ClaimAgentJobs already
		// serializes jobs per conversation, so two alerts can only race
		// after a lease expiry, and the worst case is one duplicate
		// neutral notice.
		recent, err := s.Store.HasExecutedOwnerSummarySince(ctx, id.UserID, req.ConversationID,
			IntentAssistantManipulation, time.Now().UTC().Add(-manipulationAlertWindow))
		if err != nil {
			logHandlerErr(tool, err)
			writeJSONError(w, http.StatusInternalServerError, "request failed")
			return
		}
		if recent {
			// Not inserted as an action: the (job_id, action_type) key
			// allows one summary per job, and a suppressed row would
			// swallow a security alert the same job sends next. The tool
			// call log is the audit record.
			reason := "assistant_manipulation alert already sent for this conversation within 6 hours"
			s.audit(ctx, id.UserID, tool, "suppressed", reason)
			writeJSON(w, http.StatusOK, map[string]any{"suppressed": true, "reason": reason})
			return
		}
	}

	result := policy.Evaluate(policy.Input{
		Profile: *profile, Conversation: conv,
		Action:     policy.Action{Type: actionType, Intent: req.Intent, Text: req.Text},
		GlobalKill: s.globalKill(), Now: time.Now(),
	})
	if result.Decision == policy.Deny {
		s.m.CountPolicyDenial(string(result.DenyCode()), policySurfaceForOwnerTool(tool))
	}

	// Owner-facing action types short-circuit to Allow inside Evaluate, but
	// ONLY after the global gates (kill switch, mode==off) have already had a
	// chance to deny — see policy.go's ordering. A Deny here can now only come
	// from one of those two account-wide gates (never conversation state, the
	// sender blocklist, or autopilot paused — owner-facing actions are exempt
	// from the pause gate, issue #581), and it must actually stop the
	// notification from going out: the emergency kill switch exists precisely
	// to silence every owner-facing message too, not just replies.
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
