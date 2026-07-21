package agentapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// eventsPollInterval is how often the long-poll loop re-checks the queue
// when the first claim attempt comes up empty.
const eventsPollInterval = 1 * time.Second

// jobEnvelope is the payload GET /events returns per claimed job. It carries
// only identity/routing fields — the worker fetches the full event body via
// GET /event/{eventID}, keeping the wake-up response small and avoiding a
// second encryption round-trip on jobs that never get past dedup.
type jobEnvelope struct {
	JobID          int64  `json:"job_id"`
	EventID        string `json:"event_id"`
	ConversationID int64  `json:"conversation_id,omitempty"`
	// Attempt is the claim identity a worker must echo back on
	// POST /jobs/{id}/complete — see internal/db.CompleteAgentJob's fencing
	// comment. Without it a worker whose claim was reclaimed by the stale-
	// job sweeper could clobber a newer claim's outcome.
	Attempt  int    `json:"attempt"`
	Deadline string `json:"deadline"` // RFC3339; advisory, see Server.jobVisibility
}

// handleEvents is GET /events — a long-poll claim of the next due job(s).
// Honors an optional integer ?limit= (default 1, capped at 10). Always
// responds 200; an empty "jobs" array means the poll window elapsed with
// nothing to claim, not an error.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	limit := 1
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > 10 {
			n = 10
		}
		limit = n
	}

	ctx := r.Context()
	deadline := time.Now().Add(s.longPollTimeout)
	for {
		jobs, err := s.Queue.Claim(ctx, limit)
		if err != nil {
			logHandlerErr("get_events", err)
			writeJSONError(w, http.StatusInternalServerError, "claim failed")
			return
		}
		if len(jobs) > 0 {
			out := make([]jobEnvelope, 0, len(jobs))
			for _, j := range jobs {
				out = append(out, jobEnvelope{
					JobID:          j.ID,
					EventID:        j.EventID,
					ConversationID: j.ConversationID,
					Attempt:        j.Attempts,
					Deadline:       j.ClaimedAt.Add(s.jobVisibility).UTC().Format(time.RFC3339),
				})
			}
			s.audit(ctx, id.UserID, "get_events", "ok", "")
			writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
			return
		}
		select {
		case <-ctx.Done():
			writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
			return
		case <-time.After(eventsPollInterval):
			if time.Now().After(deadline) {
				writeJSON(w, http.StatusOK, map[string]any{"jobs": []jobEnvelope{}})
				return
			}
		}
	}
}

// eventResponse is the full payload for GET /event/{eventID}.
type eventResponse struct {
	EventID    string `json:"event_id"`
	Kind       string `json:"kind"`
	ChatTGID   int64  `json:"chat_tg_id"`
	SenderTGID int64  `json:"sender_tg_id"`
	MessageID  int64  `json:"message_id"`
	Body       string `json:"body"`
	Meta       string `json:"meta"`
	CreatedAt  string `json:"created_at"`
}

func (s *Server) handleGetEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	eventID := chi.URLParam(r, "eventID")
	if eventID == "" {
		writeJSONError(w, http.StatusBadRequest, "event id required")
		return
	}
	ev, err := s.Store.GetIncomingEvent(r.Context(), id.UserID, eventID)
	if errors.Is(err, db.ErrIncomingEventNotFound) {
		writeJSONError(w, http.StatusNotFound, "event not found")
		return
	}
	if err != nil {
		logHandlerErr("get_event", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	s.audit(r.Context(), id.UserID, "get_event", "ok", "")
	writeJSON(w, http.StatusOK, eventResponse{
		EventID:    ev.EventID,
		Kind:       ev.Kind,
		ChatTGID:   ev.ChatTGID,
		SenderTGID: ev.SenderTGID,
		MessageID:  ev.MessageID,
		Body:       ev.Body,
		Meta:       ev.Meta,
		CreatedAt:  ev.CreatedAt.UTC().Format(time.RFC3339),
	})
}

type completeJobRequest struct {
	Attempt int    `json:"attempt"`
	Status  string `json:"status"`
	Note    string `json:"note"`
}

// handleJobComplete is POST /jobs/{id}/complete. A job may only be completed
// as "completed" once its result is durably persisted: the handler requires
// a matching agent_actions row to already exist for status=completed,
// turning "worker acked without producing a result" into an explicit 409
// instead of a silently-lost job. status=failed/ignored carry no such
// requirement — those are legitimate terminal outcomes with no action to
// show for them.
func (s *Server) handleJobComplete(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	jobIDStr := chi.URLParam(r, "id")
	jobID, err := strconv.ParseInt(jobIDStr, 10, 64)
	if err != nil || jobID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid job id")
		return
	}
	var req completeJobRequest
	if err := decodeStrict(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Status {
	case db.JobCompleted, db.JobFailed, db.JobIgnored:
	default:
		writeJSONError(w, http.StatusBadRequest, "status must be completed, failed, or ignored")
		return
	}
	ctx := r.Context()
	if _, err := s.Store.GetAgentJob(ctx, id.UserID, jobID); err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			writeJSONError(w, http.StatusNotFound, "job not found")
			return
		}
		logHandlerErr("complete_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	if req.Status == db.JobCompleted {
		has, err := s.Store.HasAgentActionForJob(ctx, id.UserID, jobID)
		if err != nil {
			logHandlerErr("complete_agent_job", err)
			writeJSONError(w, http.StatusInternalServerError, "lookup failed")
			return
		}
		if !has {
			writeJSONError(w, http.StatusConflict,
				"cannot mark job completed without a persisted action result — propose a reply, save a lead, or send a notification first")
			return
		}
	}
	if err := s.Queue.Complete(ctx, jobID, req.Attempt, req.Status, req.Note); err != nil {
		if errors.Is(err, db.ErrAgentJobNotFound) {
			// Lost the compare-and-set race (stale claim, already completed by
			// another attempt after a visibility-timeout requeue) — the caller's
			// ack is simply too late, not a server error.
			writeJSONError(w, http.StatusConflict, "job is no longer claimed under that attempt")
			return
		}
		logHandlerErr("complete_agent_job", err)
		writeJSONError(w, http.StatusInternalServerError, "complete failed")
		return
	}
	s.audit(ctx, id.UserID, "complete_agent_job", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"completed": true})
}
