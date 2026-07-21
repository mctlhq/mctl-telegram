package agentapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

type conversationMessageDTO struct {
	Direction string `json:"direction"`
	Body      string `json:"body"`
	CreatedAt string `json:"created_at"`
}

type conversationDTO struct {
	ID              int64  `json:"id"`
	PeerTGID        int64  `json:"peer_tg_id"`
	PeerUsername    string `json:"peer_username,omitempty"`
	PeerDisplayName string `json:"peer_display_name,omitempty"`
	State           string `json:"state"`
	AutonomousTurns int    `json:"autonomous_turns"`
}

type leadDTO struct {
	ID            int64  `json:"id"`
	Company       string `json:"company,omitempty"`
	Role          string `json:"role,omitempty"`
	RecruiterName string `json:"recruiter_name,omitempty"`
	RecruiterTGID int64  `json:"recruiter_tg_id,omitempty"`
	Compensation  string `json:"compensation,omitempty"`
	Status        string `json:"status"`
	Detail        string `json:"detail"`
}

func toLeadDTO(l *db.JobLead) leadDTO {
	return leadDTO{
		ID: l.ID, Company: l.Company, Role: l.Role, RecruiterName: l.RecruiterName,
		RecruiterTGID: l.RecruiterTGID, Compensation: l.Compensation, Status: l.Status, Detail: l.Detail,
	}
}

// handleConversationContext is GET /conversations/{id}/context. Returns the
// conversation row, its most recent messages (?limit=, default 20, max 100),
// and the associated job lead if one has been saved — everything a worker
// needs to draft a reply in one round trip instead of three.
func (s *Server) handleConversationContext(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	convID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || convID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation id")
		return
	}
	limit := 20
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeJSONError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > 100 {
			n = 100
		}
		limit = n
	}

	ctx := r.Context()
	conv, err := s.Store.GetConversation(ctx, id.UserID, convID)
	if errors.Is(err, db.ErrConversationNotFound) {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	if err != nil {
		logHandlerErr("get_conversation_context", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	msgs, err := s.Store.ListConversationMessages(ctx, id.UserID, convID, limit)
	if err != nil {
		logHandlerErr("get_conversation_context", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	msgDTOs := make([]conversationMessageDTO, 0, len(msgs))
	for _, m := range msgs {
		msgDTOs = append(msgDTOs, conversationMessageDTO{
			Direction: m.Direction, Body: m.Body, CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	var lead *leadDTO
	if l, err := s.Store.GetJobLeadByConversation(ctx, id.UserID, convID); err == nil {
		dto := toLeadDTO(l)
		lead = &dto
	} else if !errors.Is(err, db.ErrJobLeadNotFound) {
		logHandlerErr("get_conversation_context", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	s.audit(ctx, id.UserID, "get_conversation_context", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"conversation": conversationDTO{
			ID: conv.ID, PeerTGID: conv.PeerTGID, PeerUsername: conv.PeerUsername,
			PeerDisplayName: conv.PeerDisplayName, State: conv.State, AutonomousTurns: conv.AutonomousTurns,
		},
		"messages": msgDTOs,
		"lead":     lead,
	})
}

// handleGetLead is GET /leads/{id}.
func (s *Server) handleGetLead(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	leadID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || leadID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid lead id")
		return
	}
	lead, err := s.Store.GetJobLead(r.Context(), id.UserID, leadID)
	if errors.Is(err, db.ErrJobLeadNotFound) {
		writeJSONError(w, http.StatusNotFound, "lead not found")
		return
	}
	if err != nil {
		logHandlerErr("get_lead", err)
		writeJSONError(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	s.audit(r.Context(), id.UserID, "get_lead", "ok", "")
	writeJSON(w, http.StatusOK, toLeadDTO(lead))
}
