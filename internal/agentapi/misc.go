package agentapi

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

type policyResponse struct {
	Mode               string `json:"mode"`
	AutopilotPaused    bool   `json:"autopilot_paused"`
	MaxAutonomousTurns int    `json:"max_autonomous_turns"`
	MaxMsgsPerMinute   int    `json:"max_msgs_per_minute"`
	MaxReplyChars      int    `json:"max_reply_chars"`
	IntentAllowlist    string `json:"intent_allowlist"`
	GlobalKill         bool   `json:"global_kill"`
}

// handlePolicy is GET /policy — the caller's current policy configuration,
// so the model can reason about what it is allowed to propose before it
// bothers proposing it. This is advisory only: internal/agent/policy.Evaluate
// is the actual authority, re-run server-side on every propose_reply call
// regardless of what the model read here.
func (s *Server) handlePolicy(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	p, ok := s.loadProfile(w, ctx, id.UserID)
	if !ok {
		return
	}
	s.audit(ctx, id.UserID, "get_policy", "ok", "")
	writeJSON(w, http.StatusOK, policyResponse{
		Mode: p.Mode, AutopilotPaused: p.AutopilotPaused, MaxAutonomousTurns: p.MaxAutonomousTurns,
		MaxMsgsPerMinute: p.MaxMsgsPerMinute, MaxReplyChars: p.MaxReplyChars,
		IntentAllowlist: p.IntentAllowlist, GlobalKill: s.globalKill(),
	})
}

// handleRecruiterProfile is GET /recruiters/{peer} — the owner's public
// profile (restricted fields already stripped by the OwnerProfileProvider
// implementation), so the model can answer "what's your background" without
// ever seeing the owner's restricted section. peer is the recruiter's
// Telegram id; validated but otherwise unused until a future
// OwnerProfileProvider wants to vary the response per-recruiter.
func (s *Server) handleRecruiterProfile(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	peerTGID, err := strconv.ParseInt(chi.URLParam(r, "peer"), 10, 64)
	if err != nil || peerTGID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid peer id")
		return
	}
	if s.Profile == nil {
		writeJSONError(w, http.StatusNotImplemented, "owner profile not configured")
		return
	}
	if s.ProfileOwnerTGID == 0 || id.TelegramID != s.ProfileOwnerTGID {
		// This deployment's mounted profile belongs to one specific account
		// (see ProfileOwnerTGID's doc comment on Server); an agent token
		// minted for any other account this multi-tenant service hosts —
		// even a legitimately admin-issued one — must not be able to read
		// it off this endpoint.
		writeJSONError(w, http.StatusForbidden, "owner profile not available for this account")
		return
	}
	profile, err := s.Profile.PublicProfile(peerTGID)
	if err != nil {
		logHandlerErr("get_recruiter_profile", err)
		writeJSONError(w, http.StatusInternalServerError, "profile lookup failed")
		return
	}
	s.audit(r.Context(), id.UserID, "get_recruiter_profile", "ok", "")
	writeJSON(w, http.StatusOK, profile)
}

type autopilotPauseRequest struct {
	Paused *bool `json:"paused"`
}

// handleAutopilotPause is POST /autopilot/pause. Body {"paused": bool} — an
// omitted field defaults to true (pause), matching the tool's name; pass
// {"paused": false} to resume. Distinct from the AGENT_KILL_SWITCH env var:
// this is per-account and DB-backed (the operator or the agent itself can
// toggle it), the kill switch is process-wide and env-only.
func (s *Server) handleAutopilotPause(w http.ResponseWriter, r *http.Request) {
	id, ok := identity(w, r)
	if !ok {
		return
	}
	var req autopilotPauseRequest
	// Decode unconditionally rather than gating on r.ContentLength (which is
	// -1, not 0, for chunked Transfer-Encoding — a length check would
	// silently skip a real {"paused":false} chunked body and default to
	// pause=true). An empty body decodes to io.EOF, which is the expected
	// "no fields provided" case, not a client error.
	if err := decodeStrict(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	paused := true
	if req.Paused != nil {
		paused = *req.Paused
	}
	if err := s.Store.SetAgentAutopilotPaused(r.Context(), id.UserID, paused); err != nil {
		if errors.Is(err, db.ErrAgentProfileNotFound) {
			writeJSONError(w, http.StatusNotFound, "agent profile not configured for this account")
			return
		}
		logHandlerErr("pause_autopilot", err)
		writeJSONError(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.audit(r.Context(), id.UserID, "pause_autopilot", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"autopilot_paused": paused})
}
