package agentapi

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

type upsertAgentProfileRequest struct {
	// TelegramID is the account whose profile is being created or updated —
	// same "target, not caller" shape as mintAgentTokenRequest.
	TelegramID         int64   `json:"telegram_id"`
	Mode               string  `json:"mode,omitempty"`
	AutopilotPaused    *bool   `json:"autopilot_paused,omitempty"`
	ListenerEnabled    *bool   `json:"listener_enabled,omitempty"`
	DisclosureText     *string `json:"disclosure_text,omitempty"`
	MaxAutonomousTurns int     `json:"max_autonomous_turns,omitempty"`
	MaxMsgsPerMinute   int     `json:"max_msgs_per_minute,omitempty"`
	MaxReplyChars      int     `json:"max_reply_chars,omitempty"`
	IntentAllowlist    *string `json:"intent_allowlist,omitempty"`
	BlockedSenders     *string `json:"blocked_senders,omitempty"`
}

type agentProfileResponse struct {
	TelegramID         int64  `json:"telegram_id"`
	Mode               string `json:"mode"`
	AutopilotPaused    bool   `json:"autopilot_paused"`
	ListenerEnabled    bool   `json:"listener_enabled"`
	DisclosureText     string `json:"disclosure_text"`
	MaxAutonomousTurns int    `json:"max_autonomous_turns"`
	MaxMsgsPerMinute   int    `json:"max_msgs_per_minute"`
	MaxReplyChars      int    `json:"max_reply_chars"`
	IntentAllowlist    string `json:"intent_allowlist"`
	BlockedSenders     string `json:"blocked_senders"`
}

// NewAdminAgentProfileHandler returns the http.HandlerFunc for PUT
// /api/admin/agent/profile — the only way today to create or change an
// account's agent_profiles row over HTTP; before this handler existed the row
// could only be written with a direct SQL insert. Admin-scoped exactly like
// NewAgentTokenHandler: same "admin:users" scope, meant to be mounted under
// the regular MCP provider (auth.Middleware(provider, ...)), never the
// aud=agent provider — a deployed worker's own token must never be able to
// loosen its own guardrails (turn itself off observe mode, unpause its own
// autopilot, or enable its own listener).
//
// Semantics are read-modify-write, not blind replace: an existing profile's
// fields are only overwritten by the ones actually present in the request
// body (nil pointer / zero-value / empty-string fields are left untouched),
// so a caller can flip just listener_enabled without resending mode/limits
// and accidentally resetting them. A brand-new profile starts from the safe
// C1 defaults (observe, autopilot paused, listener off) before the request's
// fields are applied on top — matching the "fail closed" posture of every
// other communication-agent default in this codebase.
func NewAdminAgentProfileHandler(store *db.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if !id.HasScope("admin:users") {
			writeJSONError(w, http.StatusForbidden, "admin scope required")
			return
		}
		var req upsertAgentProfileRequest
		if err := decodeStrict(w, r, &req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.TelegramID <= 0 {
			writeJSONError(w, http.StatusBadRequest, "telegram_id required")
			return
		}
		switch req.Mode {
		case "", db.AgentModeObserve, db.AgentModeGuarded, db.AgentModeOff:
		default:
			writeJSONError(w, http.StatusBadRequest, "mode must be observe, guarded, or off")
			return
		}

		ctx := r.Context()
		targetUserID, err := store.UserIDByTelegramID(ctx, req.TelegramID)
		if errors.Is(err, db.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, "no user has ever signed in with that telegram_id")
			return
		}
		if err != nil {
			logHandlerErr("admin.agent_profile.upsert", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to resolve telegram_id")
			return
		}

		p := db.AgentProfile{
			UserID:             targetUserID,
			Mode:               db.AgentModeObserve,
			AutopilotPaused:    true,
			ListenerEnabled:    false,
			MaxAutonomousTurns: 6,
			MaxMsgsPerMinute:   2,
			MaxReplyChars:      1200,
		}
		if existing, err := store.GetAgentProfile(ctx, targetUserID); err == nil {
			p = *existing
		} else if !errors.Is(err, db.ErrAgentProfileNotFound) {
			logHandlerErr("admin.agent_profile.upsert", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load existing profile")
			return
		}

		if req.Mode != "" {
			p.Mode = req.Mode
		}
		if req.AutopilotPaused != nil {
			p.AutopilotPaused = *req.AutopilotPaused
		}
		if req.ListenerEnabled != nil {
			p.ListenerEnabled = *req.ListenerEnabled
		}
		if req.DisclosureText != nil {
			p.DisclosureText = *req.DisclosureText
		}
		// > 0, not != 0: UpsertAgentProfile itself replaces any <= 0 value with
		// the default (agent_domain.go), but that clamping happens on its own
		// local copy of p after this handler has already built the response
		// below. A negative value would sail through here, get silently
		// snapped to the default in the DB, while the response still echoed
		// the negative number back to the caller as if it had been honored.
		if req.MaxAutonomousTurns > 0 {
			p.MaxAutonomousTurns = req.MaxAutonomousTurns
		}
		if req.MaxMsgsPerMinute > 0 {
			p.MaxMsgsPerMinute = req.MaxMsgsPerMinute
		}
		if req.MaxReplyChars > 0 {
			p.MaxReplyChars = req.MaxReplyChars
		}
		if req.IntentAllowlist != nil {
			p.IntentAllowlist = *req.IntentAllowlist
		}
		if req.BlockedSenders != nil {
			p.BlockedSenders = *req.BlockedSenders
		}

		// Read-modify-write, not a transaction: a concurrent PUT for the same
		// telegram_id between the GetAgentProfile above and this Upsert can
		// silently clobber the other request's fields. Accepted for now — this
		// route is admin-only and today's expected call pattern is one operator
		// making sequential changes (enable listener, then later flip mode),
		// not concurrent writers. Add a CAS (e.g. compare updated_at) or a
		// per-user advisory lock here if that assumption stops holding.
		if err := store.UpsertAgentProfile(ctx, p); err != nil {
			logHandlerErr("admin.agent_profile.upsert", err)
			store.LogToolCall(ctx, id.UserID, "admin.agent_profile.upsert", "", "error", err.Error(), "")
			writeJSONError(w, http.StatusInternalServerError, "failed to save agent profile")
			return
		}
		store.LogToolCall(ctx, id.UserID, "admin.agent_profile.upsert", "", "ok", "", "")
		slog.Info("agent profile upserted",
			"admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "target_user_id", targetUserID,
			"mode", p.Mode, "listener_enabled", p.ListenerEnabled, "autopilot_paused", p.AutopilotPaused)

		writeJSON(w, http.StatusOK, agentProfileResponse{
			TelegramID:         req.TelegramID,
			Mode:               p.Mode,
			AutopilotPaused:    p.AutopilotPaused,
			ListenerEnabled:    p.ListenerEnabled,
			DisclosureText:     p.DisclosureText,
			MaxAutonomousTurns: p.MaxAutonomousTurns,
			MaxMsgsPerMinute:   p.MaxMsgsPerMinute,
			MaxReplyChars:      p.MaxReplyChars,
			IntentAllowlist:    p.IntentAllowlist,
			BlockedSenders:     p.BlockedSenders,
		})
	}
}
