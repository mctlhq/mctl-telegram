package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	agentprofile "github.com/mctlhq/mctl-telegram/internal/agent/profile"
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
	SenderAllowlist    *string `json:"sender_allowlist,omitempty"`
	// OwnerProfile is a strict JSON document matching profile.Data. Omitted
	// means unchanged; null clears it.
	OwnerProfile json.RawMessage `json:"owner_profile,omitempty"`
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
	SenderAllowlist    string `json:"sender_allowlist"`
	// The profile contents are deliberately never echoed from this
	// administrative policy response.
	OwnerProfileConfigured bool `json:"owner_profile_configured"`
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
// Semantics are a true partial update, not read-modify-write: only the
// fields actually present in the request body are ever written (via
// db.UpdateAgentProfileFields, a single UPDATE naming just those columns),
// so a caller can flip just listener_enabled without resending mode/limits
// and accidentally resetting them -- and, unlike an earlier version of this
// handler that read the whole row then wrote it back, this can never
// silently revert a concurrent single-field writer such as
// SetAgentAutopilotPaused (called by POST /autopilot/pause and the owner's
// /mctl pause command): there is no local copy of the untouched columns to
// go stale between read and write, because they are never read here at all.
// A brand-new profile is bootstrapped via db.EnsureAgentProfile with the
// safe C1 defaults (observe, autopilot paused, listener off) before the
// request's fields are applied on top.
//
// Known limitation: telegram_id is resolved via db.UserIDByTelegramID, which
// only looks at users.telegram_login_id -- populated for accounts that have
// signed in through the local-jwt OAuth flow. An account connected only via
// local-dev/shared-hmac-legacy auth (github_login-created, Telegram identity
// tracked in telegram_accounts.telegram_user_id instead) will 404 here even
// though it exists. Not a blocker for C1 (mctl-telegram-preview runs
// local-jwt), but resolving through the connected-account table too is a
// follow-up if this endpoint needs to provision non-local-jwt accounts.
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
		var ownerProfileDocument []byte
		clearOwnerProfile := false
		if len(req.OwnerProfile) > 0 {
			if bytes.Equal(bytes.TrimSpace(req.OwnerProfile), []byte("null")) {
				clearOwnerProfile = true
			} else {
				parsed, err := agentprofile.ParseJSON(req.OwnerProfile)
				if err != nil {
					writeJSONError(w, http.StatusBadRequest, "invalid owner_profile")
					return
				}
				ownerProfileDocument, err = json.Marshal(parsed)
				if err != nil {
					writeJSONError(w, http.StatusBadRequest, "invalid owner_profile")
					return
				}
			}
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

		if err := store.EnsureAgentProfile(ctx, targetUserID); err != nil {
			logHandlerErr("admin.agent_profile.upsert", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to initialize agent profile")
			return
		}

		update := db.AgentProfileUpdate{
			AutopilotPaused: req.AutopilotPaused,
			ListenerEnabled: req.ListenerEnabled,
			DisclosureText:  req.DisclosureText,
			IntentAllowlist: req.IntentAllowlist,
			BlockedSenders:  req.BlockedSenders,
			SenderAllowlist: req.SenderAllowlist,
		}
		if clearOwnerProfile {
			empty := []byte(nil)
			update.OwnerProfileDocument = &empty
		} else if len(ownerProfileDocument) > 0 {
			update.OwnerProfileDocument = &ownerProfileDocument
		}
		if req.Mode != "" {
			update.Mode = &req.Mode
		}
		// > 0, not != 0: a negative limit must not be written at all, not even
		// clamped -- writing it would let it briefly diverge between this
		// handler's later response and whatever floor a future validation
		// layer might enforce. Omitting it here just leaves the existing
		// stored value in place, exactly like any other unset field.
		if req.MaxAutonomousTurns > 0 {
			update.MaxAutonomousTurns = &req.MaxAutonomousTurns
		}
		if req.MaxMsgsPerMinute > 0 {
			update.MaxMsgsPerMinute = &req.MaxMsgsPerMinute
		}
		if req.MaxReplyChars > 0 {
			update.MaxReplyChars = &req.MaxReplyChars
		}

		if err := store.UpdateAgentProfileFields(ctx, targetUserID, update); err != nil {
			logHandlerErr("admin.agent_profile.upsert", err)
			store.LogToolCall(ctx, id.UserID, "admin.agent_profile.upsert", "", "error", err.Error(), "")
			writeJSONError(w, http.StatusInternalServerError, "failed to save agent profile")
			return
		}
		p, err := store.GetAgentProfile(ctx, targetUserID)
		if err != nil {
			logHandlerErr("admin.agent_profile.upsert", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load saved profile")
			return
		}
		ownerProfileConfigured := true
		if _, err := store.GetAgentOwnerProfile(ctx, targetUserID); errors.Is(err, db.ErrAgentOwnerProfileNotFound) {
			ownerProfileConfigured = false
		} else if err != nil {
			logHandlerErr("admin.agent_profile.get_owner_profile", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load owner profile state")
			return
		}

		store.LogToolCall(ctx, id.UserID, "admin.agent_profile.upsert", "", "ok", "", "")
		slog.Info("agent profile upserted",
			"admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "target_user_id", targetUserID,
			"mode", p.Mode, "listener_enabled", p.ListenerEnabled, "autopilot_paused", p.AutopilotPaused)

		writeJSON(w, http.StatusOK, agentProfileResponse{
			TelegramID:             req.TelegramID,
			Mode:                   p.Mode,
			AutopilotPaused:        p.AutopilotPaused,
			ListenerEnabled:        p.ListenerEnabled,
			DisclosureText:         p.DisclosureText,
			MaxAutonomousTurns:     p.MaxAutonomousTurns,
			MaxMsgsPerMinute:       p.MaxMsgsPerMinute,
			MaxReplyChars:          p.MaxReplyChars,
			IntentAllowlist:        p.IntentAllowlist,
			BlockedSenders:         p.BlockedSenders,
			SenderAllowlist:        p.SenderAllowlist,
			OwnerProfileConfigured: ownerProfileConfigured,
		})
	}
}
