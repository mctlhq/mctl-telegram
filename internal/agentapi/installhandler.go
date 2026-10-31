package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	agentprofile "github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
	"github.com/mctlhq/mctl-telegram/internal/assistantinstall"
	"github.com/mctlhq/mctl-telegram/internal/assistantregistry"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/jsonstrict"
)

// installAgentRequest is the body of PUT /api/admin/agent/install.
type installAgentRequest struct {
	TelegramID int64 `json:"telegram_id"`
	// Install is an AssistantInstall document (docs/assistants/spec.md).
	Install json.RawMessage `json:"install"`
}

var installAgentKeys = [...]string{"telegram_id", "install"}

type installAgentResponse struct {
	agentProfileResponse
	Assistant        string `json:"assistant"`
	AssistantVersion string `json:"assistant_version"`
}

// NewAdminAgentInstallHandler returns the http.HandlerFunc for PUT
// /api/admin/agent/install: it validates an AssistantInstall against its
// catalog definition and applies everything it resolves to — the profile
// settings, the owner profile, the assistant reference and the install
// itself — in one UPDATE, so an account never runs one assistant's
// instructions with another's settings. Unlike PUT /api/admin/agent/profile
// this is a full replacement: every setting comes from the install or the
// definition's defaults.
//
// With registry set (ASSISTANT_REGISTRY_ENABLED, #1020) the definition is
// fetched from the mctl-api registry instead of the embedded catalog, its
// digest checked against the registry's contentHash, and the materialized
// document stored as a snapshot in the same transaction as the profile
// UPDATE, so claims and restarts never need the registry. A new install
// needs lifecycle published; deprecated is accepted only for the
// name@version the account already runs. With registry nil the embedded
// catalog is the source, as before.
//
// Admin-scoped and mounted like NewAdminAgentProfileHandler; an agent's own
// token must never reach it.
func NewAdminAgentInstallHandler(store *db.Store, catalog *assistant.Catalog, registry *assistantregistry.Client) http.HandlerFunc {
	svc := assistantinstall.New(store, catalog, registry)
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		if !id.HasScope("admin:users") {
			writeJSONError(w, http.StatusForbidden, "admin scope required")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil || agentprofile.RejectDuplicateJSONKeys(raw) != nil ||
			jsonstrict.ObjectKeysWithin(raw, installAgentKeys[:]...) != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		var req installAgentRequest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.TelegramID <= 0 {
			writeJSONError(w, http.StatusBadRequest, "telegram_id required")
			return
		}
		if len(bytes.TrimSpace(req.Install)) == 0 {
			writeJSONError(w, http.StatusBadRequest, "install required")
			return
		}

		// The validation messages name variables and rules, and go back
		// only to the administrator who sent the document; they are never
		// logged, since a schema message can quote a submitted value.
		prepared, err := svc.Prepare(r.Context(), req.Install)
		if err != nil {
			writeInstallError(w, err, registry != nil)
			return
		}

		ctx := r.Context()
		targetUserID, err := store.UserIDByTelegramID(ctx, req.TelegramID)
		if errors.Is(err, db.ErrUserNotFound) {
			writeJSONError(w, http.StatusNotFound, "no user has ever signed in with that telegram_id")
			return
		}
		if err != nil {
			logHandlerErr("admin.agent_install", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to resolve telegram_id")
			return
		}
		res, err := svc.Commit(ctx, targetUserID, prepared, assistantinstall.CommitOptions{})
		if err != nil {
			var ie *assistantinstall.Error
			if errors.As(err, &ie) && ie.Kind == assistantinstall.KindInternal && ie.Msg == assistantinstall.MsgSaveFailed {
				store.LogToolCall(ctx, db.ToolCall{UserID: id.UserID, Tool: "admin.agent_install", Status: "error", ErrMsg: ie.Err.Error()})
			}
			writeInstallError(w, err, registry != nil)
			return
		}
		if res.CleanupErr != nil {
			logHandlerErr("admin.agent_install", res.CleanupErr)
		}
		p := res.Profile
		name, version := res.Name, res.Version

		store.LogToolCall(ctx, db.ToolCall{UserID: id.UserID, Tool: "admin.agent_install", Status: "ok"})
		slog.Info("agent assistant installed",
			"admin_user_id", id.UserID, "target_tg_id", req.TelegramID, "target_user_id", targetUserID,
			"assistant", name, "assistant_version", version,
			"mode", p.Mode, "listener_enabled", p.ListenerEnabled, "autopilot_paused", p.AutopilotPaused,
			"disclosure_disabled", p.DisclosureDisabled)

		writeJSON(w, http.StatusOK, installAgentResponse{
			agentProfileResponse: agentProfileResponse{
				TelegramID:             req.TelegramID,
				Mode:                   p.Mode,
				AutopilotPaused:        p.AutopilotPaused,
				ListenerEnabled:        p.ListenerEnabled,
				DisclosureText:         p.DisclosureText,
				DisclosureDisabled:     p.DisclosureDisabled,
				MaxAutonomousTurns:     p.MaxAutonomousTurns,
				MaxMsgsPerMinute:       p.MaxMsgsPerMinute,
				MaxReplyChars:          p.MaxReplyChars,
				IntentAllowlist:        p.IntentAllowlist,
				IntentDenylist:         p.IntentDenylist,
				WorkingHours:           p.WorkingHours,
				AudienceExcludes:       p.AudienceExcludes,
				BlockedSenders:         p.BlockedSenders,
				SenderAllowlist:        p.SenderAllowlist,
				OwnerProfileConfigured: true,
			},
			Assistant:        name,
			AssistantVersion: version,
		})
	}
}

// writeInstallError answers an assistantinstall error with the status the
// admin route has always used for it. The full validator message goes
// back to the administrator who sent the document; nothing of it is
// logged. An unknown assistant is 404 from the registry and, as before it,
// 400 from the embedded catalog.
func writeInstallError(w http.ResponseWriter, err error, fromRegistry bool) {
	var ie *assistantinstall.Error
	if !errors.As(err, &ie) {
		logHandlerErr("admin.agent_install", err)
		writeJSONError(w, http.StatusInternalServerError, "failed to save agent install")
		return
	}
	switch ie.Kind {
	case assistantinstall.KindInvalid:
		writeJSONError(w, http.StatusBadRequest, ie.Full())
	case assistantinstall.KindNotFound:
		status := http.StatusBadRequest
		if fromRegistry {
			status = http.StatusNotFound
		}
		writeJSONError(w, status, ie.Msg)
	case assistantinstall.KindLifecycle, assistantinstall.KindRevisionConflict, assistantinstall.KindNoInstall:
		writeJSONError(w, http.StatusConflict, ie.Msg)
	case assistantinstall.KindUpstream:
		logHandlerErr("admin.agent_install", ie.Err)
		writeJSONError(w, http.StatusBadGateway, ie.Msg)
	case assistantinstall.KindUnavailable:
		logHandlerErr("admin.agent_install", ie.Err)
		writeJSONError(w, http.StatusServiceUnavailable, ie.Msg)
	default:
		logHandlerErr("admin.agent_install", ie.Err)
		writeJSONError(w, http.StatusInternalServerError, ie.Msg)
	}
}
