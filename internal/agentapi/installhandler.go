package agentapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	agentprofile "github.com/mctlhq/mctl-telegram/internal/agent/profile"
	"github.com/mctlhq/mctl-telegram/internal/assistant"
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
		in, err := assistant.ParseInstall(req.Install)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid install: "+err.Error())
			return
		}
		reqRef := in.Spec.Assistant.Name + "@" + in.Spec.Assistant.Version
		var entry *assistant.Entry
		lifecycle := ""
		if registry == nil {
			e, ok := catalog.Lookup(in.Spec.Assistant.Name, in.Spec.Assistant.Version)
			if !ok {
				writeJSONError(w, http.StatusBadRequest, "unknown assistant "+reqRef)
				return
			}
			entry = e
		} else {
			fetched, err := registry.Fetch(r.Context(), in.Spec.Assistant.Name, in.Spec.Assistant.Version)
			switch {
			case errors.Is(err, assistantregistry.ErrNotFound):
				writeJSONError(w, http.StatusNotFound, "unknown assistant "+reqRef)
				return
			case errors.Is(err, assistantregistry.ErrDigestMismatch):
				logHandlerErr("admin.agent_install", err)
				writeJSONError(w, http.StatusBadGateway, "assistant registry digest mismatch: install refused")
				return
			case errors.Is(err, assistantregistry.ErrInvalid):
				logHandlerErr("admin.agent_install", err)
				writeJSONError(w, http.StatusBadGateway, "assistant registry returned an invalid definition: install refused")
				return
			case err != nil:
				logHandlerErr("admin.agent_install", err)
				writeJSONError(w, http.StatusServiceUnavailable, "assistant registry unavailable")
				return
			}
			entry, lifecycle = fetched.Entry, fetched.Lifecycle
			if lifecycle == db.AssistantLifecycleDisabled {
				writeJSONError(w, http.StatusConflict, "assistant "+reqRef+" is disabled")
				return
			}
		}
		resolved, err := assistant.Resolve(entry.Definition, in)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid install: "+err.Error())
			return
		}
		parsed, err := agentprofile.ParseJSON(resolved.OwnerProfile)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid install: owner profile")
			return
		}
		ownerProfile, err := json.Marshal(parsed)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid install: owner profile")
			return
		}
		var installDoc bytes.Buffer
		if err := json.Compact(&installDoc, req.Install); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid install")
			return
		}
		installBytes := installDoc.Bytes()

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
		if err := store.EnsureAgentProfile(ctx, targetUserID); err != nil {
			logHandlerErr("admin.agent_install", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to initialize agent profile")
			return
		}

		name, version := entry.Definition.Metadata.Name, entry.Definition.Metadata.Version
		// Every install, including a switch to another assistant, moves the
		// install revision in the same UPDATE as the settings. Work created
		// under an earlier revision is refused at propose, approve and send
		// (#1018), so no queued job or pending approval of the old install
		// can act; denying its proposed and approved actions below is only
		// cleanup (drafts awaiting approval are refused at /mctl approve,
		// which tells the owner why).
		// Conversation transcripts stay as account history.
		current, err := store.GetAgentAssistantRef(ctx, targetUserID)
		if err != nil {
			logHandlerErr("admin.agent_install", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load current assistant")
			return
		}
		switching := current.Name != name
		// A deprecated version stays with the accounts that installed it;
		// it is not offered to new ones. A never-installed profile names
		// hr-recruiter@0.1.0 only through the column defaults, which is not
		// an install of it.
		if lifecycle == db.AssistantLifecycleDeprecated && (!current.Installed || switching || current.Version != version) {
			writeJSONError(w, http.StatusConflict, "assistant "+reqRef+" is deprecated: only an account already running it may reinstall it")
			return
		}
		installedAt := time.Now()
		digest := entry.Digest
		update := db.AgentProfileUpdate{
			Mode:                 &resolved.Mode,
			AutopilotPaused:      &resolved.AutopilotPaused,
			ListenerEnabled:      &resolved.ListenerEnabled,
			DisclosureText:       &resolved.DisclosureText,
			DisclosureDisabled:   &resolved.DisclosureDisabled,
			MaxAutonomousTurns:   &resolved.MaxAutonomousTurns,
			MaxMsgsPerMinute:     &resolved.MaxMsgsPerMinute,
			MaxReplyChars:        &resolved.MaxReplyChars,
			IntentAllowlist:      &resolved.IntentAllowlist,
			IntentDenylist:       &resolved.IntentDenylist,
			WorkingHours:         &resolved.WorkingHours,
			AudienceExcludes:     &resolved.AudienceExcludes,
			BumpInstallRevision:  true,
			AssistantDigest:      &digest,
			BlockedSenders:       &resolved.BlockedSenders,
			SenderAllowlist:      &resolved.SenderAllowlist,
			AssistantName:        &name,
			AssistantVersion:     &version,
			InstallDocument:      &installBytes,
			OwnerProfileDocument: &ownerProfile,
		}
		// A new assistant's new chats start at the switch; a reinstall of
		// the same one keeps its first install moment.
		if switching {
			update.ResetInstalledAt = &installedAt
		} else {
			update.MarkInstalledAt = &installedAt
		}
		var saveErr error
		if registry != nil {
			saveErr = store.InstallAgentAssistant(ctx, targetUserID, db.AssistantDefinition{
				Digest: digest, Name: name, Version: version,
				Document: entry.Materialized, Lifecycle: lifecycle,
			}, update)
		} else {
			saveErr = store.UpdateAgentProfileFields(ctx, targetUserID, update)
		}
		if err := saveErr; err != nil {
			logHandlerErr("admin.agent_install", err)
			store.LogToolCall(ctx, db.ToolCall{UserID: id.UserID, Tool: "admin.agent_install", Status: "error", ErrMsg: err.Error()})
			writeJSONError(w, http.StatusInternalServerError, "failed to save agent install")
			return
		}
		if _, err := store.DenyActionsFromEarlierInstalls(ctx, targetUserID, policy.ReasonInstallChanged); err != nil {
			// Cleanup only: the revision check already keeps these from
			// acting, so the install stands.
			logHandlerErr("admin.agent_install", err)
		}
		p, err := store.GetAgentProfile(ctx, targetUserID)
		if err != nil {
			logHandlerErr("admin.agent_install", err)
			writeJSONError(w, http.StatusInternalServerError, "failed to load saved profile")
			return
		}

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
