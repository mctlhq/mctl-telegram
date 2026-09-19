package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

// AccountCloser is the subset of *telegram.ClientPool that account handlers
// need. Kept narrow so the web package does not have to import telegram (and
// to make tests trivial). RemoveAtomic is required for disconnect/delete to
// be race-free against concurrent Borrow; Close stays around because the
// abstraction also covers tests that don't exercise concurrency.
type AccountCloser interface {
	Close(userID int64) bool
	RemoveAtomic(userID int64, fn func() error) error
}

// AccountHandlers exposes self-service controls for the authenticated user.
// Routes are registered as paths relative to the mount point — call
// mux.Mount("/api/account", router) and the effective URLs become:
//
//	GET    /api/account              -> {"connected":bool, …}
//	POST   /api/account/disconnect   -> {"disconnected":true, "had_active_session":bool}
//	DELETE /api/account              -> {"deleted":true, "rows_removed":int}
//	GET    /api/account/audit        -> {"entries":[…], "count":N}
//
// All handlers require an *auth.Identity in context — wire them behind the
// same auth middleware as the MCP endpoint. Anonymous requests get 401.
// Audit rows are written through the same Store.LogToolCall path used by MCP
// tools so /api/account calls show up in get_my_auditLog too.
type AccountHandlers struct {
	Store *db.Store
	Pool  AccountCloser
}

func NewAccountHandlers(store *db.Store, pool AccountCloser) *AccountHandlers {
	return &AccountHandlers{Store: store, Pool: pool}
}

// Register binds the account endpoints onto a router. Paths are
// relative — when mounted at "/api/account" the resulting routes are
// "/api/account", "/api/account/disconnect", DELETE "/api/account", and
// GET/PUT "/api/account/notifications". chi's *chi.Mux already satisfies
// the widened interface (it has a Put method), so no caller needs to change.
func (h *AccountHandlers) Register(mux interface {
	Get(pattern string, fn http.HandlerFunc)
	Post(pattern string, fn http.HandlerFunc)
	Put(pattern string, fn http.HandlerFunc)
	Delete(pattern string, fn http.HandlerFunc)
}) {
	mux.Get("/", h.get)
	mux.Post("/disconnect", h.disconnect)
	mux.Delete("/", h.delete)
	mux.Get("/audit", h.auditLog)
	mux.Get("/audit/verify", h.auditVerify)
	mux.Get("/notifications", h.getNotifications)
	mux.Put("/notifications", h.putNotifications)
}

func (h *AccountHandlers) get(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	info, err := h.Store.GetActiveAccount(r.Context(), id.UserID)
	h.audit(r, id, "GET /api/account", err)
	if err != nil {
		slog.Warn("account.get", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, info)
}

func (h *AccountHandlers) disconnect(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	// Pool eviction and DB revoke share the pool mutex via RemoveAtomic
	// so a concurrent Borrow() cannot race between them. See
	// telegram.ClientPool.RemoveAtomic for the full rationale.
	var had bool
	var err error
	if h.Pool != nil {
		err = h.Pool.RemoveAtomic(id.UserID, func() error {
			var e error
			had, e = h.Store.RevokeActiveSession(r.Context(), id.UserID, "disconnect")
			return e
		})
	} else {
		had, err = h.Store.RevokeActiveSession(r.Context(), id.UserID, "disconnect")
	}
	h.audit(r, id, "POST /api/account/disconnect", err)
	if err != nil {
		slog.Warn("account.disconnect", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "disconnect failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, map[string]any{
		"disconnected":       true,
		"had_active_session": had,
	})
}

func (h *AccountHandlers) delete(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var rows int64
	var err error
	if h.Pool != nil {
		err = h.Pool.RemoveAtomic(id.UserID, func() error {
			var e error
			rows, e = h.Store.HardDeleteAccount(r.Context(), id.UserID)
			return e
		})
	} else {
		rows, err = h.Store.HardDeleteAccount(r.Context(), id.UserID)
	}
	h.audit(r, id, "DELETE /api/account", err)
	if err != nil {
		slog.Warn("account.delete", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "delete failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, map[string]any{
		"deleted":      true,
		"rows_removed": rows,
	})
}

// auditLog handles GET /api/account/audit. Query params:
//
//	limit  — int, default 50, max 500
//	before — RFC3339; only entries strictly older than this are returned
//
// Returns {"entries":[…], "count":N}. Like the matching get_my_auditLog
// MCP tool, this handler never reads cross-user rows — the SQL filter is
// pinned to id.UserID resolved from the authenticated identity. We
// intentionally do NOT audit this call itself to avoid recursive
// audit-of-audit rows on every page fetch.
func (h *AccountHandlers) auditLog(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	q := r.URL.Query()
	limit := 50
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil {
			writeAccountErr(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
		limit = n
	}
	var before time.Time
	if raw := q.Get("before"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeAccountErr(w, http.StatusBadRequest, "before must be RFC3339")
			return
		}
		before = parsed
	}
	entries, err := h.Store.ListAuditFor(r.Context(), id.UserID, limit, before)
	if err != nil {
		slog.Warn("account.auditLog", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"count":   len(entries),
	})
}

// auditVerify handles GET /api/account/audit/verify. Walks the caller's
// audit-log rows and recomputes the hash chain. Returns the verification
// result verbatim (OK / Verified / FirstBadID / Reason). Anonymous-safe
// in the sense that the SQL filter still pins to id.UserID, but the
// endpoint itself requires authentication.
func (h *AccountHandlers) auditVerify(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	res, err := h.Store.VerifyAuditChain(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("account.audit_verify", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "verify failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, res)
}

// getNotifications handles GET /api/account/notifications. Returns every
// category with its resolved state, whether it was explicitly decided, its
// classification (marketing/operational) and source/decided_at when
// explicit.
func (h *AccountHandlers) getNotifications(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	prefs, err := h.Store.ResolveNotificationPrefs(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("account.get_notifications", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, map[string]any{"categories": prefs})
}

// maxNotificationsBodyBytes caps the PUT /api/account/notifications body
// before it reaches json.Decode, matching the MaxBytesReader pattern used
// for every other body decode in this codebase (oauth/server.go's
// handleClientRegistration, internal/agentapi/json.go, internal/workertoken/
// json.go). The category/state map is tiny in practice; 1 MiB is generous
// headroom while still bounding decoder memory against an oversized body.
const maxNotificationsBodyBytes = 1 << 20 // 1 MiB

// putNotifications handles PUT /api/account/notifications. The request body
// is {"<category>":"<state>", ...} — only the categories present are
// applied; every other category is left untouched. An unknown category or
// state rejects the WHOLE request with HTTP 400 and writes nothing. Audited
// with source "account_api"; the audit row records only the tool name and
// status, never the request body, matching the existing audit(...) helper's
// contract.
func (h *AccountHandlers) putNotifications(w http.ResponseWriter, r *http.Request) {
	id := auth.From(r.Context())
	if id == nil {
		writeAccountErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxNotificationsBodyBytes)
	var changes map[string]string
	if err := json.NewDecoder(r.Body).Decode(&changes); err != nil {
		writeAccountErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	err := h.Store.SetNotificationPrefs(r.Context(), id.UserID, changes, "account_api")
	h.audit(r, id, "PUT /api/account/notifications", err)
	if err != nil {
		if errors.Is(err, db.ErrUnknownNotificationCategory) || errors.Is(err, db.ErrUnknownNotificationState) {
			writeAccountErr(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Warn("account.put_notifications", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	prefs, err := h.Store.ResolveNotificationPrefs(r.Context(), id.UserID)
	if err != nil {
		slog.Warn("account.put_notifications: resolve after write", "err", err)
		writeAccountErr(w, http.StatusInternalServerError, "lookup failed")
		return
	}
	writeAccountJSON(w, http.StatusOK, map[string]any{"categories": prefs})
}

func (h *AccountHandlers) audit(r *http.Request, id *auth.Identity, tool string, err error) {
	status := "ok"
	msg := ""
	if err != nil {
		status = "error"
		msg = err.Error()
	}
	h.Store.LogToolCall(r.Context(), id.UserID, tool, "", status, msg, "")
}

func writeAccountJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAccountErr(w http.ResponseWriter, code int, msg string) {
	writeAccountJSON(w, code, map[string]string{"error": msg})
}
