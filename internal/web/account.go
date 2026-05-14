package web

import (
	"encoding/json"
	"log/slog"
	"net/http"

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
//
// All handlers require an *auth.Identity in context — wire them behind the
// same auth middleware as the MCP endpoint. Anonymous requests get 401.
// Audit rows are written through the same Store.LogToolCall path used by MCP
// tools so /api/account calls show up in get_my_audit_log too.
type AccountHandlers struct {
	Store *db.Store
	Pool  AccountCloser
}

func NewAccountHandlers(store *db.Store, pool AccountCloser) *AccountHandlers {
	return &AccountHandlers{Store: store, Pool: pool}
}

// Register binds the three account endpoints onto a router. Paths are
// relative — when mounted at "/api/account" the resulting routes are
// "/api/account", "/api/account/disconnect", and DELETE "/api/account".
func (h *AccountHandlers) Register(mux interface {
	Get(pattern string, fn http.HandlerFunc)
	Post(pattern string, fn http.HandlerFunc)
	Delete(pattern string, fn http.HandlerFunc)
}) {
	mux.Get("/", h.get)
	mux.Post("/disconnect", h.disconnect)
	mux.Delete("/", h.delete)
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
			had, e = h.Store.RevokeActiveSession(r.Context(), id.UserID)
			return e
		})
	} else {
		had, err = h.Store.RevokeActiveSession(r.Context(), id.UserID)
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

func (h *AccountHandlers) audit(r *http.Request, id *auth.Identity, tool string, err error) {
	status := "ok"
	msg := ""
	if err != nil {
		status = "error"
		msg = err.Error()
	}
	h.Store.LogToolCall(r.Context(), id.UserID, tool, "", status, msg)
}

func writeAccountJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAccountErr(w http.ResponseWriter, code int, msg string) {
	writeAccountJSON(w, code, map[string]string{"error": msg})
}
