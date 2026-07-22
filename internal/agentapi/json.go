package agentapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// writeJSON encodes body as the response, setting Content-Type and status
// code first so a marshal error mid-stream cannot flip an already-sent 200
// into something else — matches the fire-and-forget encode style used
// elsewhere in this codebase (bridge.writeJSONError, web.writeAccountJSON).
func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// writeJSONError writes a JSON {"error": msg} body. Duplicated locally
// rather than imported, matching the established convention in this codebase
// (see internal/bridge/tokenhandler.go's writeJSONError comment) — each
// HTTP-facing package owns its own copy so error-response shape can drift
// independently and no package needs an extra cross-import just for this.
func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// maxRequestBodyBytes caps every POST body this package decodes. Without it
// a compromised long-lived agent token (see tokenhandler.go's TTL — weeks,
// not hours) could POST an unbounded body to any action endpoint; the
// notification/action handlers encrypt and persist whatever they're given,
// so an unbounded body is both a memory-exhaustion and a storage-bloat
// vector. 1 MiB is comfortably above any legitimate payload here (message
// text, lead details) with headroom.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// decodeStrict decodes the request body into dst, rejecting unknown fields,
// trailing data, and bodies over maxRequestBodyBytes. This is this package's
// "strict JSON schema validation" (see A-PR6 issue spec) for the shape of the
// payload — required-field and value-range checks are the caller's job on
// top of a successful decode.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// identity returns the caller's *auth.Identity or writes a 401 and reports
// ok=false. Every handler in this package starts with this call — the outer
// auth.Middleware(agentProvider, true, m) already guarantees a non-nil
// Identity in practice, but each handler still guards defensively rather
// than trusting a context value blindly, matching
// internal/bridge/tokenhandler.go's pattern.
func identity(w http.ResponseWriter, r *http.Request) (*auth.Identity, bool) {
	id := auth.From(r.Context())
	if id == nil {
		writeJSONError(w, http.StatusUnauthorized, "authentication required")
		return nil, false
	}
	return id, true
}

// audit is a thin wrapper over Store.LogToolCall so every handler logs with
// the same call shape. callPath is always "" (hosted call, not bridge-
// relayed) — the agent worker talks to this API directly, there is no local
// bridge daemon in this path.
func (s *Server) audit(ctx context.Context, userID int64, tool, status, errMsg string) {
	if s.Store == nil {
		return
	}
	s.Store.LogToolCall(ctx, userID, tool, "", status, errMsg, "")
}

func logHandlerErr(tool string, err error) {
	slog.Warn("agentapi handler error", "tool", tool, "err", err)
}
