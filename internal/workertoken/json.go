package workertoken

import (
	"encoding/json"
	"net/http"
)

// writeJSON encodes body as the response, setting Content-Type and status
// code first so a marshal error mid-stream cannot flip an already-sent 200
// into something else — matches internal/agentapi/json.go's writeJSON.
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

// maxRequestBodyBytes caps the POST body this package decodes. Mirrors
// internal/agentapi/json.go's rationale: an unbounded body is a memory-
// exhaustion vector even for a small request shape like this one.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// decodeStrict decodes the request body into dst, rejecting unknown fields,
// trailing data, and bodies over maxRequestBodyBytes. Matches
// internal/agentapi/json.go's decodeStrict.
func decodeStrict(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
