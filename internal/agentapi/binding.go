package agentapi

import (
	"fmt"
	"net/http"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// A job credential (audience "agent-job", minted by handleClaimJobs) is bound
// to one job, one attempt and one conversation through signed claims. The
// account-wide "agent" token carries none of them and is never restricted
// here. A credential counts as bound when it carries a job id, even if the
// job has no conversation yet: such a token must not reach any conversation.

// jobBound reports whether id is a job-bound credential.
func jobBound(id *auth.Identity) bool { return id != nil && id.JobID != 0 }

// denyBinding writes the 403 and audits the refusal as "denied".
func (s *Server) denyBinding(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool, reason string) {
	s.audit(r.Context(), id.UserID, tool, "denied", "conversation binding: "+reason)
	writeJSONError(w, http.StatusForbidden, "credential is bound to another conversation")
}

// enforceBinding checks the conversation, job and attempt a request names
// against the credential's binding. A zero request value means "not named"
// and is not compared. It is a no-op for an account token. It reports
// whether the request may proceed; when false the response is written.
func (s *Server) enforceBinding(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool string, convID, jobID int64, attempt int) bool {
	if !jobBound(id) {
		return true
	}
	if convID != 0 && convID != id.ConversationID {
		s.denyBinding(w, r, id, tool, fmt.Sprintf("token conv=%d request conv=%d", id.ConversationID, convID))
		return false
	}
	if jobID != 0 && jobID != id.JobID {
		s.denyBinding(w, r, id, tool, fmt.Sprintf("token job=%d request job=%d", id.JobID, jobID))
		return false
	}
	if attempt != 0 && attempt != id.JobAttempt {
		s.denyBinding(w, r, id, tool, fmt.Sprintf("token attempt=%d request attempt=%d", id.JobAttempt, attempt))
		return false
	}
	return true
}

// requireAccountToken rejects a job credential on routes that claim or list
// work across conversations. It reports whether the request may proceed.
func (s *Server) requireAccountToken(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool string) bool {
	if !jobBound(id) {
		return true
	}
	s.denyBinding(w, r, id, tool, "job credential cannot call an account-scoped route")
	return false
}
