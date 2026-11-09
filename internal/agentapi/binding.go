package agentapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
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

// denyBindingCode is denyBinding with a stable typed code (#1267): the audit
// row's error column reads "conversation binding: <code>: <detail>" (detail
// holds only numeric ids from the credential and request, never message text)
// and the denial is counted under that policy.DenyCode. The audit write is
// checked: when it fails the request is still refused (fail closed) but with a
// sanitized 500, not the 403 that would imply a recorded denial.
func (s *Server) denyBindingCode(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool string, code policy.DenyCode, detail string) {
	s.m.CountPolicyDenial(string(code), metrics.PolicySurfaceToolGate)
	if err := s.auditChecked(r.Context(), id.UserID, tool, "denied", "conversation binding: "+string(code)+": "+detail); err != nil {
		writeBindingAuditFailure(w, tool, err)
		return
	}
	writeJSONError(w, http.StatusForbidden, "credential is bound to another conversation")
}

// auditChecked is audit with the write outcome returned, for refusals that must
// not be reported as recorded unless the chained row was committed. It uses the
// same single audit implementation (chain, scrubbing, tenant scoping) as audit.
func (s *Server) auditChecked(ctx context.Context, userID int64, tool, status, errMsg string) error {
	if s.Store == nil {
		return nil
	}
	return s.Store.LogToolCallChecked(ctx, db.ToolCall{UserID: userID, Tool: tool, Status: status, ErrMsg: errMsg})
}

// writeBindingAuditFailure answers a binding refusal whose durable audit write
// failed: a sanitized 500, never the normal denial (which would imply a record
// exists). The caller has already stopped before any business effect.
func writeBindingAuditFailure(w http.ResponseWriter, tool string, err error) {
	logHandlerErr(tool+"_binding_audit", err)
	writeJSONError(w, http.StatusInternalServerError, "denial could not be recorded")
}

// enforceBinding checks the conversation, job and attempt a request names
// against the credential's binding. A zero request value means "not named"
// and is not compared. It is a no-op for an account token. It reports
// whether the request may proceed; when false the response is written.
// Routes that act (propose, notify, save lead) must also call
// requireBoundJob: a read route may omit the job, an action may not.
func (s *Server) enforceBinding(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool string, convID, jobID int64, attempt int) bool {
	if !jobBound(id) {
		return true
	}
	if convID != 0 && convID != id.ConversationID {
		s.denyBindingCode(w, r, id, tool, policy.DenyJobBindingMismatch, fmt.Sprintf("token conv=%d request conv=%d", id.ConversationID, convID))
		return false
	}
	if jobID != 0 && jobID != id.JobID {
		s.denyBindingCode(w, r, id, tool, policy.DenyJobBindingMismatch, fmt.Sprintf("token job=%d request job=%d", id.JobID, jobID))
		return false
	}
	if attempt != 0 && attempt != id.JobAttempt {
		s.denyBindingCode(w, r, id, tool, policy.DenyJobBindingMismatch, fmt.Sprintf("token attempt=%d request attempt=%d", id.JobAttempt, attempt))
		return false
	}
	return true
}

// requireBoundJob refuses an action from a job credential that does not name
// its own job and attempt. Without it an omitted job_id would skip every job
// check and land as a standalone, jobless action (#1267). It is a no-op for
// an account token, whose jobless actions are a supported contract. Call it
// after enforceBinding; it runs before any business effect.
func (s *Server) requireBoundJob(w http.ResponseWriter, r *http.Request, id *auth.Identity, tool string, jobID int64, attempt int) bool {
	if !jobBound(id) {
		return true
	}
	if jobID == 0 || attempt == 0 {
		s.denyBindingCode(w, r, id, tool, policy.DenyJobBindingMissing, fmt.Sprintf("token job=%d attempt=%d request job=%d attempt=%d", id.JobID, id.JobAttempt, jobID, attempt))
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

// requireNotPool makes a route unreachable for the managed-runtime pool
// credential (aud "agent-pool"), which may only call POST /jobs/claim. It
// runs outside toolGate: the gate resolves a tool set from id.UserID, which
// is 0 for a pool. The refusal is a slog line and a policy-denial metric;
// audit_logs.user_id is a foreign key to users, so a row is written only
// under the job owner when the route names a job that resolves.
func (s *Server) requireNotPool(route string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := auth.From(r.Context())
		if !id.IsPool() {
			h(w, r)
			return
		}
		slog.Warn("agentapi pool credential refused", "pool", id.Pool, "route", route, "jti", id.Jti)
		s.m.CountPolicyDenial("pool_claim_only", metrics.PolicySurfaceToolGate)
		if s.Store != nil && strings.Contains(route, "/jobs/{id}") {
			if jobID, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64); err == nil {
				if owner, found, err := s.Store.AgentJobOwner(r.Context(), jobID); err == nil && found {
					s.audit(r.Context(), owner, route, "denied", "pool:"+id.Pool+" claim-only")
				}
			}
		}
		writeJSONError(w, http.StatusForbidden, "pool_credential_claim_only")
	}
}
