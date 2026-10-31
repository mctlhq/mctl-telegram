package agentapi

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/mctlhq/mctl-telegram/internal/agent/policy"
	"github.com/mctlhq/mctl-telegram/internal/agent/tools"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// The tool set a job carries is a capability boundary, not only the list
// the model is shown (#1041). Each route a worker's MCP tool calls is mapped
// to its tools in tools.Endpoints; a request to such a route is refused
// unless the caller's tool set holds one of them. A forged MCP config or a
// direct request with the job's own token reaches no further than the
// definition allows.
//
// The tool set comes from the credential, never from the request:
//   - a job token carries it as the signed claim job_tools, bound at claim
//     from the account's resolved definition;
//   - an account-wide token, or a job token minted before that claim
//     existed, has it resolved from the account's installed definition on
//     every request. A definition that cannot be resolved refuses the
//     request: a tool set that could not be read is not the full one.

// errToolSetUnknown means the caller's tool set could not be resolved.
var errToolSetUnknown = errors.New("tool set unknown")

// toolGate wraps h, the handler of route ("METHOD pattern"), with the tool
// check. A route that serves no tool, or a mandatory one every tool set
// holds, is returned unwrapped.
func (s *Server) toolGate(route string, h http.HandlerFunc) http.HandlerFunc {
	served, ok := tools.Endpoints[route]
	if !ok || slices.ContainsFunc(served, func(t string) bool { return slices.Contains(tools.Mandatory, t) }) {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		id := auth.From(r.Context())
		if id == nil {
			h(w, r) // writes the 401
			return
		}
		set, err := s.toolSet(r.Context(), id)
		if err != nil {
			logHandlerErr(served[0], err)
			s.audit(r.Context(), id.UserID, served[0], "denied", "tool gate: "+errToolSetUnknown.Error())
			writeJSONError(w, http.StatusServiceUnavailable, "tool set unavailable")
			return
		}
		if !slices.ContainsFunc(served, func(t string) bool { return slices.Contains(set, t) }) {
			s.audit(r.Context(), id.UserID, served[0], "denied", "tool gate: "+string(policy.DenyToolNotAllowed))
			s.m.CountPolicyDenial(string(policy.DenyToolNotAllowed), metrics.PolicySurfaceToolGate)
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": string(policy.DenyToolNotAllowed),
				"tool":  served[0],
			})
			return
		}
		h(w, r)
	}
}

// toolSet returns the canonical tools id may call: the job token's signed
// claim when it has one, otherwise the account's.
func (s *Server) toolSet(ctx context.Context, id *auth.Identity) ([]string, error) {
	if jobBound(id) && len(id.JobTools) > 0 {
		return id.JobTools, nil
	}
	return s.accountTools(ctx, id.UserID)
}

// accountTools resolves the canonical tool set of userID's installed
// definition, the same definition a claim would bind. Without a catalog, or
// without a configured assistant, no definition restricts the account and
// every tool is allowed, as a claim would bind then. The registry lifecycle
// is not applied: it decides whether new jobs start, not which tools a job
// may call.
func (s *Server) accountTools(ctx context.Context, userID int64) ([]string, error) {
	if s.catalog == nil {
		return tools.Canonical, nil
	}
	a, err := s.Store.GetAgentAssistant(ctx, userID)
	if errors.Is(err, db.ErrAgentProfileNotFound) {
		return tools.Canonical, nil
	}
	if err != nil {
		return nil, err
	}
	entry, _, err := s.lookupAssistant(ctx, a)
	if err != nil {
		return nil, err
	}
	bindings, err := tools.ForJob(entry.Definition.Spec.Tools)
	if err != nil {
		return nil, err
	}
	return tools.CanonicalNames(bindings), nil
}
