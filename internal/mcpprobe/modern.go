package mcpprobe

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
)

// discoverResult is the subset of server/discover the report keeps.
type discoverResult struct {
	SupportedVersions []string  `json:"supportedVersions"`
	Meta              *mcp.Meta `json:"_meta"`
}

// runModern drives the stateless 2026-07-28 path: server/discover, then
// tools/list, then at most one read-only tools/call.
//
// There is no initialize here and no fallback to the legacy lifecycle. If
// discovery fails, the run reports a failed modern measurement; it does not
// quietly become a legacy run wearing a modern label.
func runModern(ctx context.Context, c *rpcClient, o *Options, r *Report) error {
	version := o.protocolVersion()
	id := 0
	next := func() int { id++; return id }

	discover, err := c.do(ctx, rpcRequest{
		method:          mcp.MethodServerDiscover,
		id:              next(),
		modern:          true,
		protocolVersion: version,
	})
	step := Step{Label: "discover", Method: string(mcp.MethodServerDiscover)}
	if err != nil && !errors.Is(err, errMalformedBody) {
		step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		r.addStep(step)
		return err
	}
	step.HTTPStatus = discover.httpStatus
	step.JSONRPCode = discover.errorCode
	noteSession(r, discover)
	switch {
	case errors.Is(err, errMalformedBody):
		step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
	case discover.errorCode != nil:
		step.Outcome, step.Reason = OutcomeFail, ReasonJSONRPCError
	case discover.httpStatus != 200:
		step.Outcome, step.Reason = OutcomeFail, ReasonHTTPStatus
	default:
		var parsed discoverResult
		if json.Unmarshal(discover.result, &parsed) != nil {
			step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
			break
		}
		r.Server.SupportedVersions = parsed.SupportedVersions
		if info := parsed.Meta.ServerInfo(); info != nil {
			r.Server.Name, r.Server.Version = info.Name, info.Version
		}
		step.Outcome = OutcomePass
	}
	r.addStep(step)
	if step.Outcome != OutcomePass {
		// Everything downstream needs a working modern path; recording them
		// as failures too would multiply one finding into several.
		r.addStep(Step{Label: "tools_list", Method: string(mcp.MethodToolsList),
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		r.addStep(Step{Label: "tools_call_readonly", Method: string(mcp.MethodToolsCall), Tool: o.Tool,
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		return nil
	}

	// Session observation continues past discovery: the claim is that the
	// modern path mints no identifier at all, and a run that only inspected
	// the first response would not have measured the later ones.
	listed := probeToolsList(ctx, c, r, rpcRequest{
		method:          mcp.MethodToolsList,
		id:              next(),
		modern:          true,
		protocolVersion: version,
	})
	if !listed {
		r.addStep(Step{Label: "tools_call_readonly", Method: string(mcp.MethodToolsCall), Tool: o.Tool,
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		return nil
	}

	probeReadOnlyCall(ctx, c, o, r, func(params any) rpcRequest {
		return rpcRequest{
			method:          mcp.MethodToolsCall,
			params:          params,
			id:              next(),
			modern:          true,
			protocolVersion: version,
		}
	})
	return nil
}

// probeToolsList performs tools/list and records the reduced inventory.
func probeToolsList(ctx context.Context, c *rpcClient, r *Report, req rpcRequest) bool {
	out, err := c.do(ctx, req)
	step := Step{Label: "tools_list", Method: string(mcp.MethodToolsList)}
	if err != nil && !errors.Is(err, errMalformedBody) {
		step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		r.addStep(step)
		return false
	}
	step.HTTPStatus = out.httpStatus
	step.JSONRPCode = out.errorCode
	noteSession(r, out)
	switch {
	case errors.Is(err, errMalformedBody):
		step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
	case out.errorCode != nil:
		step.Outcome, step.Reason = OutcomeFail, ReasonJSONRPCError
	case out.httpStatus != 200:
		step.Outcome, step.Reason = OutcomeFail, ReasonHTTPStatus
	default:
		tools, perr := parseTools(out.result)
		if perr != nil {
			step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
			break
		}
		r.Tools = tools
		step.Outcome = OutcomePass
	}
	r.addStep(step)
	return step.Outcome == OutcomePass
}

// probeReadOnlyCall invokes exactly one tool, and only when the server's own
// annotation says it is read-only.
func probeReadOnlyCall(ctx context.Context, c *rpcClient, o *Options, r *Report, build func(params any) rpcRequest) {
	step := Step{Label: "tools_call_readonly", Method: string(mcp.MethodToolsCall), Tool: o.Tool}
	if _, err := selectReadOnlyTool(r.Tools, o.Tool); err != nil {
		step.Outcome = OutcomeSkipped
		if errors.Is(err, errToolNotListed) {
			step.Reason = ReasonToolNotListed
		} else {
			step.Reason = ReasonToolNotReadOnly
		}
		r.addStep(step)
		return
	}
	out, err := c.do(ctx, build(map[string]any{"name": o.Tool, "arguments": map[string]any{}}))
	if err != nil && !errors.Is(err, errMalformedBody) {
		step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		r.addStep(step)
		return
	}
	step.HTTPStatus = out.httpStatus
	step.JSONRPCode = out.errorCode
	noteSession(r, out)
	switch {
	case errors.Is(err, errMalformedBody):
		step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
	case out.errorCode != nil:
		step.Outcome, step.Reason = OutcomeFail, ReasonJSONRPCError
	case out.httpStatus != 200:
		step.Outcome, step.Reason = OutcomeFail, ReasonHTTPStatus
	default:
		// isError is a protocol-level flag, not content: recording it says
		// whether the call succeeded without repeating anything the tool
		// produced.
		var envelope struct {
			IsError bool `json:"isError"`
		}
		if json.Unmarshal(out.result, &envelope) != nil {
			step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
			break
		}
		step.IsError = boolPtr(envelope.IsError)
		if envelope.IsError {
			step.Outcome, step.Reason = OutcomeFail, ReasonToolReportedError
		} else {
			step.Outcome = OutcomePass
		}
	}
	r.addStep(step)
}

// noteSession records whether a response carried a session identifier. The
// value is never stored: presence and length answer the compatibility
// question, and the identifier is a credential for the session it names.
func noteSession(r *Report, out rpcOutcome) {
	if out.sessionID == "" {
		return
	}
	r.Session.HeaderPresent = true
	r.Session.IDLength = len(out.sessionID)
}
