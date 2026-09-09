package mcpprobe

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
)

// syntheticSessionID returns an identifier shaped like the one the server
// issued but with a different body, so a server that validates only the
// format accepts it while one tracking real sessions does not.
//
// The replacement is a fixed nil-ish UUID rather than a random one: a probe
// should be reproducible, and this value is a credential for nothing. When
// the issued identifier does not end in something UUID-shaped, the bare
// synthetic UUID is returned rather than guessing at the format.
func syntheticSessionID(issued string) string {
	const syntheticUUID = "00000000-0000-4000-8000-000000000000"
	if len(issued) > len(syntheticUUID) {
		return issued[:len(issued)-len(syntheticUUID)] + syntheticUUID
	}
	return syntheticUUID
}

// initializeResult is the slice of a legacy initialize response the report
// keeps: the version the server actually selected and who it says it is.
type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

// runLegacy drives the 2025-era lifecycle: initialize, capture whatever
// session identifier is minted, then list and call using it.
//
// It also answers a question the modern path cannot: whether that identifier
// is merely issued or actually required. A server that mints an identifier
// and then accepts requests without it is not session-bound, and knowing
// which of the two it is decides whether anything in front of it needs
// session affinity.
func runLegacy(ctx context.Context, c *rpcClient, o *Options, r *Report) error {
	version := o.protocolVersion()
	id := 0
	next := func() int { id++; return id }

	out, err := c.do(ctx, rpcRequest{
		method: mcp.MethodInitialize,
		id:     next(),
		params: map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": probeClientName, "version": probeClientVersion},
		},
	})
	step := Step{Label: "initialize", Method: string(mcp.MethodInitialize)}
	if err != nil && !errors.Is(err, errMalformedBody) {
		step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		r.addStep(step)
		return err
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
		var parsed initializeResult
		if json.Unmarshal(out.result, &parsed) != nil {
			step.Outcome, step.Reason = OutcomeFail, ReasonMalformedBody
			break
		}
		r.Server.Name = parsed.ServerInfo.Name
		r.Server.Version = parsed.ServerInfo.Version
		if parsed.ProtocolVersion != "" {
			r.Server.SupportedVersions = []string{parsed.ProtocolVersion}
		}
		step.Outcome = OutcomePass
	}
	r.addStep(step)
	if step.Outcome != OutcomePass {
		r.addStep(Step{Label: "tools_list", Method: string(mcp.MethodToolsList),
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		r.addStep(Step{Label: "tools_call_readonly", Method: string(mcp.MethodToolsCall), Tool: o.Tool,
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		return nil
	}

	session := out.sessionID
	// Is the identifier load-bearing? Ask without it and see. A server that
	// never minted one has nothing to answer, so the field stays unset
	// rather than claiming a measurement that was not taken.
	if session == "" {
		r.addStep(Step{Label: "tools_list_without_session", Method: string(mcp.MethodToolsList),
			Outcome: OutcomeSkipped, Reason: ReasonNoSessionID})
	} else {
		probe, perr := c.do(ctx, rpcRequest{method: mcp.MethodToolsList, id: next()})
		bare := Step{Label: "tools_list_without_session", Method: string(mcp.MethodToolsList)}
		if perr != nil && !errors.Is(perr, errMalformedBody) {
			bare.Outcome, bare.Reason = OutcomeFail, ReasonTransport
		} else {
			bare.HTTPStatus = probe.httpStatus
			bare.JSONRPCode = probe.errorCode
			rejected := probe.httpStatus >= 400 || probe.errorCode != nil
			r.Session.Required = boolPtr(rejected)
			// Either answer is a valid measurement of this deployment, so
			// the step passes and the report carries the observation.
			bare.Outcome = OutcomePass
		}
		r.addStep(bare)
	}

	// Second question: does the identifier have to be one this process
	// issued? A synthetic value of the same shape separates a server that
	// merely wants the header from one that is genuinely session-bound, and
	// only the latter forces a router to pin requests to a replica.
	if session != "" {
		foreign := syntheticSessionID(session)
		probe, perr := c.do(ctx, rpcRequest{method: mcp.MethodToolsList, id: next(), sessionID: foreign})
		step := Step{Label: "tools_list_with_foreign_session", Method: string(mcp.MethodToolsList)}
		if perr != nil && !errors.Is(perr, errMalformedBody) {
			step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		} else {
			step.HTTPStatus = probe.httpStatus
			step.JSONRPCode = probe.errorCode
			accepted := probe.httpStatus < 400 && probe.errorCode == nil
			r.Session.ForeignAccepted = boolPtr(accepted)
			step.Outcome = OutcomePass
		}
		r.addStep(step)
	}

	if !probeToolsList(ctx, c, r, rpcRequest{method: mcp.MethodToolsList, id: next(), sessionID: session}) {
		r.addStep(Step{Label: "tools_call_readonly", Method: string(mcp.MethodToolsCall), Tool: o.Tool,
			Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		return nil
	}
	probeReadOnlyCall(ctx, c, o, r, func(params any) rpcRequest {
		return rpcRequest{method: mcp.MethodToolsCall, params: params, id: next(), sessionID: session}
	})
	return nil
}
