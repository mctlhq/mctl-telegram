package mcpprobe

import (
	"context"
	"errors"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
)

// runModernNegatives checks that the server enforces the modern binding
// rather than merely tolerating a well-formed request.
//
// Each case mutates exactly one thing about an otherwise valid request, so a
// rejection can be attributed to that one thing. Note what is deliberately
// not tested: whether the routing headers are echoed back. Echo is not the
// contract — validation is — and a server that reflected headers while
// ignoring them would pass an echo test and fail every real gateway.
func runModernNegatives(ctx context.Context, c *rpcClient, o *Options, r *Report) {
	version := o.protocolVersion()
	id := 1000
	next := func() int { id++; return id }

	// A negative probe is still a request. If discovery did not succeed,
	// nothing has been established about this endpoint — including whether
	// it validates anything — so sending more traffic measures nothing and
	// the cases are recorded as unmeasured instead.
	// Each negative is gated on the positive step for the same method: the
	// tools/list cases need an unmutated tools/list to have worked, and the
	// tools/call cases need the guarded read-only call to have worked.
	listBaseline := stepOutcome(r, "tools_list") == OutcomePass
	callBaseline := stepOutcome(r, "tools_call_readonly") == OutcomePass

	if stepOutcome(r, "discover") != OutcomePass {
		for _, label := range mandatoryNegatives(ModeModern) {
			r.addNegative(Step{Label: label, Outcome: OutcomeSkipped, Reason: ReasonPrerequisiteFailed})
		}
		return
	}

	// initialize is removed in the modern protocol. A server that still
	// answers it has not implemented the modern path, whatever it advertises.
	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "modern_initialize_removed",
		Method: string(mcp.MethodInitialize),
	}, rpcRequest{
		method:          mcp.MethodInitialize,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		params: map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": probeClientName, "version": probeClientVersion},
		},
	}, ReasonMethodNotFound, listBaseline))

	deleted := (*string)(nil)
	mismatched := string(mcp.MethodPromptsList)

	// The protocol version header is part of the same binding. A request
	// whose metadata declares the modern version while the header is absent
	// is self-contradictory, and a server that serves it anyway is not
	// enforcing the version it claims to speak.
	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "missing_protocol_version_header",
		Method: string(mcp.MethodToolsList),
	}, rpcRequest{
		method:          mcp.MethodToolsList,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		headerOverrides: map[string]*string{mcp.HeaderProtocolVersion: deleted},
	}, ReasonHeaderMismatch, listBaseline))

	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "missing_method_header",
		Method: string(mcp.MethodToolsList),
	}, rpcRequest{
		method:          mcp.MethodToolsList,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		headerOverrides: map[string]*string{mcp.HeaderMethod: deleted},
	}, ReasonHeaderMismatch, listBaseline))

	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "mismatched_method_header",
		Method: string(mcp.MethodToolsList),
	}, rpcRequest{
		method:          mcp.MethodToolsList,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		headerOverrides: map[string]*string{mcp.HeaderMethod: &mismatched},
	}, ReasonHeaderMismatch, listBaseline))

	// The name-header cases need a tools/call, the only probed method whose
	// binding requires one. They are guarded by the same read-only check as
	// the positive call, and for the same reason: the probe is asserting
	// that a malformed request is refused, so it must not depend on that
	// refusal actually happening. Against a server that ignores the binding
	// the request goes through, and then the only thing standing between
	// this probe and an unintended side effect is the guard.
	if _, err := selectReadOnlyTool(r.Tools, o.Tool); err != nil {
		reason := ReasonToolNotReadOnly
		if errors.Is(err, errToolNotListed) {
			reason = ReasonToolNotListed
		}
		for _, label := range []string{"missing_name_header", "mismatched_name_header"} {
			r.addNegative(Step{Label: label, Method: string(mcp.MethodToolsCall), Tool: o.Tool,
				Outcome: OutcomeSkipped, Reason: reason})
		}
		return
	}
	callParams := map[string]any{"name": o.Tool, "arguments": map[string]any{}}

	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "missing_name_header",
		Method: string(mcp.MethodToolsCall),
		Tool:   o.Tool,
	}, rpcRequest{
		method:          mcp.MethodToolsCall,
		params:          callParams,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		headerOverrides: map[string]*string{mcp.HeaderName: deleted},
	}, ReasonHeaderMismatch, callBaseline))

	otherName, _ := mcp.EncodeHeaderValue(o.Tool + "_not_this_one")
	r.addNegative(expectRejection(ctx, c, Step{
		Label:  "mismatched_name_header",
		Method: string(mcp.MethodToolsCall),
		Tool:   o.Tool,
	}, rpcRequest{
		method:          mcp.MethodToolsCall,
		params:          callParams,
		id:              next(),
		modern:          true,
		protocolVersion: version,
		headerOverrides: map[string]*string{mcp.HeaderName: &otherName},
	}, ReasonHeaderMismatch, callBaseline))
}

// expectRejection runs a request that must not succeed. A 2xx with no
// JSON-RPC error is the failure case here: it means the server accepted
// something the protocol says it must refuse.
// expectRejection runs a request that must not succeed, and — this is the
// part that makes the result mean anything — only counts a rejection as
// evidence when the unmutated request is known to have succeeded.
//
// Without that baseline the cell is a false positive waiting to happen. An
// endpoint that serves discovery anonymously but wants a bearer for
// tools/list answers 401 to every one of these probes, and a naive reading
// would record "the binding is enforced" from a refusal the mutated header
// had no part in. The summary would still fail the run, but the per-cell
// claim is the entire point of this probe, so being wrong there is worse
// than being silent.
//
// baselinePassed says whether the same method succeeded unmutated earlier in
// this run. When it did not, the case is reported as unmeasured rather than
// guessed.
func expectRejection(ctx context.Context, c *rpcClient, step Step, req rpcRequest, want Reason, baselinePassed bool) Step {
	if !baselinePassed {
		step.Outcome, step.Reason = OutcomeSkipped, ReasonPrerequisiteFailed
		return step
	}
	out, err := c.do(ctx, req)
	if err != nil && !errors.Is(err, errMalformedBody) {
		step.Outcome, step.Reason = OutcomeFail, ReasonTransport
		return step
	}
	step.HTTPStatus = out.httpStatus
	step.JSONRPCode = out.errorCode
	switch {
	case out.httpStatus == http.StatusUnauthorized || out.httpStatus == http.StatusForbidden:
		// An authentication refusal is not a protocol refusal, even though
		// both are refusals. Recording it as enforcement would credit the
		// server for a check it never performed.
		step.Outcome, step.Reason = OutcomeSkipped, ReasonUnauthenticatedProbe
	case out.errorCode != nil:
		step.Outcome, step.Reason = OutcomePass, want
	case out.httpStatus >= 400:
		// Rejected at the HTTP layer without a JSON-RPC envelope. Still a
		// rejection, and still the behaviour a gateway needs.
		step.Outcome, step.Reason = OutcomePass, want
	default:
		step.Outcome, step.Reason = OutcomeFail, ReasonUnexpectedSuccess
	}
	return step
}
