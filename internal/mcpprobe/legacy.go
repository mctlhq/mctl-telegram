package mcpprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

// LegacyConfig configures one ModeLegacy probe run: the pre-2026-07-28
// initialize/session lifecycle mctl-telegram's own current clients
// (cmd/canary, the load generator) use.
type LegacyConfig struct {
	// BaseURL is the scheme://host[:port] of the target. Required.
	BaseURL string
	// MCPPath is the MCP endpoint path. Defaults to DefaultMCPPath.
	MCPPath string
	// ProtocolVersion is the legacy protocol version negotiated at
	// initialize. Defaults to DefaultLegacyProtocolVersion. Operator
	// configurable, per requirements.md acceptance criterion B.
	ProtocolVersion string
	// BearerToken authenticates every call. Empty is valid; see
	// ModernConfig.BearerToken for the same convention.
	BearerToken string
	// ReadOnlyTool is the only tool this probe will ever pass to tools/call.
	// Defaults to DefaultReadOnlyTool.
	ReadOnlyTool string
	// ReadOnlyToolArguments are the arguments sent with ReadOnlyTool.
	ReadOnlyToolArguments map[string]any
	// HTTPClient is the client used for every request. Defaults to
	// &http.Client{Timeout: 30 * time.Second}.
	HTTPClient *http.Client
}

func (c LegacyConfig) mcpPath() string {
	if c.MCPPath != "" {
		return c.MCPPath
	}
	return DefaultMCPPath
}

func (c LegacyConfig) protocolVersion() string {
	if c.ProtocolVersion != "" {
		return c.ProtocolVersion
	}
	return DefaultLegacyProtocolVersion
}

func (c LegacyConfig) readOnlyTool() string {
	if c.ReadOnlyTool != "" {
		return c.ReadOnlyTool
	}
	return DefaultReadOnlyTool
}

func (c LegacyConfig) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c LegacyConfig) url() string {
	return strings.TrimRight(c.BaseURL, "/") + c.mcpPath()
}

// ProbeLegacy runs the legacy-mode probe: initialize, then tools/list and
// exactly one guarded tools/call using the minted session id, recording
// whether the session id was minted and whether it is required.
func ProbeLegacy(ctx context.Context, cfg LegacyConfig) (*LegacyResult, error) {
	client := cfg.httpClient()
	url := cfg.url()
	pv := cfg.protocolVersion()

	result := &LegacyResult{ProtocolVersion: pv}

	initParams := map[string]any{
		"protocolVersion": pv,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": defaultClientName, "version": defaultClientVersion},
	}
	initOutcome, err := postJSONRPC(ctx, client, url, 1, mcp.MethodInitialize, initParams, nil, cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: legacy initialize: %w", err)
	}

	initObs := &LegacyInitializeObservation{
		HTTPStatus:      initOutcome.status,
		SessionIDMinted: initOutcome.sessionIDPresent,
		SessionIDLength: initOutcome.sessionIDLength,
	}
	if initOutcome.hasResult() {
		var decoded struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if err := json.Unmarshal(initOutcome.rpc.Result, &decoded); err == nil {
			initObs.NegotiatedProtocolVersion = decoded.ProtocolVersion
		}
	}
	result.Initialize = initObs

	if initOutcome.status != http.StatusOK {
		// Nothing further can be attempted without a working handshake; the
		// initialize observation above already records the failure mode.
		return result, nil
	}

	sessionHeader := func(sessionID string) map[string]string {
		if sessionID == "" {
			return nil
		}
		return map[string]string{mcp.HeaderSessionID: sessionID}
	}

	// httpOutcome's exported-shaped fields (sessionIDPresent/sessionIDLength)
	// deliberately never carry the raw session id, so nothing else in this
	// package can leak it into a Report. Legacy mode still needs the
	// verbatim value to replay in the Mcp-Session-Id header on subsequent
	// calls; sessionIDRaw is unexported, read only here, held only in this
	// function's local scope, and discarded when ProbeLegacy returns.
	sessionID := initOutcome.sessionIDRaw

	toolsListOutcome, err := postJSONRPC(ctx, client, url, 2, mcp.MethodToolsList, map[string]any{}, sessionHeader(sessionID), cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: legacy tools/list: %w", err)
	}
	toolsListObs, tools := legacyCallObservationFrom(toolsListOutcome)

	if sessionID != "" {
		withoutSession, err := postJSONRPC(ctx, client, url, 3, mcp.MethodToolsList, map[string]any{}, nil, cfg.BearerToken)
		if err != nil {
			return nil, fmt.Errorf("mcpprobe: legacy tools/list (no session, negative check): %w", err)
		}
		toolsListObs.SessionIDRequired = legacyCallWasRefused(withoutSession)
	}
	result.ToolsList = toolsListObs

	targetTool := cfg.readOnlyTool()
	toolCallObs, err := legacyGuardedToolCall(ctx, client, url, targetTool, cfg.ReadOnlyToolArguments, tools, sessionID, cfg.BearerToken, sessionHeader)
	if err != nil {
		return nil, err
	}
	result.ToolCall = toolCallObs

	return result, nil
}

// legacyCallObservationFrom projects a raw legacy tools/list outcome into
// LegacyCallObservation and returns the decoded tools for the read-only
// guard.
func legacyCallObservationFrom(o *httpOutcome) (*LegacyCallObservation, []ToolSummary) {
	obs := &LegacyCallObservation{
		Attempted:        true,
		HTTPStatus:       o.status,
		JSONRPCErrorCode: o.jsonrpcErrorCode(),
	}
	if !o.hasResult() {
		return obs, nil
	}
	tools := decodeToolSummaries(o.rpc.Result)
	obs.ToolCount = len(tools)
	return obs, tools
}

// legacyCallWasRefused reports whether a legacy call's outcome looks like a
// session-related refusal: a non-2xx HTTP status or a JSON-RPC error. Used
// only to set SessionIDRequired; the outcome's session id fields and result
// are otherwise discarded.
func legacyCallWasRefused(o *httpOutcome) bool {
	if o.status < 200 || o.status >= 300 {
		return true
	}
	return o.jsonrpcErrorCode() != 0
}

// legacyGuardedToolCall issues the single real tools/call this probe ever
// makes in legacy mode, or refuses and records why -- mirroring modern
// mode's guardedToolCall but with a session header instead of modern
// per-request `_meta`/headers.
//
// It returns an error only when the no-session negative check could not be
// performed: SessionIDRequired=false must mean "the server accepted the
// replay", never "the replay never happened", so a transport failure there
// is surfaced rather than serialized as an observation -- the same contract
// as the equivalent tools/list check in ProbeLegacy. A failure of the main
// guarded call is still recorded in the observation (RefusalReason).
func legacyGuardedToolCall(
	ctx context.Context,
	client *http.Client,
	url, name string,
	args map[string]any,
	tools []ToolSummary,
	sessionID string,
	bearerToken string,
	sessionHeader func(string) map[string]string,
) (*LegacyCallObservation, error) {
	obs := &LegacyCallObservation{}

	ok, reason := readOnlyGuard(tools, name)
	if !ok {
		obs.Attempted = false
		obs.RefusalReason = reason
		return obs, nil
	}

	if args == nil {
		args = map[string]any{}
	}
	params := map[string]any{"name": name, "arguments": args}
	outcome, err := postJSONRPC(ctx, client, url, 4, mcp.MethodToolsCall, params, sessionHeader(sessionID), bearerToken)
	if err != nil {
		obs.Attempted = true
		obs.RefusalReason = "request failed: " + err.Error()
		return obs, nil
	}
	obs.Attempted = true
	obs.HTTPStatus = outcome.status
	obs.JSONRPCErrorCode = outcome.jsonrpcErrorCode()
	if outcome.hasResult() {
		var decoded struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(outcome.rpc.Result, &decoded); err == nil {
			obs.IsError = decoded.IsError
		}
	}

	if sessionID != "" {
		withoutSession, err := postJSONRPC(ctx, client, url, 5, mcp.MethodToolsCall, params, nil, bearerToken)
		if err != nil {
			return nil, fmt.Errorf("mcpprobe: legacy tools/call (no session, negative check): %w", err)
		}
		obs.SessionIDRequired = legacyCallWasRefused(withoutSession)
	}
	return obs, nil
}
