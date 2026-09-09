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

// ModernConfig configures one ModeModern probe run.
type ModernConfig struct {
	// BaseURL is the scheme://host[:port] of the target. Required.
	BaseURL string
	// MCPPath is the MCP endpoint path. Defaults to DefaultMCPPath.
	MCPPath string
	// ProtocolVersion is the modern protocol version probed. Defaults to
	// DefaultModernProtocolVersion. Must be >= 2026-07-28 for this probe to
	// be testing what it claims; ProbeModern does not check this, since a
	// deployment intentionally restricted to legacy-only versions rejecting
	// every modern request here IS the measurement (requirements.md
	// acceptance criterion A: "not permission to fall back silently").
	ProtocolVersion string
	// BearerToken authenticates the tools/call step. Empty is valid: the
	// probe still runs discover/tools-list/negative tests, and records the
	// tools/call outcome (typically an auth error) as an observation like
	// any other -- it does not skip the call outright, unlike the OAuth
	// probe's authenticated cells. A deployment that requires auth for
	// tools/list will also surface that in ToolsListObservation.
	BearerToken string
	// ReadOnlyTool is the only tool this probe will ever pass to tools/call.
	// Defaults to DefaultReadOnlyTool. The probe refuses to call it unless
	// tools/list annotates it readOnlyHint=true.
	ReadOnlyTool string
	// ReadOnlyToolArguments are the arguments sent with ReadOnlyTool.
	ReadOnlyToolArguments map[string]any
	// HTTPClient is the client used for every request. Defaults to
	// &http.Client{Timeout: 30 * time.Second}.
	HTTPClient *http.Client
}

func (c ModernConfig) mcpPath() string {
	if c.MCPPath != "" {
		return c.MCPPath
	}
	return DefaultMCPPath
}

func (c ModernConfig) protocolVersion() string {
	if c.ProtocolVersion != "" {
		return c.ProtocolVersion
	}
	return DefaultModernProtocolVersion
}

func (c ModernConfig) readOnlyTool() string {
	if c.ReadOnlyTool != "" {
		return c.ReadOnlyTool
	}
	return DefaultReadOnlyTool
}

func (c ModernConfig) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c ModernConfig) url() string {
	return strings.TrimRight(c.BaseURL, "/") + c.mcpPath()
}

// ProbeModern runs the full modern-mode (>= 2026-07-28) probe: server/
// discover, tools/list, exactly one guarded tools/call, the initialize
// removed-method negative test, and the header mismatch negative battery.
// It never sends `initialize` to bootstrap the session and never sends
// `Mcp-Session-Id` (requirements.md acceptance criterion A).
func ProbeModern(ctx context.Context, cfg ModernConfig) (*ModernResult, error) {
	client := cfg.httpClient()
	url := cfg.url()
	pv := cfg.protocolVersion()

	result := &ModernResult{ProtocolVersion: pv}

	discoverOutcome, err := postJSONRPC(ctx, client, url, 1, mcp.MethodServerDiscover,
		map[string]any{"_meta": modernMeta(pv)},
		modernHeaders(pv, mcp.MethodServerDiscover, ""),
		cfg.BearerToken,
	)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: server/discover: %w", err)
	}
	result.Discover = discoverObservationFrom(discoverOutcome)

	toolsListOutcome, err := postJSONRPC(ctx, client, url, 2, mcp.MethodToolsList,
		map[string]any{"_meta": modernMeta(pv)},
		modernHeaders(pv, mcp.MethodToolsList, ""),
		cfg.BearerToken,
	)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: tools/list: %w", err)
	}
	toolsObs, tools := toolsListObservationFrom(toolsListOutcome)
	result.ToolsList = toolsObs

	targetTool := cfg.readOnlyTool()
	result.ToolCall = guardedToolCall(ctx, client, url, pv, targetTool, cfg.ReadOnlyToolArguments, tools, cfg.BearerToken, 3)

	initOutcome, err := postJSONRPC(ctx, client, url, 4, mcp.MethodInitialize,
		map[string]any{"_meta": modernMeta(pv)},
		modernHeaders(pv, mcp.MethodInitialize, ""),
		cfg.BearerToken,
	)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: initialize removed-method test: %w", err)
	}
	result.InitializeRemovedMethod = &NegativeCase{
		Name:             "initialize is a removed method in protocol version " + pv,
		HTTPStatus:       initOutcome.status,
		JSONRPCErrorCode: initOutcome.jsonrpcErrorCode(),
		Rejected:         initOutcome.jsonrpcErrorCode() == mcp.METHOD_NOT_FOUND,
	}

	// The header-negative battery sends real tools/call bodies, and a server
	// that does not enforce the SEP-2243 headers -- the exact class this probe
	// targets -- would dispatch them. So it may only ever name a tool the
	// read-only guard cleared; otherwise it probes with a sentinel name and no
	// arguments, which still exercises header validation (enforced before
	// dispatch) but cannot resolve to a real, possibly side-effecting tool.
	negativeTool, negativeArgs := targetTool, cfg.ReadOnlyToolArguments
	if cleared, _ := readOnlyGuard(tools, targetTool); !cleared {
		negativeTool, negativeArgs = unverifiedToolPlaceholder, nil
	}
	negatives, err := headerNegativeCases(ctx, client, url, pv, negativeTool, negativeArgs, cfg.BearerToken)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: header negative tests: %w", err)
	}
	result.HeaderNegativeTests = negatives

	return result, nil
}

// discoverObservationFrom projects a raw server/discover outcome into the
// redacted DiscoverObservation shape.
func discoverObservationFrom(o *httpOutcome) *DiscoverObservation {
	obs := &DiscoverObservation{
		HTTPStatus:       o.status,
		JSONRPCErrorCode: o.jsonrpcErrorCode(),
		SessionIDPresent: o.sessionIDPresent,
		SessionIDLength:  o.sessionIDLength,
	}
	if !o.hasResult() {
		return obs
	}
	var decoded struct {
		SupportedVersions []string       `json:"supportedVersions"`
		Meta              map[string]any `json:"_meta"`
	}
	if err := json.Unmarshal(o.rpc.Result, &decoded); err != nil {
		return obs
	}
	obs.SupportedVersions = decoded.SupportedVersions
	if serverInfo, ok := decoded.Meta[mcp.MetaKeyServerInfo].(map[string]any); ok {
		if name, ok := serverInfo["name"].(string); ok {
			obs.ServerName = name
		}
		if version, ok := serverInfo["version"].(string); ok {
			obs.ServerVersion = version
		}
	}
	return obs
}

// toolsListObservationFrom projects a raw tools/list outcome into the
// redacted ToolsListObservation shape and also returns the decoded tool
// summaries for the read-only guard to consult -- kept separate from the
// Report type itself, which only ever stores ToolSummary.
func toolsListObservationFrom(o *httpOutcome) (*ToolsListObservation, []ToolSummary) {
	obs := &ToolsListObservation{
		HTTPStatus:       o.status,
		JSONRPCErrorCode: o.jsonrpcErrorCode(),
		SessionIDPresent: o.sessionIDPresent,
		SessionIDLength:  o.sessionIDLength,
	}
	if !o.hasResult() {
		return obs, nil
	}
	summaries := decodeToolSummaries(o.rpc.Result)
	obs.ToolCount = len(summaries)
	obs.Tools = summaries
	return obs, summaries
}

// decodeToolSummaries decodes a tools/list result's `tools` array into the
// redacted ToolSummary shape (name + readOnlyHint only). Shared by both
// modern and legacy tools/list decoding, since the result shape itself does
// not vary by protocol era.
func decodeToolSummaries(result json.RawMessage) []ToolSummary {
	var decoded struct {
		Tools []struct {
			Name        string `json:"name"`
			Annotations *struct {
				ReadOnlyHint *bool `json:"readOnlyHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &decoded); err != nil {
		return nil
	}
	summaries := make([]ToolSummary, 0, len(decoded.Tools))
	for _, t := range decoded.Tools {
		s := ToolSummary{Name: t.Name}
		if t.Annotations != nil {
			s.ReadOnlyHint = t.Annotations.ReadOnlyHint
		}
		summaries = append(summaries, s)
	}
	return summaries
}

// unverifiedToolPlaceholder is the tool name the header-negative battery
// uses when the read-only guard refused the configured tool. It is not a
// tool any server exposes, so even a target that ignores the SEP-2243
// headers can only answer "unknown tool" -- the header contract is still
// probed, but no real tool is ever invoked without the guard's clearance.
const unverifiedToolPlaceholder = "mcpprobe-unverified-tool"

// readOnlyGuard reports whether tools is allowed to name a real tools/call
// target: found in the list, with readOnlyHint explicitly true. Absence of
// the annotation (nil) is treated the same as false -- an unannotated tool
// is not proven read-only, and this probe only ever calls tools it can
// prove are safe (requirements.md acceptance criterion C).
func readOnlyGuard(tools []ToolSummary, name string) (ok bool, reason string) {
	for _, t := range tools {
		if t.Name != name {
			continue
		}
		if t.ReadOnlyHint != nil && *t.ReadOnlyHint {
			return true, ""
		}
		return false, fmt.Sprintf("tool %q is not annotated readOnlyHint=true; refusing to call it", name)
	}
	return false, fmt.Sprintf("tool %q was not found in tools/list; refusing to call an unverified tool", name)
}

// guardedToolCall issues the single real tools/call this probe ever makes,
// or refuses and records why.
func guardedToolCall(
	ctx context.Context,
	client *http.Client,
	url, protocolVersion, name string,
	args map[string]any,
	tools []ToolSummary,
	bearerToken string,
	id int,
) *ToolCallObservation {
	obs := &ToolCallObservation{ToolName: name}

	ok, reason := readOnlyGuard(tools, name)
	if !ok {
		obs.Attempted = false
		obs.RefusalReason = reason
		return obs
	}

	if args == nil {
		args = map[string]any{}
	}
	params := map[string]any{
		"name":      name,
		"arguments": args,
		"_meta":     modernMeta(protocolVersion),
	}
	outcome, err := postJSONRPC(ctx, client, url, id, mcp.MethodToolsCall, params,
		modernHeaders(protocolVersion, mcp.MethodToolsCall, name),
		bearerToken,
	)
	if err != nil {
		obs.Attempted = true
		obs.RefusalReason = "request failed: " + err.Error()
		return obs
	}

	obs.Attempted = true
	obs.HTTPStatus = outcome.status
	obs.JSONRPCErrorCode = outcome.jsonrpcErrorCode()
	obs.SessionIDPresent = outcome.sessionIDPresent
	obs.SessionIDLength = outcome.sessionIDLength
	if outcome.hasResult() {
		var decoded struct {
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(outcome.rpc.Result, &decoded); err == nil {
			obs.IsError = decoded.IsError
		}
	}
	return obs
}

// headerNegativeCases exercises the missing/mismatched Mcp-Method / Mcp-Name
// / Mcp-Protocol-Version cases (tasks.md task 4). It tests a tools/call
// request throughout so that both header contracts (Mcp-Method and Mcp-Name)
// are exercised by the same battery; it never uses a tool the read-only
// guard has not cleared, so callers must have already vetted toolName via
// tools/list and must pass unverifiedToolPlaceholder instead when the guard
// refused. The negative cases still run in that case -- they probe header
// validation, which SEP-2243 requires the transport to enforce before
// dispatch, independent of whether the tool itself exists.
func headerNegativeCases(
	ctx context.Context,
	client *http.Client,
	url, protocolVersion, toolName string,
	args map[string]any,
	bearerToken string,
) ([]NegativeCase, error) {
	if args == nil {
		args = map[string]any{}
	}
	params := map[string]any{
		"name":      toolName,
		"arguments": args,
		"_meta":     modernMeta(protocolVersion),
	}

	cases := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "missing Mcp-Protocol-Version header",
			headers: map[string]string{
				mcp.HeaderMethod: string(mcp.MethodToolsCall),
				mcp.HeaderName:   toolName,
			},
		},
		{
			name: "missing Mcp-Method header",
			headers: map[string]string{
				mcp.HeaderProtocolVersion: protocolVersion,
				mcp.HeaderName:            toolName,
			},
		},
		{
			name: "Mcp-Method disagrees with body method",
			headers: map[string]string{
				mcp.HeaderProtocolVersion: protocolVersion,
				mcp.HeaderMethod:          string(mcp.MethodToolsList),
				mcp.HeaderName:            toolName,
			},
		},
		{
			name: "missing Mcp-Name header",
			headers: map[string]string{
				mcp.HeaderProtocolVersion: protocolVersion,
				mcp.HeaderMethod:          string(mcp.MethodToolsCall),
			},
		},
		{
			name: "Mcp-Name disagrees with body name",
			headers: map[string]string{
				mcp.HeaderProtocolVersion: protocolVersion,
				mcp.HeaderMethod:          string(mcp.MethodToolsCall),
				mcp.HeaderName:            toolName + "-mismatched",
			},
		},
	}

	results := make([]NegativeCase, 0, len(cases))
	for i, tc := range cases {
		outcome, err := postJSONRPC(ctx, client, url, 100+i, mcp.MethodToolsCall, params, tc.headers, bearerToken)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tc.name, err)
		}
		results = append(results, NegativeCase{
			Name:             tc.name,
			HTTPStatus:       outcome.status,
			JSONRPCErrorCode: outcome.jsonrpcErrorCode(),
			Rejected:         outcome.jsonrpcErrorCode() == mcp.HEADER_MISMATCH,
		})
	}
	return results, nil
}
