package mcpprobe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
)

// maxResponseBytes bounds how much of an MCP response body this probe will
// read. Generous for any protocol-metadata or single-tool-result response,
// tiny next to what an attacker-controlled or misbehaving endpoint could
// otherwise make the probe buffer.
const maxResponseBytes = 1 << 20

// rpcRequest is the JSON-RPC 2.0 envelope this probe sends. id is fixed per
// call site; the probe never pipelines requests.
type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      int            `json:"id"`
	Method  mcp.MCPMethod  `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

// rpcError is the JSON-RPC 2.0 error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpcResponse is the subset of a JSON-RPC 2.0 response this probe decodes.
// Result is left as raw JSON: each call site decodes only the fields its
// Report type is allowed to carry, and never assigns the raw bytes
// themselves into a Report.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// httpOutcome is the wire-level result of one POST to the MCP endpoint. It
// is an internal type: call sites project it into the narrow, redacted
// Report types before returning anything to a caller.
type httpOutcome struct {
	status           int
	sessionIDPresent bool
	sessionIDLength  int
	// sessionIDRaw is the literal Mcp-Session-Id value. It is unexported and
	// used only within this package (legacy.go replays it in a subsequent
	// request's header); no exported type in this package ever stores it,
	// so no Report can carry it out.
	sessionIDRaw string
	rpc          *rpcResponse // nil when the body did not parse as JSON-RPC
	rawBody      []byte
}

// jsonrpcErrorCode returns o's JSON-RPC error code, or 0 when the response
// carried no error object (matching the convention that 0 is not a valid
// JSON-RPC error code).
func (o *httpOutcome) jsonrpcErrorCode() int {
	if o == nil || o.rpc == nil || o.rpc.Error == nil {
		return 0
	}
	return o.rpc.Error.Code
}

func (o *httpOutcome) hasResult() bool {
	return o != nil && o.rpc != nil && len(o.rpc.Result) > 0
}

// postJSONRPC sends one JSON-RPC POST to url with the given headers (fully
// caller-controlled, so negative-header test cases can omit or mismatch
// them) and an optional bearer token. It never sends Mcp-Session-Id itself;
// callers that need one (legacy mode) add it via headers.
func postJSONRPC(
	ctx context.Context,
	client *http.Client,
	url string,
	id int,
	method mcp.MCPMethod,
	params map[string]any,
	headers map[string]string,
	bearerToken string,
) (*httpOutcome, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: marshal %s request: %w", method, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: build %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: POST %s (%s): %w", url, method, err)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("mcpprobe: read %s response body: %w", method, err)
	}

	sessionID := resp.Header.Get(mcp.HeaderSessionID)

	out := &httpOutcome{
		status:           resp.StatusCode,
		sessionIDPresent: sessionID != "",
		sessionIDLength:  len(sessionID),
		sessionIDRaw:     sessionID,
		rawBody:          raw,
	}

	var parsed rpcResponse
	if err := json.Unmarshal(raw, &parsed); err == nil {
		out.rpc = &parsed
	}

	return out, nil
}

// modernMeta builds the per-request `_meta` that every modern
// (>= 2026-07-28) request must carry (SEP-2575): protocol version, client
// identity, and client capabilities. Matches the shape the pinned
// mark3labs/mcp-go v1.0.0 test suite (server/streamable_http_modern_test.go)
// exercises against its own server.
func modernMeta(protocolVersion string) map[string]any {
	return map[string]any{
		mcp.MetaKeyProtocolVersion: protocolVersion,
		mcp.MetaKeyClientInfo: map[string]any{
			"name":    defaultClientName,
			"version": defaultClientVersion,
		},
		mcp.MetaKeyClientCapabilities: map[string]any{},
	}
}

// modernHeaders builds the standard HTTP headers a conformant modern request
// carries (SEP-2243): MCP-Protocol-Version and Mcp-Method always, Mcp-Name
// when the method names a capability (tools/call, resources/read,
// prompts/get). Negative-header test cases build their own header maps by
// hand rather than mutating this one, so the "conformant" shape stays a
// single, obviously-correct source of truth.
func modernHeaders(protocolVersion string, method mcp.MCPMethod, name string) map[string]string {
	h := map[string]string{
		mcp.HeaderProtocolVersion: protocolVersion,
		mcp.HeaderMethod:          string(method),
	}
	if name != "" {
		h[mcp.HeaderName] = name
	}
	return h
}
