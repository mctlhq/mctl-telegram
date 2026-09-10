package mcpprobe

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// maxResponseBytes bounds what the probe will read from a target. A probe
// pointed at a hostile or broken endpoint should fail, not exhaust memory.
const maxResponseBytes = 4 << 20

// probeClientName identifies this client to the server. It is deliberately
// distinct from the production clients so a server operator reading logs can
// tell a compatibility run from real traffic.
const (
	probeClientName    = "mctl-mcpprobe"
	probeClientVersion = "1"
)

// rpcRequest is one JSON-RPC POST. headerOverrides is what makes the negative
// probes expressible: a case can delete or corrupt exactly one header while
// everything else stays correct, which is the only way to attribute a
// rejection to that header.
type rpcRequest struct {
	method    mcp.MCPMethod
	params    any
	id        int
	sessionID string
	// modern selects per-request metadata and the 2026-07-28 header binding.
	modern bool
	// protocolVersion is the version declared in metadata and headers.
	protocolVersion string
	// headerOverrides is applied last. A nil value deletes the header.
	headerOverrides map[string]*string
	// omitMeta suppresses the per-request _meta block, for negative probes.
	omitMeta bool
}

// rpcOutcome is what came back. The result body stays a raw message inside
// this package and is never carried into a Report: callers extract the named
// fields they need and discard the rest.
type rpcOutcome struct {
	httpStatus  int
	contentType string
	sessionID   string
	errorCode   *int
	result      json.RawMessage
}

type rpcClient struct {
	httpClient *http.Client
	url        string
	token      string
}

// jsonRPCEnvelope is the response shape. Only the code of an error is read;
// the message is deliberately left on the floor, since it is server-chosen
// text and this package promises never to relay such text.
type jsonRPCEnvelope struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code int `json:"code"`
	} `json:"error"`
}

func (c *rpcClient) do(ctx context.Context, req rpcRequest) (rpcOutcome, error) {
	params, err := buildParams(req)
	if err != nil {
		return rpcOutcome{}, err
	}
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      req.id,
		"method":  string(req.method),
	}
	if params != nil {
		body["params"] = json.RawMessage(params)
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return rpcOutcome{}, fmt.Errorf("encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(encoded))
	if err != nil {
		return rpcOutcome{}, fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	if req.modern {
		httpReq.Header.Set(mcp.HeaderProtocolVersion, req.protocolVersion)
		for k, v := range mcp.StandardHeaders(req.protocolVersion, req.method, params) {
			httpReq.Header.Set(k, v)
		}
	} else if req.sessionID != "" {
		httpReq.Header.Set(mcp.HeaderSessionID, req.sessionID)
	}
	for name, value := range req.headerOverrides {
		if value == nil {
			httpReq.Header.Del(name)
			continue
		}
		httpReq.Header.Set(name, *value)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return rpcOutcome{}, fmt.Errorf("request %s: %w", req.method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return rpcOutcome{}, fmt.Errorf("read response for %s: %w", req.method, err)
	}
	out := rpcOutcome{
		httpStatus:  resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		sessionID:   resp.Header.Get(mcp.HeaderSessionID),
	}
	payload := extractPayload(out.contentType, raw)
	if len(bytes.TrimSpace(payload)) == 0 {
		return out, nil
	}
	var env jsonRPCEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		// A body that is not a JSON-RPC envelope is itself a finding; the
		// caller records it as a malformed body rather than as a transport
		// failure, and the unparsed bytes go no further than this frame.
		return out, errMalformedBody
	}
	if env.Error != nil {
		code := env.Error.Code
		out.errorCode = &code
	}
	out.result = env.Result
	return out, nil
}

// errMalformedBody signals a response that was delivered but was not a
// JSON-RPC envelope.
var errMalformedBody = fmt.Errorf("response body is not a JSON-RPC envelope")

// buildParams renders the params object, attaching the per-request metadata
// the modern protocol requires. Client capabilities must be present even when
// empty: the server rejects a modern request that omits them.
func buildParams(req rpcRequest) (json.RawMessage, error) {
	base := map[string]any{}
	if req.params != nil {
		encoded, err := json.Marshal(req.params)
		if err != nil {
			return nil, fmt.Errorf("encode params: %w", err)
		}
		if err := json.Unmarshal(encoded, &base); err != nil {
			return nil, fmt.Errorf("normalize params: %w", err)
		}
	}
	if req.modern && !req.omitMeta {
		meta := &mcp.Meta{}
		meta.SetProtocolVersion(req.protocolVersion)
		meta.SetClientInfo(mcp.Implementation{Name: probeClientName, Version: probeClientVersion})
		meta.SetClientCapabilities(mcp.ClientCapabilities{})
		base["_meta"] = meta
	}
	if len(base) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("encode params: %w", err)
	}
	return encoded, nil
}

// extractPayload returns the JSON document from a response body. A streamable
// HTTP server may answer a POST either as plain JSON or as a one-shot event
// stream; reading the last data line of the latter is body parsing, not a
// second transport, and the probe never opens a standalone stream.
func extractPayload(contentType string, raw []byte) []byte {
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		return raw
	}
	var last []byte
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
	for scanner.Scan() {
		line := scanner.Bytes()
		if data, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			last = append(last[:0], bytes.TrimSpace(data)...)
		}
	}
	return last
}
