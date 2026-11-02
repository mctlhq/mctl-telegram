package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// CallToolInProcess performs one MCP initialize and one tools/call against a
// fresh instance of the registered tool surface, without HTTP. It exists for
// the live login proof (cmd/login-proof), which has to show that a session
// just created by the product login path serves a real tool call.
//
// The call goes through the same registered handlers, scope filter and
// middleware as an HTTP request, so an identity that lacks the tool's scope is
// refused exactly as it would be there. A JSON-RPC level failure is returned
// as an error; a tool that ran and reported failure is a result with IsError.
func (s *Server) CallToolInProcess(ctx context.Context, id *auth.Identity, tool string, args map[string]any) (*mcplib.CallToolResult, error) {
	if id == nil {
		return nil, errors.New("identity required")
	}
	ctx = auth.With(ctx, id)
	srv := s.newMCPServer()
	if _, err := rpcInProcess(ctx, srv.HandleMessage, "initialize", map[string]any{
		"protocolVersion": mcplib.LATEST_LEGACY_PROTOCOL_VERSION,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "login-proof", "version": "1"},
	}); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}
	raw, err := rpcInProcess(ctx, srv.HandleMessage, "tools/call", map[string]any{
		"name":      tool,
		"arguments": args,
	})
	if err != nil {
		return nil, fmt.Errorf("tools/call %s: %w", tool, err)
	}
	res, err := mcplib.ParseCallToolResult(&raw)
	if err != nil {
		return nil, fmt.Errorf("decode %s result: %w", tool, err)
	}
	return res, nil
}

func rpcInProcess(ctx context.Context, handle func(context.Context, json.RawMessage) mcplib.JSONRPCMessage, method string, params any) (json.RawMessage, error) {
	req, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return nil, err
	}
	respRaw, err := json.Marshal(handle(ctx, req))
	if err != nil {
		return nil, err
	}
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(respRaw, &env); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if env.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", env.Error.Code, env.Error.Message)
	}
	if len(env.Result) == 0 {
		return nil, errors.New("empty result")
	}
	return env.Result, nil
}
