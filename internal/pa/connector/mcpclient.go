// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

// mcpclient.go is the minimal MCP Streamable HTTP client the dispatcher
// uses to reach a catalog server (#1315): initialize, tools/list and
// tools/call, nothing else; each session is ended with DELETE. Every
// request goes through an internal/pa/egress client (threat model T9, I8):
// HTTPS only, the endpoint's host only, no redirects, bounded bodies. The bearer is the connection's access token,
// opened server-side for this one call (I1); it is never logged and never
// returned.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/egress"
)

// mcpProtocolVersion is the MCP revision the client speaks.
const mcpProtocolVersion = "2025-06-18"

// maxListPages bounds a paginated tools/list. A server that keeps handing
// out cursors past it is a failed read, not a shorter list.
const maxListPages = 20

// sessionCloseTimeout bounds the DELETE that ends a session. It runs even
// when the request's own deadline has passed.
const sessionCloseTimeout = 5 * time.Second

var (
	// ErrMCPProtocol wraps every malformed or unexpected server response:
	// a failed read (I9), never an empty one.
	ErrMCPProtocol = errors.New("pa connector: mcp protocol error")
	// ErrMCPUnauthorized is a 401 or 403 from the server: it refused the
	// connection's token.
	ErrMCPUnauthorized = errors.New("pa connector: mcp server refused the token")
	// ErrMCPTokenRejected is the 401 case of ErrMCPUnauthorized: the server
	// did not accept the token as a credential, which a refreshed token
	// can fix. The request was rejected before it ran (#1318 slice C2b).
	ErrMCPTokenRejected = fmt.Errorf("%w: token rejected (401)", ErrMCPUnauthorized)
	// ErrMCPForbidden is the 403 case of ErrMCPUnauthorized: the server
	// accepted the token and refused the request. A refresh does not
	// change that, so it is never retried.
	ErrMCPForbidden = fmt.Errorf("%w: forbidden (403)", ErrMCPUnauthorized)
)

// Endpoint is one catalog server's MCP URL with its egress client.
type Endpoint struct {
	server string
	url    string
	client *http.Client
	ids    atomic.Int64
}

// NewEndpoint builds the endpoint of server at rawURL. The URL must be
// https on the default port; the egress client is allowed exactly its
// host. tg must be reached directly, never through the gateway: the
// gateway prefixes tool names (tg_list_dialogs), which the pin does not
// know, so every pinned tool would be denied (see GatewayPrefixed).
func NewEndpoint(server, rawURL string) (*Endpoint, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("pa connector: endpoint for %q must be an https URL", server)
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, fmt.Errorf("pa connector: endpoint for %q must use port 443", server)
	}
	client, err := egress.New(egress.Config{Purpose: egress.PurposeMCP, AllowedHosts: []string{u.Hostname()}})
	if err != nil {
		return nil, fmt.Errorf("pa connector: egress for %q: %w", server, err)
	}
	return &Endpoint{server: server, url: u.String(), client: client}, nil
}

// Server is the catalog server the endpoint belongs to.
func (e *Endpoint) Server() string { return e.server }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int64 `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code int `json:"code"`
	} `json:"error"`
}

// session is one initialized MCP session.
type session struct {
	e     *Endpoint
	token connection.Secret
	id    string
}

// open runs initialize and notifications/initialized.
func (e *Endpoint) open(ctx context.Context, token connection.Secret) (*session, error) {
	s := &session{e: e, token: token}
	_, hdr, err := s.call(ctx, "initialize", map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mctl-telegram-pa", "version": "1"},
	})
	if err != nil {
		return nil, err
	}
	s.id = hdr.Get("Mcp-Session-Id")
	if err := s.notify(ctx, "notifications/initialized"); err != nil {
		s.close(ctx)
		return nil, err
	}
	return s, nil
}

// close ends the session with DELETE (MCP Streamable HTTP), so the server
// does not keep one session per call. Best effort: a server without
// session termination answers 405, and nothing the caller does depends on
// the answer.
//
// A cancelled ctx (fence, revoke or deadline) skips it: the bearer must not
// go out again after the call was stopped, and the server expires the
// session on its own.
func (s *session) close(ctx context.Context) {
	if s.id == "" || ctx.Err() != nil {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionCloseTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodDelete, s.e.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+s.token.Reveal())
	req.Header.Set("Mcp-Session-Id", s.id)
	req.Header.Set("Mcp-Protocol-Version", mcpProtocolVersion)
	resp, err := s.e.client.Do(req)
	if err != nil {
		return
	}
	drain(resp)
}

// ListTools returns every page of the server's tools/list, each the
// JSON-RPC result object, in order. Any failure is an error; there is no
// partial result (I9).
func (e *Endpoint) ListTools(ctx context.Context, token connection.Secret) ([][]byte, error) {
	s, err := e.open(ctx, token)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	var pages [][]byte
	cursor := ""
	for range maxListPages {
		var params any
		if cursor != "" {
			params = map[string]any{"cursor": cursor}
		}
		res, _, err := s.call(ctx, "tools/list", params)
		if err != nil {
			return nil, err
		}
		pages = append(pages, res)
		var next struct {
			NextCursor *string `json:"nextCursor"`
		}
		if err := json.Unmarshal(res, &next); err != nil {
			return nil, fmt.Errorf("%w: tools/list result", ErrMCPProtocol)
		}
		if next.NextCursor == nil || *next.NextCursor == "" {
			return pages, nil
		}
		cursor = *next.NextCursor
	}
	return nil, fmt.Errorf("%w: tools/list exceeds %d pages", ErrMCPProtocol, maxListPages)
}

// CallTool runs tools/call and returns its JSON-RPC result object.
func (e *Endpoint) CallTool(ctx context.Context, token connection.Secret, tool string, args json.RawMessage) ([]byte, error) {
	s, err := e.open(ctx, token)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	res, _, err := s.call(ctx, "tools/call", map[string]any{"name": tool, "arguments": args})
	return res, err
}

// CallToolExact runs tools/call with args as the "arguments" member byte
// for byte (threat model T7, S2-D7; #1320 slice P2-S3). CallTool hands its
// arguments to encoding/json, which compacts a RawMessage and escapes '<',
// '>', '&', U+2028 and U+2029 in it: the same JSON value, but not the bytes
// an approval's args_sha names. Here the request body is assembled around
// args instead, so what the server receives hashes to what the card showed.
//
// args must be exactly one JSON object with no byte outside it; anything
// else is refused before a request is made. It is never retried here.
func (e *Endpoint) CallToolExact(ctx context.Context, token connection.Secret, tool string, args []byte) ([]byte, error) {
	if !jsonObject(args) || len(bytes.TrimSpace(args)) != len(args) {
		return nil, fmt.Errorf("%w: tools/call arguments are not one JSON object", ErrMCPProtocol)
	}
	name, err := json.Marshal(tool)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMCPProtocol, err)
	}
	s, err := e.open(ctx, token)
	if err != nil {
		return nil, err
	}
	defer s.close(ctx)
	id := e.ids.Add(1)
	var body bytes.Buffer
	body.WriteString(`{"jsonrpc":"2.0","id":`)
	body.WriteString(strconv.FormatInt(id, 10))
	body.WriteString(`,"method":"tools/call","params":{"name":`)
	body.Write(name)
	body.WriteString(`,"arguments":`)
	body.Write(args)
	body.WriteString(`}}`)
	res, _, err := s.exchange(ctx, "tools/call", id, body.Bytes())
	return res, err
}

func (s *session) notify(ctx context.Context, method string) error {
	resp, err := s.post(ctx, rpcRequest{JSONRPC: "2.0", Method: method})
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return statusErr(resp.StatusCode)
	}
	return nil
}

func (s *session) call(ctx context.Context, method string, params any) (json.RawMessage, http.Header, error) {
	id := s.e.ids.Add(1)
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: encode: %v", ErrMCPProtocol, err)
	}
	return s.exchange(ctx, method, id, body)
}

// exchange posts one JSON-RPC request body, already encoded with id, and
// returns the result of the response with that id.
func (s *session) exchange(ctx context.Context, method string, id int64, reqBody []byte) (json.RawMessage, http.Header, error) {
	resp, err := s.postBody(ctx, method, reqBody)
	if err != nil {
		return nil, nil, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, nil, statusErr(resp.StatusCode)
	}
	body, err := egress.ReadBody(resp)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read %s: %v", ErrMCPProtocol, method, err)
	}
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	var msg rpcResponse
	switch ct {
	case "application/json":
		if err := json.Unmarshal(body, &msg); err != nil {
			return nil, nil, fmt.Errorf("%w: %s response", ErrMCPProtocol, method)
		}
	case "text/event-stream":
		if msg, err = fromSSE(body, id); err != nil {
			return nil, nil, fmt.Errorf("%w: %s stream: %v", ErrMCPProtocol, method, err)
		}
	default:
		return nil, nil, fmt.Errorf("%w: %s content type", ErrMCPProtocol, method)
	}
	if msg.JSONRPC != "2.0" || string(msg.ID) != strconv.FormatInt(id, 10) {
		return nil, nil, fmt.Errorf("%w: %s response id", ErrMCPProtocol, method)
	}
	if msg.Error != nil {
		return nil, nil, fmt.Errorf("%w: %s returned error %d", ErrMCPProtocol, method, msg.Error.Code)
	}
	if len(bytes.TrimSpace(msg.Result)) == 0 || bytes.Equal(bytes.TrimSpace(msg.Result), []byte("null")) {
		return nil, nil, fmt.Errorf("%w: %s has no result", ErrMCPProtocol, method)
	}
	return msg.Result, resp.Header, nil
}

func (s *session) post(ctx context.Context, m rpcRequest) (*http.Response, error) {
	body, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("%w: encode: %v", ErrMCPProtocol, err)
	}
	return s.postBody(ctx, m.Method, body)
}

func (s *session) postBody(ctx context.Context, method string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.e.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: request: %v", ErrMCPProtocol, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+s.token.Reveal())
	if s.id != "" {
		req.Header.Set("Mcp-Session-Id", s.id)
		req.Header.Set("Mcp-Protocol-Version", mcpProtocolVersion)
	}
	resp, err := s.e.client.Do(req)
	if err != nil {
		// The error names the URL, never the header.
		return nil, fmt.Errorf("pa connector: %s %s: %w", s.e.server, method, err)
	}
	return resp, nil
}

func statusErr(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return ErrMCPTokenRejected
	case http.StatusForbidden:
		return ErrMCPForbidden
	}
	return fmt.Errorf("%w: status %d", ErrMCPProtocol, code)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
}

// fromSSE returns the JSON-RPC response with id from an event stream. Other
// messages (notifications, progress) are skipped. No matching response is
// an error.
func fromSSE(body []byte, id int64) (rpcResponse, error) {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), len(body)+1)
	var data strings.Builder
	want := strconv.FormatInt(id, 10)
	flush := func() (rpcResponse, bool) {
		defer data.Reset()
		if data.Len() == 0 {
			return rpcResponse{}, false
		}
		var msg rpcResponse
		if err := json.Unmarshal([]byte(data.String()), &msg); err != nil || string(msg.ID) != want {
			return rpcResponse{}, false
		}
		return msg, true
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if msg, ok := flush(); ok {
				return msg, nil
			}
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return rpcResponse{}, err
	}
	if msg, ok := flush(); ok {
		return msg, nil
	}
	return rpcResponse{}, errors.New("no response for the request")
}
