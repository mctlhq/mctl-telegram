// Package tools registers the seven contract tools of the Glovo facade. Every
// handler follows one template: strict argument validation, scope check,
// per-call mctl-api Resolve, one mctl-api operation, output-schema
// validation, typed refusal. The tenant and principal only ever come from the
// verified token and mctl-api, never from arguments.
package tools

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/mctlhq/mctl-telegram/internal/glovo/authn"
	"github.com/mctlhq/mctl-telegram/internal/glovo/contract"
	"github.com/mctlhq/mctl-telegram/internal/glovo/mctlapi"
	"github.com/mctlhq/mctl-telegram/internal/jsonstrict"
)

// ServerName is the pinned MCP serverInfo.name.
const ServerName = "mctl-glovo-mcp"

// Event describes one finished tool call. It carries no arguments, results
// or tokens.
type Event struct {
	Tool      string
	Outcome   string // "ok" or a refusal code
	Duration  time.Duration
	Subject   string
	Tenant    string
	RequestID string
}

// Deps are the handler dependencies.
type Deps struct {
	Contract *contract.Contract
	API      mctlapi.Client
	// Allow is the per-principal rate limiter; nil allows everything.
	Allow func(subject string) bool
	// Observe receives one Event per call; nil is a no-op.
	Observe func(Event)
	Version string
}

type impl struct {
	op     mctlapi.Op
	pathID string // argument name carried in the path instead of a body
	body   bool   // POST operations send the arguments as the body
}

var impls = map[string]impl{
	"glovo_auth_status":       {op: mctlapi.OpConnection},
	"glovo_connect_account":   {op: mctlapi.OpConnect, body: true},
	"glovo_get_order_history": {op: mctlapi.OpOrders, body: true},
	"glovo_preview_reorder":   {op: mctlapi.OpPreview, body: true},
	"glovo_get_basket":        {op: mctlapi.OpBasket},
	"glovo_prepare_order":     {op: mctlapi.OpPrepare, body: true},
	"glovo_order_status":      {op: mctlapi.OpOrder, pathID: "order_id"},
}

// NewMCPServer builds the MCP server exposing exactly the contract tools: no
// resources, prompts, sampling or other capability.
func NewMCPServer(d Deps) (*mcpserver.MCPServer, error) {
	v := d.Version
	if v == "" {
		v = "dev"
	}
	srv := mcpserver.NewMCPServer(ServerName, v,
		mcpserver.WithToolCapabilities(false),
		mcpserver.WithRecovery(),
	)
	for _, t := range d.Contract.Tools {
		im, ok := impls[t.Name]
		if !ok {
			return nil, errors.New("contract tool without handler: " + t.Name)
		}
		tool := mcplib.NewToolWithRawSchema(t.Name, t.Description, t.InputRaw)
		tool.RawOutputSchema = t.OutputRaw
		srv.AddTool(tool, d.handler(t, im))
	}
	if len(d.Contract.Tools) != len(impls) {
		return nil, errors.New("handler without contract tool")
	}
	return srv, nil
}

func (d Deps) handler(t *contract.Tool, im impl) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
		start := time.Now()
		ctx, span := otel.Tracer("mctl-glovo-mcp").Start(ctx, "glovo.tool/"+t.Name)
		defer span.End()

		ev := Event{Tool: t.Name, RequestID: authn.RequestID(ctx)}
		out, tenant, code := d.run(ctx, t, im, req)
		ev.Tenant, ev.Duration = tenant, time.Since(start)
		if p := authn.FromContext(ctx); p != nil {
			ev.Subject = p.Subject
			if ev.Tenant == "" {
				ev.Tenant = p.Tenant
			}
		}
		ev.Outcome = "ok"
		if code != "" {
			ev.Outcome = code
			span.SetStatus(codes.Error, code)
		}
		span.SetAttributes(
			attribute.String("glovo.tool", t.Name),
			attribute.String("glovo.outcome", ev.Outcome),
			attribute.String("glovo.request_id", ev.RequestID),
		)
		if d.Observe != nil {
			d.Observe(ev)
		}
		if code != "" {
			return refusal(code), nil
		}
		return &mcplib.CallToolResult{
			Content:           []mcplib.Content{mcplib.NewTextContent(string(out))},
			StructuredContent: out,
		}, nil
	}
}

// run executes the single handler template. It returns either a validated
// result or a refusal code; tenant is the mctl-api-resolved tenant when known.
func (d Deps) run(ctx context.Context, t *contract.Tool, im impl, req mcplib.CallToolRequest) (json.RawMessage, string, string) {
	p := authn.FromContext(ctx)
	if p == nil {
		return nil, "", mctlapi.CodeNotAuthorized
	}
	raw := []byte(req.Params.RawArguments)
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	if jsonstrict.RejectDuplicateKeys(raw) != nil || t.ValidateInput(raw) != nil {
		return nil, "", mctlapi.CodeInvalidArguments
	}
	if !p.HasScope(t.RequiredScope) {
		return nil, "", mctlapi.CodeNotAuthorized
	}
	if d.Allow != nil && !d.Allow(p.Subject) {
		return nil, "", mctlapi.CodeRateLimited
	}
	var args map[string]any
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, "", mctlapi.CodeInvalidArguments
	}
	scope, err := d.API.Resolve(ctx)
	if err != nil {
		return nil, "", codeOf(err)
	}
	var body any
	pathID := ""
	if im.body {
		body = args
	}
	if im.pathID != "" {
		pathID, _ = args[im.pathID].(string)
	}
	out, err := d.API.Do(ctx, scope, im.op, body, pathID)
	if err != nil {
		return nil, scope.Tenant, codeOf(err)
	}
	if err := t.ValidateOutput(out); err != nil {
		return nil, scope.Tenant, mctlapi.CodeUpstreamInvalid
	}
	return out, scope.Tenant, ""
}

func codeOf(err error) string {
	var re *mctlapi.RefusalError
	if errors.As(err, &re) {
		return re.Code
	}
	return mctlapi.CodeUpstreamUnavailable
}

// refusal is the only failure shape: a code from the closed set, never
// upstream text.
func refusal(code string) *mcplib.CallToolResult {
	b, _ := json.Marshal(map[string]string{"error": code})
	return &mcplib.CallToolResult{
		IsError:           true,
		Content:           []mcplib.Content{mcplib.NewTextContent(string(b))},
		StructuredContent: json.RawMessage(b),
	}
}
