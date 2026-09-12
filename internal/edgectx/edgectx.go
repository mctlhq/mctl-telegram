// Package edgectx carries the request-identity facts an MCP call arrived with
// from the HTTP layer down to the audit write.
//
// It exists because of what Slice 1 of mctlhq/mctl-telegram#617 measured at the
// tg.mctl.ai ingress on 2026-09-12. Two results shape this package:
//
//   - Cf-Ray arrives on BOTH routes. The zone is proxied, so a direct consumer
//     call gets a ray of its own. It is a per-request identifier and nothing
//     more; it is not evidence that a call came through the Portal.
//   - The route discriminator is Cf-Worker (gateway.agents.cloudflare.com on the
//     Portal leg, absent on the direct leg), and the Portal additionally
//     forwards Mcp-Method and Mcp-Name — the tool-level evidence the Gateway
//     spike (mctlhq/.github#43) established Cloudflare cannot supply.
//
// IMPORTANT: every field here is a header as RECEIVED. It is evidence for
// reading an audit trail, never an authorization input. A direct caller can
// send any header it likes, and whether Cloudflare strips a client-supplied
// Cf-Worker on the way in was NOT measured. Nothing in mctl may grant on the
// basis of Route.
package edgectx

import (
	"context"
	"net/http"
	"strings"
)

// Context is the set of request-identity facts recorded with an audit entry.
// Every field is optional: a call that arrived without the header leaves it
// empty, and an empty field is itself information (no Portal, no protocol
// header) rather than a gap to be filled in with a default.
type Context struct {
	// RequestID is Cf-Ray as received: unique per request on both routes.
	RequestID string
	// Route is RoutePortal when Cf-Worker was present, RouteDirect otherwise.
	Route string
	// MCPMethod and MCPName are Mcp-Method / Mcp-Name as received. The Portal
	// sends both (Mcp-Name only on tools/call); a direct client may send
	// neither, and may send anything.
	MCPMethod string
	MCPName   string
	// ProtocolVersion is MCP-Protocol-Version as received.
	ProtocolVersion string
}

// Route values. Kept as plain strings because they are written to an audit
// column and read back by operators, not compared against an enum in policy.
const (
	RoutePortal = "portal"
	RouteDirect = "direct"
)

// Empty reports whether nothing was captured, which is the case for a call
// that never came through an HTTP request (a test, an internal caller).
func (c Context) Empty() bool {
	return c == Context{}
}

type ctxKey struct{}

// With returns a context carrying c.
func With(ctx context.Context, c Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// From returns the Context stored by With, or the zero value.
func From(ctx context.Context) Context {
	c, _ := ctx.Value(ctxKey{}).(Context)
	return c
}

// FromRequest reads the facts off an inbound request. Values are sanitized:
// they are attacker-controlled on the direct route, and they end up in a
// database column, a JSON tool response and a log line.
func FromRequest(r *http.Request) Context {
	route := RouteDirect
	if r.Header.Get("Cf-Worker") != "" {
		route = RoutePortal
	}
	return Context{
		RequestID:       sanitize(r.Header.Get("Cf-Ray")),
		Route:           route,
		MCPMethod:       sanitize(r.Header.Get("Mcp-Method")),
		MCPName:         sanitize(r.Header.Get("Mcp-Name")),
		ProtocolVersion: sanitize(r.Header.Get("MCP-Protocol-Version")),
	}
}

// maxValue bounds one recorded value. The real ones are short (a Cf-Ray is 20
// bytes, a tool name tens); the bound is for the header a hostile direct caller
// sends, which would otherwise reach the audit table at header size.
const maxValue = 200

// sanitize keeps printable ASCII and drops the rest. A value that is not
// entirely printable is dropped rather than partially kept: these are opaque
// identifiers, so a mangled one is worse than an absent one -- absent is a
// fact the reader can act on, mangled invites a false join.
func sanitize(v string) string {
	if v == "" {
		return ""
	}
	if len(v) > maxValue {
		return ""
	}
	if strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
		return ""
	}
	return v
}
