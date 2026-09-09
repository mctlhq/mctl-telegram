// Package mcpprobe is a standalone Cloudflare MCP Portal compatibility probe
// for mctl-telegram's /mcp endpoint and OAuth surface (issue #585, execution
// child of mctlhq/.github#44).
//
// It is deliberately isolated from cmd/canary and the load generator: those
// are legacy-style clients (initialize -> Mcp-Session-Id -> tools/call) used
// for paging/SLO purposes, and this spike must not change their behavior.
//
// The probe distinguishes two explicit, non-overlapping protocol modes:
//
//   - ModeModern exercises the stateless protocol core introduced in MCP
//     protocol version 2026-07-28 (SEP-2567, SEP-2575, SEP-2243): every
//     request is self-describing (per-request `_meta`), `server/discover`
//     replaces `initialize` as the discovery entry point, `initialize` is a
//     removed method, and no `Mcp-Session-Id` is minted or sent.
//   - ModeLegacy exercises the pre-2026-07-28 initialize/session lifecycle
//     that mctl-telegram's own current clients use.
//
// A failed or partial modern-mode run is never silently reported as legacy,
// or vice versa: see Report.Modern and Report.Legacy, which are independent,
// optional fields.
//
// Reports are structurally redacted (see Report): the type carries only
// labels, protocol versions/modes, HTTP status and JSON-RPC error codes,
// method/tool names, readOnlyHint annotations, booleans, counts, and
// session-id presence/length. There is no field capable of holding a bearer
// token, an authorization code, a tool result body, a chat title, a peer id,
// or a phone number, so no redaction step can be forgotten — the shape
// itself is the guarantee (requirements.md acceptance criterion C).
//
// The only tools/call this package will ever issue is a single, structurally
// guarded read-only call: it refuses to invoke any tool whose tools/list
// annotation does not report readOnlyHint=true.
package mcpprobe
