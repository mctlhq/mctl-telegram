# MCP Apps (SEP-1865) spike: a Telegram research and triage App

Issue: [mctlhq/mctl-telegram#569](https://github.com/mctlhq/mctl-telegram/issues/569).
Live-host testing, screenshots and connector-submission positioning are
explicitly out of scope here and belong to
[mctlhq/mctl-telegram#650](https://github.com/mctlhq/mctl-telegram/issues/650).

This document is the technical report the proposal's tasks.md (task 12)
requires. Every claim in it is either a fact about the code merged in this
PR, or an automated probe run against that code, or is explicitly marked as
not measured here.

## 1. Host-compatibility matrix

| Host | Extension advertised | Resource listed | Resource readable | Tools carry `_meta.ui` | Notes |
| --- | --- | --- | --- | --- | --- |
| This repository's own `mcpprobe`, in-process, `MCP_APPS_ENABLED=true` | yes | yes | yes | yes (7 tools) | Reference-host row below, produced by an actual local run. |
| Claude.ai / Claude Desktop | not measured here | not measured here | not measured here | not measured here | owned by mctlhq/mctl-telegram#650 |
| ChatGPT (Apps SDK) | not measured here | not measured here | not measured here | not measured here | owned by mctlhq/mctl-telegram#650 |

### Reference-host row: raw `mcpprobe` output

Produced by starting the real HTTP handler (`internal/mcp.Server.HTTPHandler`,
the same code `cmd/server` serves) in-process behind the real
`auth.Middleware`, with `WithAppsEnabled(true)`, and running
`mcpprobe.Run` against it in legacy mode with a valid bearer token and
`SkipOAuth: true`. This is exactly the fixture pattern
`internal/mcpprobe/inprocess_test.go` already uses
(`TestInProcess_AppsProbe_AdvertisedAgainstFlagOnEndpoint`,
`internal/mcpprobe/apps_test.go`), run once by hand for this report and
pasted verbatim:

```json
{
  "schema": "mctl-mcpprobe/1",
  "timestamp": "2026-09-19T09:06:40.022019957Z",
  "source": "in-process-current-main",
  "mode": "legacy",
  "protocol_version": "2025-06-18",
  "target_host": "127.0.0.1:35785",
  "summary": "PASS",
  "server": {
    "name": "mctl-telegram",
    "version": "report-run",
    "supported_versions": [
      "2025-06-18"
    ]
  },
  "session": {
    "header_present": true,
    "id_length": 48,
    "required": true,
    "foreign_accepted": true
  },
  "steps": [
    { "label": "initialize", "method": "initialize", "http_status": 200, "outcome": "PASS" },
    { "label": "tools_list_without_session", "method": "tools/list", "http_status": 404, "outcome": "PASS" },
    { "label": "tools_list_with_foreign_session", "method": "tools/list", "http_status": 200, "outcome": "PASS" },
    { "label": "tools_list", "method": "tools/list", "http_status": 200, "outcome": "PASS" },
    { "label": "tools_call_readonly", "method": "tools/call", "tool": "get_my_send_status", "http_status": 200, "is_error": false, "outcome": "PASS" }
  ],
  "apps": {
    "extension_advertised": true,
    "extension_mime_types": ["text/html;profile=mcp-app"],
    "resource_listed": true,
    "resource_uri": "ui://mctl-telegram/triage",
    "resource_mime_type": "text/html;profile=mcp-app",
    "resource_readable": true,
    "ui_tool_names": [
      "get_messages",
      "get_unread_messages",
      "list_dialogs",
      "prepare_get_media",
      "prepare_send_message",
      "search_messages",
      "send_message"
    ],
    "outcome": "PASS"
  }
}
```

(`tools` — the reduced `tools/list` inventory the probe also records — is
omitted above for length; it lists all thirty-one registered tools including
`prepare_send_message`, each with its `read_only` annotation, which is the
input `internal/mcpprobe/readonly.go` used to pick `get_my_send_status` as
the one read-only call it made.)

The same run against the identical wiring with `MCP_APPS_ENABLED` **unset**
(the default) produces `"apps": {"extension_advertised": false, "outcome":
"SKIPPED", "reason": "not-applicable"}` and an unchanged `"summary": "PASS"`
— see `TestInProcess_AppsProbe_NotAdvertisedAgainstFlagOffEndpoint`
(`internal/mcpprobe/apps_test.go`). That pair of tests is what CI runs on
every change to this surface; this report quotes one instance of their output.

## 2. Implementation-path decision

**Decision: implement MCP Apps natively in this Go binary**, in a new
`internal/mcpui` package, using primitives already present in the pinned
`mark3labs/mcp-go v1.0.0` (`go.mod:14`). No Node/TypeScript sidecar, no
vendored SDK fork, no upstream contribution was needed to ship this spike.

| SEP-1865 need | mcp-go v1.0.0 symbol |
| --- | --- |
| `capabilities.extensions["io.modelcontextprotocol/ui"]` | `server.WithExtensions(map[string]any)` — `server/server.go:675`, applied at `server/server.go:1261`; `mcp.ServerCapabilities.Extensions` — `mcp/types.go:633` |
| Resource capability | `server.WithResourceCapabilities(subscribe, listChanged)` — `server/server.go:344` |
| `ui://` resource with a non-standard mimeType | `MCPServer.AddResource(mcp.Resource, ResourceHandlerFunc)` — `server/server.go:797`; `Resource.URI` / `Resource.MIMEType` are free strings — `mcp/types.go:883,897` |
| Resource `_meta` (`csp`, `prefersBorder`, ...) | `mcp.Resource.Meta *mcp.Meta` — `mcp/types.go:881`; `mcp.TextResourceContents.Meta map[string]any` — `mcp/types.go:956`, doc comment: "Allows `_meta` to be used for MCP-UI features" |
| Tool `_meta.ui` | `mcp.Tool.Meta *mcp.Meta` — `mcp/tools.go:658`; `Meta.AdditionalFields` — `mcp/types.go:217`; `mcp.ToolOption` is `func(*Tool)` — `mcp/tools.go:887` (offsets in this SDK version), so a local option (`withUIResource`, `internal/mcp/apps.go`) composes with the existing tool builders |
| Structured payloads for the App | `CallToolResult.StructuredContent` — `mcp/tools.go:47`, already emitted by `jsonResult` for every tool |
| Long-running work | `mcp/tasks.go`, `server/task_hooks.go`, a `toolCallTasks` capability — present in the SDK, not used by this spike (see §5) |

There is no MCP-Apps *helper* in the SDK — no `NewUIResource`, no
`WithUIResourceMeta`. Every literal (`io.modelcontextprotocol/ui`, `ui://`,
`text/html;profile=mcp-app`, the nested `_meta.ui` shape) is written by hand,
in one place (`internal/mcpui/app.go`), and asserted by
`internal/mcpui/app_test.go` and the `mcpprobe` Apps step above.

### Alternatives considered and dropped

- **A thin Node/TypeScript MCP Apps adapter in front of the Go service.**
  Dropped: it would cost a second deployable, a second auth hop to `/mcp`
  (exactly the "duplicated credential path" this spike's security model
  forbids), a second place Telegram semantics could drift, and a Node
  runtime in an image that is deliberately Go-only
  (`Dockerfile`; `Dockerfile.agent-worker` exists as a separate image
  precisely so the main one stays Go-only).
- **Serve the App from a static HTTP route (`tg.mctl.ai/apps/*` or a CDN).**
  Dropped: this repository has no `embed.FS` and no `http.FileServer`
  anywhere today. A static route would be this repository's first, and would
  drag in integrity hashing, a cache policy, a dedicated CSP, and an
  `OriginGuard`/CORS question for iframe fetches that the inline
  `resources/read` delivery this PR ships avoids entirely (see §4).
- **Fork or patch `mark3labs/mcp-go` to add first-class MCP Apps helpers.**
  Dropped for this spike: the missing pieces are a dozen literal JSON keys,
  not missing SDK capability. An upstream contribution is a reasonable
  follow-up once the shape has proven itself, but was not on the critical
  path of answering the issue's question.
- **A dedicated `open_telegram_triage` opener tool, instead of attaching
  `_meta.ui` to the existing read tools.** Dropped as the default (recorded
  as an open question in the proposal): it would add a tool whose only job is
  to exist, need its own portal-allowlist decision, and be visible to the
  model in every session regardless of whether the App is ever opened.

## 3. Threat model

The design goal was that **an iframe button click grants no authority** — no
scope, no identity, no send permission — over what a model-originated call
already had. Concretely:

- **Iframe → tool invocation.** The App never talks to `tg.mctl.ai` directly.
  It posts JSON-RPC messages to the *host*, which proxies `tools/call` and
  `resources/read` on the host's own already-authenticated MCP session. Every
  such call re-enters this server through the exact same
  `auth.Middleware` → `requireScope`/`evaluateSendGate` path a model-issued
  call takes (`internal/mcp/server.go`'s `HTTPHandler`, unchanged by this
  PR). The App itself never holds a credential of any kind.
- **Untrusted Telegram content.** Every message body the App can show already
  passed through `sanitize.UserContent`, `sanitize.SensitiveTelegramContent`,
  and `WrapUntrustedContent` (`internal/mcp/format.go`) before the App ever
  sees it — the same pipeline a model client gets. `triage.html` additionally
  inserts every Telegram-derived string via `document.createElement` +
  `textContent` only (never `innerHTML` or equivalent; enforced by
  `TestTriageHTMLHasNoExternalDeps`, `internal/mcpui/app_test.go`, mirroring
  `internal/ui/chrome_test.go`'s `TestLiteChromeHasNoExternalDeps`), and
  strips the `<telegram-content …>` envelope by strict prefix/suffix string
  match rather than any HTML parse, keeping a visible "untrusted · Telegram"
  marker either way.
- **Identity.** Every App-originated call is identified solely by
  `auth.From(ctx)`, populated by `auth.Middleware` from the bearer token —
  never from a tool argument. No tool on this server accepts an identity
  hint of any kind, App or not.
- **Scopes.** Scopes come from the OAuth token the host already holds for its
  session; the App has no mechanism to request, name, or widen one. The read
  tools the App composes (`list_dialogs`, `get_unread_messages`,
  `get_messages`, `search_messages`, `prepare_get_media`) apply the exact
  same `requireScope` calls they apply to a model-originated call —
  unmodified by this PR.
- **Confirmations.** `prepare_send_message` issues a single-shot
  `confirmation_id` bound to `sha256(peer, NUL, text)` via the pre-existing
  `HashSendPayload` (`internal/mcp/confirm.go`, previously written but never
  called from production code). `send_message`'s optional `confirmation_id`
  is consumed **before** `evaluateSendGate` runs, and a mismatched,
  reused, foreign, or unknown id fails closed — see
  `TestToolSendMessage_ConfirmationMismatchedTextRefused`,
  `TestToolSendMessage_ConfirmationReuseRefused`,
  `TestToolSendMessage_ConfirmationWrongUserRefused`
  (`internal/mcp/apps_test.go`). Critically, **the confirmation is an
  additional binding, not a substitute gate**:
  `TestToolSendMessage_AppPathWithValidConfirmationStillDryRunsWhenGateClosed`
  proves a valid, freshly-issued, correctly-consumed confirmation still
  produces a `sent=false` dry-run preview when `send_enabled=false`, with no
  MTProto call made and a `send_message:draft` audit row recorded — the exact
  same outcome a model-originated call gets. The App cannot set a scope
  (scopes come from the token), cannot name an identity (no identity
  argument exists on any tool), cannot request a real send (no `mode`
  argument exists on `send_message`; the only place that ever appends one is
  server-side, after the gate has already passed), and cannot read another
  identity's confirmation (`ErrConfirmationWrongUser`).
- **Rate limiting.** An App-originated send debits the same
  per-(identity, peer) limiter (`evaluateDirectSendLimiter`) a
  model-originated send does —
  `TestToolSendMessage_AppPathDebitsSamePeerLimiter`.
- **`_meta.ui.visibility` is a host hint, never server authorization.** The
  SEP-1865 spec has a conforming host refuse `tools/call` from the App itself
  for a tool lacking `"app"` in `_meta.ui.visibility`. That protects the
  *model* from App-only tools; it gives this server nothing, because nothing
  in this repository reads it. `requireScope` and the send gate are the only
  authority a call is ever checked against, regardless of which client
  (model or App) issued it, and regardless of what a host chooses to enforce
  on its own side. This is stated once, here, as the threat-model position,
  and again as a code comment on `mcpui.ToolMeta()`.
- **Credential/secret leakage.** No Telegram session, MTProto credential,
  API id/hash, OAuth token, or bearer credential is ever placed into the
  resource body (`triage.html` is a static embedded asset with no template
  interpolation) or into any tool result the App reads (unchanged from the
  model-facing surface).
- **Exfiltration channel.** `_meta.ui.csp` declares empty
  `connectDomains`/`resourceDomains`/`frameDomains`/`baseUriDomains`
  (`mcpui.Resource().Meta`, `mcpui.Contents(...)`'s `TextResourceContents.Meta`),
  so a conforming host applies a `default-src 'none'` baseline to the iframe.
  Even a DOM-injection bug in the App would have no network destination to
  reach.
- **Auth-gated resource read.** `resources/read` for the triage document
  refuses with an error when `auth.From(ctx) == nil`
  (`Server.handleReadAppResource`, `internal/mcp/server.go`), asserted by
  `TestAppResourceHandler_RequiresAuth`
  (`internal/mcp/apps_surface_test.go`) — so a deployment that happens to run
  with `AUTH_REQUIRED=false` still does not serve the App body anonymously.
- **Flag-off byte-identical surface.** With `MCP_APPS_ENABLED` unset
  (default, and what this PR ships), `initialize` advertises no
  `extensions`, no `resources` capability, `resources/list` is unavailable,
  and no tool carries `_meta` — asserted by
  `TestAppsFlag_Off_SurfaceUnchanged` (`internal/mcp/apps_surface_test.go`,
  T1) and reflected in the "not advertised" `mcpprobe` row above.

## 4. Hosting/asset decision

The App document is delivered **inline through `resources/read`**, not from a
new HTTP route or a static/CDN origin. This needs no new route, no static
asset pipeline, no cache policy, and no CORS story; it inherits
`auth.Middleware` for free (see the auth-gated read above); and it leaves
`OriginGuard` (`internal/web/origin.go`) completely untouched, because the
iframe never contacts `tg.mctl.ai` at all — the host proxies `tools/call` and
`resources/read` over its own MCP session, exactly like every other
capability this server exposes.

The URI (`ui://mctl-telegram/triage`) is stable and unversioned by design.
The build version travels in a separate `Version` constant
(`internal/mcpui/app.go`), and drift in the document itself is caught by a
recorded content-hash test (`TestTriageHTMLContentHash`,
`internal/mcpui/app_test.go`) rather than a version bump to the URI — a
changing URI would break any host that cached the tool → resource link.

## 5. Long-running research assessment

The App's read flows are bounded by the caps that already exist, not by any
App-specific job mechanism:

- `list_dialogs`, `get_unread_messages`, `get_messages`, `search_messages`
  each take a `limit` argument (default 50, max 200) already enforced
  server-side.
- `get_unread_messages(fetch_media=true)` is capped by `BulkMediaFetchCap`
  (5 items per page) and by `MediaDownloadMaxBytes` per item
  (`internal/mcp/bulk_media.go`).
- `prepare_get_media` / `get_media` are individually capped by
  `MediaDownloadMaxBytes` (default 20 MiB) per download.

None of the flows this App composes are close to needing a job/poll
mechanism at the scale a single triage session operates at (tens of dialogs,
tens of messages of context, one media item at a time). The flow nearest a
real bound is a broad, unscoped `search_messages` call across every dialog,
which is already limited by the tool's own `limit` argument the same way it
is for a model-originated call — this PR introduces no new unbounded
surface.

The pinned `mark3labs/mcp-go v1.0.0` already carries the task primitives a
future long-running flow would need — `mcp/tasks.go`, `server/task_*.go`,
and a `toolCallTasks`-style capability bit
(`server/server.go`'s `capabilities` struct) — but this spike does not wire
any of it, deferring that decision entirely to the MCP Tasks spike
[mctlhq/.github#41](https://github.com/mctlhq/.github/issues/41), per the
proposal's explicit scope boundary ("A task/job system for long-running
work. That is mctlhq/.github#41").

## 6. Submission-positioning note

`claude-connector-submission.md:193` currently states this server has "**no**
`ui/open-link` / interactive UI components / MCP-App widgets." That sentence
becomes false the moment a deployment sets `MCP_APPS_ENABLED=true` — this PR
makes that capability exist in the codebase, off by default, and nowhere
turned on. Updating `claude-connector-submission.md` (and any other
submission-facing document) to reflect a *deployed* App is explicitly
[mctlhq/mctl-telegram#650](https://github.com/mctlhq/mctl-telegram/issues/650)'s
responsibility, not this PR's — this PR does not enable the flag anywhere,
does not deploy it, and does not claim any host, connector, or directory has
accepted or even seen this App.

**Nothing in this report predicts directory acceptance.** It establishes
that the capability can be built correctly and safely inside this codebase's
existing security model; whether any particular host renders it usefully, or
any particular directory approves it, is unmeasured and is #650's to find
out.

## 7. Readiness checklist and proposed child issues

Readiness checklist (all satisfied by this PR unless marked otherwise):

- [x] Flag-gated, default off, byte-identical surface with the flag unset
      (T1, `mcpprobe` "not advertised" row).
- [x] Extension + resource capability + `ui://` resource + `_meta.ui` link,
      spec-shaped (T2).
- [x] Auth-gated resource read (T3).
- [x] Asset hygiene: no external origin, no markup-injection API, in the
      embedded document (T4).
- [x] Content-hash golden test on the embedded document (T5).
- [x] `prepare_send_message` reports the real send-gate verdict for all four
      gate conjuncts without ever calling Telegram (T6).
- [x] `send_message`'s optional `confirmation_id` binds to
      `(peer, text)`, single-shot, identity-bound (T7).
- [x] `send_message` without `confirmation_id` is unchanged (T8).
- [x] A valid App-path confirmation cannot open a closed send gate; the
      shared per-peer limiter is still debited on a real send (T9).
- [x] `MCP_TOOL_FILTER=read-only` still removes every write tool including
      `prepare_send_message`, while the App resource and read tools' `_meta.ui`
      remain (T10).
- [x] `docs/portal-allowlist.json` carries an explicit, disabled decision for
      `prepare_send_message`, verified by the AST-derived guard with
      `AppsEnabled=true` (T11).
- [x] `mcpprobe` Apps conformance step, additive against a flag-off endpoint
      (T12, this report's reference-host row).
- [x] `MCP_APPS_ENABLED` config flag default/override test (T13).
- [ ] Live-host measurement against Claude.ai, Claude Desktop, Claude Code,
      ChatGPT — deferred to #650.
- [ ] Connector/directory submission-document updates — deferred to #650.
- [ ] A production deployment decision (whether/when to set
      `MCP_APPS_ENABLED=true` anywhere) — an operator action, not part of
      this PR.

Proposed child issues (not filed from this PR):

1. **Live host compatibility matrix** — run `cmd/mcpprobe` (or the
   equivalent manual steps) against Claude.ai, Claude Desktop, Claude Code,
   and ChatGPT once a deployment has `MCP_APPS_ENABLED=true`, and fill in
   the two "not measured here" rows above with real evidence, screenshots,
   and a video walkthrough. (mctlhq/mctl-telegram#650, already filed.)
2. **`triage.html` visual and UX polish** — richer filters, better empty
   states, a genuine responsive layout tuned to the iframe sizes real hosts
   actually grant, informed by what #650 observes live.
3. **`open_telegram_triage` opener tool reconsideration** — revisit the
   "Which tool carries `_meta.ui`" open question if a live host turns out to
   require a distinguished opener rather than accepting `_meta.ui` on
   existing read tools.
4. **`prepare_send_message` portal exposure** — revisit the
   `docs/portal-allowlist.json` `enabled: false` decision if a real
   portal-facing use case for the draft/confirm/send affordance appears.
5. **MCP Tasks adoption for long-running research** — once
   mctlhq/.github#41 lands a decision on `mcp/tasks.go` / `server/task_*.go`
   adoption generally, revisit whether a broad, unscoped multi-channel
   search flow in the App should become a task rather than a single bounded
   call.
6. **Upstream `mark3labs/mcp-go` MCP Apps helpers** — consider contributing
   `NewUIResource`/`WithUIResourceMeta`-style helpers upstream once this
   shape has proven itself in at least one live host, so the next SDK
   consumer does not have to hand-write the same literal JSON this PR did.
