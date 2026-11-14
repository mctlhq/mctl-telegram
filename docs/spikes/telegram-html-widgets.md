# Spike: Telegram HTML widgets for read-only agent status (#1283)

Status: research and recommendation only. Refs #1283 (does not close it).
Date of research: 2026-11-14. Base: origin/main at b341c520.

Nothing in this document is an implementation, a live experiment or an owner
verdict. No bot message was sent, no Telegram API was called, no client was run.

## 1. Proposed verdict (pending owner decision)

**DEFER_COMPATIBILITY.**

Vendor documentation describes a capable widget surface, but (a) the vendor's own
sources disagree with each other (section 3.3), (b) no real-client coverage has
been measured (section 6), and (c) this repository does not yet carry the
correlation fields a status card needs (section 4). A narrow read-only status
widget (option A) looks worth a pilot once compatibility is measured. Even
then, a LIMITED_GO_READ_ONLY would only permit a later, separately approved
implementation proposal. It is not an authorization to build.

## 2. Scope and non-goals

- Surface: Bot API presentation in a **private bot DM** only.
- Not the existing user-account MTProto MCP send path (`internal/telegram/`).
- Out of scope: groups, channels, inline, and the vendor's wallet, signing and
  transaction query families (named in the changelog; unrelated to this proposal).
- Out of scope: any second webhook or `getUpdates` consumer (section 4.4).
- Dedup with existing work, not redefined here: Rich Messages #1217/#1224, Chat
  Automation #1028, delivery #1173, canonical Human Input #734 / #571.

## 3. Primary sources and capability matrix

Evidence class: **DOCUMENTED** = stated by a vendor page the orchestrator read on
2026-11-14 and relayed as bounded paraphrased notes (not full page copies; the
researcher had no network). **OBSERVED** = seen by running it (nothing here).
**UNKNOWN** = not established. **NOT_RUN** = test needed, not performed.

Sources:

1. https://core.telegram.org/bots/widgets (current page, 2026-11-14)
2. https://core.telegram.org/bots/api-changelog (section dated 2026-11-09, Bot API 10.4)
3. https://github.com/TelegramMessenger/widget-sandbox README.md (mutable `main`, no commit pin)
4. https://github.com/TelegramMessenger/widget-sandbox docs/sdk-v1.md (mutable `main`, no commit pin)

### 3.1 Capability matrix

| Capability | Fact | Class | Source |
|---|---|---|---|
| Widget unit | One self-contained HTML/CSS/JS document | DOCUMENTED | 1 |
| Max HTML size | 32768 UTF-8 bytes | DOCUMENTED | 1 |
| Max compressed size | 4096 bytes after server-side zlib level 9 | DOCUMENTED | 1 |
| Code mutability | HTML (code) immutable after sending | DOCUMENTED | 1 |
| Data mutability | Only the bot updates `chat_data` / `public_data` | DOCUMENTED | 1 |
| Runtime | QuickJS, no network APIs, external assets not loaded | DOCUMENTED | 1, 3 |
| Widget to bot | `widget_query`, max 64 bytes | DOCUMENTED | 1 |
| Bot API methods | `sendWidget`, `answerWidgetQuery`, `editMessageWidgetData` (plus shared variants `sendSharedWidget`, `editSharedWidgetData`) | DOCUMENTED | 2 |
| Update types | `widget_query`, `shared_widget_query` | DOCUMENTED | 2 |
| Message fields | Widget field on `Message` and `ExternalReplyInfo` | DOCUMENTED | 2 |
| Production availability | Private bot chats only; groups/inline/forwarding test-server-only | DOCUMENTED | 1, 2 |
| Forwarding | Production widget messages protected against forwarding; `copyMessage(s)` cannot copy them | DOCUMENTED | 2 |
| Unsupported clients | Show unsupported media with the caption | DOCUMENTED | 1 |
| Rendering consistency | Page claims cross-client consistency | DOCUMENTED (vendor claim, unverified) | 1 |
| Sandbox | QuickJS isolated thread, DOM shim (not a browser), host validators for element/CSS/URL allowlists, runtime limits | DOCUMENTED | 3 |
| SDK v1 | chatData/publicData, change events, requests to bot with bot result, layer 233; host-provided server flags and viewer context; framework-enforced schemas, activation, rate limits | DOCUMENTED | 4 |
| SDK v1 history | Original contract 2026-10-16/17, interactivity addition 2026-10-25 | DOCUMENTED | 4 |
| Exact limits for rate/activation/validator allowlists | Not in the supplied notes | UNKNOWN | - |
| Exact `sendWidget` / `answerWidgetQuery` parameter lists, error codes | Not in the supplied notes | UNKNOWN | - |
| Whether `public_data` vs `chat_data` visibility semantics matter in a private DM | Not in the supplied notes | UNKNOWN | - |
| Test-server vs production per-feature availability beyond the rows above | Not in the supplied notes | UNKNOWN | - |

### 3.2 Public versus chat state

The notes establish two mutable stores, `chat_data` and `public_data`, written
only by the bot. Their exact visibility rules are UNKNOWN (table above). The
proposal therefore assumes the worst: treat everything placed in either store
as visible to anyone who can view the message, and put no secret or customer
content in either.

### 3.3 Documentation drift (not reconciled by evidence)

- The widget-sandbox README introduction says SDK v1 sends no messages to the
  bot, and a client-team instruction names v0.1.1 as latest.
- The current `docs/sdk-v1.md` and Bot API 10.4 describe widget requests to the
  bot (`widget_query`) and a later interactivity addition.

Both fetched from mutable `main`, with no commit pin. The README statement is
possibly stale. This is recorded as documentation drift, not as a verified
upgrade path. The release-tag / commit / client-version matrix is **UNKNOWN**.
Option B depends on exactly this contested capability.

## 4. Local inventory (source-pinned to origin/main b341c520)

Observed by reading this repository only. Facts about other repositories
(mctl-api, mctl-agent, mctl-gitops) are **unobserved** here and not guessed;
where the proposal depends on them it says so.

### 4.1 Bot API sender

- `internal/botapi/botapi.go`: the single Bot API sender. Methods: `SendMessage`
  (plain), `SendHTMLMessage` (`parse_mode=HTML`, link previews disabled),
  `GetChat`. Form-encoded POSTs to `/bot<token>/<method>`; the token is stripped
  from transport errors; errors are typed `*notify.APIError` (status,
  description, retry_after) and raw bodies are never kept.
- **Absent:** `sendWidget`, `answerWidgetQuery`, `editMessageWidgetData`,
  any widget type.

### 4.2 Inbound update consumer (the only one)

- `internal/bot/receiver.go`: long-poll `getUpdates` (not a webhook), single
  replica by deployment design (Recreate, replicas 1), offset derived from the
  database, updates accepted durably before dispatch, pending sweep for retries.
- `allowed_updates` is hard-coded to `["message","callback_query"]`
  (`receiver.go:389`). A `widget_query` would not be delivered without changing
  this list, and `Update.Kind()` (`internal/bot/update.go`) would classify it
  `KindUnsupported`.
- `internal/bot/update.go`: `Update` decodes only routing facts. Callback `data`
  is deliberately not decoded. `CallbackQuery` holds `id` and originating chat.
- `internal/bot/registry.go`: handlers by kind; `isKnownChat` drops updates from
  unknown chats. `KindCallbackQuery` has no registered handler in production
  paths found (tests register one).
- `internal/bot/start.go`, `internal/bot/bridge.go`: `/start` reachability
  recording and a bearer-authenticated observation endpoint.
- Consequence: any widget interaction must be a new handler kind inside this
  receiver. A second `getUpdates` consumer would 409; a webhook would break the
  Recreate rollout assumption documented in `update.go`. Neither is proposed.

### 4.3 Human Input (canonical, #571 / #734)

- `internal/humaninput/` plus `internal/workctx/humaninput.go`,
  `docs/contracts/mctl-api-human-input.md`.
- Delivery is to the operator's **Saved Messages** (user-account side), and the
  answer is the text command `/mctl input <code> <value>`, not a callback or a
  bot DM. mctl-api owns every authorization and state decision; this repo
  renders and relays.
- `RequestView` is an allowlisted DTO (request_id, request_hash,
  request_version, work_item_id, question, options, expires_at, state...).
  Unknown fields are ignored by construction.
- `Render` caps fields, sanitizes agent text, never lets agent text start a line
  at column 0, and labels messages `INPUT REQUEST (not an approval)`.
- This is the template a widget must follow: allowlisted fields, sanitize, cap,
  and never present display as authorization.

### 4.4 Identity, tenancy and correlation fields: shipped vs absent

| Needed for a status card | In this repo | Note |
|---|---|---|
| Bot chat id to user mapping | Present as known-chat check (`Registry.isKnownChat`) and `/start` records | Mapping of chat to tenant principal beyond this is UNKNOWN to this spike |
| Work item ref | Present: `WorkItemID`, `WorkRef` (derived from local `work_item_bindings`) | `owner/repo#n` display |
| Request id, hash, version | Present for Human Input only | Not for run status |
| Agent run id / run status | Not found by search of agent schema, control and workctx client | Absent here; ownership vs mctl-agent unobserved |
| DevLoop evidence (HEAD sha, check results) | Not found | Absent here |
| Tenant / chat / run / principal correlation tuple | No single record | Would be new |
| Freshness / timestamp | `created_at`, `expires_at` exist on Human Input only | No run-status freshness |

Ownership of run status and evidence is expected to be mctl-agent / mctl-api
(unobserved). This repo must not become a second source of truth: the card must
render a server-provided read model, never compute status itself.

### 4.5 Overlap with other work

- Rich Messages (#1217/#1224), Chat Automation (#1028), delivery (#1173): the
  repository search for `rich` found no implementing code or docs, so their
  contract is unobserved here. This spike does not define message formats,
  delivery policy or automation; any widget send must go through whatever
  delivery layer #1173 settles on, not around it.

## 5. Options compared

- **A. Status-only widget.** `sendWidget` with a static-looking card, bot updates
  `chat_data` via `editMessageWidgetData`. No `widget_query`.
- **B. Constrained read-only refresh/details callback.** A adds a `widget_query`
  (max 64 bytes) that returns refreshed read-only details through
  `answerWidgetQuery`.
- **C. Existing plain HTML / Rich Message / link.** `SendHTMLMessage` or Rich
  Messages with a link to the existing web page. No new capability.

| Dimension | A | B | C |
|---|---|---|---|
| User value | Medium: glanceable, in-place updates | Medium-high: on-demand refresh | Low-medium: static, needs a new message per change |
| Build effort | Medium: new sender method, renderer, size gate | High: A plus a new update kind, handler, auth, rate limits, receiver change | Low |
| Security surface | Small: output only | Larger: new inbound untrusted channel | Smallest (existing) |
| Cost / ops | Low | Moderate (query traffic, rate limiting) | Lowest |
| Reliability | Depends on client support and edit rate | Same plus contested-doc risk (3.3) | Highest: works on every client |
| Compat risk | Unmeasured | Unmeasured plus doc drift | None |

Recommendation: C is the baseline and must exist in every option as the
fallback. A is the only candidate worth a future pilot. B stays deferred until
the doc drift is resolved and A has run clean.

## 6. Client compatibility matrix (no client was run)

| Client | Widget render | Interaction (B) | Fallback to caption |
|---|---|---|---|
| Android (current) | DOCUMENTED (vendor claim of consistency) / NOT_RUN | UNKNOWN / NOT_RUN | DOCUMENTED / NOT_RUN |
| iOS (current) | DOCUMENTED (claim) / NOT_RUN | UNKNOWN / NOT_RUN | DOCUMENTED / NOT_RUN |
| Desktop (current) | DOCUMENTED (claim) / NOT_RUN | UNKNOWN / NOT_RUN | DOCUMENTED / NOT_RUN |
| Web (current) | DOCUMENTED (claim) / NOT_RUN | UNKNOWN / NOT_RUN | DOCUMENTED / NOT_RUN |
| Old client | UNKNOWN / NOT_RUN | UNKNOWN / NOT_RUN | DOCUMENTED ("unsupported media with caption") / NOT_RUN |

No cell is OBSERVED. Minimum client versions and the SDK/layer each client
supports are UNKNOWN. The caption, text and link fallback therefore must carry
the whole meaning of the card by itself (section 8).

## 7. Threat matrix

| Threat | Vector | Mitigation (design requirement) |
|---|---|---|
| Untrusted HTML / XSS | Agent- or model-derived text reaching widget HTML | HTML is a fixed, reviewed template compiled into the binary. Dynamic values only as escaped data in `chat_data`, never string-concatenated into HTML. Vendor sandbox is defence in depth, not the control. |
| Model text / prompt injection | Run summary or commit message containing instructions or fake UI | Render only allowlisted, typed fields (enums, ids, timestamps, short sanitized labels) using the `humaninput` approach: sanitize, cap, indent. No free-form model prose in the card. |
| Profile / validator failure | Widget rejected by client validators (allowlists, SDK version) | Offline validator run before send (section 11); failure means send the fallback only. |
| Cross-chat leak | Card or `public_data` shown to the wrong chat; `public_data` visibility UNKNOWN | Send only to the bound private DM; verify chat-to-principal binding at send time; no tenant data in `public_data`. |
| Replay / stale | Old `widget_query` or old card replayed | Every query carries a short opaque reference (<= 64 bytes) resolved server-side to (tenant, chat, run, version); reject unknown, expired or superseded references; answer with an explicit stale state. |
| Stale evidence | Card shows an old HEAD as current | Show evidence timestamp and HEAD; mark stale after a TTL; unknown is shown as unknown (section 8). |
| Size | Card exceeds 32768 B or 4096 B compressed | Budget and hard gate (section 8); over budget means fallback. |
| Flood / rate | Rapid edits or queries | Per-run edit coalescing, per-principal query rate limit, vendor limits UNKNOWN so assume strict. |
| Privacy | Customer content in card | Allowlisted fields only; no message bodies, phone numbers or secrets (project safety rules; extend `internal/audit/redact.go` for new field names). |
| Retention | Card persists with old data after run ends | Final edit to a terminal state; never keep sensitive data in the message; retention of stored references bounded. |
| Display as authority | "Approved" shown, read as permission | See section 9. |

## 8. Read-only AgentRunStatus / DevLoopEvidence card

### 8.1 Payload (server-provided read model, rendered by this repo)

All fields typed and allowlisted. Anything missing renders as `unknown`, never
as a default success.

| Field | Type | Rule |
|---|---|---|
| `ref` | string <= 120 | `owner/repo#n` display ref |
| `run_state` | enum: queued, running, waiting_input, succeeded, failed, cancelled, unknown | Unrecognized value renders `unknown` |
| `head_sha` | 7 to 12 hex | Shown abbreviated; absent renders `HEAD unknown` |
| `checks` | enum: passing, failing, pending, unknown | Never inferred locally |
| `evidence_at` | RFC 3339 UTC | Rendered as absolute UTC, plus "stale" past TTL |
| `provenance` | enum: server, unverified | Only `server` displays as a fact |
| `detail_url` | https URL <= 200 | Same acceptance test as `humaninput.Render` links |
| `ref_token` | opaque <= 64 B | Only if option B |

The card contains no question text, no model prose, no logs.

### 8.2 Size budget

Hard gates enforced before send: HTML <= 32768 B and compressed (zlib level 9)
<= 4096 B, per vendor documentation. Because compressed size depends on the
data, the gate must be checked on the final rendered artifact, with a working
target of <= 3072 B compressed to leave margin. Over budget: send the fallback,
not a truncated widget. Vendor server-side compression equivalence is UNKNOWN,
so the gate should be conservative.

### 8.3 Fallback text (also the accessibility baseline)

Plain-text caption and message, no color-only meaning, meaning carried by words:

```
Run status: <run_state>
Work: <ref>
HEAD: <head_sha | unknown> (checks: <checks>)
As of: <evidence_at UTC | unknown>
Details: <detail_url>
```

Every state is spelled out in text. Interactive controls (option B) need a text
equivalent: "Refresh: open the details link". Contrast, focus order and
screen-reader behavior of the widget itself are UNKNOWN and NOT_RUN.

### 8.4 Interaction contract (option B only)

- Read-only: a query can only return a fresher copy of section 8.1 data.
- Allowed query vocabulary is a closed set of two verbs: `refresh`, `details`.
- Display of any value, including "succeeded" or "approved", is not authorization.

### 8.5 Ordered rules for update, auth, rate, cancel, stale and reference failure

Evaluate in this order; first failing rule decides:

1. **Parse**: update decodes into the narrow struct; unknown or oversize means drop and count (no content logged).
2. **Known chat**: `isKnownChat` fails means drop (existing behavior).
3. **Auth / binding**: chat maps to exactly the principal that owns the referenced run; otherwise answer a generic denial, no detail.
4. **Reference**: `ref_token` resolves; unknown or malformed means answer "no longer available".
5. **Rate**: per-principal and per-run limits; exceeded means answer "try later", no server work.
6. **Cancel / terminal**: run terminal or cancelled means answer the terminal state once, then stop updating the card.
7. **Stale**: reference version is older than current means answer the current state, never the old one.
8. **Freshness**: evidence past TTL means include stale marker; unavailable server read means `unknown`, never cached success.
9. **Reply**: answer within the vendor's response window (UNKNOWN); on timeout the client falls back to its own failure behavior.
10. **Edit**: card edits coalesced and ordered by run version; an edit with a lower version than the stored one is discarded.

## 9. Authorization boundary

- Showing "Approved" (or any state) in a card is never authorization.
- A read-only callback cannot execute merge, release, deploy, retry or permission changes. Its verb set (8.4) has no such verb and the handler has no executor, matching the stance of `internal/humaninput` (no Executor, never reads `agent_actions`).
- Any consequential action goes through canonical server-side Human Input (#571/#734) and a separate hash-bound approval, owned by mctl-api. A widget may at most link to that flow.

## 10. Reversible pilot gates and stop conditions (future, needs approval)

Gates, in order; each requires explicit owner approval:

0. Pin primary sources (commit/tag, dated snapshots) and resolve the 3.3 drift.
1. Offline renderer, validator and fallback test slice (section 11) merged, no sending.
2. Compatibility measurement on real clients (section 12), approved separately.
3. Pilot option A to the owner's own bot DM only, behind a default-off flag.
4. Evaluate B only after 3 is clean.

Stop conditions (any one ends the pilot): any client renders wrong or blank without the caption fallback; any cross-chat or stale-as-fresh display; size gate failures in production data; vendor changes or withdraws the API; unresolved doc drift. Rollback: turn the flag off; fallback text path remains.

## 11. Smallest later offline slice (not implemented here)

One new package, for example `internal/botwidget` (name not decided), pure functions, no network, no sender:

- `Render(status) (html []byte, data []byte, fallback string, err error)` from the 8.1 struct.
- `Validate(html, data)`: size gates (32768 B, 4096 B zlib level 9), no external URLs, no script-injected data, closed element allowlist (to be pinned from the SDK once sources are pinned).
- Golden tests with synthetic personas (Alice, Bob, Carol, Dana) only; no real ids.
- Fallback text golden tests, including every `unknown` combination.

Negative / mutation plan:

- Inject `<script>`, `</`, quotes and bidi controls in `ref` and `detail_url`: must be rejected or escaped.
- Oversize ref, evidence and URL: must trip the budget and yield fallback only.
- Mutation: remove the escape step; remove the size gate; make `unknown` default to `succeeded`; drop the stale TTL. Each mutation must fail at least one test.
- Property: output never contains a field outside the allowlist.

No sender, no `allowed_updates` change, no handler is part of this slice.

## 12. Proposed future compatibility test plan (requires approval; NOT_RUN)

Out of scope here and needs separate approval, a test bot and a test account:
render and fallback on Android, iOS, Desktop, Web and one old client per
platform; interaction (B) only if 3.3 is resolved; record client versions;
screenshots only from real runs, labeled OBSERVED. Cost, account and test-vs-
production-server choices are owner decisions.

## 13. Open questions for the owner

1. Is mctl-agent or mctl-api the source of run status and DevLoop evidence, and are the section 8.1 fields available there?
2. Is a bot DM the intended audience, given Human Input today goes to Saved Messages (user account)?
3. Are pinned vendor sources and a test-bot budget available for gate 0 and 2?

## 14. Limitations

- Telegram facts come from orchestrator-relayed, paraphrased notes dated 2026-11-14, not full page copies; exact parameter lists and limits not in those notes are UNKNOWN.
- The widget-sandbox sources were unpinned `main`.
- Nothing about client behavior was observed.
- Facts about mctl-api, mctl-agent and mctl-gitops are unobserved.
