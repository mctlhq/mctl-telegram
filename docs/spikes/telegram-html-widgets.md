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
3. https://raw.githubusercontent.com/TelegramMessenger/widget-sandbox/main/README.md
4. https://raw.githubusercontent.com/TelegramMessenger/widget-sandbox/main/docs/sdk-v1.md

Sources 3 and 4 were retrieved by the orchestrator on 2026-11-14 from the
mutable `main` branch. They are not pinned to a commit or tag, so they can change
under the same URL.

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
| Agent run id / run status | Not found in the files searched in this repository (agent schema, control and workctx client; targeted searches, not an exhaustive audit) | No run read model located here; which service owns it is unknown to this spike |
| DevLoop evidence (HEAD sha, check results) | Not found in the same searches | No evidence read model located here |
| Tenant / chat / run / principal correlation tuple | No single record found | Would be new |
| Freshness / timestamp | `created_at`, `expires_at` exist on Human Input only | No run-status freshness field located |

Because no run read model was located, this spike makes no claim that a status
card exists or can be built today. The owner of run status and evidence is an
open question (section 13); no owning service is assumed. Whoever owns it, this
repo must not become a second source of truth: a card must render a read model
supplied by that owner, never compute status itself. That read model contract
is **unresolved** (section 8.1).

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
- **C. Existing plain text / link / HTML message (no widget).** Two distinct
  parts, not to be conflated:
  - C1, source-proven: `SendMessage` (plain) and `SendHTMLMessage`
    (`parse_mode=HTML`, previews disabled) exist in `internal/botapi/botapi.go`
    (section 4.1) and can carry text and a link. This is existing sender
    capability only. It is not an existing status card: no run read model was
    located (section 4.4), so there is nothing yet to put in it.
  - C2, unimplemented and unverified: Rich Messages (#1217/#1224). No
    implementing code or docs were found here (section 4.5); their behavior,
    client coverage and fit are unknown and are not assumed.

| Dimension | A | B | C |
|---|---|---|---|
| User value | Medium: glanceable, in-place updates | Medium-high: on-demand refresh | Low-medium: static, needs a new message per change |
| Build effort | Medium: new sender method, renderer, size gate | High: A plus a new update kind, handler, auth, rate limits, receiver change | Low |
| Security surface | Small: output only | Larger: new inbound untrusted channel | Smallest (existing) |
| Cost / ops | Low | Moderate (query traffic, rate limiting) | Lowest |
| Reliability | Depends on client support and edit rate | Same plus contested-doc risk (3.3) | C1 uses a long-existing send path; client rendering of it was not measured here. C2 unknown |
| Compat risk | Unmeasured | Unmeasured plus doc drift | Unmeasured; not asserted to be nil |

Recommendation: a text-and-link fallback (C1) should accompany every option, but
it still needs a status read model to carry (section 8.1) and its client
behavior is unmeasured. A is the only candidate worth a future pilot. B stays
deferred until the doc drift is resolved and A has run clean.

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
| Replay / stale | Old `widget_query` or old card replayed | Every query carries a short opaque reference (<= 64 bytes) resolved internally to (tenant, chat, run), bound-checked before any fetch (8.5); unknown and mismatch give one generic error; version ordering depends on the unresolved 8.1 contract. |
| Stale evidence | Card shows an old HEAD as current | Show `as_of` and abbreviated HEAD; mark stale past `expires_at`; unknown is shown as unknown. Depends on the unresolved 8.1 contract. |
| Forged provenance | Payload or caller claims `provenance=server` | The label is not authentication; require trusted authenticated read transport and tenant ownership (8.1). |
| Size | Card exceeds 32768 B or 4096 B compressed | Budget and hard gate (section 8); over budget means fallback. |
| Flood / rate | Rapid edits or queries | Per-run edit coalescing, per-principal query rate limit, vendor limits UNKNOWN so assume strict. |
| Privacy | Customer content in card | Allowlisted fields only; no message bodies, phone numbers or secrets (project safety rules; extend `internal/audit/redact.go` for new field names). |
| Retention | Card persists with old data after run ends | Final edit to a terminal state; never keep sensitive data in the message; retention of stored references bounded. |
| Display as authority | "Approved" shown, read as permission | See section 9. |

## 8. Read-only AgentRunStatus / DevLoopEvidence card

### 8.1 Proposed read model (a requirement on a future upstream, not an existing API)

This is the **authoritative proposed** shape a card would need. No upstream API
providing it has been located or is claimed to exist (section 4.4); this
document does not invent one. Until an owner defines and ships a contract with
these properties, the contract is **UNRESOLVED**, and all behavior that depends
on the version, expiry or identity fields below is **deferred**, not specified.

All fields typed and allowlisted. Anything missing renders as `unknown`, never
as a default success.

| Field | Type | Rule |
|---|---|---|
| `ref` | string <= 120 | `owner/repo#n` display ref |
| `run_id` | opaque string | Run identity. Required: without it no stale, replay or correlation rule is decidable |
| `version` | integer, monotonic per `run_id` | Required. Ordering for edits and stale detection (8.5) |
| `run_state` | enum: queued, running, waiting_input, succeeded, failed, cancelled, unknown | Unrecognized value renders `unknown` |
| `head_sha` | full immutable commit id, 40 hex (SHA-1) or 64 hex (SHA-256) | Required for evidence. The full value is what is stored and compared; abbreviation (first 7 to 12) is for display only. Absent or not full length renders `HEAD unknown` |
| `checks` | enum: passing, failing, pending, unknown | Never inferred locally. Meaningful only for the `head_sha` it came with |
| `as_of` | RFC 3339 UTC | Required: when the owner produced this version |
| `expires_at` | RFC 3339 UTC | Required: after this instant the data must not display as current. Whether the owner supplies it or a TTL is defined elsewhere is UNRESOLVED; this repo does not pick a TTL |
| `provenance` | enum: server, unverified | A label only. It is **not authentication** (below) |
| `detail_url` | https URL <= 200 | Same acceptance test as `humaninput.Render` links |
| `ref_token` | opaque <= 64 B | Only if option B (8.5) |

The card contains no question text, no model prose, no logs.

**Trust requirement.** `provenance=server` proves nothing by itself: it is a
field inside a payload. A status may display as fact only if it arrived over a
trusted, authenticated read transport from the owning service, and that service
asserted tenant ownership of the run for the principal bound to the target chat.
A caller-supplied flag, request field or header is never proof of provenance.
The authentication mechanism and the ownership check are part of the unresolved
upstream contract; this document does not design them.

If the contract stays unresolved, no stale, version or TTL behavior is
specified here, and the verdict stays DEFER_COMPATIBILITY.

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
HEAD: <abbreviated head_sha | unknown> (checks: <checks>)
As of: <as_of UTC | unknown>
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

Design requirements only; no handler or callback is implemented or proposed for
implementation here. Evaluate in this order; first failing rule decides:

1. **Parse**: update decodes into the narrow struct; unknown or oversize means drop and count (no content logged).
2. **Known chat (cheap filter, not authority)**: `isKnownChat` failing means drop (existing behavior). Passing it grants nothing: a known chat is not proof of any right to a run.
3. **Resolve reference internally**: `ref_token` is resolved server-side, inside this service, to a stored (tenant, chat, run) record. No upstream data is fetched at this step.
4. **Bind before fetch**: verify that the authenticated viewer, the originating chat, the owning principal and the run all match that record. Only after this succeeds may any detail be fetched from the owner.
5. **Indistinguishable failure**: an unknown, malformed, expired or mismatched reference, and any binding mismatch, all produce the same generic answer, identical in text, timing class and side effects, so a caller cannot learn whether a reference or run exists.
6. **Rate**: per-principal and per-run limits; exceeded means answer "try later", with no upstream work.
7. **Fetch**: read the run through the authenticated transport of 8.1. Unavailable read means `unknown`, never a cached success.
8. **Terminal**: terminal or cancelled run means answer the terminal state once, then stop updating the card.
9. **Version and freshness**: these rules depend on `run_id`, `version` and `expires_at` from 8.1. A reference or card version below the current version is answered with the current state, never the old one; data past `expires_at` is marked stale. If the 8.1 contract is unresolved, these two rules are deferred and nothing is displayed as current.
10. **Reply**: answer within the vendor's response window (UNKNOWN); on timeout the client falls back to its own failure behavior.
11. **Edit**: edits are ordered by `version`; an edit with a version lower than or equal to the stored one is discarded. Coalescing is allowed but must keep the highest version.

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
- Short or non-hex `head_sha`: must render `HEAD unknown`; abbreviation only at display.
- Mutation: remove the escape step; remove the size gate; make `unknown` default to `succeeded`; drop the `expires_at` check (only once the 8.1 contract is resolved). Each mutation must fail at least one test.
- Property: output never contains a field outside the allowlist.

No sender, no `allowed_updates` change, no handler is part of this slice.

## 12. Proposed future compatibility test plan (requires approval; NOT_RUN)

Out of scope here and needs separate approval, a test bot and a test account:
render and fallback on Android, iOS, Desktop, Web and one old client per
platform; interaction (B) only if 3.3 is resolved; record client versions;
screenshots only from real runs, labeled OBSERVED. Cost, account and test-vs-
production-server choices are owner decisions.

## 13. Open questions for the owner

1. Which service owns run status and DevLoop evidence, does it (or will it) expose the section 8.1 read model (full HEAD, run id, monotonic version, as_of/expires_at) over an authenticated transport with tenant ownership, and who defines that contract?
2. Is a bot DM the intended audience, given Human Input today goes to Saved Messages (user account)?
3. Are pinned vendor sources and a test-bot budget available for gate 0 and 2?

## 14. Limitations

- Telegram facts come from orchestrator-relayed, paraphrased notes dated 2026-11-14, not full page copies; exact parameter lists and limits not in those notes are UNKNOWN.
- The widget-sandbox sources were unpinned `main`.
- Nothing about client behavior was observed.
- Facts about mctl-api, mctl-agent and mctl-gitops are unobserved, and no service is assumed to own run status.
- Absence findings in section 4 come from targeted searches of this repository, not an exhaustive audit, and say nothing about other repositories.
- The section 8.1 read model is a requirement on a future upstream, not an existing API.
