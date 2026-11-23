# Spike: Telegram HTML widgets (Bot API 10.4) for agent and DevLoop status

Issue: [mctlhq/mctl-telegram#1283](https://github.com/mctlhq/mctl-telegram/issues/1283).

This is a research-only spike. It changes no code path, sends no live bot
message, flips no flag and touches no GitOps file. Facts come from the sources
listed at the end (read 2026-11-23) and from this repository on `main`.
Anything not observed is marked `UNVERIFIED`. Anything no source states is
marked `UNKNOWN`.

**Recommendation: `DEFER_COMPATIBILITY`.** The target, once the gates in §8
clear, is option A: a static, read-only status card in the **PA bot** DM.

The short reasons:
- No MCTL surface that would benefit from a widget is a production private bot
  DM whose webhook this service owns.
- No client has been observed rendering a widget.
- The last new Telegram format we adopted on documentation alone, Rich
  Messages, rendered empty on Telegram Desktop (#1217).

## 1. Widget contract (source to capability matrix)

| Capability | Contract (Bot API 10.4) | Status |
| --- | --- | --- |
| Send | `sendWidget(chat_id, html, caption?, public_data?, chat_data?, allow_queries?, width?, height?, reply_markup?, protect_content?, ...)` returns a `Message` | documented |
| Shared widget | `sendSharedWidget(chat_id, widget_id, chat_data?)`, `editSharedWidgetData(widget_id, public_data, cache_time 5-3600 s)` | documented |
| State update | `editMessageWidgetData(chat_id+message_id or inline_message_id, public_data?, chat_data?)`. An omitted field is unchanged, `""` clears it. The edit is silent and counts as one sent message. | documented |
| Code after send | Immutable: "no method changes the HTML of a sent widget". The caption can be edited. | documented |
| Requests | With `allow_queries`, `TelegramWidget.request(data)` arrives as `Update.widget_query` (`id`, `from`, `chat`, `message_id`, `data` 1-64 bytes, `type`). It is answered with `answerWidgetQuery(widget_query_id, data <= 1024 bytes)` within 15 s. The answer can change no state and send no notification or URL. | documented |
| Sizes | HTML <= 32768 bytes and <= 4096 bytes after zlib level 9. `chat_data` and `public_data` <= 1024 bytes each. Caption <= 1024 chars. | documented |
| Rate | 5 requests per 5 s per user and bot. Background requests: one on appear, then one per 5 s. Shared widget: 1 edit/s. | documented |
| Runtime | QuickJS, not a WebView. No network: fetch, XHR and WS throw. External scripts, CSS, fonts and images are never loaded; images only as `data:` or inline SVG. The DOM is checked against "profile 1". No form controls, no keyboard input, nothing scrolls. | documented |
| Client budget | Bubble 200-600 x 50-600 px, 2000 nodes, 8 MB, CPU 300 ms/s, localStorage 4 KB per message | documented |
| Chats (production) | **Private chats only.** Production widgets are automatically protected content, so they cannot be forwarded. Groups, inline mode and forwards work on the test server only. Channels refuse widgets. | documented |
| Business connections | `sendWidget` has no `business_connection_id` | inferred, `UNKNOWN` |
| Accessibility | "Widgets have no accessibility semantics in this version (aria-* … do nothing)": what matters must also be in the caption | documented |
| Old clients | "Shown as unsupported media with its caption". With no caption, a localized "Widget" stub. | documented, `UNVERIFIED` |
| Minimum client versions | Gated by a per-client platform/version flag and MTProto layer 233. No version table is published. | `UNKNOWN` |
| Widgets per chat | not stated | `UNKNOWN` |

**widget-sandbox** is the client-side runtime that every Telegram app embeds:
- It consists of the QuickJS sandbox, validator, renderer, Swift/Kotlin/C++/npm
  packages, and a local preview harness.
- It is not a bot SDK and not a server emulator.
- It has no GitHub Releases. The latest tag is `v0.6.5` (2026-11-11, a DOM
  nesting-depth cap after a WebView crash); `v0.6.4`, the same day, was a QuickJS
  security release.
- Its README is stale against Bot API 10.4. It still says "no messages to the bot
  in v1", pins `v0.1.1` and gives a 64 MB cap. `docs/sdk-v1.md` itself records
  that requests and state joined v1 on 2026-10-25 and that the cap is 8 MB, so the
  SDK document and Bot API 10.4 agree. Where the README and the SDK document
  disagree, the SDK document and the Bot API are authoritative.
- Two security releases in its first week mean renderer behaviour is still
  moving. That is one more reason to observe clients rather than trust the
  documentation.

## 2. Where a widget could be sent from in MCTL

| Surface | Transport | Webhook owner | Chat type | Widget-capable in production? |
| --- | --- | --- | --- | --- |
| PA bot (preview, #1318) | Bot API webhook, `internal/pa/ingress.go`; sends via `internal/pa/output/sender.go` | **this service**; `allowed_updates` pinned to `message`, `callback_query` (`internal/pa/webhookinfo.go`, T4) | private | **yes, technically**. PA is preview-only and `PA_ENABLED` is off in prod. |
| Login bot: digest, broadcasts | `internal/botapi` (send only) | mctl-agent (`internal/bot/bridge.go` header) | private | send yes. Inbound `widget_query` would need a forward from mctl-agent, as #734 needs for callbacks. |
| mctl-agent operator notifications (tickets, PRs, daily digest) | `mctl-agent/internal/notify/telegram.go` to a configured `TELEGRAM_CHAT_ID` / tenant chats | mctl-agent | operator chat, `UNVERIFIED` whether private or group | only if the chat is private; groups are test-server only |
| Human input (#571) | MTProto user account, Saved Messages, `internal/humaninput` | n/a (user account) | Saved Messages | **no**: widgets are a Bot API message type. The user-account MCP sends are out of scope by the issue. |
| DevLoop decide page, release gate | mctl-api web page (MFA) | n/a | browser | no; it is already a web UI |
| Chat Automation (#1028) | open spike | `UNKNOWN` | `UNKNOWN` | depends on #1028's outcome |

Answer to "which component would own it":
- The only place where this service both sends and receives on a bot it fully
  owns is the PA bot.
- A **static** card (option A) needs no inbound path at all: `sendWidget` plus
  `editMessageWidgetData` through the existing Sender. `allowed_updates` stays as
  it is.
- Option B needs `widget_query` added to `allowed_updates`, a third `Kind` in the
  ingress, and a widening of the T4 threat-model row.
- No new `getUpdates` consumer and no second webhook is needed in either case.
- On the login bot, any inbound path goes through mctl-agent's webhook, exactly
  the problem #734 already tracks for callback buttons.

## 3. Client and fallback matrix

Nothing here has been observed. Sending a test widget is a live bot message,
which this spike's scope excludes.

| Client | Renders widget | Old-client fallback | Status |
| --- | --- | --- | --- |
| Telegram iOS (current) | documented "looks the same" | n/a | `UNVERIFIED` |
| Telegram Android (current) | documented | n/a | `UNVERIFIED` |
| Telegram Desktop (current) | documented | n/a | `UNVERIFIED`. This is the client that rendered Rich Messages empty in #1217. |
| Telegram macOS (current) | documented | n/a | `UNVERIFIED` |
| Telegram Web K / A | documented ("the web") | n/a | `UNVERIFIED` |
| Any client before layer 233 | no | "unsupported media" + caption | `UNVERIFIED` |
| Third-party MTProto clients, including our own read-back | `UNKNOWN` | `UNKNOWN` | `UNVERIFIED`. #1217 found that MTProto read-back of a Rich Message returned empty text. |

**Test plan (needs a separate owner OK, because it sends live messages):**
1. Prepare one fixture widget under the 4 KiB compressed budget, with
   `protect_content` (the default) and a caption that carries the full status in
   plain text.
2. Send it from the PA preview bot to one operator DM. Use no user data, only a
   synthetic run id.
3. On each client, record: renders / blank / stub / caption only. Also record dark
   and light theme and a 320 px width.
4. Send three `editMessageWidgetData` updates and confirm each client shows the
   latest state without a notification.
5. Read the message back over MTProto (the `tg` MCP `get_messages`) and record
   what the caption and the media type look like there.
6. Pass condition: every client in the matrix shows either the widget or the
   caption, never an empty bubble. The caption alone must be enough to act on.

## 4. Options

| | A: static status card | B: card + read-only request | C: no widgets |
| --- | --- | --- | --- |
| What | `sendWidget` without `allow_queries`. The bot pushes state with `editMessageWidgetData`. | A, plus `allow_queries` for "refresh" or "details" answered from server state | text, the HTML subset, inline keyboards, links, the Mini App |
| Inbound surface | none | new `widget_query` update kind on the PA webhook | none |
| Effort | small: one template plus a Sender method plus a size check | medium: ingress kind, rate limit, answer path, tests, threat-model rows | none |
| UX value | one glanceable state that updates in place | marginal over A: the bot already pushes every state change | baseline |
| Fallback | caption (required) | caption (required) | n/a |
| Accessibility | none inside the widget; caption only | same | full (text) |
| Observability | send / edit outcomes on the existing Sender metrics | plus query and answer counters | existing |
| Rate cost | one message per edit, so edits must be coalesced | plus 5 requests / 5 s per user | n/a |
| Risk | renderer drift (two security tags in week one); stale state if an edit fails | plus untrusted `data`, query flood, 15 s answer deadline | none new |

B adds an inbound attack surface to buy a refresh the server can already push,
so it is not worth it. If widgets go ahead at all, A is the shape. C stays the
default for everything else.

## 5. Threat model

| Threat | Control (design) |
| --- | --- |
| Untrusted agent or model text in the widget | The widget HTML is a **fixed, reviewed template** in the binary, the same rule as the `safetext` literal registry. No HTML ever comes from a model, a tool or a user. State carries ids and enum values only, rendered with `textContent`, never as markup. |
| Prompt injection via displayed text | No free text in `public_data` / `chat_data`. Labels come from the template's own string table, chosen by the enum. |
| Secrets or private content in the widget | "Treat the code and the shared state as public." State holds a run id, a state enum, timestamps and a short commit SHA, nothing else. No message text, account id or token. |
| State leakage across chats | Private chats only in production. Use `chat_data`, never `public_data`, and no shared widgets. Protected content blocks forwarding. |
| Stale state shown as current | Every state carries `as_of` and a monotonic `seq`. The template shows the age, and when the age passes a TTL it renders "stale, see caption". An edit that fails is retried or the caption is edited; an unknown outcome is never shown as fresh. |
| "Approved" in the UI taken as authority | **Display is never authorization.** No widget state, request or answer can approve, merge, release or deploy. Any action goes through the canonical Human Input API (#734) or the DevLoop decide page with MFA, each with its own hash-bound check. Option A has no requests at all. |
| Callback replay or forgery (option B only) | `from` is authenticated by Telegram. `data` is untrusted, as `callback_data` is. The query id is valid for 15 s. The answer is read-only and computed from server state. |
| Request flood (option B only) | Telegram caps it at 5 / 5 s per user and bot, and the PA rate window applies on top. |
| Consent | A widget in the PA DM carries run status only, not new data, so the `pa-data-flow/v1` consent is unchanged. A status card in another chat would need its own basis. |
| Audit | Log the send and edit outcome classes and the message id. Never log the state. |
| Renderer vulnerability (client side) | Out of our control. Keep the template minimal: no scripts beyond rendering, few nodes, no `data:` images. |

## 6. Proposed read-only card contract (design only)

Agent Run Status / DevLoop Evidence card, sent by the PA bot in one private DM.

- **Template:** one static HTML file in the binary, well under the 4096-byte
  compressed budget. Pin the budget in a test that runs zlib level 9 the way the
  server does. The template is unstyled apart from `--tg-theme-*`, works at
  320 px, does not scroll, and renders synchronously from `chatData`.
- **`chat_data` (JSON, <= 1024 bytes, about 200 expected):**
  ```json
  {"v":1,"kind":"run","id":"run_7Qx","state":"review","seq":4,
   "as_of":"2026-11-23T18:05:00Z","head":"4b5ea88","ttl_s":900}
  ```
  `state` is one of `queued`, `running`, `review`, `completed`, `failed` or
  `cancelled`. There are no free-text fields.
- **Caption (always sent):** the same status in plain words, with a link to the
  canonical page (the issue, the PR or the decide page). It is the fallback, the
  accessibility path and what notifications show.
- **Updates:** use `editMessageWidgetData`, coalesced to at most one per state
  change, and edit the caption at the same time. Only increase `seq`.
- **No `allow_queries`, no `reply_markup` that acts.** A link button to the
  canonical page is the only action.

## 7. Relationship to other work

| Issue | Relationship |
| --- | --- |
| #1217 (closed) | Rich Messages: rendered empty on Desktop; no fallback. Its lesson sets this spike's gate: observe clients before adopting a new format. |
| #1224 (closed) | Duplicate of #1217. Broadcasts stay on plain text and the HTML subset; widgets do not reopen that. |
| #734 (open) | The only path for widget-originated actions, and it has the same webhook-ownership problem on the login bot. Widgets add no callback authority. |
| #1028 (open) | Chat Automation. If it yields a bot DM reply path for the assistant, that DM becomes a second candidate surface. |
| #1173 (open, epic) | A competitor-gap epic. Widgets are presentation only and close no governance gap. |
| #1318 (PA) | The only surface where option A fits without new transport. It is gated on PA leaving preview. |

## 8. Decision record suggestion

**Outcome: `DEFER_COMPATIBILITY`.**

Reopen as `LIMITED_GO_READ_ONLY` (option A, PA bot only) when all of the
following hold:
1. The §3 test plan has run, with owner OK, and every listed client shows the
   widget or its caption, never an empty bubble.
2. The PA bot has a production audience, meaning `PA_ENABLED` is on in prod for
   at least one principal, or another private-DM bot surface we own exists
   (#1028).
3. A concrete consumer is named: which run or evidence state the owner wants to
   see in place, rather than the text message they get today.

Stop conditions for a later pilot:
- any client renders an empty bubble;
- the template exceeds the budget;
- an edit outcome cannot be observed;
- any proposal adds `allow_queries` or an action.

Even `LIMITED_GO_READ_ONLY` authorizes only a separately scoped proposal, not
code (issue decision gate).

## Sources

- https://core.telegram.org/bots/widgets
- https://core.telegram.org/bots/api-changelog (10.4, 2026-11-09; 10.5, 2026-11-22: no widget changes)
- https://core.telegram.org/bots/api
- https://github.com/TelegramMessenger/widget-sandbox (tags v0.6.4 and v0.6.5, 2026-11-11)
- https://github.com/TelegramMessenger/widget-sandbox/blob/main/docs/sdk-v1.md
