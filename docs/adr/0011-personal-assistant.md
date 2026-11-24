# ADR 0011: Personal Assistant, a Bot API bot that calls the user's MCTL MCP servers

Status: Proposed

This record is Phase 0 of the Personal Assistant epic (#1312). Refs #1048, the security owner for user MCP connectors, and #1088, the managed runtime. The threat model is [`docs/agent-runtime/personal-assistant-threat-model.md`](../agent-runtime/personal-assistant-threat-model.md); this record takes effect only after that threat model is accepted, and where the two disagree the threat model is authoritative.

**Accepting this record authorizes nothing to run.** It authorizes no code, deployment, flag, image or `agents:intake`. Each phase below needs its own owner GO.

## Context

- **Demand.** General-purpose assistants already let a user plug MCP servers into a chat bot. The owner connected one of them, reached through a Telegram bot, to MCTL's `tg` and `alice` servers. It played music on a kitchen speaker, set the volume, and read a Telegram chat aloud through Alice. Every one of those actions went through a third party that MCTL does not govern, including reading a private chat and speaking it in a room.
- **The catalog cannot do this today.** `/assistants` in mctl-telegram is an auto-reply assistant that runs as the user's own MTProto account. It has a closed set of 11 tools (`internal/agent/tools/tools.go`), enforced per job (`internal/agentapi/toolgate.go`, #1041). It cannot call external MCP servers, and MCTL stores no delegated downstream tokens.
- **The pieces exist:**
  - the managed runtime: pool worker, OpenAI-compatible runner, ledger with reservation caps (ADR 0008, #1089, #1090, #1092);
  - the send gate and audit chain (ADR 0002, ADR 0003);
  - the tool-surface contract (ADR 0007);
  - the job-bound capability boundary (#1041);
  - the connection and approval model of ADR 0010;
  - Bot API plumbing (`internal/bot`, today login and notifications only).
- **Governance precondition.** #1048 requires a threat model before any connector design, a per-call approval binding, an egress policy and a revocation story. This record is that design for a narrow first consumer: catalog servers only.

## Decision

### Product shape

- **Bot.** One dedicated Bot API bot, private chats only, with its own token. It is not the login bot, so the blast radius is separate. The token is held in Vault and delivered through an ExternalSecret. Joining groups is disabled.
- **Location.** It lives in mctl-telegram as a new package next to `internal/bot` and `internal/agentworker`. It is not an `AssistantInstall`, and it does not change the auto-reply assistants.
- **Catalog listing.** `/assistants` shows a "Personal assistant" card only from Phase 3.
- **Phase 1 servers:** `tg` and `alice`, read tools only.
- **Later servers.** Glovo comes later through ADR 0010 and the C2 pilot scope, and never gets checkout or payment. Custom servers by URL stay with #1048.

### Execution

- **Runtime and consent.** The model runs on the managed runtime of ADR 0008 under a **PA-specific consent**, `pa-data-flow/v1` (threat model T13). That consent is stored per principal. If it is missing or unreadable, the run is refused.
- **Connector executor.** The worker never holds a downstream credential. It proposes tool calls with a PA job token (`aud=pa-job`), which carries the principal and the signed tool set, following the #1041 pattern. The mctl-telegram server makes every MCP call after its checks. Principal, connection and revision come from the job row, never from the request.
- **Execution context.** Every run carries an `ExecutionContext`:
  - principal;
  - trigger: `interactive`, `scheduled` or `event`;
  - conversation id;
  - bound connection authority revisions;
  - budget reservation;
  - consent version.

  Tiering, provenance, approvals, audit and limits read only the context, never the trigger. Phase 1 creates only `interactive` runs. `/consent withdraw` stops all model calls and deletes the state. Routines (scheduled and event-triggered runs) can be added later without a second loop, with the same consent, permissions and audit.
- **Conversation state.** It has an explicit TTL (default 24 hours) and records provenance on every fragment from Phase 1 on. It is deleted by `/new`, by `/forget`, by expiry, and when the last connection is removed. State without provenance marks is never loaded.
- **Long-term memory.** It is a separate store behind its own interface. Until an addendum defines it, only a no-op implementation exists. Anything stored later keeps its provenance.

### Connections

- **OAuth client.** The bot is an OAuth client of each catalog server: CIMD where served, DCR otherwise. Each server has its own redirect URI and one pinned issuer.
- **Linking is cookie-free** (threat model T1):
  1. a Mini App start, verified by raw `initData` against the PA bot's token, with a single-use link token;
  2. the authorization request, with PKCE `S256`, a single-use `state`, RFC 8707 `resource`, and `prompt=consent` where supported;
  3. a callback that checks `state`, the redirect and RFC 9207 `iss`, stores the code **without** exchanging it, and redirects to a Mini App deep link carrying a single-use completion code;
  4. a second `initData` check, which must match the principal, before the code exchange;
  5. a confirm card in the bot chat showing a stable unique account identifier;
  6. for `tg`, an account-owner check: `get_my_identity` on the new token must return the principal's `telegram_id`, otherwise the connection fails.

  Steps 1–5 bind the account to the Telegram user who opens the completion link. They do not prove who did the provider login.
  - For `tg`, step 6 closes that gap.
  - For servers without a Telegram-bound identity (`alice`, Glovo), a victim who forwards the completion link to the attacker within its 5-minute TTL links their own account. That is a residual risk. It is **not accepted by this ADR**: each such server needs a recorded owner acceptance before its linking flag is turned on.
- **State machine.** The threat model T2 and this record use the same text:

      pending_link -> pending_oauth -> pending_return -> pending_confirm -> active
      active -> expired; any non-terminal -> failed; any -> revoked (terminal)

  `expired`, `failed` and `revoked` are never re-activated. A reconnect, including any scope escalation, runs the whole flow again and creates a new connection id.
- **Two counters.**
  - `authority_revision` changes with scope, identity, confirmation, disable or revocation. Jobs, approvals and standing permissions bind to it.
  - `token_generation` changes with token rotation. Nothing binds to it.

  Refresh is single-flight per connection.
- **Scopes: strict read-only token contract** (threat model T8).
  - `tg`'s `narrowGrant` keeps the membership-granted `admin:users`, `admin:users:read` and `admin:broadcast` even for a read-only request. Before any PA linking, `tg` gains a per-client scope ceiling for the PA client id: an allowlist of `telegram:dialogs:read` and `telegram:messages:read` that strips every other scope, implicit ones included, on both code and refresh grants.
  - The executor verifies, after every exchange and refresh, that the effective scope equals the allowed set. An extra, missing or unparseable scope fails the connection and revokes the token.
  - `tg` itself refuses admin and write tools for a PA token, including for admin principals. The pin is defence in depth, not the boundary.
  - If `alice` cannot narrow its scopes, Alice linking needs an owner decision.
- **Secrets.**
  - Each connection has its own DEK, wrapped by a non-exportable Vault transit key that only the service role can use. Transit is mandatory in production; a KV key is allowed only on preview with synthetic or owner-only accounts, and a production start with a KV KEK fails.
  - Leak procedures cover the database plus KEK, DCR client credentials, the bot token and the webhook secret (threat model T3).
- **Dispatch.** No transaction is held open across an outbound call.
  1. A pre-dispatch transaction re-reads the connection state and authority revision. For a write, it also consumes the receipt and records `dispatching`, then commits.
  2. The call runs with a cancellable context.
  3. A post-dispatch re-read decides the outcome: `ok`, `fenced` or `outcome_unknown`.

  A mismatch or read error at either check refuses the call or fences the result. After a crash, a leftover `dispatching` record becomes `outcome_unknown` and is never re-dispatched.
- **`/disconnect`** revokes locally first:
  1. set `revoked` and bump the revision;
  2. cancel the in-flight call;
  3. destroy the DEK wrapper;
  4. cancel queued jobs, approvals and standing permissions;
  5. then call remote revocation, best-effort.

  Cancelling an action already dispatched is best-effort, not a rollback. A late result is discarded and audited `fenced`. A write whose outcome cannot be observed (timeout, transport error, 5xx) is recorded `outcome_unknown` and never auto-retried. In both cases the user is told the effect may already have happened.

### Tools, tiers, approvals

- **Catalog pin.** A committed catalog pins each server's allowed tools:
  - name;
  - input schema hash and description hash;
  - annotations;
  - tier, class and lowerable.

  The model sees catalog-authored descriptions, never server descriptions. A new, renamed or changed tool is denied until a reviewed PR updates the pin. A failed `tools/list` is an error, never an empty set. The Phase 1 pin is listed in threat model T8.
- **Tiers and classes:**

  | Tier or class | Meaning |
  |---|---|
  | `auto` | Pinned read tools only. This departs from #1048's "approve by default", for the reasons given in threat model T8. |
  | `approve` | Default for every write. A tool marked `lowerable` can be run without a card under a standing permission. |
  | `disclosure` (class) | `alice_say_phrase` and `alice_send_command`, assigned per tool. Always a card showing the target device and the full text. Never lowerable. Text capped at 1000 characters. |
  | `never` | Telegram writes, deletes, account and session tools, checkout or payment, and every unpinned tool. |

  Lowering is limited to:
  - playback;
  - volume, up to a ceiling;
  - light;
  - device control, only for device ids listed in the permission and of type `light` or `media_device`. The type is read fresh at dispatch, and an unknown type is not lowerable.
  - (amended, P2-S14b) the type strings are the ones mctl-alice reports: a speaker is `devices.types.smart_speaker.*` (not `media_device`, which is a television or a set-top box) and a light is `devices.types.light`. `alice_play_music` is a write that is never lowerable: it hands a speaker text the caller chose.

  The following are never lowerable: appliances, relays, sockets, `alice_control_room` and `trigger_scenario`. The `trigger_scenario` card shows the scenario's steps.
- **Phase 1 has no write path.** Write tools are not in the signed tool set.
- **Approval binding:**
  - principal;
  - connection id and authority revision;
  - server and tool;
  - schema and description hashes;
  - canonical args hash of the exact arguments sent;
  - conversation id;
  - expiry of 5 minutes;
  - server-generated idempotency key.

  The receipt is single use. At dispatch, the tool definition is fetched fresh and compared with the pin and the approval. A failed fetch refuses.
- **Standing permissions.**
  - Granted only through `/permissions`, never from an approval card, and confirmed with a verified `callback_query`.
  - The grant shows the tool, device ids, value ceiling and expiry (at most 30 days).
  - Bound to the authority revision.
  - Audited and revocable.
  - The model cannot create, widen or renew one.
- **Provenance and taint** (threat model T5):
  - `user` is only `message.text` the principal typed, with no forward origin. Everything else is `external`, including unknown or unreadable provenance.
  - Any external fragment taints the run, and every write in a tainted run needs a card. Taint is the conversation's durable flag; tool results are stored as external fragments and raise it. Model output in a clean conversation does not raise it (owner decision, 2026-11-21).
  - Taint resets only on `/new`, on TTL expiry or on state deletion. Context-window eviction never resets it, and nothing a model or a tool writes resets it.
  - A reset never weakens a `disclosure` gate or a non-lowerable gate.

### Ingress, output, egress, limits, audit, switches

- **Ingress** (threat model T4):
  - constant-time webhook secret check;
  - `allowed_updates` limited to `message` and `callback_query`;
  - business, group, `sender_chat` and `via_bot` updates rejected, and any update where `chat.id != from.id`;
  - deduplication on `update_id`;
  - `getWebhookInfo` monitoring.
- **Output** (threat model T14). Every bot message has link previews disabled and is plain text. Any URL whose exact full form is not in user-provenance text is neutralised, including scheme-less, punycode and `t.me` links. Model-authored markup and URL buttons are stripped.
- **Egress** (from Phase 1, threat model T9). It covers discovery, DCR, the token and revocation endpoints, and the MCP transport:
  - HTTPS only;
  - per-server host allowlists;
  - the address checked after DNS resolution and pinned for the dial, with private, IPv6 unique-local and mapped ranges denied;
  - proxy variables ignored;
  - no redirects, except re-checked discovery hops;
  - size and time caps.
- **Limits.**
  - Message: 4096 characters.
  - Tool output: 64 KiB.
  - Tool calls per run: 8.
  - Approval card: 4 KiB.
  - Alice phrase: 1000 characters.
  - Rate limit per principal.

  When the budget is exhausted, the request is held with a message.
- **Audit.** Every call is written to the ADR 0003 chain before dispatch, digests only. If that append fails, the call is refused. `/log` shows a principal their own entries.
- **Switches.** `PA_ENABLED`, `PA_EXTERNAL_TOOLS_ENABLED`, `PA_WRITES_ENABLED` and `PA_SERVER_<NAME>_ENABLED` are independent and fail-closed. An admin can also disable a single principal. Every switch, the per-principal disable and consent are re-checked at every dispatch. Rollback is: flags off, then image rollback.

### Phases and gates

| Phase | Content | Gate to enter | Gate to leave |
|---|---|---|---|
| 0 Architecture and governance | This record, the threat model, epic #1312, draft issues | — | Owner accepts the threat model and this record |
| 1 Read-only MVP | Bot loop and execution context; ingress filter; linking for `tg` and `alice`; catalog pin and drift denial; egress policy; output hardening; read tools only; consent, ledger, audit, switches; leak runbook | Owner GO; `tg` per-client scope ceiling merged first; per-server owner acceptance of the T1 residual before `alice` linking | S1 green, then preview deployment (owner GO), then evals R1–R6, then owner GO |
| 2 Safe actions | Approval engine; standing permissions; taint; Alice actions and the `disclosure` class | Owner GO | S2 green, then writes enabled on preview, then evals A1–A7, then owner GO |
| 3 Private pilot | Owner plus 1–3 test users behind an allowlist; telemetry; revocation, injection, budget and leak drills; the `/assistants` card | Owner GO | Pilot report, then a separate GO to expand |
| 4 Expansion | Glovo after its C2 GO; memory; routines. Custom MCP by URL stays with #1048. | One addendum and review per item | — |

S1 and S2 run in CI with no deployment, and neither depends on preview evals. A checked-in manifest maps every test ID to a test. CI fails on a missing ID, and each ID has a recorded mutation run.

## Consequences

**Gains**
- The user gets the Town-style experience on MCTL's own servers.
- Credentials stay in one audited place.
- Every write is either approved per call or covered by a standing permission the principal granted outside the model. Approvals survive replay, rotation and drift.
- Speaking a private chat aloud is always an explicit, visible decision.
- Routines and memory can be added without a second loop.

**Costs**
- A new bot to operate, with a new OAuth client registration per server, a new KEK, and a leak runbook.
- Every downstream schema or description change needs a catalog PR before the tool works again.
- Approval cards add a tap to most writes. That friction is deliberate.
- Everything the bot reads reaches the model provider. The user consents to this, and is told.
- Some servers may not support token revocation or RFC 8707 `resource`. Each case is recorded per server.

**Dependencies**
- The ADR 0008 managed runtime in the target environment.
- The #1092 ledger.
- The #1041 pattern for the signed tool set.
- The #1048 gates, which this record satisfies for catalog servers only.

## Alternatives

- **Route it through the mcp.mctl.ai portal.** Rejected. The portal is a Cloudflare client-side aggregator with no server-to-server API.
- **Extend `AssistantInstall`.** Rejected. Auto-reply assistants act on inbound third-party messages as the user's account. This bot acts on the principal's own requests across systems. Merging them would mix two security models in one surface.
- **Use the Saved Messages `/mctl` control channel.** Rejected. It only works with a connected MTProto account, and it has no inline approval buttons.
- **Let the worker hold downstream tokens.** Rejected. That breaks the runtime credential invariant.
- **Link accounts with a browser cookie.** Rejected. A cookie does not prove Telegram identity, and it does not survive the hop between webview and system browser. The second `initData` check does both.
- **Wait for mcp-gateway line I** (mctl-api as the single authorization server). Not chosen. Each server already serves CIMD or DCR. Moving to mctl-api audiences later is a token-source change behind the connection record, not a redesign.
- **Allow custom MCP servers by URL from the start.** Rejected for Phase 1. It is the widest SSRF and admin-review surface in #1048.
- **Recommend third-party assistants instead.** Rejected as the answer, though client recipes may still be published. That route leaves the cross-system disclosure ungoverned.
