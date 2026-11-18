# ADR 0011: Personal Assistant, a Bot API bot that calls the user's MCTL MCP servers

Status: Proposed

Phase 0 of the Personal Assistant epic. Refs #1048, the security owner for user MCP connectors, and #1088, the managed runtime. The threat model is [`docs/agent-runtime/personal-assistant-threat-model.md`](../agent-runtime/personal-assistant-threat-model.md). This record takes effect only once that threat model is accepted. **Accepting this record authorizes no code, deployment, flag, image or `agents:intake`.** Each phase below needs its own owner GO.

## Context

- **Demand.** General-purpose assistants already let a user plug MCP servers into a chat bot. The owner connected one of them, reached through a Telegram bot, to MCTL's `tg` and `alice` servers. It played music on a kitchen speaker, set the volume, and read a Telegram chat aloud through Alice. Every one of those actions went through a third party that MCTL does not govern. That includes reading a private chat and speaking it in a room.
- **The catalog cannot do this today.** `/assistants` in mctl-telegram is an auto-reply assistant that runs as the user's own MTProto account. Its tool set is closed: 11 tools (`internal/agent/tools/tools.go`), enforced per job (`internal/agentapi/toolgate.go`). It cannot call external MCP servers, and MCTL stores no delegated downstream tokens.
- **The pieces it would need already exist:**
  - the managed runtime: pool worker, OpenAI-compatible runner, consent, ledger with reservation caps (ADR 0008, #1089, #1090, #1092);
  - the send gate and audit chain (ADR 0002, ADR 0003);
  - the tool-surface contract (ADR 0007);
  - the connection and approval model of ADR 0010;
  - a Bot API integration (`internal/bot`, today only login and notifications).
- **Governance precondition.** #1048 requires a threat model before any connector design, a per-call approval binding, an egress policy and a revocation story. This record is that design, for a narrow first consumer.

## Decision

### Product shape

- **One dedicated Bot API bot, private chats only.** The user writes to it in natural language.
- **Bot token.** The bot has its own token, separate from the login bot, so the blast radius is separate. The token is held in Vault and delivered through an ExternalSecret.
- **Placement.** It lives in mctl-telegram as a new package next to `internal/bot` and `internal/agentworker`. It is not an `AssistantInstall` and does not change the auto-reply assistants.
- **Discoverability.** `/assistants` shows it as a "Personal assistant" card, but only from Phase 3 (see Phases).
- **Phase 1 servers:** `tg` and `alice`.
- **Later servers:** Glovo comes later through ADR 0010 and the C2 pilot scope, never checkout or payment. Custom servers by URL come later through their own addendum.

### Execution

- **Runtime.** The model runs on the managed runtime of ADR 0008 (the OpenAI-compatible runner through the AI gateway) under consent `managed-data-flow/v1`, with the per-principal budget reserved at claim.
- **Connector executor.** The worker never holds a downstream credential. It proposes tool calls. The mctl-telegram server makes every MCP call after its checks. This keeps the T4 runtime invariant ("the runtime holds no credential", [threat-model.md](../agent-runtime/threat-model.md)).
- **One execution context.** Every run carries an `ExecutionContext`:
  - principal
  - trigger: `interactive`, `scheduled` or `event`
  - conversation id
  - the bound connection revisions
  - budget reservation
  - consent version

  Tiering, taint, approvals, audit and limits read only the context, never the trigger. Phase 1 creates only `interactive`. Scheduled and event-triggered runs (routines) can be added later without a second tool loop, and with the same consent, permissions and audit.
- **Conversation state** has an explicit TTL (default 24 hours). It is deleted by `/new`, `/forget`, by expiry, and when the last connection is removed.
- **Long-term memory** is a separate store behind its own interface, with only a no-op implementation until an addendum defines it. Anything stored later keeps its provenance, so external content stays external (threat model T5).

### Connections

- **The bot is an OAuth client of each catalog server.** It uses CIMD where the server serves it and DCR otherwise. The redirect URI is pinned. The catalog pins one issuer per server.
- **Linking** follows threat model T1:
  - a Telegram Mini App entry, verified by `initData` HMAC, `auth_date` and principal match;
  - a single-use link token;
  - authorization code with PKCE `S256`;
  - a bound single-use `state`;
  - RFC 9207 `iss` checks;
  - a final confirmation card in the bot chat showing the downstream account identity.

  A browser cookie never establishes identity.
- **State machine:** `pending_link -> pending_oauth -> pending_confirm -> active -> expired | failed | revoked`. `revoked` is terminal. A reconnect creates a new connection id. Every change increments the connection `revision`.
- **Scope escalation** always requires a fresh authorization and a fresh confirm, and produces a new revision. Refresh never widens scope. Scopes are the minimum per server.
- **Secrets.** Each connection has its own DEK, wrapped under a KEK that is separate from the session keys and has a rotation procedure. Refresh-token rotation is used where offered. A reuse or `invalid_grant` ends the connection and never falls back silently.
- **Revocation.** `/disconnect` revokes locally first, then remotely:
  1. set `revoked` and bump the revision;
  2. destroy the DEK wrapper;
  3. cancel queued jobs, pending approvals and in-flight calls;
  4. call the server's revocation endpoint (best-effort).

  Cancelling an action already dispatched to a server is best-effort, not a rollback. A late result is discarded and audited `fenced`, and the user is told the action may already have happened.
- **Execution-time fencing.** Immediately before each dispatch, the server re-reads the connection in the same transaction that consumes a write's approval receipt. It refuses unless the connection is `active` at the bound revision. A read failure refuses.

### Tools, tiers and approvals

- **A committed catalog pins each server's allowed tools** as `{name, input schema hash, annotations, tier, class}`. It is reviewed like the ADR 0007 snapshot. A new, renamed or changed tool is denied until the pin is updated by a PR. A failed `tools/list` is an error, not an empty set.
- **Tiers:**

  | Tier | Meaning |
  |---|---|
  | `auto` | Read tools. Writes only where `lowerable` and lowered by the principal, from Phase 2. |
  | `approve` | Default for every write. |
  | `never` | Telegram writes, deletes, account and session tools, checkout or payment. These need their own addendum. |

  The class `disclosure` covers `alice_say_phrase` and free-text `alice_send_command`. It is **always approve, never lowerable**. Its card shows the target device and the full text, the text is capped, and the approval binds both.
- **Phase 1 has no write path.** Write tools are not in the tool set at all.
- **Approval binding:**
  - principal
  - connection id
  - connection revision
  - server
  - tool
  - schema hash
  - canonical args hash
  - conversation id
  - expiry (5 minutes)
  - idempotency key

  The receipt is single use. At dispatch, the current schema is checked against both the pin and the approval. The approval is an inline button verified as `from.id == principal`.
- **Taint.** Context fragments are `user` or `external`. Once external content is in a run's context, every write in that run needs a card. Taint resets only with `/new`, TTL expiry or state deletion, never through model or tool text. A reset never weakens a `disclosure` or non-lowerable gate.

### Egress, limits, audit, switches

- **Egress (from Phase 1).** HTTPS only, per-server host allowlists, the address checked after DNS resolution and pinned for the dial, private ranges denied, no redirects except re-checked OAuth discovery hops, and size and time caps. This covers discovery, CIMD and DCR, the token and revocation endpoints and the MCP transport.
- **Limits.** Message 4096 characters, tool output 64 KiB, 8 tool calls per run, approval card 4 KiB, Alice phrase 1000 characters, plus a per-principal rate limit. An exhausted budget holds the request with a message.
- **Audit.** Every call is recorded in the ADR 0003 chain with digests only, never bodies. `/log` shows a principal their own entries.
- **Switches.** `PA_ENABLED`, `PA_EXTERNAL_TOOLS_ENABLED`, `PA_WRITES_ENABLED` and `PA_SERVER_<NAME>_ENABLED` are independent and fail-closed. Disabling a single principal is an admin action. Rollback means switching the flags off, then rolling back the image.

### Phases and gates

| Phase | Content | Gate to enter | Gate to leave |
|---|---|---|---|
| 0 Architecture and governance | This record, the threat model, epic, draft issues | — | Owner accepts threat model and ADR |
| 1 Read-only MVP | Bot loop and execution context, linking for `tg` and `alice`, catalog pin and drift denial, egress policy, read tools only, consent, ledger, audit, switches | Owner GO | Security suite S1 green, then preview deployment (owner GO), then preview evals R1–R6, then owner GO |
| 2 Safe actions | Approval engine, taint, Alice media, volume, light and device control (`approve`), `disclosure` class | Owner GO | Security suite S2 green, then writes enabled on preview, then evals A1–A7, then owner GO |
| 3 Private pilot | Owner plus 1–3 test users behind an allowlist, telemetry, revocation, injection and budget drills, `/assistants` card and connect page | Owner GO | Pilot report, then a separate GO to expand |
| 4 Expansion | Glovo after its C2 GO; custom MCP by URL (closes the #1048 egress and admin-review items); memory; routines | One addendum and review per item | — |

S1 and S2 run in CI with no deployment and do not depend on preview evals. Each test is mutation-verified.

## Consequences

**Gains:**
- The user gets the Town-style experience on MCTL's own servers.
- Credentials stay in one audited place.
- Writes are approved per call, with a binding that survives replay, rotation and drift.
- Reading a private chat aloud is an explicit, visible decision, not a side effect.
- Routines and memory can be added without a second loop.

**Costs:**
- A new bot, a new OAuth client registration per server and a new KEK to operate.
- Every downstream schema change needs a catalog PR before the tool works again.
- Approval cards add a tap to every write. That friction is deliberate.
- Everything the bot reads reaches the model provider. This is accepted through consent, and the user is told.
- Some servers may not support token revocation. Their tokens stay valid at the server until they expire, though MCTL can no longer use them.

**Dependencies:**
- the ADR 0008 managed runtime in the target environment;
- the #1092 ledger;
- the #1048 gates, which this record satisfies for catalog servers only.

## Alternatives

- **Route it through the mcp.mctl.ai portal.** Rejected. The portal is a Cloudflare client-side aggregator with no server-to-server API, and it would put a second identity system in front of every call.
- **Extend `AssistantInstall`.** Rejected. Auto-reply assistants act on inbound third-party messages as the user's account. This bot acts on the principal's own requests across systems. Merging them would put both security models in one surface.
- **Use the Saved Messages `/mctl` control channel.** Rejected. It only works for users with a connected MTProto account, and it has no inline approval buttons.
- **Let the worker hold downstream tokens.** Rejected. That breaks the runtime credential invariant and puts tokens in front of the model provider's trust boundary.
- **Wait for mcp-gateway line I** (mctl-api as the single authorization server). Not chosen. Each server already serves CIMD or DCR. Moving to mctl-api audiences later is a token-source change behind the connection record, not a redesign.
- **Allow custom MCP servers by URL from the start.** Rejected for Phase 1. It is the widest SSRF and admin-review surface in #1048, and it needs its own addendum.
- **Recommend third-party assistants instead.** Rejected as the answer, though client recipes may still be published. It leaves the cross-system disclosure ungoverned.
