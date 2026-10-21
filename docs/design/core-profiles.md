# Restricted tool profiles: core-readonly and core-reply

Status: Accepted (owner, 2026-10-21). Rollout step 1 (the mechanism and
core-readonly) shipped in 0.85.0 (#798); step 2 (core-reply) is
implemented after 0.85.0; steps 3-5 are open.

## Problem

One `/mcp` endpoint offers 37 tools. Since #785 (0.82.0), what a caller sees
and can call follows its scopes (`internal/mcp/toolscopes.go`). Scopes
describe what a *user* may do. They do not describe what a *client* should
be offered. An assistant connected through the public Claude Directory, or
Town, then gets the full user surface: global search across every chat,
unbounded history paging, media download, forwarding, deletion, broadcast
and admin tools for the owner's own account.

We need one server-side, reusable way to give a named client a small,
reviewed surface. It must not be built per client (no `/mcp/claude`), and it
must be possible to reason about it without reading prompts.

## Decision (proposed)

A **profile** is a named, server-side allowlist of tools with per-tool
argument constraints. It is bound to the OAuth client, not chosen by the
caller.

1. **Intersection, never union.** The effective surface is
   `toolScopes(identity) ∩ profile.tools`. A profile can only hide tools
   or tighten their arguments. It never grants a scope and never shows a
   tool the scopes would hide.
2. **No profile = today's behaviour.** Clients without a binding (operator
   tokens, worker and bridge credentials, existing DCR connections) are
   unchanged.
3. **Fail closed.** A binding that names an unknown profile, or a token
   whose profile claim cannot be read, gets an empty tool list and a
   refusal on every call, not the full surface. "Could not resolve the
   profile" is never "no profile".
4. **Bound at mint, carried in the token.** The authorization server
   resolves the profile from the client whenever it mints an access token,
   on code exchange and on refresh, and stamps it into the token (claim
   `prf`), next to `client_id`. Refresh
   re-resolves it, so a mapping change takes effect at the next refresh at
   the latest. The MCP layer reads `Identity.Profile` and never looks the
   client up per request. The profile is a property of the credential,
   never of the transport: localjwt also accepts the token from the
   `mctl_connect_token` cookie, so "arrived through the browser" proves
   nothing and must not select or skip a profile.
5. **Binding table in config, owned by gitops.** `MCP_CLIENT_PROFILES` maps
   an exact `client_id` to a profile name: a CIMD `client_id` URL (stable
   per product) or a preregistered client id. An entry that matches no
   client is harmless. A malformed table, an unknown profile name or a
   duplicate `client_id` is a startup error. Binding by `redirect_uri` is
   **not supported** for now (revised 2026-10-21, see Decisions 5): a
   record that uses it is a startup error, never silently ignored.
6. **Enforced on both paths.** The filter applies on `tools/list` and
   `tools/call` through the existing `WithToolFilter` hook. Argument
   constraints are enforced in the handler, because a filter only changes
   what is listed. A refusal writes an audit row `profile_denied` with the
   profile name and the tool (detached context, as `scope_denied`).
   A profiled credential is admitted **only on the MCP endpoint**: every
   other authenticated HTTP route (`/api/account`, the worker-token and
   bridge-token mints, `/telegram/connect/manage`) refuses it with 403,
   because none of them applies the profile, and the account routes and
   the token mints would otherwise give the restricted client its full
   scopes or an unprofiled credential. Refusal is the default in
   `auth.Middleware`; `/mcp` opts in.
7. **Each profile is a reviewed contract (ADR 0007).** Every profile gets
   its own descriptor snapshot, `docs/tool-descriptors.<profile>.json`, and
   the product-updates gate covers it like the full surface.

## The two profiles

### core-readonly

| Tool | Constraint under the profile |
|---|---|
| `list_dialogs` | Metadata only (type, title, username, unread count). Unchanged. |
| `get_messages` | `limit` default 20, max 50. No `fetch_media`. No `before_id` paging beyond one page per call. |
| `get_unread_messages` | `peer` **required** (listed as required in the schema). No cross-chat mode. |
| `search_messages` | `peer` **required**. No global search. |
| `get_my_identity` | Unchanged. |
| `get_my_send_status` | Unchanged. |
| `get_my_audit_log` | Unchanged (no message text). |

### core-reply = core-readonly plus

| Tool | Behaviour |
|---|---|
| `draft_reply(peer, text)` | Sends nothing. Resolves `peer` to a chat that already exists in the user's dialog list (refuses any other), returns the exact text and recipient as the server will send them, plus a one-shot `confirmation_id` (10 min, bound to user, profile, resolved chat id and text hash). Annotated read-only. |
| `send_reply(confirmation_id)` | Takes **only** the id. Recipient and text come from the server-side record, so the model cannot change them between draft and send. Without a valid, unexpired, unconsumed id it returns an error. When the send gate is closed it returns an error that names the condition, never a successful preview. Annotated destructive. |

As implemented (`internal/mcp/reply_tools.go`, `reply_store.go`):

- "Exists in the dialog list" is checked with `messages.getPeerDialogs`:
  the peer must be in the account's dialogs with at least one message,
  and for a group or channel the account must be a member (not left, not
  a min object). Readable is not enough: a public channel resolves by
  `@username` and its history reads fine for a non-member. A response that
  could not be read is an error, not a refusal.
- The text limit is 4096 UTF-16 units, as Telegram counts them (most emoji
  cost two), checked at draft time so it can never fail after the
  confirmation is spent.
- The draft stores the resolved peer itself, access hash included, and
  the exact text. `send_reply` sends to that peer and never re-resolves,
  so a username that changes hands after the draft cannot re-point it.
- The confirmation is bound to the user id and the profile name. Another
  user, another profile, an expired, used or unknown id all get the same
  answer: not found, draft again.
- `send_reply` evaluates the send gate (and the account mode) before it
  consumes the confirmation, so a refusal the user can fix, such as
  `send_enabled=false`, leaves the draft usable for the rest of its 10
  minutes. The per-peer rate limit is checked the same way, on a peek of
  the draft, before it is consumed.
- `send_reply` returns its own result type (`sent`, `recipient`, `text`,
  `message_id`), with no preview fields: it has no dry run.
- `draft_reply` reports whether the gate is open (`send_gate_open`,
  `send_gate_reason`) so the user learns before approving, but does not
  enforce it.
- The reviewer/demo account is part of the gate: `send_reply` refuses it
  with the preview-only reason, like any closed gate.
- Local Bridge accounts are refused by both tools in v1 (no bridge-side
  implementation).
- Both tools need `telegram:messages:send` in addition to the profile.
  Callers without a profile never see them
  (`toolprofile.ProfileOnly`); they are disabled in
  `docs/portal-allowlist.json` for the same reason.

Confirmations live in process memory and are lost on restart or
rollout. For `send_reply` that is acceptable only
because the failure is loud: an unknown id is an error that tells the
model to draft again, never a silent send or a preview. A pod that did not
issue the id must answer the same way.

`draft_reply`/`send_reply` are new tool names, not a mode of
`send_message`. `send_message` keeps its current contract for clients
without a profile (optional `confirmation_id`, successful `sent=false`
preview when the gate is closed); `prepare_send_message` stays behind the
MCP Apps flag.

### Not in any core profile

`disconnect_telegram_account`, `delete_telegram_account` (owner decision
2026-10-21), `set_send_consent` and the rest of `account:manage`, media,
forward, edit, delete, reactions, broadcast and admin tools.

Pin (`prepare_pin_message`/`pin_message`) is deferred to v2: in a group it
notifies members, it needs the same server-bound shape as `send_reply`,
and `prepare_pin_message` today checks no scope. Deferred by
owner decision (see Decisions).

## Telegram terms: what a profile does and does not solve

Telegram's Content Licensing terms, section "Large Language Models and AI"
(<https://telegram.org/tos/content-licensing>, read 2026-10-21), prohibit
using platform data to engage in the deployment of artificial intelligence.
The exception requires that "all relevant users individually provide
explicit, informed, affirmative and continued consent", limited to the
specific chat or non-global context, and not transferable to other chats.
API Terms §1.5 (<https://core.telegram.org/api/terms>) binds API use to
the same rule, and §1.4 forbids acting on a user's behalf without their
knowledge and consent.

What the profiles do:

- remove every global or bulk read (cross-chat search, cross-chat unread,
  unbounded paging), so each read is one chat the user named, in one call;
- make every write an explicit two-step with a server-bound payload.

What they do **not** do:

- obtain consent from the *other* people in a chat. Messages from a
  1:1 partner or group members still reach the model. Under a conservative
  reading the exception is not met. This needs a legal opinion and a
  product decision (per-chat consent, own-messages-only mode), outside
  this design.
- prove that excluding broadcast channels, or the reviewer mode, fixes
  anything. Both remain hypotheses until checked.
- replace the human confirmation in the client. `send_reply` binds the
  payload; the person still approves the destructive call in Claude or
  Town.

## Rollout

1. Profile type, `prf` claim, binding table, filter and handler
   constraints, `profile_denied` audit. Binding table empty: no behaviour
   change.
2. `draft_reply` / `send_reply`, registered only for core-reply.
3. Descriptor snapshots per profile, product-update entries.
4. Gitops: bind Town's client to a profile once Town uses a URL
   `client_id` (until then it is an implicit DCR host and cannot be bound,
   see Decisions 5), and the Directory connector once it exists.
5. Later, separately: binding DCR and implicit clients by `redirect_uri`,
   with the profile persisted in the refresh-token family.

Each step is proven both ways: a test that passes with the profile
applied and fails when the intersection is replaced by the scope check
alone.

## Decisions (owner, 2026-10-21)

1. The profile is bound at mint and carried in the `prf` claim; it is not
   re-resolved per request. Existing tokens keep their surface until the
   next refresh.
2. `send_reply` only sends to a chat that already exists in the user's
   dialog list. `draft_reply` refuses any other peer, including a bare
   `@username` the user has never talked to.
3. Pin is deferred to v2.
4. `get_messages` returns at most 50 messages per call, 20 by default.
5. **Revised: bind by exact `client_id` only.** The accepted text of
   point 5 also bound DCR clients by their registered `redirect_uri`. That
   cannot be honoured with point 4: the profile is re-resolved at every
   refresh, but the refresh request carries only the `client_id`, and the
   `redirect_uri` of an implicit or DCR client is not stored anywhere the
   refresh path could re-read it. A `redirect_uri` binding would therefore
   apply at code exchange and silently lapse at the first refresh, putting
   the client back on its full scope surface. The first implementation
   (#798) binds by exact `client_id` only and refuses `redirect_uri` records
   at startup. Binding by `redirect_uri` comes back as its own change once
   the refresh-token family persists the profile (or another stable client
   identifier), which needs a schema migration the first step avoids.
