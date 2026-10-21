# Restricted tool profiles: core-readonly and core-reply

Status: Accepted (owner, 2026-10-21). Not implemented yet.

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
   resolves the profile from the client when it issues the code and stamps
   it into the access token (claim `prf`), next to `client_id`. Refresh
   re-resolves it, so a mapping change takes effect at the next refresh at
   the latest. The MCP layer reads `Identity.Profile` and never looks the
   client up per request. The profile is a property of the credential,
   never of the transport: localjwt also accepts the token from the
   `mctl_connect_token` cookie, so "arrived through the browser" proves
   nothing and must not select or skip a profile.
5. **Binding table in config, owned by gitops.** `MCP_CLIENT_PROFILES` maps
   a client key to a profile name:
   - CIMD clients: the exact `client_id` URL (stable per product).
   - DCR clients: the exact registered `redirect_uri` (DCR client ids are
     random per registration, so they cannot be keys).
   An entry that matches no client is harmless; a client that matches two
   entries with different profiles is a startup error.
6. **Enforced on both paths.** The filter applies on `tools/list` and
   `tools/call` through the existing `WithToolFilter` hook. Argument
   constraints are enforced in the handler, because a filter only changes
   what is listed. A refusal writes an audit row `profile_denied` with the
   profile name and the tool (detached context, as `scope_denied`).
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

Confirmations live in process memory (`internal/mcp/confirm.go`) and are
lost on restart or rollout. For `send_reply` that is acceptable only
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
   `client_id` (until then it is an implicit DCR host), and the Directory
   connector once it exists.

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
