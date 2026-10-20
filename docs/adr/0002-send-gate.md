# 0002. One send gate with three independent conditions

Status: Accepted

## Context

An AI model calling `send_message` on a real Telegram account is the most
damaging thing this service can do: a message to the wrong person cannot be
unsent from their device. Clients differ in how they confirm a write
(ChatGPT may resolve its own confirmation automatically), so the client
cannot be the safety mechanism. The operator, the token and the account
owner each need a separate way to say no.

## Decision

- Every write goes through one gate, `evaluateWriteGate`
  (`internal/mcp/tools.go`). A send is real only when all three hold:
  1. the deployment allows it (`ALLOW_SEND=true`, default `false`,
     `internal/config/config.go`);
  2. the token carries the `telegram:messages:send` scope;
  3. the account owner has turned sending on (`send_enabled`, stored per
     account, default false in the schema).
- When any condition fails the call does not error: it returns a preview
  with `sent=false` and a `dry_reason` naming the condition. The model sees
  what it would have sent and why it was not.
- `get_my_send_status` answers from the same gate code, so the status a
  client shows and the outcome of a send cannot disagree.
- A per-recipient budget (`PeerSendCap`, 20 per hour,
  `internal/audit/ratelimit.go`) applies on top, against bulk sending from
  one account.
- New accounts start read-only. The connect wizard pre-selects "Read only",
  and sending is a separate opt-in (`internal/oauth/enable_access.go`,
  0.80.1, #770).
- Actions that are hard to undo or expensive use prepare and confirm: a
  `prepare_*` tool returns a single-use confirmation id bound to the exact
  arguments, valid for ten minutes (`internal/mcp/confirm.go`). This covers
  pinning and media download (0.43.0, #279).
- Broadcasts cannot be approved by any tool. `prepare_broadcast` returns a
  link, and a human approves in a browser after signing in with Telegram
  (`internal/broadcast`, 0.68.0, #439).

## Consequences

- Each party has its own off switch, and none depends on another: the
  operator through the environment, the client's grant through scopes, the
  owner through the account flag.
- A model that hits the gate gets a useful answer instead of an error, so
  clients do not retry blindly.
- Confirmation ids live in memory, so a restart drops pending
  confirmations. With a ten-minute lifetime that costs a retry, not data.
- More conditions mean more ways to be confused about why a send did not
  go out. `dry_reason` and `get_my_send_status` exist to make that visible.

## Alternatives

- **Rely on the client's write confirmation.** Not under our control, and
  not consistent across clients.
- **A single server flag.** Lets nobody but the operator decide, and turns
  on sending for every account at once.
- **Allow approval of broadcasts through a tool.** Rejected outright: an
  approval a model can produce is not an approval.
