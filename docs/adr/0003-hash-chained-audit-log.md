# 0003. A per-user hash-chained audit log, and redaction by handler

Status: Accepted

## Context

Users hand an AI model access to their private messages. They need to be
able to see what was done with that access, and to trust that the record
was not quietly edited afterwards. At the same time, the logs that
operators read must not become a second copy of the data the service is
trusted with: message text, phone numbers, tokens.

## Decision

- Every tool call writes a row to `audit_logs`. Each row carries
  `prev_hash` and `entry_hash`, forming one chain per user
  (`internal/db/audit_chain.go`, `hashAuditEntry`).
- `entry_hash` is SHA-256 over the previous hash, the user id, the tool,
  the redacted peer, the status, the error and the timestamp, with
  length-prefixed fields and the request metadata (request id, route, MCP
  method and name, protocol version) when present. A user's first row
  chains from 32 zero bytes. Appends are serialized per user
  (`SELECT … FOR UPDATE` on Postgres, `BEGIN IMMEDIATE` on SQLite) so the
  chain cannot fork.
- A user can read their own log (`get_my_audit_log`) and check the chain
  end to end with `GET /api/account/audit/verify`, which walks it and
  reports the first broken row. The endpoint needs the user's token, and
  checks only that user's chain. An operator reads another user's log
  through an admin-only tool (`get_user_audit_log`).
- No message content goes into the audit row: the peer is stored
  redacted, and the free-text `reason` column is deliberately outside the
  hash.
- Application logs go through `RedactingHandler`
  (`internal/audit/redact.go`), installed as the root slog handler. Any
  attribute whose key is on its list (message text, phone, codes, session
  blobs, tokens, secrets, names, media payloads) is replaced by
  `[redacted len=N]`, including inside nested groups. Free text passes
  through `ScrubText`, which masks `@handles` and phone-like numbers.

## Consequences

- Editing or deleting a row in the middle of a user's history breaks the
  chain, and the user can see it. This makes tampering detectable, not
  impossible: someone with write access to the database could rewrite a
  whole chain from the edited row on. Anchoring chain heads outside the
  database would close that, and has not been done.
- Redaction is enforced in one place instead of relying on every call site
  to remember. A new sensitive field still has to be added to the list,
  as `CONTRIBUTING.md` asks.
- Serialized appends cost a row lock per write per user. At the current
  call rates this is not measurable.

## Alternatives

- **A plain append-only table.** Cheaper, but gives the user nothing to
  verify.
- **One global chain.** Would serialize every write in the service and
  make each user's verification walk everyone's rows.
- **Redaction at each log call.** The approach that leaks the first time
  someone forgets.
