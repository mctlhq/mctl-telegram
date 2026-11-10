# Durable deny codes (#1271)

Refs #1271. A denial used to leave only prose (`agent_actions.policy_reasons`)
and a metric label. Nothing durable said which stable code refused an action.
This change stores the code and writes one audit row per denied action in the
same transaction as the denial.

## Schema

Two additive, nullable columns, added with the existing idempotent
`addColumnIfMissing` (`ADD COLUMN IF NOT EXISTS` on PostgreSQL, a
`pragma_table_info` probe on SQLite). Re-running the migration is a no-op.

| Column | Meaning |
| --- | --- |
| `agent_actions.deny_code` | stable code of the denial that moved the action to `denied` |
| `audit_logs.deny_code` | the same code on the audit row of that denial, or of an audit-only refusal |

There is no default and no backfill: every row written before this change, and
every row that is not a denial, has `NULL`. `NULL` therefore means "no code
recorded", never "allowed".

## Code semantics

- A policy denial keeps the exact `policy.DenyCode` string (for example
  `autopilot_paused`, `install_changed`, `legacy_install_revision_missing`,
  `job_binding_mismatch`, `tool_not_allowed`).
- A denial with no policy code stores `unknown`: retention sweep, owner
  takeover and install sweeps, send-gate and Telegram-refusal paths, a
  `RequireApproval` escalation at send time. `internal/db` does not import the
  policy package; it holds the two literals it needs (`unknown`,
  `source_message_superseded`) and takes every other code as a string.
- Draft withdrawn because its source message was edited or deleted:
  `source_message_superseded`.
- `delivery_unknown`, `rejected`, `expired` and every non-terminal status never
  get a code and never get a denial audit row.
- `policy_reasons` prose, its parsing, and the MCP reason taxonomy are
  unchanged.

## Atomicity

Every transition to `denied` runs `UPDATE agent_actions ... RETURNING id,
user_id` inside a transaction and writes one `agent_action_denied` audit row per
returned row, in that transaction (`denyActionsTx`). Consequences:

- Only rows the UPDATE actually moved are audited. A lost compare-and-set or a
  replay returns no rows and writes nothing.
- A failed audit insert rolls the status change back; a failed or cancelled
  commit leaves neither. The caller gets an error, never a reported success.
- Bulk paths audit per action, not per batch: conversation sweep, source-message
  sweep, message-delete, earlier-install sweep and the retention sweep. There is
  no summary row.
- An action inserted already `denied` (`propose_reply` and the owner-facing
  tools on a policy deny) is audited in the insert transaction. A job-tied
  redelivery that hits the `(job_id, action_type)` unique index returns the
  existing row and audits nothing.
- The audit INSERT is one tx-aware helper (`insertAuditTx`) shared with
  `LogToolCallChecked`, so scrubbing, tenant scope, correlation fields and
  timestamps are identical. It uses the caller's context, so a cancelled caller
  rolls both writes back.

Audit-only refusals (job binding, tool gate) create no action row. They write a
checked audit row with the typed code and a fixed error text derived from the
code alone (`conversation binding: <code>: denied`, `tool gate: <code>`); the
numeric ids that used to follow are logged instead. If that write fails the
request answers with the sanitized 500, never the normal refusal.
`propose_reply` no longer writes a successful `ok` audit row for a call whose
persisted action is `denied`.

Not changed: the one-shot migration `retire_pre_executor_approved_v1`, which
retires pre-executor rows once per database. Its rows stay `NULL`, like every
other legacy row.

## Audit hash chain

Field 10 of the canonical hash input is appended **only when `deny_code` is not
NULL**: marker byte `0x02`, then the length-prefixed code. It follows the
correlation block (marker `0x01`), so:

- a row with `NULL` deny_code hashes byte-for-byte as before; old chains verify;
- the two optional blocks cannot be mistaken for each other;
- editing a code, removing it (set to `NULL`) or adding one to a legacy row
  fails `VerifyAuditChain`; mixed old and new chains verify.

`hashAuditEntry` keeps its signature and delegates to
`hashAuditEntryWithDenyCode` with `NULL`.

### Rollback compatibility

A binary built before this change recomputes a row that has a deny code without
field 10 and reports it as tampered. Rolling back to such a binary after coded
rows exist makes `VerifyAuditChain` fail on those rows. There is no
discriminator in the old format that would let an old verifier recognise the
unknown block, so this is not detected or papered over: roll forward, or accept
failed verification for the coded rows.

## Known limitation: PostgreSQL predecessor race

Reading the previous hash and inserting the next row takes no user-level lock
on PostgreSQL. Two concurrent audit writers for one user can chain from the
same predecessor. That race predates this change and is tracked in #1277
(design first). This change does not add advisory locks or any serialization.
Same-transaction atomicity of action and audit row is guaranteed; it does not
serialize concurrent chain writers.

## Tests

`internal/db/agent_deny_code_test.go`, `audit_chain_test.go`,
`internal/agentapi/actions_test.go`, `internal/agent/executor/executor_test.go`.
The PostgreSQL test needs `TEST_DATABASE_URL` and is skipped without it.
