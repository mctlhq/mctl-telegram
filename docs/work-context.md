# Work-context surface adapter (issue-443)

Binds a Telegram Saved Messages thread to a canonical mctl-api WorkItem and
lets the owner request platform execution from their phone, without
mctl-telegram ever owning the work state itself. See
[docs/contracts/mctl-api-work-context.md](contracts/mctl-api-work-context.md)
for the exact routes and the "bot never supplies an actor" rules this
adapter is built to.

Off by default (`WORK_CONTEXT_ENABLED=false`). With the flag off, `/mctl
work` and `/mctl link` reply with the ordinary unknown-command help text —
no mctl-api client is even constructed.

## One-time setup: linking your Telegram account

1. On a platform surface you already have a GitHub identity on, request a
   link code: `POST /api/v1/surface-identities/challenges {"surface":
   "telegram"}` with your GitHub credential. The code is valid for 10
   minutes.
2. Send the code to the bot: `/mctl link <code>`.
3. The bot never echoes or logs the code. A successful link means every
   later `/mctl work` command in this Telegram account acts as you, not as
   the bot.

## The four `/mctl work` forms

- `/mctl work https://github.com/mctlhq/<repo>/issues/<n>` — creates (or,
  through mctl-api's `external_key` dedupe, opens) the canonical WorkItem
  for that issue and submits a `start` execution request. The pilot only
  accepts an explicit mctlhq GitHub issue URL — no title-only work, no
  guessing a target from chat text.
- `/mctl work status` — shows the work item's id, state, latest execution
  and snapshot pointers, and the state of the last execution request
  submitted from the most recently updated binding in this chat:
  - `pending` — waiting for the platform to pick it up;
  - `claimed` — the platform is starting it;
  - `fulfilled` — done, with the execution id it produced;
  - `failed: <reason>` — rejected, with the platform's typed reason
    (`no_runnable_target`, `loop_active` — the issue's DevLoop is already
    running, `unsupported_kind`, `resume_refused:<r>`,
    `fulfil_refused:<c>`, `engine_run_ended`, or an unrecognised code shown
    verbatim). mctl-api's free-text message is never shown.
- `/mctl work note <text>` — appends an intent to the bound work item. The
  bot never mirrors the surrounding chat, only this exact text.
- `/mctl work resume` — submits a `resume` execution request against the
  work item's current state; on a state-version conflict it re-reads once
  and retries, then tells you to try again rather than looping.

## Env vars

| Var | Default | Notes |
|---|---|---|
| `WORK_CONTEXT_ENABLED` | `false` | Master flag. |
| `MCTL_API_BASE_URL` | `https://api.mctl.ai` | mctl-api root. |
| `MCTL_SURFACE_TELEGRAM_TOKEN` | *(none)* | Bearer for the `surface:telegram` principal — required when the flag is on. |
| `MCTL_WORK_ITEM_TENANT` | *(none)* | The mctl-api tenant every Telegram-originated work item belongs to — required when the flag is on. |

## Metrics

- `mctl_work_context_requests_total{route, outcome}` — every outbound
  mctl-api call; `outcome` is `ok` or `error`. A sustained `error` rate on
  one `route` is the signal to alert on.
- `mctl_work_context_bindings_total{result}` — thread binding writes:
  `created`, `reused` (crash redelivery, or a rebind of the same issue) or
  `refused` (thread already bound to a different issue).

Both families are pre-created at zero for their full label set.

## Manual cross-surface verification

1. Enable the flag with a valid token and tenant, and link your account
   (`/mctl link <code>`).
2. `/mctl work https://github.com/mctlhq/<repo>/issues/<n>` — note the work
   item id and request id in the reply.
3. `/mctl work status` until the request shows `claimed`, then `fulfilled →
   <execution id>`.
4. From a second surface (CLI/MCP or web, whichever is available), open the
   same `work_item_id` and confirm it shows the same execution and snapshot
   pointer — no Telegram history was replayed to get there.
5. Resume from the second surface, then `/mctl work status` in Telegram
   again and confirm it reflects the new execution.

## Rollback

Set `WORK_CONTEXT_ENABLED=false` and restart. No outbound request is made
after that, and `/mctl work`/`/mctl link` fall back to the unknown-command
reply. Every other `/mctl` subcommand, the listener, the executor and the
notifier are untouched. Already-created work items remain valid canonical
state, reachable from any other surface.

## Agent clarification questions (`/mctl input`, issue-571)

When an agent stops with a typed `needs_input` outcome, mctl-api records a human-input request and parks the workflow. With `HUMAN_INPUT_ENABLED=true` (which requires `WORK_CONTEXT_ENABLED=true`), mctl-telegram polls `GET /api/v1/human-input` for each enrolled operator and posts one message into Saved Messages:

```
INPUT REQUEST (not an approval)
Work: mctlhq/mctl-telegram#571
Question: ...
Options:
  1. ...
  2. ...
Deadline: 2026-10-04 12:00 UTC
Answer: /mctl input K7QM3R <number>
Ref: request <request_id> v<version>
```

- Answer a single-choice question with `/mctl input <code> <number>`, and a free-text question with `/mctl input <code> <your answer>`.
- `/mctl input status [code]` shows the canonical state from mctl-api; local state is never authoritative.
- The bot replies `Answered by you: <value>. Agent will resume.` only after mctl-api confirms the answer. `This question is no longer active.` means it expired, was cancelled, was superseded by a newer version (which arrives under a new code), or was answered elsewhere. `Already answered.` means the answer was recorded earlier. If the platform cannot be reached the bot says `Could not confirm; check again with /mctl input status <code>`, never success.
- Authorization stays in mctl-api. The answer code is not an approval code: `/mctl approve` and `/mctl reject` are unchanged and never accept it.
- Enrollment: an operator is polled once they have run `/mctl link`, a successful `/mctl work status`, or `/mctl input status`; existing work-item bindings are backfilled at startup.
- The contract the adapter assumes is in [contracts/mctl-api-human-input.md](contracts/mctl-api-human-input.md); it is unverified against a deployed mctl-api until its revision is pinned there.
- Rollback: set `HUMAN_INPUT_ENABLED=false` and restart. The poller stops and `/mctl input` becomes an unknown command. Pending requests stay owned by mctl-api.
