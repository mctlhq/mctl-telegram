# Gate #889: conversation-plane gate and managed-runtime soak

Status: PLANNED, NOT APPROVED FOR EXECUTION (2026-11-04). Nothing in this plan
has been run. Issue #889 stays open and its acceptance criteria are not changed
by this document. Related: #334 (`gate-334-quota-isolation.md`), #1088, ADR 0008,
checklist `gate-889-soak-preflight.md`.

#889 was written for the conversation plane (`agent_jobs`, bounded worker,
claim-time coalescing). The managed runtime reuses that plane with a different
worker. The two have different workers, different concurrency and different
evidence, so this plan keeps them as two separate acceptances:

- **Part A: the original #889 gate**, exactly as the issue words it.
- **Part B: a managed-runtime soak**, a new acceptance that this plan proposes
  to add. It is not part of the issue until the owner accepts it on the issue.

Neither part substitutes for the other. An owner amendment of Part A is the only
way to close Part A without new evidence.

## 1. Closure and production rules

- #889 closes when Part A is met, or when Part A is amended and the amendment is
  recorded by the owner on #889 itself.
- #334 closes independently. Its closure does not wait for #889 and #889's does
  not wait for #334.
- Production GO for the managed runtime needs both issues closed and Part B
  PASS. A GO is a separate owner decision; this plan enables nothing.

## 2. Part A: original #889 gate, current status

Window of the soak that ran: 2026-10-31 11:33Z to 2026-11-03 11:33Z, preview.
Interim result: 2026-11-01; the final analysis is not yet posted.

| Original criterion | Status | Evidence and what is missing |
|---|---|---|
| #885 merged and on preview | Issue closed; build not verified | Confirm by `git merge-base --is-ancestor` against the preview image tag (preflight B1). |
| #886 merged | Issue closed; build not verified | Same. |
| 0 OOMKilled and 0 restarts on both pods; worker peak against 512Mi | Met in the interim result | Peak RSS 15.4 MiB, 0 restarts. Confirm over the full window. |
| Session health: no `AUTH_KEY_*` or `unauthorized` | Met in the interim result | 0 lines in 26 h of logs. Confirm over the full window. |
| `dead_letter` = 0, `routed` only for policy reasons, no job `processing` past the visibility timeout | Met in the interim result | 0 / 0 / 0. Confirm over the full window. |
| **At least one observed moment with 2 concurrent claims on different conversations; never more than 2 globally, never more than 1 per conversation** | **NOT MET** | The soak ran one worker at concurrency 1, so the maximum observed was 1 globally. A concurrency-1 run cannot show the 2-claim moment or the global bound of 2. It is not "not applicable". |
| Isolation: no binding rejection outside tests, each explained | Met in the interim result | 0 rejections. |
| Cost per completed turn against the baseline | **NOT MET** | The window had no completed turn to compare. Baseline: 668 jobs as 667 turns, $0.0123 mean, $0.0107 median (2026-10-19 to 2026-10-23); confirm how that mean was computed before comparing (3.3 defines the denominators used here). |
| Minimum traffic: at least 3 coalesced bursts, otherwise inconclusive | **NOT MET** | 1 coalesced burst in 16 jobs; 15 of them `ignored` after #1012 and the contacts exclusion. |

Verdict today: stability criteria met; the concurrency, cost and traffic
criteria are not met, so Part A is **INCONCLUSIVE and open**. Declaring Part A
passed on a concurrency-1 run is not allowed without an amendment.

Ways to close Part A (owner chooses, D-A):

1. A new preview run with worker concurrency 2 and traffic that meets the
   minimum. `agent-worker-preview` already sets `AGENT_WORKER_CONCURRENCY: "2"`
   with `replicaCount: 0`, so the change is to scale that worker (or raise the
   managed pool worker's concurrency), not a new setting; the Mac mini worker that
   served the first soak follows production release tags. Only one listener per
   account is safe, so a second worker must not listen on the same account. The
   window must also end before the Anthropic promotional credit expires on
   2026-11-11. Owner approval is needed for whichever worker is scaled, and the run showing the 2-claim moment and
   the bounds. This satisfies the issue as written.
2. An owner amendment recorded on #889: the conversation plane is accepted at
   concurrency 1, with the reasoning, and the global bound of 2 is replaced by
   the bound that holds at concurrency 1. The issue's criteria are not edited by
   this plan; the owner decides.

Production observe-mode traffic from 2026-11-01 may be reported as supplementary
evidence, labelled production, and does not turn an INCONCLUSIVE Part A into a
pass by itself.

Step A0 (read-only, no approval): post the final analysis of the finished soak
on #889, using the table above, with the window and the figures filled in.

## 3. Part B: managed-runtime 72 h soak

### 3.1 Preconditions

See `gate-889-soak-preflight.md` for the checklist. In short: #885 and #886 are
in the build under test (same check as Part A), the pool worker is on GLM-5.1 via
Nebius with concurrency 1, the audience and consent are set by the owner, caps
are recorded, the sampler runs, and the build is frozen for the window. A
rollout restarts the 72 h clock unless the owner waives it; the rollout 503 gap
(tg#1108) counts as a rollout effect.

### 3.2 Traffic source (decision D1): allowlist of consenting testers

Preview allows `MANAGED_RUNTIME_MAX_ACCOUNTS: "1"`; the managed account is
the managed test account, whose `audience.onlySenders` holds one test sender, so it receives no
real inbound. The chosen variant is a limited allowlist of testers who agreed:

- The allowlist is `audience.onlySenders` of the managed install, set before
  `listening: true`. Only people who agreed in writing are on it; the audience is
  not widened, there is no scope opening and no contacts access.
- Each tester is told, before the window, that: messages they send to @mctlhq are
  processed by an AI model hosted by a third-party provider; no reply will be sent
  to them (observe mode, sending off), so they should not expect one; the owner
  sees a held draft or summary; they can withdraw at any time and are removed
  from the allowlist. The consent record is kept by the owner outside this
  repository. No names, handles or numeric ids are written to the repository or
  to GitHub; documents refer to "tester 1..N".
- Proposed size: 3 to 6 testers, asked to write in bursts of 2 or more messages
  at gaps shorter than 3 s and longer than 8 s, plus edits and deletes, over the
  whole window. A schedule is agreed with them.
- Testers must be fresh non-contacts with no existing chat with the account: on
  2026-11-01 `onlySenders` admitted nobody who was in the contacts or chats, and
  opening scope exclusions is a separate owner permission that this plan does not
  assume. The existing test sender is removed from `onlySenders` or kept, as the
  owner says in D1.
- Setting the allowlist, setting `listening: true` and the consent step are
  separate owner permissions (D2). This plan does not perform them.

If fewer testers agree than the minimum traffic needs, the run is reported as
INCONCLUSIVE, not widened.

### 3.3 Acceptance criteria (Part B, over the 72 h window)

Job statuses are those of `agent_jobs`: `pending`, `processing`, `completed`,
`failed`, `dead_letter`, `ignored`, `coalesced`, `routed`. Every query filters on
`created_at` in the window, because the table holds older rows (for example
earlier `dead_letter` rows).

Cost denominators, defined once:

- Total cost = the sum of `agent_usage.cost_usd` (the ledger, one row per job
  and attempt, so retries are counted) over the jobs created in the window.
  `agent_jobs.cost_usd` holds only the last attempt and is NULL for coalesced
  members, so it is a cross-check, not the total. Jobs closed as `ignored`
  without a model call (#1012, conversation not active) have no usage row; the
  report splits ignored jobs into model-invoking and model-less, and cost per job
  is computed over all jobs and over model-invoking jobs.
- Cost per job = total cost / number of jobs. GLM-5.1 preview baseline: $0.6585
  / 32 = $0.0206.
- Cost per completed turn = total cost / number of completed turns, where a turn
  is a `turn_id` with a `completed` head. Baseline: $0.6585 / 23 = $0.0286
  (23 completed, 9 ignored in the 32-job run).
- The pass test uses cost per completed turn (it carries the cost of the work
  that produced no reply); cost per job is reported next to it. The traffic mix
  differs from the fixtures, so the ratio of ignored to completed is reported
  too.

| # | Criterion | Pass condition | Source |
|---|---|---|---|
| 1 | Uptime and restarts | 0 OOMKilled and 0 crash restarts for the preview server pods and the pool worker; highest sampled working set against the 256Mi worker limit (a sampled peak). Rollout restarts excluded only under a recorded owner waiver of the freeze. | `kubectl get pod`, `lastState`, `kubectl top`, sampler |
| 2 | Session health | 0 `AUTH_KEY_*` or `unauthorized` revocations of the managed account. | server logs |
| 3 | Job outcomes | For the managed account: `dead_letter` = 0 for jobs of the window (an explained dead letter still fails); no job `processing` with `claimed_at` older than the visibility timeout (5 min); each `attempts > 1` listed and explained; `routed` only for policy reasons, never `worker_unclaimed` (route reason in `event_outbox`). The isolation account is excluded here and covered by criterion 6, because the server routes any `pending` job with 0 attempts older than `AGENT_UNCLAIMED_ROUTE_AFTER` (5 m) to `routed(worker_unclaimed)` whatever its runtime. | `agent_jobs`, `event_outbox` |
| 4 | Concurrency and claim | Worker concurrency is 1: never more than 1 concurrent claim globally and never more than 1 per conversation. This says nothing about Part A's 2-claim criterion and is not offered as evidence for it. | `agent_job_attempts` overlap query |
| 5 | Coalescing | At least 3 coalesced turns (a `turn_id` grouping 2 or more jobs; `coalesced` rows point to the head through `coalesced_into`). | `agent_jobs` |
| 6 | Isolation | A second account on `runtime: own` with `listening: true` exists for part of the window; its jobs are never claimed: 0 attempts, no `agent_usage` row, status `pending` or `routed` with reason `worker_unclaimed`, and the pool worker claims nothing for it. 0 binding rejections outside tests, each explained. | `agent_jobs.user_id`, `agent_usage`, logs |
| 7 | Ledger | No `agent_usage` row older than visibility timeout plus one sweep outside `settled`; `mctl_agent_usage_held_usd` is 0 whenever no job is processing (it sums held rows of the current UTC day, so only idle moments are checked). | `agent_usage`, vmsingle |
| 8 | Cost | Cost per completed turn at most 2x $0.0286; total within the window cap (D3). A ledger figure at list prices, not an invoice. | `agent_usage.cost_usd` (cross-check `agent_jobs.cost_usd`) |
| 9 | Latency | p95 job latency at most 60 s (baseline p95 34 s, max 55.8 s). Proposed. | timestamps |
| 10 | Provider health | Rates of `error_provider_429`, `error_provider`, `error_provider_no_usage` reported; no run of 3 or more consecutive jobs failing for provider reasons. | `last_error`, worker log |
| 11a | No peer sends | `propose_reply` is the only peer-addressed action type. 0 rows with `action_type='propose_reply'` and (`executed_tg_message_id IS NOT NULL` or `status IN ('approved','executing','executed','delivery_unknown')` or `send_attempts > 0`), so an unconfirmed send also fails. Every `propose_reply` ends in `pending_approval`, `expired`, `denied` or `rejected`. A single peer send is a stop condition. Queries filter on `action_type`; `status='executed'` alone also matches owner summaries. | `agent_actions` |
| 11b | Owner-only notifications | `send_owner_summary` and `request_owner_approval` actions (security alerts are an intent of `send_owner_summary`) and `owner_notifications` rows (`kind` summary, approval_request, alert, human_input) are expected; a drafted `propose_reply` also yields an `approval_request` notification. Counted by `kind`, with the rate reported. Delivery goes to the managed account's own Saved Messages through the self-sender, there is no recipient column, and owner actions carry no `executed_tg_message_id`, so the evidence is `owner_notifications.status='sent'` with a `tg_message_id`. They are not peer sends and do not fail 11a. A notification that cannot be tied to the self-sender (for example a send logged to a peer) fails this row. | `owner_notifications`, `agent_actions` |
| 12 | Budget behaviour | No unexplained `budget_paused_until`; any cap that is hit is recorded with whether it was intended. At the 1.00 per-account day cap a 72 h window spans up to four UTC days and about $4, so a $6 total needs the day cap raised (D3); otherwise the cap pause is expected and is not a failure. | `mctl_agent_budget_*`, `agent_usage` |
| 13 | Observation integrity | No sampler gap longer than 15 minutes and logs cover the whole window; otherwise every dependent criterion is INCONCLUSIVE, never PASS. | sampler log |

Minimum for a conclusive verdict: at least 3 coalesced turns and at least 30
completed turns (proposed, D5). `ignored` jobs do not count. Below the minimum
the verdict is INCONCLUSIVE and Part B stays open.

### 3.4 Observability and evidence

A read-only sampler runs every 5 minutes: restart counts and last termination
reason, `kubectl top pod`, job counts by status, `processing` rows past the
timeout, usage rows not settled, owner-only notification counts, and
previous-container logs saved to a file whenever a restart is seen. At the end
the criteria are computed from `agent_jobs`, `agent_job_attempts`,
`agent_usage`, `agent_actions` (metadata only; draft bodies are encrypted and are
not read) and the metrics `mctl_agent_jobs_total`,
`mctl_agent_job_cost_usd_total`, `mctl_agent_usage_cost_usd_total`,
`mctl_agent_usage_held_usd`, `mctl_agent_budget_exhausted_total`,
`mctl_agent_budget_deferred_total`, `mctl_agent_managed_accounts`,
`mctl_agent_credential_domain`. The AI Gateway keeps no logs by design.

Result: one comment on #889 per part, with the table filled in, the build tags,
the tester count (not identities), any waiver, and the verdict (PASS, FAIL,
INCONCLUSIVE).

### 3.5 Stop conditions and rollback

Stop conditions:

- a peer send (11a), or an owner-only notification addressed to anyone else;
- an `AUTH_KEY_*` or `unauthorized` revocation of the managed account;
- an OOMKill, or two crash restarts in 24 h;
- `dead_letter` greater than 0 for a job of the window;
- a job of a different account claimed by the pool worker;
- spend above the window cap, or an `agent_usage` row that never settles;
- a tester withdraws consent (remove that tester at once);
- the owner asks to stop.

A targeted stop (spend, a single-account problem, an auth revocation, a
withdrawn tester): set `listening: false` first so nothing new is ingested, then
`paused: true`; do not close the whole pool (runbook, spend-storm mitigation; the listening step is an addition to the runbook text).
A full rollback (a pool-level defect, a cross-account claim) follows the
runbook "Managed runtime rollback" in order: account to `runtime: own` with
`listening: false`, worker `replicaCount: 0`, revoke the pool token, then
`MANAGED_RUNTIME_ENABLED: "false"`. After either, the isolation account stays
`own` with `listening: false`, sending stays off, held replies stay unapproved.
These stop actions are pre-authorised by the owner in D2 for the window; the
agent does nothing beyond them and reports at once.

### 3.6 Owner decisions (D)

- D-A. How Part A is closed: a concurrency-2 run, or an owner amendment (section 2).
- D1. Tester allowlist: how many testers, who asks them and records consent.
- D2. Set the allowlist, switch to `listening: true`, bring up the isolation
  account, and pre-authorise the stop actions in 3.5. Each is a separate
  permission; nothing here is done without it.
- D3. Window caps (raising the per-account day cap is required to reach $6). $6 over 72 h is about 210 completed turns at the $0.0286
  baseline; the arithmetic is a proposal and the observed first-24 h rate
  corrects it. Only per-account day (1.00 now, 3.00 if raised), per-account
  month (15.00) and global day (5.00) are enforceable in config; the 72 h total
  is a sampler stop condition. Raising and reverting the day cap are mctl-gitops
  PRs.
- D4. Worker stays on GLM-5.1 / Nebius (already decided).
- D5. Thresholds: p95 60 s, cost per completed turn 2x, 30 completed turns, 15 min
  sampler gap.
- D6. Whether production observe numbers count as supplementary evidence for Part A.
- D7. Minting or rotating the pool token or scaling the worker if needed; starting
  the sampler against the preview database.

Not in this plan, and each needs its own approval when it comes up: Cloudflare
apply, Vault writes, production deploys or flags, any change of listening or
sending outside D2.

### 3.7 GO / NO-GO

Part B is PASS only if every criterion 1 to 13 is PASS with none INCONCLUSIVE,
the minimum traffic is met by organic tester traffic from at least 3 distinct
testers (no scripted or fixture-replay input counts toward the minimum), no stop
condition fired, the preflight was complete with each recorded value quoted, and
tester consent covered the whole window. Part B PASS is evidence for the managed-runtime production
decision; it does not close #889 by itself (section 1).

An inconclusive Part A or Part B never counts as a pass. NO-GO or INCONCLUSIVE
keeps the gate open; extend or repeat.

### 3.8 Risks

- With 3 to 6 testers the volume may be too low (the 2026-10-31 soak was). The
  result is then INCONCLUSIVE and the audience is not widened.
- Testers see no reply, which can confuse them; the briefing says so.
- The Nebius rate limit is unmeasured; a provider 429 storm resembles an
  application defect. Criterion 10 separates them.
- Messages from testers go to a third-party model provider. Consent text
  `managed-data-flow/v1` applies to the managed account; the tester briefing
  covers the testers.
- Self-update restarts and rollouts can look like crashes; the freeze and
  criterion 1 handle them.
