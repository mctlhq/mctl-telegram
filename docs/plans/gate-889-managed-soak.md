# Gate #889: 72-hour stability soak (conversation plane and managed runtime)

Status: draft plan, 2026-11-04. Nothing in this plan has been executed. Issue
#889 stays open until its acceptance evidence is posted and the owner decides.
Related: #334 (quota isolation, `gate-334-quota-isolation.md`), #1088 (managed
runtime epic), ADR 0008.

## 1. Where the gate stands

| Item | State | Source |
|---|---|---|
| #885 coalescing of jobs queued behind an in-flight turn | Issue closed. Confirm the fix commit is in the build that the soak runs (step P1). | #885 |
| #886 no false ERROR on same-conversation hand-off | Issue closed. Same confirmation (P1). | #886 |
| 72 h soak of the conversation plane, 2026-10-31 11:33Z to 2026-11-03 11:33Z | Ran on preview. Interim result 2026-11-01: stability criteria PASS, outcome criteria INCONCLUSIVE (16 jobs, 1 coalesced burst, minimum is 3). The final analysis (next-step item 1 in the 2026-11-03 comment) is not posted. | #889 comments |
| Conversation plane in production | Enabled in observe mode on 2026-11-01 by owner decision (gitops#2330), so the "before production enablement" wording of the gate was overtaken for the Claude worker. | #889 comments |
| Managed runtime (GLM-5.1 / Nebius, pool worker) | Preview only. Two 32-job runs on 2026-11-04 (not a soak). Production has no `MANAGED_*` flags set. | #1088 |

Two soaks are therefore needed, and they are different things:

- **S-A, close out the conversation-plane soak.** Analysis only, no new traffic.
- **S-B, managed-runtime soak.** A new 72 h run of the pool worker on preview.
  This is the gate for enabling `runtime: managed` in production.

## 2. S-A: finish the conversation-plane analysis (no approvals needed)

Read-only. Post the result in #889 using the criteria table in section 3.3,
restricted to `agent_jobs` with id > 11903 and the window above. Required
statements: pod restarts and OOM, worker RSS from the worker host sampler log,
`dead_letter`, routing reasons, stale claims, concurrency, coalesced bursts,
cost per completed turn against the baseline ($0.0123 mean, $0.0107 median,
668 jobs as 667 turns, 2026-10-19 to 2026-10-23), and a note that #1012 and the
contacts audience exclusion cut traffic during the window. Expected verdict,
per the interim result: stability PASS, outcomes INCONCLUSIVE. An inconclusive
soak is not a pass (the gate says so) and it does not count toward GO in
section 3.7. Production observe traffic from 2026-11-01 may be reported next to
it as supplementary evidence, labelled as production and not as soak. Whether
that supplementary evidence is enough for the conversation plane is an owner
decision (D6), recorded on #889.

## 3. S-B: managed-runtime 72 h soak

### 3.1 Preconditions (P)

- P1. Verify #885 and #886 in the deployed build: find the merge commits, check
  they are ancestors of the preview server image tag and of the pool worker
  image (`git merge-base --is-ancestor`), and record both tags.
- P2. The preview server and the pool worker run the same release lineage; the
  worker is on GLM-5.1 via Nebius (`labs/agent-worker-managed-preview`, 1
  replica, `AGENT_WORKER_CONCURRENCY` 1).
- P3. A traffic source is chosen (decision D1).
- P4. Caps for the window are set and recorded (decision D3).
- P5. The evidence sampler (3.4) is running and has produced a baseline sample,
  and the retention of server and worker logs is checked to cover 72 h.
- P6. Build freeze: no preview rollout, image bump or gitops change to the
  server or the worker during the window. A rollout restarts the 72 h clock
  unless the owner waives it; the known rollout 503 gap (tg#1108) is counted as
  a rollout effect, not a defect of the soak.

### 3.2 Traffic source (decision D1)

Preview allows `MANAGED_RUNTIME_MAX_ACCOUNTS: "1"`, and the one managed account
is @mctlhq, which has `onlySenders` limited to a test sender, so it receives no
real inbound messages. Production owns the owner's real account, and only one
listener may serve a session. Real inbound traffic on preview therefore needs
one of these owner decisions:

1. Widen the audience of the managed account to chosen real senders (the
   audience is set before `listening: true`).
2. Raise `MANAGED_RUNTIME_MAX_ACCOUNTS` through a gitops PR and put a second
   account on managed.
3. Synthetic replay: a test sender posts fixtures at a realistic cadence
   (bursts of 3 or more, edits, deletes, media, injection attempts). This
   needs a written waiver of the "real-traffic account" wording of #889.

Without option 1 or 2, S-B cannot be a real-traffic soak and cannot close the
gate (3.7). Sending stays off in every option, the account stays in `observe`,
and every reply stays `pending_approval`.

### 3.3 Acceptance criteria (measured over the 72 h window)

Job statuses are those of `agent_jobs`: `pending`, `processing`, `completed`,
`failed`, `dead_letter`, `ignored`, `coalesced`, `routed`.

| # | Criterion | Pass condition | Source of evidence |
|---|---|---|---|
| 1 | Uptime and restarts | 0 OOMKilled, 0 crash restarts for the preview server pods and the pool worker; rollout restarts are excluded only if the owner waived the freeze. Report the highest sampled working set against the 256Mi worker limit (it is a sampled peak). | `kubectl get pod`, `lastState`, `kubectl top`, sampler |
| 2 | Session health | 0 `AUTH_KEY_*` or `unauthorized` revocations of the soak account. | server logs, sampler |
| 3 | Job outcomes | `dead_letter` = 0 for jobs created in the window (an explained dead letter still fails this criterion); no job `processing` with `claimed_at` older than the visibility timeout (5 min); every job with `attempts > 1` listed and explained; `routed` only for policy reasons, never `worker_unclaimed` (reason is on the outbox route, see `internal/db/event_outbox.go`). | `agent_jobs`, `event_outbox` |
| 4 | Concurrency and claim/lease | Never more than 1 concurrent claim globally (worker concurrency is 1) and never more than 1 per conversation. The two-concurrent-claims observation from #889 does not apply while concurrency is 1 and is reported as not applicable, not as passed. | `agent_job_attempts` overlap query |
| 5 | Coalescing | At least 3 coalesced turns, where a coalesced turn is a `turn_id` that groups 2 or more jobs (`coalesced` rows point to their head through `coalesced_into`). Fewer is INCONCLUSIVE. | `agent_jobs.turn_id`, `coalesced_into` |
| 6 | Isolation | A second account on `runtime: own` with `listening: true` is present for part of the window (it is the only way to make "not claimed" non-vacuous); its jobs stay `pending` with 0 attempts, no claim and no `agent_usage` row, and the pool worker claims nothing for it. 0 conversation-binding rejections outside tests; every rejection explained. | `agent_jobs.user_id`, `agent_usage`, server logs |
| 7 | Ledger | No `agent_usage` row older than the visibility timeout plus one sweep in a state other than `settled`; `mctl_agent_usage_held_usd` is 0 whenever no job is processing (it sums held rows of the current UTC day, so it is checked at idle moments only). | `agent_usage`, vmsingle |
| 8 | Cost | Cost per completed turn within 2x of the GLM-5.1 preview baseline ($0.0206 mean over 32 jobs, 2026-11-04); total within the window cap (D3). A ledger figure at list prices, not an invoice. | `agent_jobs.cost_usd` |
| 9 | Latency | p95 job latency at or below 60 s (baseline p95 34 s, max 55.8 s). Proposed threshold. | `agent_jobs` timestamps |
| 10 | Provider health | Rates of `error_provider_429`, `error_provider` and `error_provider_no_usage` reported; no run of 3 or more consecutive jobs failing for provider reasons. | job `last_error`, worker log |
| 11 | No sends | 0 actions with an executed Telegram message id; every `propose_reply` stays `pending_approval` or ends `expired`. | `agent_actions` |
| 12 | Budget behaviour | No unexplained `budget_paused_until`; a cap that is hit is recorded and the verdict says whether it was intended. | `mctl_agent_budget_*`, `agent_usage` |
| 13 | Observation integrity | The sampler has no gap longer than 15 minutes and the logs cover the whole window; a longer gap or a missing log segment makes every criterion that depends on it INCONCLUSIVE, never PASS. | sampler log |

Minimum traffic for a conclusive verdict: at least 3 coalesced turns (5) and at
least 30 completed turns (proposed, D5). `ignored` jobs do not count, because
owner-handled conversations are closed without invoking the model. Below the
minimum the verdict is INCONCLUSIVE and the gate stays open.

### 3.4 Observability and evidence

A read-only sampler runs every 5 minutes for the whole window (same method as
the 2026-10-31 soak): restart counts and last termination reason, `kubectl top
pod`, job status counts, `processing` rows past the visibility timeout, usage
rows not settled, and previous-container logs saved to a file whenever a
restart is seen. At the end the criteria are computed from `agent_jobs`,
`agent_job_attempts`, `agent_usage` and `agent_actions` (metadata only; drafts
are encrypted and are not read) and the metrics `mctl_agent_jobs_total`,
`mctl_agent_job_cost_usd_total`, `mctl_agent_usage_cost_usd_total`,
`mctl_agent_usage_held_usd`, `mctl_agent_budget_exhausted_total`,
`mctl_agent_budget_deferred_total`, `mctl_agent_managed_accounts`,
`mctl_agent_credential_domain`. The AI Gateway keeps no logs by design.

Result format: one comment on #889 with the table filled in, the build tags
from P1, the traffic source, any waiver, and the verdict (PASS, FAIL,
INCONCLUSIVE).

### 3.5 Stop conditions and rollback

Stop conditions:

- an executed Telegram message id on any action of the soak account;
- an `AUTH_KEY_*` or `unauthorized` revocation of the soak account;
- an OOMKill, or two crash restarts in 24 h;
- `dead_letter` greater than 0 for a job created in the window;
- a job of a different account claimed by the pool worker;
- spend above the window cap (D3) or an `agent_usage` row that never settles;
- the owner asks to stop.

Two levels of response. A targeted stop (spend, a single-account problem, an
auth revocation) is: set the account `listening: false` first so no new
message is ingested, then `paused: true`, then keep the runtime as it is; do not
close the whole pool (runbook, spend-storm mitigation). A full rollback (a
pool-level defect, a cross-account claim) follows the runbook section "Managed
runtime rollback" in order: account back to `runtime: own` (with
`listening: false`), worker `replicaCount: 0`, revoke the pool token, then
`MANAGED_RUNTIME_ENABLED: "false"`. After either, leave the second account
`own` with `listening: false`, sending off, and held replies unapproved.

The targeted stop and the full rollback are changes to preview, so they are
pre-authorised by the owner in D2 for the duration of the window; the agent
reports at once and does nothing beyond that list.

### 3.6 Owner approvals needed before the run (D)

- D1. Traffic source and account (3.2), including any waiver of "real traffic".
- D2. Switching that account to `runtime: managed` with consent, enabling
  `listening: true`, keeping sending off, bringing up the second `own`
  isolation account, and pre-authorising the stop and rollback actions in 3.5.
- D3. Window caps. Baseline cost is $0.0206 per completed turn, so $6 over 72 h
  is about 290 completed turns, 1.4x a 70-jobs-per-day guess (the 70 has no
  source; use the observed volume of the first 24 h to confirm). Only per-account
  day (1.00 now, 3.00 if raised), per-account month (15.00) and global day
  (5.00) caps are enforceable in config; the 72 h total is a sampler stop
  condition. Raising the day cap is a mctl-gitops PR, and so is reverting it
  after the window.
- D4. Keeping the worker on GLM-5.1 / Nebius for the window (already decided).
- D5. The thresholds proposed here (latency 60 s, cost 2x, 30 completed turns,
  15-minute sampler gap).
- D6. Whether production observe numbers are accepted as supplementary evidence
  for the conversation plane (section 2).
- D7. Minting or rotating the pool token or scaling the worker, if either is
  needed at start; a test sender posting fixtures (option 3 of 3.2); starting the
  sampler against the preview database.

Not part of this plan and needing a separate approval whenever they come up:
Cloudflare apply, Vault writes, production deploys, production flag changes,
any change of listening or sending outside D2.

### 3.7 GO / NO-GO for the gate

GO to close #889 for the managed runtime only if all of these hold:

- S-B is PASS on real traffic (option 1 or 2 of 3.2), or the owner recorded a
  waiver of the real-traffic wording for synthetic replay (option 3), and the
  report says which;
- the minimum traffic in 3.3 is met and criterion 13 holds;
- P1 is confirmed and P6 was respected;
- no stop condition fired;
- S-A is posted, with its INCONCLUSIVE verdict and D6 recorded if it is.

An inconclusive S-A or S-B never counts as a pass. A GO on #889 does not
enable production; that is a separate owner decision after #334 is closed.
NO-GO or INCONCLUSIVE keeps the gate open; extend or repeat S-B.

### 3.8 Risks

- Real traffic on preview is probably absent without D1 option 1 or 2. This is
  the same cause that starved the 2026-10-31 soak (#1012 and the contacts
  exclusion).
- The Nebius rate limit is unmeasured; a provider 429 storm would look like an
  application defect. Criterion 10 separates them.
- A real-traffic account on managed sends third-party message text to the model
  provider. Consent text `managed-data-flow/v1` applies; D2 covers that
  account only.
- Self-update restarts and rollouts can be mistaken for crashes; P6 and
  criterion 1 handle them.
- Old data in `agent_jobs` (for example earlier `dead_letter` rows) must be
  excluded by window; every query filters on `created_at`.
