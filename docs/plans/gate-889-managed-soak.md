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

Read-only. Post the result in #889 using the criteria table in section 4,
restricted to `agent_jobs` with id > 11903 and the window above. Required
statements: pod restarts and OOM, worker RSS from the worker host sampler log,
`dead_letter`, routing reasons, stale claims, concurrency, coalesced bursts,
cost per completed turn against the baseline ($0.0123 mean, $0.0107 median,
668 jobs as 667 turns, 2026-10-19 to 2026-10-23), and a note that #1012 and the
contacts audience exclusion cut traffic during the window. Expected verdict,
per the interim result: stability PASS, outcomes INCONCLUSIVE. Production
observe traffic from 2026-11-01 can supply the missing bursts and turns; say so
explicitly and label those numbers as production, not soak.

## 3. S-B: managed-runtime 72 h soak

### 3.1 Preconditions (P)

- P1. Verify #885 and #886 in the deployed build: find the merge commits, check
  they are ancestors of the preview server image tag and of the pool worker
  image (`git merge-base --is-ancestor`), and record both tags.
- P2. Preview server and pool worker run the same release lineage; the worker
  is on GLM-5.1 via Nebius (`labs/agent-worker-managed-preview`, 1 replica).
- P3. A traffic source is chosen (decision D1 below).
- P4. Caps for the window are set and recorded (decision D3).
- P5. The evidence sampler (3.4) is running and has produced a baseline sample.

### 3.2 Traffic source (decision D1)

A real-traffic account must be the only listener on its Telegram session, so it
cannot be an account that production already listens on. Options:

1. A preview account that receives real inbound messages, switched to
   `runtime: managed` with consent, `listening: true`, sending off, and
   `onlySenders` / audience set explicitly (set the audience before listening).
2. Scheduled replay: a test sender posts fixture messages at a realistic
   cadence (bursts of 3 or more, edits, deletes, media, injection attempts).
   The result is labelled a synthetic-traffic soak, not real traffic.

Either way sending stays off and every reply stays `pending_approval`.

### 3.3 Acceptance criteria (all measured over the 72 h window)

| # | Criterion | Pass condition | Source of evidence |
|---|---|---|---|
| 1 | Uptime and restarts | 0 OOMKilled, 0 crash restarts for the preview server pods and the pool worker; self-update restarts counted separately. Worker peak working set reported against its 256Mi limit. | `kubectl get pod`, `lastState`, `kubectl top`, sampler |
| 2 | Session health | 0 `AUTH_KEY_*` or `unauthorized` revocations of the soak account; session pool sticky routing unchanged. | server logs, `accounts` state |
| 3 | Job outcomes | `dead_letter` = 0; no job `claimed` past the visibility timeout; `attempts > 1` rows each explained; routed only for policy reasons, never `worker_unclaimed`. | `agent_jobs` |
| 4 | Concurrency and claim/lease | Never more than the configured worker concurrency globally and never more than 1 per conversation; at least one observed moment of concurrent claims on different conversations (if concurrency > 1). | `agent_job_attempts` overlap query |
| 5 | Coalescing | At least 3 coalesced bursts, otherwise the run is reported inconclusive, not passed. | `agent_jobs` status `coalesced` |
| 6 | Isolation | 0 conversation-binding rejections outside tests; every rejection explained; no job of another account claimed by the pool worker. | server logs, `agent_jobs.user_id` |
| 7 | Ledger | Every `agent_usage` row `settled`; 0 held rows older than visibility timeout plus one sweep; `mctl_agent_usage_held_usd` returns to 0 between jobs. | `agent_usage`, vmsingle |
| 8 | Cost | Cost per completed turn within 2x of the GLM-5.1 preview baseline ($0.0206 mean, 32 jobs, 2026-11-04); total within the window cap (D3). Report at list prices and say it is a ledger figure, not an invoice. | `agent_jobs.cost_usd` |
| 9 | Latency | p95 job latency at or below 60 s (baseline p95 34 s, max 55.8 s). Threshold is proposed, owner may change it. | `agent_jobs` timestamps |
| 10 | Provider health | `error_provider_429` and provider 5xx rates reported; no sustained run (3 or more consecutive jobs) failing for provider reasons. | job `last_error`, worker log |
| 11 | No sends | 0 actions with an executed Telegram message id; every `propose_reply` stays `pending_approval` or ends `expired`. | `agent_actions` |
| 12 | Budget behaviour | No unexplained `budget_paused_until`; if a cap is hit, it is hit on purpose and recorded. | `mctl_agent_budget_*`, `agent_usage` |

Minimum traffic: at least 3 coalesced bursts and at least 100 jobs, otherwise
the verdict is INCONCLUSIVE, which keeps the gate open.

### 3.4 Observability and evidence

A read-only sampler runs every 5 minutes for the whole window (same method as
the 2026-10-31 soak): `kubectl get pod` restart counts and last termination
reason, `kubectl top pod`, job status counts, claims older than the visibility
timeout, held usage rows, and the worker host `ps` RSS where relevant. At the
end, the criteria are computed from `agent_jobs`, `agent_job_attempts`,
`agent_usage`, `agent_actions` (metadata only; drafts are encrypted and are not
read) and the metrics `mctl_agent_jobs_total`, `mctl_agent_job_cost_usd_total`,
`mctl_agent_usage_cost_usd_total`, `mctl_agent_usage_held_usd`,
`mctl_agent_budget_exhausted_total`, `mctl_agent_budget_deferred_total`,
`mctl_agent_managed_accounts`, `mctl_agent_credential_domain`. The AI Gateway
keeps no logs by design, so there are no gateway logs to cite.

Result format: one comment on #889 with the table above filled in, the build
tags from P1, the traffic source, and the verdict (PASS, FAIL, INCONCLUSIVE).

### 3.5 Stop conditions

Stop the soak and roll back if any of these happens:

- an executed Telegram message id appears on any action of the soak account;
- an `AUTH_KEY_*` or `unauthorized` revocation of the soak account;
- an OOMKill, or two crash restarts in 24 h;
- `dead_letter` greater than 0 that is not explained by the first retry cycle;
- a job of a different account claimed by the pool worker;
- spend above the window cap (D3), or a held ledger row that never settles;
- the owner asks to stop.

Rollback follows the runbook section "Managed runtime rollback", in order:
account back to `runtime: own`, worker `replicaCount: 0`, revoke the pool
token, then `MANAGED_RUNTIME_ENABLED: "false"`. Then set the account
`listening: false` and leave held replies unapproved.

### 3.6 Actions that need owner approval before the run (D)

- D1. Traffic source and the account to use (3.2).
- D2. Switching that account to `runtime: managed`, enabling consent, setting
  `listening: true`, and leaving sending off.
- D3. Window caps: proposed total spend cap $6 for 72 h (about 4x the expected
  $1.5 at 70 jobs per day), per-account day budget 3.00 for the window and
  1.00 afterwards, per-job 0.25 unchanged. Raising a cap is a gitops change.
- D4. Keeping the worker on GLM-5.1 / Nebius for the window (already decided).
- D5. Verdict thresholds in 3.3 that were proposed here (latency 60 s, cost 2x,
  100 jobs minimum).

Not needed and not done: Cloudflare apply, Vault writes, production changes.

### 3.7 GO / NO-GO for the gate

GO to close #889 for the managed runtime only if S-A is posted, S-B is PASS
with the minimum traffic met, P1 is confirmed, and no stop condition fired. A
GO on #889 does not enable production. That is a separate owner decision after
#334 is also closed.
NO-GO or INCONCLUSIVE keeps the gate open; extend or repeat S-B.

### 3.8 Risks

- Real traffic volume may be too low for 3 bursts (the 2026-10-31 soak was).
  Mitigation: replay fixtures in addition, and label them.
- The Nebius rate limit is unmeasured; a provider 429 storm would look like an
  application defect. Mitigation: criterion 10 separates them.
- A real-traffic account on managed sends third-party message text to the
  model provider. Consent text `managed-data-flow/v1` applies; owner approval D2
  covers it for that account only.
- Self-update restarts of the worker can be mistaken for crashes. Count them
  separately.
