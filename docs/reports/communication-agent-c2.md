# Communication Agent C2 go/no-go report

The durable evidence log for mctlhq/mctl-telegram#334, the production quota
isolation gate. Plan: `docs/plans/gate-334-quota-isolation.md` (PR #1121).

Do not copy Telegram message bodies, credentials, key fragments, Vault values
or raw console screenshots into this file. Identifiers recorded here are
non-secret. Testers, if any, are "tester 1..N".

Go/no-go: no-go

The line above stays `no-go` until every row of the table below has passed for
the production credential, or is covered by an owner-accepted amendment recorded
on #334. Only the owner changes it. A `go` here closes nothing by itself and
enables nothing: production activation also needs #889 closed and a recorded
PASS of its Part B soak (`docs/runbook.md`, "Managed runtime activation", step 0).

Status as of 2026-11-04: nothing in this table has passed. **No production
worker or production credential exists yet**, and the evidence below is for
the preview worker `labs/agent-worker-managed-preview`.

## Acceptance table

The criteria are the seven of #334, as the issue words them. The issue text is
the gate until the owner accepts an amendment (decision D6). A date and a
`yes` are filled in only with evidence that was actually observed.

| # | Criterion (#334) | Evidence | Date | Owner | Passed |
|---|---|---|---|---|---|
| 1 | Worker credential belongs to a quota domain not used by interactive Claude Code or `claude-review.yml` | Preview: no Anthropic dependency, dedicated Vault path. Separate path is not separate quota: Nebius project and limit scope unread (W5). Production credential: none | | owner, W5 | no |
| 2 | Credential stored only in Vault and mounted only into the worker pod | Preview, 2026-11-04: Secret only in `labs`, one consuming pod. Vault readers unread (W4, D5) | | agent and owner, W4 | no |
| 3 | Per-job budget remains configured; monthly budget and rate-limit alerts are tested | Per-job cap 0.25 on preview. Alert rules merged (gitops#2396), routed to the operator (gitops#2398). Route delivery and resolve observed; a real rule firing not yet (W7, see Alert evidence). Production budgets undecided (W6, D3) | | owner, W2, W6, W7 | no |
| 4 | Revocation and rotation documented and exercised without exposing the credential | Documented: `docs/runbook.md`, "Managed runtime: model and gateway credential rotation". Exercised on preview, 2026-11-09 (section "Rotation drill"): new key live in the worker, controlled jobs 12208 and 12209 settled, old key refused. Open: the old key was still accepted at least 32 minutes after the console deletion time the owner read, so revocation latency is not established | 2026-11-09 | owner, W8 | yes, with the latency note |
| 5 | A controlled invocation succeeds while the interactive or review pool is unavailable or independently rate-limited | Not run. Row 5(b) and 5(c) deferred until the support pilot ends, 2026-11-11, and then only on owner command (W9, D7) | | owner, W9 | no |
| 6 | C1-style evidence records the credential domain, budget controls, alert evidence and drill result | This report; every section below is still empty | | agent, W10 | no |
| 7 | Production promotion has an explicit go/no-go check referencing #334 | `docs/runbook.md` step 0 and the line at the top of this report | | agent, W10 | no |

Row 7 is marked `no` until this report is merged and the owner has accepted the
check.

## Credential domain

| Fact | Value | Who read it | Date |
|---|---|---|---|
| Non-secret domain identifier, preview | `platform/labs/agent-worker-managed-preview/openai-nebius` (a Vault path label, `AGENT_CREDENTIAL_DOMAIN_ID`; not a Nebius quota-domain id) | values file | 2026-11-04 |
| Non-secret domain identifier, production | none yet | | |
| Nebius project id, managed key | | | |
| Nebius project id, support key | | | |
| Same project | | | |
| Limit scope (key, project, organisation) | | | |
| RPM and TPM for GLM-5.1 | | | |
| Budget or alert at Nebius, and recipient | | | |
| Gateway rate limits, `mctl-telegram` | | | |

## Budget controls

| Control | Preview | Production |
|---|---|---|
| Per job, `MANAGED_MAX_JOB_COST_USD` and `AGENT_MAX_BUDGET_USD` | 0.25 | undecided (D3) |
| Per account per UTC day, `MANAGED_BUDGET_USD_PER_ACCOUNT_DAY` | 1.00 | undecided (D3) |
| Per account per month, `MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH` | 15.00 (code default; not set in the preview values) | undecided (D3) |
| Global per UTC day, `MANAGED_BUDGET_USD_GLOBAL_DAY` | 5.00 | undecided (D3) |
| Global per month | does not exist | undecided: bounded only by the global day cap times 30 and by a provider-side alert |

## Alert evidence

For each alert: the condition exercised, the time it fired, the time it resolved,
the channel that received it and the delivery time against the stated maximum.
An alert that exists in a rules file but reaches nobody does not count.

Route and delivery test, preview, 2026-11-04. Four synthetic alerts, labelled as a
delivery test, were posted to the Alertmanager API, one per alert name. This
proves routing and delivery only: the rules' expressions are covered by promtool
tests in CI and have not yet fired on a real condition.

| Alert | Receivers read back | Posted | Resolved posted |
|---|---|---|---|
| `MctlAgentManagedAccountMonthCapHit` | `telegram`, `mctl-agent-paged` | 23:17:38Z | 23:24:41Z |
| `MctlAgentManagedBudgetDeferredSustained` | `telegram`, `mctl-agent-paged` | 23:17:38Z | 23:24:41Z |
| `MctlAgentManagedUsageHeld` | `telegram`, `mctl-agent-paged` | 23:17:38Z | 23:24:41Z |
| `MctlAgentProviderRateLimitHigh` | `telegram`, `mctl-agent-paged` | 23:17:38Z | 23:24:41Z |

`alertmanager_notifications_total{integration="telegram"}` went from 150 to 154
within 46 seconds of posting and to 158 within 6 minutes of resolving, with every
`alertmanager_notifications_failed_total{integration="telegram"}` at 0.
The counter is not per alert, so the message text in the channel is the owner's
to confirm.

Still to do: one real firing through a temporarily lowered preview cap, with the
cap restored before the #889 window. It needs a pending managed job, so it follows
listening on the managed account.

## Rotation drill

Preview only, 2026-11-09, W8 of the plan, under owner decision D5. The credential
is the Nebius model key of `labs/agent-worker-managed-preview`, Vault path
`secret/platform/labs/agent-worker-managed-preview/openai-nebius`, property
`token`. No key value and no key fragment is recorded here. The new key was
moved from the owner's clipboard into Vault and the Keychain through a pipe, and
checked only through Vault metadata, Kubernetes status fields and HTTP status
codes.

| Step | What happened | Time (UTC) |
|---|---|---|
| 1. New key in the same Nebius project | Created by the owner, named `managed runtime`. The console listed it as created about an hour before the check; the exact minute was not recorded | before 12:00:19Z |
| 2. Vault write | Version 2 written from the clipboard. Version 1 had been written 2026-11-04T01:34:58Z | 12:00:19Z |
| 3. Vault check | `vault kv metadata get`: `current_version` 2, `oldest_version` 0 | 12:00Z |
| 4. ExternalSecret | `labs-agent-worker-managed-preview-openai` forced to refresh: `SecretSynced`, synced resource version changed | 12:01:10Z |
| 5. Worker rolled | `rollout restart`, Ready in 26 s (image `main-d0f0b5d`) | 12:01:46Z to 12:02:12Z |
| 6. Controlled job on the new key | Tester 1 sent one message. Job 12208: `completed` on the first attempt, lead 272 linked, `agent_usage` `settled`, 23537 input and 5846 output tokens, 0.00645 USD | sent 12:28:20Z, settled 12:29:46Z |
| 7. Old key deleted | Row `test` (created 2026-11-04) deleted by the owner. The time is the one the owner read in the console: 13:05 local, UTC+1, that is 12:05Z. It is not confirmed by an audit log entry; none was available | 12:05Z (owner, console) |
| 8a. Old key refused | The owner ran a script that reads Vault version 1 into a pipe and prints only the HTTP status of a models call. The first run returned 200 (it was expected to be a before-deletion check). A later run returned 401 | 200 observed after 12:37:57Z; 401 observed before 12:59Z; exact minutes not recorded |
| 8b. Controlled job after the old key was refused | Job 12209: `completed` on the first attempt, lead 272 linked, `agent_usage` `settled`, 24498 input and 2792 output tokens, 0.0050707 USD | sent 12:59:45Z, settled 13:00:10Z |

Identification of the old key. Vault version 1 cannot be read by the agent, so
the console row was matched by evidence: it was the only key created on
2026-11-04, the day version 1 was written. The strong confirmation is the
status flip: the version 1 key answered 200 and then 401 around the deletion,
and the new key kept answering 200. Other keys in the project (other services)
were not touched and still answer 200.

Revocation latency, an open finding. The script that returned 200 was written at
12:37:57Z, so that 200 was observed after the deletion time the owner read in the
console (12:05Z): the deleted key was still accepted for at least 32 minutes.
There are two readings and the evidence does not separate them: either Nebius
applies a key deletion with a delay of at least half an hour, or the console time
was misread or is not in UTC+1. The 200 was labelled "before deletion" when the
script was handed over, which is why the owner and the agent noticed the
mismatch only afterwards. To settle it: the Nebius audit log entry for the
deletion (not available in the console view used), or a repeat of the drill with
a timestamped call before and every minute after the deletion. Until then this
row states that the old key was refused after a delay, not that revocation is
immediate. For a suspected leak the runbook's ordering (revoke first, expect a
window) must assume that delay.

Result for #334 row 4: the procedure was exercised end to end on preview and the
new key carries traffic; the old key no longer works. It is not shown that
revocation is immediate.

## Independence drill

Row 5(a), static proof: not yet recorded for a production worker. Row 5(b), a
real occurrence of an exhausted review pool: none recorded. Row 5(c), the
measured neighbour test: not run, deferred.

## Disclosure

On 2026-11-04 one read of the preview Secret used `-o json`, so its `data` was
fetched into a local pipe. Only metadata keys were printed; nothing was displayed,
logged or stored. See `docs/plans/gate-334-readonly-checks.md`. The owner may
treat this as a reason to rotate during the drill.

On 2026-11-09, during the rotation drill, the owner shared two screenshots of the
Nebius API keys page in the agent session. The console masks the middle of each
key but shows its beginning and end, so a short fragment of the then-live key
`managed runtime` and of the other keys appeared in the session transcript. The
old worker key was deleted afterwards; the other fragments belong to keys of
other services. Nothing from the screenshots is recorded here. The agent also
compared Keychain values with the console fragments locally and printed only the
row names. The owner may treat the screenshots as a reason to rotate `managed
runtime` again at the next planned rotation.
