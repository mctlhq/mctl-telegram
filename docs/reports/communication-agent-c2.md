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
| 3 | Per-job budget remains configured; monthly budget and rate-limit alerts are tested | Per-job cap 0.25 on preview. Alert rules: draft PRs, unmerged. Fire-and-resolve test not run (W7, D4). Production budgets undecided (W6, D3) | | owner, W2, W6, W7 | no |
| 4 | Revocation and rotation documented and exercised without exposing the credential | Documented: `docs/runbook.md`, "Managed runtime: model and gateway credential rotation". Not exercised (W8, D5) | | owner, W8 | no |
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
| Per account per month, `MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH` | 15.00 | undecided (D3) |
| Global per UTC day, `MANAGED_BUDGET_USD_GLOBAL_DAY` | 5.00 | undecided (D3) |
| Global per month | does not exist | undecided: bounded only by the global day cap times 30 and by a provider-side alert |

## Alert evidence

For each alert: the condition exercised, the time it fired, the time it resolved,
the channel that received it and the delivery time against the stated maximum.
An alert that exists in a rules file but reaches nobody does not count.

Not run yet.

## Rotation drill

The times of key creation and revocation, the Vault version numbers, the
controlled job, and proof that the old key fails.

Not run yet.

## Independence drill

Row 5(a), static proof: not yet recorded for a production worker. Row 5(b), a
real occurrence of an exhausted review pool: none recorded. Row 5(c), the
measured neighbour test: not run, deferred.

## Disclosure

On 2026-11-04 one read of the preview Secret used `-o json`, so its `data` was
fetched into a local pipe. Only metadata keys were printed; nothing was displayed,
logged or stored. See `docs/plans/gate-334-readonly-checks.md`. The owner may
treat this as a reason to rotate during the drill.
