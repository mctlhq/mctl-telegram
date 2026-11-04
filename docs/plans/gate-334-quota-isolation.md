# Gate #334: production quota isolation for the agent worker

Status: draft plan, 2026-11-04. Nothing here has been executed. Issue #334
stays open and the gate is not lifted by this document. Related: #889
(`gate-889-managed-soak.md`), #1088, ADR 0008, `communication-agent.md`.

## 1. Why the requirements need a reading for the managed runtime

#334 was written for the Option C worker that shells out to `claude -p`. Its
failure story is a shared Claude credential pool used by interactive sessions
and `claude-review.yml`. The managed runtime (ADR 0008) does not use Claude at
all: the pool worker `labs/agent-worker-managed-preview` calls GLM-5.1 on
Nebius through the Cloudflare AI Gateway `mctl-telegram` with a dedicated key.
The invariants of #334 still hold and stay mandatory:

1. a credential and quota domain of its own, not shared with anything else that
   spends money or hits a rate limit;
2. the credential lives only in Vault and is mounted only into the worker pod;
3. a per-job budget, a monthly budget and rate-limit controls, with tested
   alerts;
4. a documented rotation and revocation procedure that has been exercised;
5. proof that the worker keeps working when other pools are exhausted, and the
   reverse;
6. evidence recorded with a non-secret domain identifier;
7. a go/no-go check that names this issue before production promotion.

What changes is the wording of the evidence. "The interactive or review pool is
unavailable" cannot be produced on demand against a third-party pool, and for
Nebius the relevant neighbours are other Nebius consumers (for example the
support agent pilot, which also uses GLM-5.1 on Nebius with its own Vault key),
not Claude Code.

## 2. Gap matrix

| # | Requirement (#334 acceptance) | Current evidence | Gap | Proposed verification |
|---|---|---|---|---|
| 1 | Credential belongs to a quota domain not used by interactive Claude Code or `claude-review.yml` | Managed path has no Anthropic dependency. Dedicated key at `secret/platform/labs/agent-worker-managed-preview/openai-nebius`; `AGENT_CREDENTIAL_DOMAIN_ID` is set to that path and exported as `mctl_agent_credential_domain`. | Separate Vault path is not separate quota. Whether the Nebius project or key is shared with other Nebius consumers (the support pilot uses a different Vault key) is unknown from the repo. A Cloudflare gateway token is shared across providers (auth only, not quota). | Owner confirms in the Nebius console which project each key belongs to and its rate limits; record non-secret project ids. If shared, decision D2. |
| 2 | Credential only in Vault, mounted only into the worker pod | ExternalSecret `labs-agent-worker-managed-preview-openai` reads the Vault path above; one consuming Deployment. | Not proven that the Secret is not reflected into other namespaces (a past incident reflected a different PAT everywhere) or readable by other Vault roles. | `kubectl get secret` annotations and a search of all namespaces for the name; Vault policy listing for readers of the path (owner-assisted login). |
| 3a | Per-job budget configured | `AGENT_MAX_BUDGET_USD: "0.25"`, server `MANAGED_MAX_JOB_COST_USD` 0.25, reservation at claim, settle at completion. | None for configuration. | Existing store tests; link them in the C2 report. |
| 3b | Monthly budget configured | `MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH` default 15.00, per-account day and global day caps. | Caps exist only on preview. Production has no `MANAGED_*` values, so the production numbers are undecided. | Decision D3; set them in gitops with the rollout PR, not before. |
| 3c | Budget and rate-limit alerts tested | Metrics exist: `mctl_agent_budget_exhausted_total`, `mctl_agent_budget_deferred_total`, `mctl_agent_usage_held_usd`, `mctl_agent_managed_accounts`. Existing alerts: `MctlAgentClaudeUsageLimit` (class `usage_limit` of the Claude result metric), `MctlAgentJobCostHigh`, `MctlAgentDeadLetter`. | No alert on budget exhaustion, held ledger rows, or provider 429 for the OpenAI runner. The Claude usage-limit alert does not cover `error_provider_429`. Provider-side budget alerts at Nebius are unverified. | New rules with promtool unit tests (exhausted, held rows stuck, 429 rate), recipient and delivery time stated, plus one fire-and-resolve test in preview (D4). Owner confirms any Nebius billing alert. |
| 4 | Rotation and revocation documented and exercised | Rollback order in the runbook revokes the pool token. Credential rotation section is Claude-specific. | No managed-runtime procedure for rotating the Nebius key or the gateway token. Never exercised. | Write the procedure; exercise on preview: new key to Vault, ExternalSecret refresh, worker restart, controlled job, old key revoked at Nebius, confirm the old key fails. Needs Vault write and a Nebius console action (D5). |
| 5 | Controlled invocation while the other pool is unavailable | Independent by construction (no shared dependency). | Not demonstrated. A forced outage of a third-party pool is not possible. | Replace by (a) static proof: the worker image and env contain no Anthropic or Claude variables and the pod has no route need for them; (b) reverse drill: a managed job completes while `claude-review.yml` is rate-limited or credential-less, using a real occurrence or a repository-level check run; (c) Nebius-side exhaustion shown by a low per-key limit on preview if the owner can set one. Amendment proposed (section 3). |
| 6 | C1-style evidence with non-secret identifiers | Results are in #1088 comments; `docs/reports/communication-agent-c1.md` is Claude-era. | No C2 report for the managed runtime. | Create `docs/reports/communication-agent-c2.md` (or a managed-runtime report) with domain id, caps, alert evidence, drill results and a `Go/no-go` line. |
| 7 | Explicit go/no-go referencing #334 | Runbook activation steps A1 to A6 do not mention the gates. | No enforced check. | Add a step 0 to the runbook activation section that requires #334 and #889 closed and the C2 report with `Go/no-go: go`; add a docs test marker. |

Proposal 334 in mctl-gitops (`issue-334-c2-gate-isolate-production-communication`)
has status `proposed`. Several of its tasks appear already present in main
(credential domain id, per-job cost metric, usage-limit class and alert). Before
anyone flips it to `accepted`, reconcile its task list with the matrix above to
avoid duplicate work and to drop Claude-only tasks.

## 3. Proposed amendment to the issue wording

Do not edit or close the issue from this plan. Propose, via a PR that changes
`docs/plans/communication-agent.md` Rollout gate 2 and the new C2 report, that
the acceptance criteria read for any worker runtime:

- "quota domain not used by interactive Claude Code or `claude-review.yml`"
  becomes "a quota domain of its own, shared with no other consumer that spends
  money or has a rate limit; sharing is shown to be absent in the provider
  console";
- "controlled invocation succeeds while the interactive or review pool is
  unavailable" becomes the three checks in matrix row 5;
- "monthly budget and rate-limit alerts are tested" additionally names the
  managed ledger metrics and the provider 429 rate;
- the Claude-specific rotation procedure is kept for the Claude runner and a
  managed one is added.

The owner decides whether this amendment is accepted. Until then the original
text is the gate.

## 4. Work plan

| Step | Work | Needs owner approval | Depends on |
|---|---|---|---|
| W1 | Reconcile the gitops proposal with the matrix | No | none |
| W2 | Alert rules and promtool tests for rows 3c | No (PR, review) | W1 |
| W3 | Managed rotation and revocation procedure in the runbook | No (PR) | none |
| W4 | Static proofs: secret reflection, readers of the Vault path, no Anthropic env in the worker | No for kubectl reads; Vault policy read needs login (D5) | none |
| W5 | Nebius project and limits confirmation, billing alert at Nebius | Yes (D2, owner console) | none |
| W6 | Production budget numbers | Yes (D3) | W5 |
| W7 | Alert fire-and-resolve test on preview | Yes (D4): lowers a cap temporarily via gitops | W2, W6 |
| W8 | Rotation drill on preview | Yes (D5): Vault write, Nebius console | W3, W5 |
| W9 | Reverse-direction drill | Yes if it needs a deliberate rate limit | W5 |
| W10 | C2 report with go/no-go and runbook step 0 | No (PR) | W2 to W9 |

No Cloudflare apply, Vault write, account switch, listening or sending change,
production deploy or flag change happens without a separate owner approval.

## 5. GO / NO-GO

GO for closing #334 only if every row of the matrix is either closed with
evidence or covered by an owner-accepted amendment, the C2 report carries
`Go/no-go: go`, and #889 is also closed. A GO here does not enable production.
NO-GO if the Nebius quota is shared with another consumer and no separate key or
project is provisioned, if the rotation drill fails, or if any alert test does
not fire within the stated delivery time.

## 6. Risks

- A shared Nebius project would let the support agent exhaust the managed
  runtime quota, which is the exact failure #334 exists to prevent.
- A key in one Vault path that several roles can read breaks row 2 even though
  the pod mount is correct.
- Alerts that exist in the rules file but route nowhere. Each test must show the
  receiving channel.
- The free promotional credit used by other agents expires 2026-11-11; do not
  confuse that budget with the managed runtime budget.

## 7. Decisions for the owner

- D2. Is the Nebius key for the managed runtime in its own Nebius project, and
  if not, will one be created.
- D3. Production budget numbers (day, month, global).
- D4. Permission to lower a cap temporarily on preview for the alert test.
- D5. Permission for the rotation drill (Vault write, Nebius console) and for a
  Vault policy read.
- D6. Accept or reject the amendment in section 3.
