# Gate #334: production quota isolation for the agent worker

Status: PLANNED, NOT APPROVED FOR EXECUTION (2026-11-04). Only the read-only
Kubernetes checks in `gate-334-readonly-checks.md` have been run. Issue #334
stays open and its acceptance criteria are not changed by this document.
Related: #889 (`gate-889-managed-soak.md`), #1088, ADR 0008,
`communication-agent.md`.

Closure rule: #334 closes on its own evidence. It does not wait for #889 and
#889 does not wait for it. Production GO for the managed runtime needs both
closed (and the #889 Part B soak), as a separate owner decision.

## 1. Why the requirements need a reading for the managed runtime

#334 was written for the Option C worker that shells out to `claude -p`. Its
failure story is a shared Claude credential pool used by interactive sessions
and `claude-review.yml`. The managed runtime (ADR 0008) does not use Claude at
all: the pool worker `labs/agent-worker-managed-preview` calls GLM-5.1 on
Nebius through the Cloudflare AI Gateway `mctl-telegram` with a dedicated key.
The list below is a paraphrase of the seven acceptance criteria of #334, in some
places stricter than the issue text. The issue text is the gate until the owner
accepts a change (section 3). The invariants stay mandatory:

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
| 1 | Credential belongs to a quota domain not used by interactive Claude Code or `claude-review.yml` | Managed path has no Anthropic dependency. Dedicated key at `secret/platform/labs/agent-worker-managed-preview/openai-nebius`; `AGENT_CREDENTIAL_DOMAIN_ID` is set to that Vault path label (a label, not a Nebius quota-domain id) and exported as `mctl_agent_credential_domain`; the criterion-6 identifier should become the Nebius project id once D2 provides it. | All of this evidence is for the preview worker; no production worker or production credential exists yet, so a production credential domain is a separate artifact still to be provisioned and evidenced. Separate Vault path is not separate quota. Whether the Nebius project or key is shared with other Nebius consumers (the support pilot uses a different Vault key) is unknown from the repo. A Cloudflare gateway token is shared across providers (auth only, not quota). | Owner confirms in the Nebius console which project each key belongs to and its rate limits; record non-secret project ids and the limit scope (key, project or organization). The AI Gateway account is also shared with the support agent, so record gateway-level limits too. The values file says the Nebius limit was not measured. If shared, decision D2. |
| 2 | Credential only in Vault, mounted only into the worker pod | ExternalSecret `labs-agent-worker-managed-preview-openai` reads the Vault path above. Read-only kubectl on 2026-11-04: the Secret exists only in `labs`, is not reflected, is referenced by one pod, the worker has no `ANTHROPIC` or `CLAUDE` variable and its `envFrom` is three Secrets (`-api`, `-openai`, `-gateway`). | The cluster has one ClusterSecretStore, `vault-backend`, with the Vault role `external-secrets`. Whether that role (or any human or CI role) can read the managed path, for example through a `platform/*` wildcard, is unknown. | Vault checks in `gate-334-readonly-checks.md` section 2 (owner login, metadata and policy reads only, covering every auth mount, identity group and entity, and cluster-side ClusterExternalSecret, PushSecret and SecretStore objects; so far only ExternalSecrets were listed). |
| 3a | Per-job budget configured | `AGENT_MAX_BUDGET_USD: "0.25"`, server `MANAGED_MAX_JOB_COST_USD` 0.25, reservation at claim, settle at completion. | None for configuration. | Existing store tests; link them in the C2 report. |
| 3b | Monthly budget configured | `MANAGED_BUDGET_USD_PER_ACCOUNT_MONTH` default 15.00, per-account day and global day caps. | Caps exist only on preview. Production has no `MANAGED_*` values, so the production numbers are undecided. The server has per-account day, per-account month and global day caps only; there is no global monthly cap, so cross-account monthly spend is bounded only by the global day cap times 30 and by a provider-side billing alert. | Decision D3; set them in gitops with the rollout PR, not before. |
| 3c | Budget and rate-limit alerts tested | Metrics exist: `mctl_agent_budget_exhausted_total`, `mctl_agent_budget_deferred_total`, `mctl_agent_usage_held_usd`, `mctl_agent_managed_accounts`. Existing alerts: `MctlAgentClaudeUsageLimit` (class `usage_limit` of the Claude result metric), `MctlAgentJobCostHigh`, `MctlAgentDeadLetter`. | Deployed in mctl-gitops (`vm-rules/mctl-telegram-ops.yaml`): `MctlAgentManagedGlobalCapHit` (global day scope), `MctlAgentManagedSpendHigh` (OpenAI runner spend per hour) and `MctlAgentManagedPoolWorkerDown`. `error_provider_429` already maps to class `usage_limit`, so `MctlAgentClaudeUsageLimit` fires when the provider retry loop is exhausted, but its text and runbook are Claude-worded and it is a presence test, not a rate. Remaining gaps: no alert for the `account_day` and `account_month` scopes (deliberately omitted today), `budget_deferred_total`, `usage_held_usd` or `usage_held_rows`; no rate-based 429 alert; Nebius-side billing alert unverified. The repo file `deploy/alerts/mctl-telegram.rules.yaml` is a mirror that is already out of date: it lacks the three managed alerts above. The deployed copy lives in mctl-gitops. | Decide which missing alerts are required (D3); add them in the mirror and in a mctl-gitops PR, reword the usage-limit alert and runbook for provider 429, add promtool unit tests, state recipient and maximum delivery time, then one fire-and-resolve test on preview (D4). Owner confirms any Nebius billing alert. |
| 4 | Rotation and revocation documented and exercised | Rollback order in the runbook revokes the pool token. Credential rotation section is Claude-specific. | No managed-runtime procedure for rotating the Nebius key or the gateway token. Never exercised. | Write the procedure; exercise on preview: new key to Vault, ExternalSecret refresh, worker restart, controlled job, old key revoked at Nebius, confirm the old key fails. Needs Vault write and a Nebius console action (D5). |
| 5 | Controlled invocation while the other pool is unavailable | Independent by construction (no shared dependency). | Not demonstrated. A forced outage of a third-party pool is not possible. | All three are required, none optional. (a) Static proof: the worker image and env contain no Anthropic or Claude variables. (b) Reverse direction: a managed job completes while the review pool is exhausted, using a real occurrence recorded with timestamps; if none occurs, this check stays open. (c) Measured isolation from every consumer of the Nebius project and the gateway (the list comes from the Nebius console and the gateway and is recorded). With the strongest neighbour (for example the support pilot) driven to a stated load, a managed job still completes, the managed p95 latency stays within 1.5x of its idle value and the provider 429 count is 0 over at least 20 jobs. These bounds are proposed and need the owner (D7). The test names the limit it exercises (gateway or Nebius; key, project or organisation); a project- or organisation-scoped limit cannot be shown isolated by lowering a per-key limit. It is repeated for the production credential's project once that exists. Lowering any limit or loading a neighbour needs owner approval (D7); changing a Nebius limit is outside this plan. Amendment in section 3. |
| 6 | C1-style evidence with non-secret identifiers | Results are in #1088 comments; `docs/reports/communication-agent-c1.md` is Claude-era. | No C2 report for the managed runtime. | Create `docs/reports/communication-agent-c2.md` (or a managed-runtime report) with domain id, caps, alert evidence, drill results and a `Go/no-go` line. |
| 7 | Explicit go/no-go referencing #334 | Runbook activation steps A1 to A6 do not mention the gates. | No enforced check. | Add a step 0 to the runbook activation section that requires #334 and #889 closed, a PASS of the #889 Part B managed soak, and the C2 report with `Go/no-go: go`; add a docs test marker. |

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
  unavailable or independently rate-limited" becomes all three checks in matrix
  row 5, including the measured neighbour test; the by-construction argument
  alone does not satisfy it;
- "monthly budget and rate-limit alerts are tested" additionally names the
  managed ledger metrics and the provider 429 rate, and states that a global
  monthly cap does not exist and which control stands in for it;
- the Claude-specific rotation procedure is kept for the Claude runner and a
  managed one is added.

The owner decides whether this amendment is accepted, and the decision (D6) is
recorded as a comment on #334 itself, so the gate text and the issue cannot
diverge. Until then the original text is the gate.

## 4. Work plan

| Step | Work | Needs owner approval | Depends on |
|---|---|---|---|
| W1 | Reconcile the gitops proposal with the matrix | No | none |
| W2 | Alert rules and promtool tests for row 3c: mirror file here and the deployed copy in mctl-gitops (a gitops PR, merged under the gitops approval rule) | No for the PRs; the deployed rules take effect only on merge | W1, D3 |
| W3 | Managed rotation and revocation procedure in the runbook | No (PR) | none |
| W4 | Static proofs. Kubernetes part done (read-only). Vault part: readers of the path, per `gate-334-readonly-checks.md` section 2 | No for read-only kubectl; the Vault part needs the owner's login (D5) and reads metadata and policies only | none |
| W5 | Nebius project and quota scope, billing alert, per `gate-334-readonly-checks.md` section 3 (read-only, owner reads the console) | Yes (D2, owner console); no change to keys or limits | none |
| W6 | Production budget numbers | Yes (D3) | W5 |
| W7 | Alert fire-and-resolve test on preview | Yes (D4): lowers a cap temporarily via gitops | W2, W6 |
| W8 | Rotation drill on preview | Yes (D5): Vault write, Nebius console | W3, W5 |
| W9 | Reverse-direction and neighbour drills (row 5 b and c) | Yes, always (D7): they can load or limit a shared system, and the review pool outage is the incident this gate exists to prevent. Changing any Nebius limit is not part of this plan | W5 |
| W10 | C2 report with go/no-go, a table of the seven criteria with columns evidence, date, owner, passed, and runbook step 0 | No (PR) | W2 to W9 |

No Cloudflare apply, Vault write, account switch, listening or sending change,
production deploy or flag change, Nebius limit change, or load or limit placed on
a neighbour consumer happens without a separate owner approval.

## 5. GO / NO-GO

GO for closing #334 only if every row of the matrix is either closed with
evidence or covered by an owner-accepted amendment, a passing measured
neighbour test (row 5c, with its numeric bound and load stated) is recorded for
the production credential's project, and the C2 report carries `Go/no-go: go`. Closure does not depend on #889. A GO here does not enable
production: production GO needs #334 and #889 both closed plus the Part B soak.
NO-GO if isolation from other Nebius consumers is not demonstrated by the
measured neighbour test (an owner statement from the console is evidence to
record, not a substitute), if the production credential domain does not exist
yet, if the rotation drill fails, or if any alert test does not fire within the
stated delivery time.

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
- D6. Accept or reject the amendment in section 3. Note: the monthly-budget
  bullet would document the missing global monthly cap as accepted, which can be
  read as weakening the gate; the owner decides knowingly.
- D7. Permission for the neighbour and reverse drills (row 5 b and c, W9) and the
  numeric bounds of row 5(c). Without D7 those drills do not run.
