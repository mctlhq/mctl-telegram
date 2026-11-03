# 0008. Managed runtime: one pooled platform worker, OpenAI-compatible models through the AI gateway

Status: Accepted (2026-11-03; owner GO with amendments, 2026-11-01). Epic: #1088 (P5 of
#1002; manifest `roadmap/epics/telegram-managed-runtime.yaml` in mctlhq/.github).
Slices: #1089 runtime field and consent, #1090 pool credential and claim path,
#1091 OpenAI runner, #1092 ledger and caps, #1093 C1 gate, #1094 CI image,
mctlhq/mctl-gitops#2345 deployment, #1095 docs. Spike: mctlhq/.github#293.
Builds on #1046 (P4.5, external runtime contract) and [0002](0002-send-gate.md).

Unlike 0001-0007 this record was written before the code. Where it names
files and symbols it named the code the change would touch; once implemented,
the code is authoritative and this record is corrected to match it. It has now
been reconciled with the code on `main` (a787e97).

Implementation status: #1089 runtime field and consent, #1091 OpenAI runner
(both in code on `main`; PR numbers not recorded here), #1090 pool credential
and claim path (#1105), #1092 ledger and caps (#1113), #1094 CI image (#1114),
mctlhq/mctl-gitops#2345 deployment (inert, `replicaCount: 0`). #1093 (C1
gate) is not confirmed as merged by this reconciliation. Activation is a
separate owner decision; see the runbook.

## Context

An installed assistant only works while something claims its jobs. Today that
something is `cmd/agent-worker` on the owner's Mac mini, holding an
account-scoped worker token (`aud=agent`, `sub=tg:<id>`), minted by the
admin-only route `POST /api/agent/token` (`internal/agentapi/tokenhandler.go`),
and an Anthropic credential of the owner's own. Nobody else can run an
assistant: a user would need an admin to mint them a token, a machine to run
the worker on and their own model credential.

Facts the decision rests on:

- The user's MCP server is `tg.mctl.ai/mcp` (Telegram identity). The
  platform's `api.mctl.ai/mcp` is a different realm: the Telegram relay
  cannot reach `/operations/*/execute`, and mctl-support is read-only and
  tenant-bound by design (600 s task deadline, no deploy or secret-write
  tools, a secret would cross an LLM transcript). Neither can provision a
  worker for a Telegram user.
- One worker serves exactly one account. `Queue.Claim` filters by `user_id`
  in both claim queries: the plain one in `internal/db/agent_jobs.go`
  (`ClaimAgentJobs`) and the turn coalescer in
  `internal/db/agent_turn_claim.go` (`claimCoalesced`, used whenever
  `AGENT_TURN_QUIET` is set).
- Everything after the claim is already account- and job-bound: the claim
  response carries a per-job token (`aud=agent-job`, `mintJobToken` in
  `internal/agentapi/events.go`) with `job_tools`, the server renders the
  instructions from that account's install before claiming, `toolGate` and
  `enforceBinding` refuse any call outside the job, and every send passes
  the policy and the send gate. The worker holds no Telegram credential.
- The worker's model call is the `claude` CLI as a subprocess
  (`internal/agentworker/claudeinvoker.go`); there is no provider
  abstraction. `Runner` (`internal/agentworker/worker.go`) is the seam:
  `NewWorker(client, runner)`.
- The Anthropic organisation is disabled (29.10). The platform's model path
  is Cloudflare AI Gateway with custom providers `nebius` (GLM-5.1, 1.40 /
  4.40 USD per MTok) and `hetzner` (Qwen, free while experimental, 10
  requests per 60 s per key, not for production). Both speak the OpenAI
  chat-completions format. The gateway is BYOK, logs off; it reports cost 0
  for custom providers, so cost accounting has to live in mctl.
- Hetzner inference measured on 2026-11-01: 3-7 s for a 200-token reply
  (Qwen3.8-27B, Qwen3.6-35B-A3B), HTTP 200 on every probe.
- The quality gate for any model or runner is the C1 eval: 32 fixtures,
  `minClassification: 29` (`assistants/hr-recruiter/eval/0.1.0/suite.yaml`),
  0 leaks, 0 binding violations, 0 wrong auto-sends.
- Production has the conversation plane on since gitops#2330 (2026-11-01,
  observe mode); its quota domain and rollout gates are #334 and #889.

## Decision

A user chooses who runs their assistant with one field on the install,
`runtime: own | managed` (default `own`, today's behaviour). `managed` means
the platform's own worker claims that account's jobs. The platform runs
**one** such worker per environment, not one per account, and that worker
drives OpenAI-compatible models through the AI gateway with an in-process
tool loop. No token or credential ever reaches the user.

### 1. Consent, not a setting

Switching `own -> managed` sends the content of Telegram messages (the job
context, the owner-profile view, records the tools return) to a third-party
model provider through MCTL's gateway. That is a data-flow change, so it is
a confirmed operation:

- `install_assistant` and `update_install` refuse `runtime: managed` with
  `managed_consent_required` unless the call carries
  `consent: "managed-data-flow/v1"`. The manage page shows a checkbox with
  the same text and sends the same value. `managed -> own` needs no consent and erases the stored consent (version and time), so a later `own -> managed` by the owner, or by an admin through the profile route, needs a new current consent. An install document that does not state `runtime` leaves the account's runtime unchanged; only an explicit `own` moves a managed account back.
- Consent text, verbatim: *Messages needed to perform assistant tasks will
  be sent to MCTL's configured third-party AI provider through MCTL's AI
  gateway; gateway logging and caching are disabled.*
- The profile stores `managed_consent_version` and `managed_consent_at`;
  the change is audited. A new consent version (a provider change) holds
  existing managed installs: their jobs stay pending and the owner is
  notified once, until they re-consent.

### 2. Pool credential: claim-only

- A new credential shape, `aud=agent-pool`, `sub=pool:<name>`,
  `TelegramID=0`, with a `jti` and `orig_iat`. It is verified by a new
  `localjwt.PoolProvider` (no `EnsureUserByTelegramID`, which rejects
  `tgID <= 0`), chained after the agent and job providers in
  `cmd/server/main.go`, and present only when `MANAGED_RUNTIME_ENABLED`.
  A pool token that carries a Telegram id or a job id is rejected (shape
  confusion). `derivedAudiences` in `internal/auth/localjwt/issuer.go` gains
  `agent-pool`, so the revocation check always runs.
- Minted by `POST /api/agent/pool-token` (scope `admin:users`, body
  `{pool_name, ttl_hours}`, TTL 30 d default, 90 d cap, same constants as
  the account token), mounted only under the flag (`managedPoolEnabled` also requires the JWT
  signing secret). It is not an MCP tool:
  one mint per environment per rotation. The value lives in Vault and
  reaches the worker as `AGENT_API_TOKEN` through an ExternalSecret.
- A pool identity may call exactly one route: `POST /jobs/claim`. A new
  `requireNotPool` guard in `internal/agentapi/binding.go` returns 403 and
  records the refusal (a `slog` warning and a policy-denial metric; an
  `audit_logs` row under the job owner only when the route names a job, since
  `audit_logs.user_id` requires a real user) on every other route, including `GET /jobs/{id}` and
  `POST /jobs/{id}/cost`. The worker therefore uses the job token for every
  per-job call (`GetJobStatus`, `ReportJobCost`, the tool routes); in pool
  mode (`AGENT_POOL_MODE=true`) a job without a job token is a hard error,
  never a fallback to the pool token. `MANAGED_MAX_INFLIGHT_PER_ACCOUNT`
  (default 1) caps processing jobs per managed account. The cap is enforced
  inside the claim transaction (`Store.ClaimManagedAgentJobs`: a per-account
  `pg_advisory_xact_lock`, then the processing count, then the claim), so
  concurrent pool workers cannot exceed it; the candidate list read before it
  is only a hint. An account under a
  blanket revocation (`RevocationCache.IsBlanketRevoked`) is skipped by the
  pool claim, because job tokens inheriting the pool's `orig_iat` would be
  dead on arrival. A pool-claimed job whose token cannot be minted is released
  with `Store.ReleaseUnissuedClaim`, never `RetryAgentJob`, so a signer outage
  does not spend its retry budget.
- Revocation: the existing `revoke_worker_token` tool by `jti` revokes the
  pool. Job tokens inherit the parent's `jti` and `orig_iat` (as today), so
  revoking the pool also revokes every job token derived from it within
  the revocation cache TTL (15 s). Blanket revocation of one account by
  Telegram id keys on that id; the pool carries 0, so revoking an account
  stops that account's in-flight managed job and leaves the pool running.
  The named test for this is in section 7.

### 3. Claim semantics: the runtime predicate lives in SQL

- `agent_profiles.runtime TEXT NOT NULL DEFAULT 'own'`. Both claim queries
  gain the predicate
  `COALESCE((SELECT runtime FROM agent_profiles ap WHERE ap.user_id = j.user_id), 'own') = $runtime`.
  An account token claims with `own`, a pool token with `managed`. This is
  the invariant: an own-runtime token can never claim a managed account's
  job and the pool can never claim an own account's job, enforced in the
  database rather than in the handler. A profile-less account stays
  claimable as `own`.
- The claimed job records `agent_jobs.runtime` (the claim-time snapshot),
  so a later switch cannot relabel a finished job.
- The pool branch of `handleClaimJobs`:
  1. refuses with 503 when no job-token signer is configured (a pool claim
     without job tokens would leave the worker with no credential);
  2. lists candidate accounts: `runtime = 'managed'`, a due pending job the
     claim could take (the claim's per-conversation rule, so an account
     blocked head-of-line is not listed), a Telegram login id (so a job token
     can be minted), fewer than `MANAGED_MAX_INFLIGHT_PER_ACCOUNT` jobs
     processing, budget available (section 5), oldest waiting first;
  3. for each candidate renders the instructions **before** claiming (as
     today; an account whose assistant is disabled or unknown is skipped and
     its jobs stay pending), then claims one job for that account, round
     robin, until the requested limit is reached. One job per account per
     response: concurrency across accounts, not within one. The candidate
     order is walked page by page with a keyset cursor (oldest claimable
     job, then user id; not an offset, because a served account drops out of
     the order mid-walk) until `limit` jobs are claimed or it is exhausted,
     not read as one fixed window: a skipped account (blanket
     revocation, an assistant that cannot render) keeps its place at the
     front, and a fixed window would let a few of them starve every other
     managed account. A request that skipped candidates and served nobody
     logs one warning with the skip reasons;
  4. mints the job token from the **job's** user (`Store.TelegramIDByUserID`),
     not from the parent, keeping the pool's `jti` and `orig_iat`;
  5. audits each claim under the job's user id with `pool:<name>` as the
     message (`audit_logs.user_id` has a foreign key; a pool has no user).
- Switching runtime is an install change, so it bumps `install_revision`
  (`RuntimeChange.Apply`, which also covers the admin profile route). The
  bump makes `policy.Evaluate` deny whatever the old attempt proposes
  (`DenyInstallChanged`, checked at propose, approve and send). Completion
  is fenced separately: the completion CAS in `internal/db/agent_jobs.go`
  (`completeRuntimeFence`) refuses to close an attempt whose
  `agent_jobs.runtime` differs from the profile's, so the old worker gets
  409 and the job stays processing. `RequeueStaleAgentJobs` returns it to
  pending after `AGENT_JOB_VISIBILITY` and the new runtime claims it. The
  sweep requeues such a fenced job before its dead-letter rule runs and gives
  it one more attempt if it was on its last, so a switch never dead-letters
  the job. The old job token stays valid until its deadline, but nothing it
  does can act. No double send is possible. `/mctl assistant` and the manage
  page show the runtime, so an own worker that suddenly sees an empty queue
  is diagnosable.

### 4. One runner contract, two runners

- The tool set is extracted from `NewMCPServer`
  (`internal/agentworker/mcpserver.go`) into `buildToolSet`, which returns
  the same `mcplib.Tool` definitions and the same handlers (serialised,
  completion-aware, pinned to the job). `NewMCPServer` becomes a loop over
  it; the new runner executes the same handlers directly. There is no
  second tool implementation and therefore no second policy surface.
- `OpenAIRunner` (`internal/agentworker/openairunner.go`, plus a minimal
  `net/http` client, no SDK dependency) runs the loop against
  `POST {base}/chat/completions`: non-streaming, `tool_choice: auto`,
  function schemas straight from `mcplib.Tool.InputSchema`, headers
  `Authorization: Bearer <provider key>`,
  `cf-aig-authorization: Bearer <gateway token>`, `cf-aig-collect-log: false`.
  Stops on `complete_agent_job`, on no tool calls, on `AGENT_MAX_TURNS`, or
  when the accumulated cost exceeds the per-job cap. Retries 429 and 5xx
  with backoff and `Retry-After`, never past the job deadline; a
  process-wide minimum interval (`AGENT_OPENAI_MIN_INTERVAL`) respects
  Hetzner's 10 requests per minute.
- Cost comes from the response `usage` and the prices in
  `MODEL_INPUT_USD_PER_MTOK` / `MODEL_OUTPUT_USD_PER_MTOK` (the names
  mctl-support already uses). The result is mapped onto the existing
  `ClaudeResult` subtypes (`success`, `error_max_turns`,
  `error_max_budget`, `error_provider`, `error_provider_429`, the last one
  in the `usage_limit` class) and finished by a `finishRun` shared with the
  Claude runner, so `CheckResult`, metrics and the usage-limit alert keep
  working unchanged.
- Nothing is shared between jobs except the HTTP transport, the rate
  limiter and the metrics registry: a fresh tool set, a fresh client with
  that job's token and a fresh message list per job. The runner never logs
  message bodies, tool arguments or tool results.
- The worker selects the runner with `AGENT_RUNNER=claude|openai`
  (`claude` is the default, so the Mac mini is unaffected). `openai`
  requires `AGENT_MODEL`, `AGENT_OPENAI_BASE_URL`, `AGENT_OPENAI_API_KEY`,
  the two prices, and optionally `AGENT_GATEWAY_TOKEN`; a missing value
  refuses to start, as `AGENT_CREDENTIAL_DOMAIN_ID` does today. The C1 eval
  harness gains `AGENT_C1_EVAL_RUNNER=openai`.

### 5. Budget: hard caps by reservation, a server-authoritative ledger

- Table `agent_usage` (one row per job attempt, `UNIQUE(job_id, attempt)`):
  user, runtime (copied from `agent_jobs.runtime`), runner, model, input and
  output tokens, `reserved_usd`, `cost_usd`, `status reserved|held|settled`,
  timestamps. There is no `released` status. `agent_jobs.cost_usd` stays as
  the last attempt's cost for existing dashboards.
- **Reservation at claim.** Claiming a managed job inserts a `reserved`
  row for the server's per-job cap (`MANAGED_MAX_JOB_COST_USD`, default
  0.50), which the server puts in the claim envelope as `max_job_cost_usd`
  so worker and server agree on the number; in pool mode the worker's model
  budget is the smaller of `AGENT_MAX_BUDGET_USD` and that value. Available
  budget is cap minus settled cost minus every unsettled reservation
  (`reserved` and `held`) of the window, computed inside the claim
  transaction with the global budget lock held, so two concurrent claims on
  an account (or on two accounts under the global cap) with budget for one
  job yield exactly one claim. A cap checked only at claim time would be
  advisory; this one is not.
- **Lock order.** A managed claim with a budget takes the global budget
  advisory lock first, then the account advisory lock (`reserveInflight`),
  then its `FOR UPDATE SKIP LOCKED` row locks. There is no
  `agent_profiles` row lock: the global lock already serializes every such
  claim, and the global pause updates other accounts' profile rows while
  holding it, so any claim that held an account or profile lock while
  waiting for the global lock could close a deadlock cycle.
- **Windows.** Day and month are UTC calendar windows; an attempt belongs to
  the window of its `created_at`, the claim time.
- **Settle, hold, delete.** The cost report settles the row (a `held` row
  too, while `agent_jobs.attempts` still equals that attempt). When the
  sweeper requeues, dead-letters or fences a stale managed attempt its
  reservation becomes `held`, never released: the job token has left the
  server, the run may have spent up to the cap, and a pool job token expires
  at the same deadline the sweeper uses, so its cost report can be refused
  with 401. A `held` row keeps counting at `reserved_usd` until a report
  settles it or its window ends, and is exposed as
  `mctl_agent_usage_held_usd` / `mctl_agent_usage_held_rows` (the
  reconciliation drift). Only `ReleaseUnissuedClaim`, where no token for the
  attempt ever left the server and the attempt number is reused, deletes a
  reservation without a cost report.
- **Attempts the worker ends without a report.** A worker can complete,
  fail or retry its job and never report cost (an unknown cost, a crash, a
  failed POST). The sweeper holds such a reservation once the job has not
  transitioned for `reservationEndGrace` (2 minutes) and is no longer
  processing under that attempt, so the missing spend counts as durable and
  exhaustion pauses and notifies instead of deferring silently. The grace
  exists because the agent can close its job through a tool before the
  worker's cost report lands. A run that is still processing under its
  attempt stays in flight however long it runs.
- **Late reports.** A `held` row settles only while `agent_jobs.attempts`
  still equals its attempt. Once the job is re-claimed, a report for the old
  attempt is refused and the row charges the full `reserved_usd` until its
  window ends. This is deliberate: it is the conservative bound, and a pool
  job token for that attempt has expired anyway.
- **Overshoot.** The runner checks its budget after each model call
  (`totalCost > MaxBudgetUSD`), so one attempt can spend more than
  `reserved_usd` by at most one call. The settle records the actual cost and
  the next claim sees it, so a cap can be overrun by at most one model call
  per in-flight managed attempt.
- Caps: per job (`AGENT_MAX_BUDGET_USD`, enforced in the runner and
  reserved by the server), per account per day and per month
  (`MANAGED_BUDGET_USD_PER_ACCOUNT_DAY` 1.00, `_MONTH` 15.00, with an
  admin-settable per-account override), global per day
  (`MANAGED_BUDGET_USD_GLOBAL_DAY` 20.00). The per-account override is
  `managed_budget_usd_day` / `managed_budget_usd_month` on the admin profile
  route (a non-negative number, or null to clear).
- **Durable versus in-flight exhaustion.** Durable usage is settled cost
  plus `held` reservations; in-flight usage is `reserved` rows of attempts
  still running, which settle within the claim deadline. Only durable
  exhaustion pauses: the claim sets `budget_paused_until` to the end of the
  window and counts `mctl_agent_budget_exhausted_total{scope}`; a global
  exhaustion pauses every managed account with pending jobs. A cap that has
  room except for in-flight reservations only defers the claim
  (`mctl_agent_budget_deferred_total{scope}`): no pause, no notification.
- When a cap is durably reached the account's jobs are **held pending** until the
  window resets: the owner is notified once per window, and the unclaimed
  sweeper does not route them to the operator (`budget_paused_until` on the
  profile, read by the candidate query and by `RouteUnclaimedAgentJobs`).
  The router also holds a managed account's jobs while the global day budget
  has no room for one more reservation, even when the global pause never
  stamped that account, using the same predicate as the candidate query.
  Messages are never dropped; the reply may be late.
- **The ledger is server-authoritative.** `POST /jobs/{id}/cost` accepts
  only `model`, `input_tokens`, `output_tokens`, `runner`, `cost_usd`. The
  server derives the user, the runtime and the job and attempt from the
  authenticated job token and the job row; a body that names a user, a
  runtime or a job is rejected by the strict decoder. A repeated report
  with identical fields is a no-op (200); one with different tokens, cost
  or model is refused with 409 `usage_conflict` and audited. An own job can
  never be labelled managed, and the worker can never pick the account it
  bills. A managed-runtime job's usage is accepted only with the job token
  the pool was issued for it: an account token naming the attempt is
  refused with 403 and audited, decided under the job row lock, so an owner
  cannot settle their own reservations at zero.
- Metrics (runner is clamped to `claude|openai|other`; model to at most 16
  distinct values plus `other` and `unknown`, because any worker credential
  can name a model, and only a report on a managed-runtime job, by the job
  row, can take a free slot): `mctl_agent_usage_cost_usd_total{runner,model}`,
  `mctl_agent_usage_tokens_total{direction,model}`,
  `mctl_agent_budget_exhausted_total{scope}`,
  `mctl_agent_budget_deferred_total{scope}`, `mctl_agent_managed_accounts`,
  `mctl_agent_usage_held_usd` and `mctl_agent_usage_held_rows`. The
  `mctl_agent_openai_requests_total{status_class}` and retries metrics named
  in the original design are not implemented. Alerts live
  in mctl-gitops: global cap hit, hourly spend above a threshold, pool
  worker down while managed accounts exist.

### 6. Deployment and rollout

- Preview first: component `agent-worker-managed-preview` in `labs`,
  cloned from the existing `agent-worker-preview` values (same image, which
  already contains the binary; a slimmer image without Node and the Claude
  CLI is a follow-up), `AGENT_RUNNER=openai`, `AGENT_POOL_MODE=true`,
  Hetzner model via `custom-hetzner`, shadow prices at Nebius rates so the
  ledger and caps are exercised, concurrency 1, in-cluster API URL. Three
  ExternalSecrets from `secret/platform/labs/agent-worker-managed-preview/`:
  the pool token, the provider key, the gateway token. A dedicated gateway
  `mctl-telegram` (its own `cloudflare_ai_gateway` and run token, declared
  in gitops as the mctl-support one was) keeps counters and revocation
  separate from mctl-support.
- Server flags on tg-preview: `MANAGED_RUNTIME_ENABLED`,
  `MANAGED_RUNTIME_MAX_ACCOUNTS` (1 at first), the budget caps.
- Order: merge everything with the flag off; enable the flag and caps;
  mint the pool token and write the three secrets; deploy the component
  with one replica (expect: healthy, polling, zero claims); the owner
  switches the preview account to `managed` with consent; soak at least 30
  real jobs and record p50/p95 job latency, cost per job, reservation
  reconciliation drift (must be 0) and cross-account violations (calls
  refused by `enforceBinding` or `toolGate` for another job or account;
  must be 0, any other value stops the rollout), plus gateway logs still at
  0. Production only after #889 and #334, on `custom-nebius`, with the
  release image `ghcr.io/mctlhq/agent-worker:<tag>` published by the
  release workflow.
- Rollback, fastest first: `runtime: own` (the fence does the rest); scale
  the component to 0; revoke the pool `jti` (15 s); flag off (pool tokens
  get 401). With the flag off, jobs of accounts still on `runtime: managed`
  are claimed by nobody: own workers never take them. They are paused, or
  routed to the operator after `AGENT_UNCLAIMED_ROUTE_AFTER` when operator
  routing is on, until each account moves back to `runtime: own`. The server
  logs the number of such accounts at start, so the flag is never turned off
  silently. Flag off is therefore a pause for managed accounts, not a
  fallback to their own workers.

### 7. Tests that must exist (each fails with the bug put back)

- Runtime predicate in **both** claim queries: own claims only own, managed
  only managed, profile-less as own. Mutation: drop the predicate from
  either query.
- `TestPoolRevocation_KillsIssuedJobToken`: mint pool, claim, obtain the
  derived job token, revoke the pool `jti`, call `propose_reply` with the
  **existing** job token: refused within 15 s; the claim path refuses too.
  Mutation: skip the `jti` check for the `agent-job` audience.
- Pool identity is claim-only: a table over every registered route.
- Job token minted from the job's user, with the pool's `jti`.
- Round robin and in-flight cap across accounts; render-before-claim skips
  a disabled assistant and leaves its jobs pending. The cap holds under
  concurrent pool claims (`TestClaimManagedAgentJobs_InflightCap_Postgres`:
  parallel transactions, cap 1, exactly one claim).
- Budget race: two concurrent claim transactions, budget for one job,
  exactly one claim. Reservation settled on cost report, held (never
  released) on requeue and on a worker-ended attempt without a report.
  Exhausted account held, notified once, not routed to the operator.
- Ledger: `TestRecordCost_IgnoresBodyIdentity`,
  `TestRecordCost_IdempotentSame`, `TestRecordCost_ConflictRefused`; an own
  job cannot be relabelled managed.
- Consent: `managed` refused without the consent value; stored version and
  timestamp; a new version holds existing managed installs.
- Runner: tool loop completes, stops after `complete_agent_job`, max turns,
  budget stop, 429 with `Retry-After` within the deadline, job token on
  every call, no shared state across two concurrent jobs, both gateway
  headers present, exact cost arithmetic, logs carry no content, and the
  function schemas equal what `NewMCPServer` registers.
- Runtime switch fences the in-flight attempt and the job is reclaimed by
  the new runtime.

## Consequences

- A Telegram user gets a working assistant from their MCP client with no
  admin, no machine and no credential of their own; the platform pays and
  caps the spend.
- The pool token is a wider credential than an account token: its holder
  can claim and act within every managed account's job stream, through the
  normal job API and under the same policy. This is accepted because it is
  bounded (claim-only, `jti` revocable with its derived tokens, 30-day TTL,
  `MANAGED_RUNTIME_MAX_ACCOUNTS`, per-account and global caps, in-cluster
  URL) and because today's account token has no `jti` at all.
- Message content now reaches a third-party model provider (Nebius or
  Hetzner) through Cloudflare. The consent in section 1 states it; gateway
  logging and caching stay off (`cf-aig-collect-log: false`, no cache on
  the gateway); checking the provider's terms on training is an owner
  action before production.
- Two runners share one tool set, so a policy change lands in both or in
  neither. The cost is a refactor of `mcpserver.go` before the runner exists.
- The Mac mini path (`own`) is untouched: `AGENT_RUNNER` defaults to
  `claude` and the account token path does not change.
- The quality of replies depends on a model that is not Claude. The C1
  gate (29 of 32, 0 leaks) decides whether a model may serve the managed
  tier; Hetzner is the dev and eval candidate, Nebius the production one.

## Alternatives

- **One Deployment per account**, provisioned through
  `mctl_deploy_service`. Possible today, but it needs a fixed-image service
  template (the removed `openclaw` precedent), an `image-names.txt` entry,
  a Vault path and an Argo CD application per account, and workers in
  other namespaces can only reach the server over the public hostname. It
  buys no isolation: the key, the cluster and the policy are the same, and
  isolation already comes from the job token and the SQL predicate.
- **Delegate provisioning to mctl-support.** Its tokens are read-only and
  tenant-bound, it has no write tools, its prompt refuses changes, its task
  deadline is 600 s, and a token would travel through an LLM transcript.
- **Translate Anthropic calls to OpenAI behind `ANTHROPIC_BASE_URL`** and
  keep the Claude CLI. Tool-calling fidelity and `total_cost_usd` would be
  the proxy's guess, and the CLI's own usage limits would still apply.
- **A plain `runtime` setting without consent.** Rejected: a change in who
  reads the user's messages is not a preference.
- **Caps checked at claim time only.** Rejected: two concurrent jobs can
  both see the remaining budget and together exceed it.
- **Marking exhausted accounts' jobs `ignored`.** Cleaner queue metrics,
  but the next budget window could no longer answer the message.
