# Spike: repository boundary for the shared assistant/provider runtime

Verdict: REUSE_EXISTING

Status: Recommendation, owner decides on mctlhq/.github#324. This is a provisional
recommendation for a fake-adapter proof of concept only. It is not an approved
repository decision, and it does not authorize any code, repository, image,
Temporal namespace, Glovo API access, GitOps change, DNS or deployment.

Runtime blockers (apply whichever repository is chosen):

- Temporal client authorization (mctl-gitops#2456). The frontend has no client
  authentication today.
- A verified inter-namespace bridge between the control and provider Temporal namespaces
  (see "Inter-namespace bridge"). Without one, runtime activation is held.
- The connector threat model (#1048).
- A sanctioned provider API. None is known.
- Separately approved mctl-api Glovo-scoped endpoints (see "mctl-api contract status").

Labels: every claim is marked `source-backed` (with a path or tool call) or `model-only`.
Source of the deployed-state facts: the `mctl-gitops` checkout read during the
investigation. Live Temporal state, and the source of `mctl-api` and `mctl-agents`,
were not observed.

## Why this is not just a repository question

Four boundaries are easy to conflate. They protect different things.

| Boundary | Isolates | Does not isolate | Current state |
| --- | --- | --- | --- |
| Temporal namespace | Workflow history, visibility, retention, and (with an authorizer) which identity may act on which workflows. Stock authorizer roles are per namespace, not per task queue (model-only). | Anything at the network level, and anything inside the namespace between task queues. | source-backed: `infra-components/data/temporal/tenant-namespace-job.yaml` registers `kuptsi` (7d) and `mctl-agents` (30d). There is no `mctl-assistants` namespace. The header notes a Temporal namespace is independent of a Kubernetes namespace. |
| Kubernetes namespace | Network policy scope, egress allowlist, secrets and service accounts, resource quota. | Temporal access. A pod in its own Kubernetes namespace can still call Temporal if the network allows it and no authorizer exists. | source-backed: `infra-components/data/temporal/networkpolicy.yaml` header: the frontend "has no client authentication ... the network is the only boundary". Ingress to 7233 is allowed from mctl-api, `admins-mctl-agents-worker{,-exec,-implement}` and `labs-kuptsi-app`. mctl-telegram is not a client. |
| GitHub repository | Who can change code, who can publish an image, which CI and release pipeline runs. | Anything at runtime. A repository split changes none of the controls above. | source-backed: this repo publishes `ghcr.io/mctlhq/mctl-telegram` and `ghcr.io/mctlhq/agent-worker` through `.github/workflows/release-please.yml` and `.github/workflows/preview-deploy.yml`. |
| MCTL tenant | Which user and tenant may start, view or approve an order. Owned by mctl-api. | Infrastructure. A tenant check does not stop a worker from reaching a network peer. | model-only for mctl-api internals. source-backed (design text of #1184, D2): mctl-api derives the workflow ID and checks tenant and owner. |

Consequence: a repository split adds release, CI and permission surface without adding
runtime isolation. Runtime isolation comes from the Temporal namespace plus authorizer,
the Kubernetes namespace plus NetworkPolicy, and mctl-api tenant/user checks.

## Current topology inventory

| Item | Fact | Label |
| --- | --- | --- |
| Images in this repo | `Dockerfile` builds the server; `Dockerfile.agent-worker` builds a separate runtime image from `cmd/agent-worker` (image comment records why it is kept apart from the public server image). | source-backed: `Dockerfile`, `Dockerfile.agent-worker` |
| Image publishing | Both images and the preview image go through release-please and preview-deploy, then the centralized `mctl-gitops` release-deploy workflow. | source-backed: `.github/workflows/release-please.yml`, `.github/workflows/preview-deploy.yml` |
| Managed runtime | One pooled platform worker per environment, a claim-only `aud=agent-pool` credential, a per-job `aud=agent-job` token, no Telegram credential. Effects pass through `internal/agent/policy` and the send gate. | source-backed: `docs/adr/0008-managed-runtime.md`, `docs/agent-worker.md`, `docs/agent-runtime/threat-model.md`, `internal/agentapi/events.go` |
| Runner seam | `NewWorker(client, runner)`. | source-backed: `internal/agentworker/worker.go` |
| Assistant model | Embedded definitions, registry fetched from the mctl-api catalog, install `runtime: own or managed`. | source-backed: `assistants/`, `internal/assistant`, `internal/assistantregistry`, `docs/assistants/spec.md` |
| SSRF-safe egress | Required by the #1184 adapter contract. | source-backed: `internal/netsafe/netsafe.go` |
| Temporal in this repo | No `go.temporal.io` dependency. | source-backed: `go.mod` |
| Glovo in this repo | No file mentions Glovo at the investigated commit. #1184 artifacts (`docs/reports/glovo-assistant-spike.md`, `docs/adr/0009-assistant-temporal-tenancy.md`, `test/glovo-poc/`) were not present; whether PR #1187 merged was not observed. | source-backed (absence at investigated commit) |
| mctl-agents workers | One `ghcr.io/mctlhq/mctl-agents` image runs as three Deployments split by `--role control, execution, implementation`, sharing `TEMPORAL_NAMESPACE: mctl-agents` and holding a GitHub token. | source-backed: `services/admins/mctl-agents-worker*/values.yaml` |
| mctl-api as Temporal client | mctl-api is a client of `mctl-agents`. | source-backed: `bootstrap/templates/mctl-platform/mctl-api.yaml` (lines ~350-356) |
| Tenant Temporal namespace precedent | `labs-kuptsi-app` uses its own namespace `kuptsi` with a sidecar worker on the same image. | source-backed: `services/labs/kuptsi-app/values.yaml` |
| mctl-telegram flags | image `0.134.0`, `AGENT_ENABLED "true"`, `AGENT_KILL_SWITCH "false"`, `ASSISTANT_REGISTRY_ENABLED "true"`. | source-backed: `services/labs/mctl-telegram/values.yaml` |
| Managed preview worker | `replicaCount: 1`, per-service Vault paths, ordered rollback recipe in comments. | source-backed: `services/labs/agent-worker-managed-preview/values.yaml` |
| Live Temporal state | Which namespaces exist, whether an authorizer is configured. | not observed |
| mctl-api and mctl-agents source | Internal worker structure, queue registration, Temporal client code. | not observed; claims beyond GitOps are model-only |

## Target topology (amended 2026-11-08)

The owner selected multi-tenant from the first usable release at
`https://glovo.mctl.ai/mcp`, a non-Telegram MCP surface. The trust boundary is two
Temporal namespaces, not two queues in one namespace.

- Control: Temporal namespace `mctl-assistants`, task queue `assistants-control`.
  Trusted. (model-only: proposed.)
- Provider: Temporal namespace `mctl-assistants-provider-glovo`, a separate Kubernetes
  workload namespace, provider task queue. Lower trust. It has no identity or role on the
  control namespace or on `mctl-agents`. (model-only: proposed.)
- Authorization of MCTL user, tenant and order stays with mctl-api. A Kubernetes
  namespace alone does not enforce Temporal namespace access.
- Per-tenant semaphore and per-provider circuit breaker; per-tenant queues only after
  measured noisy-neighbour impact. This is independent of the repository. (model-only.)
- The public facade is packaged separately and delegates OAuth subject, tenant, install,
  order and `aar_` checks to mctl-api. It must not reuse the `tg.mctl.ai` Telegram-token
  identity, and must not fall back to a Telegram OAuth principal or to a
  deployment-wide `labs` or `mctl` tenant. (model-only: requirement.)

Shared-namespace rule: while the Temporal frontend has no client authorizer, any shared
`mctl-assistants` Temporal namespace is BLOCKED for multi-tenant use. It is allowed only
behind Temporal client authorization (mctl-gitops#2456) plus mctl-api tenant and user
checks. (source-backed for the missing authorizer: the networkpolicy header.)

Required negative test: the provider identity cannot start, signal, query, describe,
list or terminate any workflow in the control namespace or in DevLoop `mctl-agents`.

## Inter-namespace bridge

An ordinary Temporal Activity is a task in its workflow's namespace and cannot execute
in another namespace (model-only, Temporal semantics). A bridge must therefore be chosen.
Neither option may weaken provider least privilege.

| Aspect | Temporal Nexus | Authenticated mctl-api command/results bridge |
| --- | --- | --- |
| Status | BLOCKED until proven: exact running OSS server version, SDK version, endpoint registry, endpoint permissions and negative calls must be shown. None was observed. | Candidate. Not built; needs a separately approved mctl-api slice. |
| Authorization | Caller namespace allowed on the endpoint, target authorizes the caller. Both ends must be tested. | mctl-api signs commands (signed issuer); provider verifies. Provider posts results with a per-job credential scoped to one command. |
| Idempotency and dedupe | Operation ID per request. | Command ID plus replay protection (nonce, expiry); results deduplicated by command ID. |
| Timeout, retry, cancel | Operation timeouts and cancellation. | Explicit deadline per command, bounded retries with backoff, cancel command honored by the provider. |
| Payload and secrets | Bounded opaque payloads; no Glovo credentials in workflow history. | Bounded opaque payloads; credentials fetched by the provider from its own Vault path, never carried in the command. |
| Consent | Revalidated by mctl-api before each side-effecting step. | Same; per-user consent revalidated at command issue and at result apply. |
| Failure | Compensating error recorded as a workflow outcome. | Compensating failure result; stuck commands expire and are marked failed. |
| Revocation | Remove endpoint permission. | Revoke provider credential and signing key. |

Selection: the report does not claim either is verified. Rule: without a verified
bridge, hold runtime activation. Required denial tests include provider to control
(start, signal, query, terminate, list), provider to `mctl-agents`, replayed command,
expired command, cross-tenant command and revoked consent. (model-only.)

## mctl-api contract status

mctl-api#948 (AutomationDefinition v1, part of .github#322) was `proposed` in the
2026-11-07 investigator snapshot. PR #950 merged on 2026-11-08 and contains contracts
only. It does not implement Glovo connection ownership, tenant selection, a per-order
index or ActionApprovalRequest (`aar_`) integration. Those need their own mctl-api
implementation issue and separate approval. Nothing here upgrades the contract PR to an
implemented capability.

## A / B / C comparison

Options: A, no new repository (Automation Control Plane in `mctl-api`, Temporal
execution in `mctl-agents`, Telegram commands and UI in `mctl-telegram`, adapter as an
isolated image). B, new `mctl-assistants` runtime repository. C, small
`mctl-provider-adapters` repository.

| Axis | A | B | C |
| --- | --- | --- | --- |
| Queue topology | Same two-namespace topology; no repo dependence. (model-only) | Same topology; repo does not change it. (model-only) | Same topology. (model-only) |
| Worker image lifecycle | Own `cmd/`, own Go module, own Dockerfile and image name in this repo, mirroring `Dockerfile.agent-worker`. (source-backed: `Dockerfile.agent-worker`) | New image pipeline from scratch. (model-only) | New image pipeline for the adapter only. (model-only) |
| Release governance | Reuses release-please and centralized release-deploy. Same maintainers merge adapter and Telegram code. (source-backed: workflows) | Separate release path; a fourth owner of workflow code. (model-only) | Separate release path; distinct merge and publish rights possible. (model-only) |
| Runtime security | Isolation comes from Kubernetes namespace, NetworkPolicy, no Vault token, Temporal namespace plus authorizer. The repo adds nothing. (source-backed: networkpolicy header) | Same runtime controls as A; no extra runtime isolation. (model-only) | Same runtime controls as A; adds supply-chain separation of who publishes provider code. (model-only) |
| Build and release CI | Existing CI, a second Go module needs its own job. (model-only) | New CI, branch protection, GitHub App installation. (model-only) | New CI, branch protection, GitHub App installation, smaller. (model-only) |
| Secrets | Per-service Vault paths and no Vault token in the provider workload, as in the managed preview worker. (source-backed: `agent-worker-managed-preview/values.yaml`) | Same, plus new repo secrets and permissions. (model-only) | Same, plus new repo secrets and permissions. (model-only) |
| Kill switch | Layered, see below. (source-backed for `AGENT_KILL_SWITCH`: `services/labs/mctl-telegram/values.yaml`) | Same layers; a separate repo adds no switch. (model-only) | Same layers. (model-only) |
| Failure modes | Adapter regressions ship with Telegram releases unless the module and image are versioned separately. (model-only) | Risk of duplicating the scheduler or registry, ownership gaps. (model-only) | Cross-repo version skew between adapter and callers. (model-only) |
| Cost | Lowest: no new repo or pipeline. (model-only) | Highest: new repo, CI, release, review surface. (model-only) | Medium: new repo for one adapter. (model-only) |

## Kill switches by layer

1. Install `runtime` back to `own` (assistant spec). (source-backed: `docs/assistants/spec.md`)
2. `AGENT_KILL_SWITCH` and `AGENT_ENABLED` in mctl-telegram. (source-backed: `services/labs/mctl-telegram/values.yaml`)
3. Public MCP facade disabled in its own deployment. (model-only)
4. Provider worker `replicaCount: 0`. (source-backed pattern: `agent-worker-managed-preview/values.yaml`)
5. Revoke the provider credential and the bridge signing key. (model-only)
6. Temporal namespace deny via the authorizer, once it exists (mctl-gitops#2456). (model-only)

## Recommendation rationale

The recommendation is A, as a provisional choice for a fake-adapter proof of concept.

1. The controls that keep a provider worker away from DevLoop are runtime controls
   (Temporal namespace plus authorizer, Kubernetes namespace plus NetworkPolicy, mctl-api
   tenant checks). A repository only controls who changes and publishes code.
2. An isolated image without a new repository already has precedent here:
   `Dockerfile.agent-worker` (source-backed).
3. B would be a fourth owner of workflow code. The scheduler and workers are in
   `mctl-agents`, registry and Automation Control Plane in `mctl-api`, assistant
   definitions and Telegram UX in `mctl-telegram` (model-only on mctl-api and
   mctl-agents internals).
4. C is the right shape later, and the 2026-11-08 amendment makes its first trigger
   already relevant: `glovo.mctl.ai/mcp` is a non-Telegram, multi-tenant surface. For
   any REAL provider credential, the owner should re-evaluate C before adopting A. For a
   fake adapter with no credentials, A remains the low-friction option.
5. Evidence is insufficient to settle point 3 without reading `mctl-api` and
   `mctl-agents` source. The owner may prefer to defer on that basis.

### Promotion triggers for option C

- A second provider or a non-Telegram surface consumes the adapter. (The second is
  already true for the planned Glovo MCP surface; it must be re-evaluated before real
  credentials.)
- Different people must be able to merge provider code or publish its image than the
  mctl-telegram maintainers.
- The adapter's dependency or license profile must not enter this repository.

### Checklist for a later repository-creation approval

If a trigger fires, a separate approval must name each of: repository name, visibility,
automation (bots and Apps), branch protection, CI, release process (including image
names and the gitops wiring), and permissions (teams, secrets, deploy rights). This
report creates no repository.

## Cross-repo ownership map (proposed)

| Concern | Owner repo | Notes |
| --- | --- | --- |
| Automation Control Plane, order index, identity links, tenant/owner checks, the only Temporal client for start/signal/query/list | mctl-api | .github#318, .github#322, mctl-api#948. model-only on internals. |
| Temporal workflow host for control workflows (`assistants-control`) | mctl-agents (separate worker role, namespace `mctl-assistants`) | model-only: `--role` split precedent |
| Provider adapter interface, mock and Glovo implementations, adapter image | mctl-telegram (own Go module and `Dockerfile.provider-adapter`) | moves to C if a trigger fires |
| Telegram commands, preview UI, callbacks | mctl-telegram | |
| Claude/ChatGPT MCP tool surface for orders (`glovo.mctl.ai/mcp`) | mctl-api, or a separately packaged facade delegating to mctl-api | open question |
| Temporal namespaces, authorizer, NetworkPolicy, Kubernetes namespaces, Vault paths, Deployments | mctl-gitops | mctl-gitops#2456, #2457 |
| Commerce and payment | .github#173 | out of scope |

## Implementation slices

None of S1-S8 is approved by this report. Each needs its own approval.

| Slice | Owner repo | Depends on | Approval needed |
| --- | --- | --- | --- |
| S0: this report | mctl-telegram | none | this proposal (docs only) |
| S1: owner decision on .github#324 | .github | S0 | owner decision |
| S2: Temporal client authorization with per-identity namespace scoping, and bridge validation | mctl-gitops | S1 | GitOps approval (mctl-gitops#2456) |
| S3: Glovo-scoped mctl-api endpoints (connection ownership, tenant selection, per-order index, `aar_` integration) | mctl-api | S1 | separate mctl-api issue and approval |
| S4: connector threat model accepted (#1048) | mctl-telegram or .github | S1 | threat-model review |
| S5: provider-adapter module and image, mock provider only | mctl-telegram | S1, S4 | runtime-coding approval |
| S6: control workflows and bridge | mctl-agents, mctl-api | S2, S3, S5 | runtime-coding approval |
| S7: mock deployment (`mctl-assistants-poc`, provider Kubernetes namespace, NetworkPolicy) | mctl-gitops | S2, S5, S6 | GitOps approval (mctl-gitops#2457) |
| S8 (conditional): repository creation for option C | .github or org admin | S1 | repository-creation approval |

The graph is acyclic: S0 -> S1 -> {S2, S3, S4, S8}; S4 -> S5; S3, S5 and S2 -> S6; S2,
S5, S6 -> S7.

## Draft decision text for mctlhq/.github#324

> Recommendation from the spike (mctl-telegram `docs/reports/assistant-runtime-boundary-spike.md`):
> REUSE_EXISTING, for a fake-adapter proof of concept only. No new repository is
> recommended now. The repository does not provide runtime isolation; Temporal
> namespace separation with client authorization, Kubernetes namespace policy and
> mctl-api tenant checks do. Because `glovo.mctl.ai/mcp` is a non-Telegram multi-tenant
> surface, option C (a provider-only repository) must be re-evaluated before any real
> provider credential is introduced. Runtime activation stays held until Temporal client
> authorization (mctl-gitops#2456), a verified inter-namespace bridge, the connector
> threat model (#1048), a sanctioned provider API and the separate mctl-api Glovo
> endpoints exist.
>
> The evidence is not sufficient to discriminate fully: the `mctl-api` and `mctl-agents`
> source and the live Temporal state were not reviewed. If the owner prefers, choose
> DEFER until that review is done.
>
> This is a recommendation. The owner decides. No decision has been made by this text.

## References and observed status

| Reference | Observed status | Date |
| --- | --- | --- |
| mctlhq/mctl-telegram#1184 / PR #1187 (Glovo assistant spike) | proposal `status: implemented`; whether PR #1187 merged was not observed; its files were absent at the investigated commit | 2026-11-07 |
| mctlhq/mctl-telegram#1225 | this spike's issue | 2026-11-08 |
| mctlhq/mctl-api#948 | `proposed` in the investigator snapshot; PR #950 merged 2026-11-08, contracts only | 2026-11-07 / 2026-11-08 |
| mctlhq/.github#322 | referenced as the parent of mctl-api#948; status not read | not observed |
| mctlhq/.github#324 | open decision this report feeds; not decided | not observed |
| mctlhq/.github#173 (commerce/payment) | status not read; out of scope | not observed |
| mctlhq/mctl-gitops#2456 (Temporal auth) | content not read; treated as an unmet prerequisite, consistent with the networkpolicy comment | not observed |
| mctlhq/mctl-gitops#2457 (deployment plan) | content not read | not observed |
| mctlhq/mctl-telegram#1048 (connector threat model) | status not read; treated as unmet | not observed |
| `docs/adr/0008-managed-runtime.md` | Accepted | in clone |

## Open questions

- mctl-api#948 was `proposed` in the 2026-11-07 snapshot; PR #950 merged on 2026-11-08 as
  contract-only. A new issue is required for the Glovo-specific APIs.
- #1184 is `status: implemented` with PR #1187, but the investigated `main` has none of
  its files. Whether PR #1187 merged was not observed; dependence on unmerged artifacts
  is flagged.
- The `mctl-agents` and `mctl-api` source was not readable. Claims about their worker
  structure, queue registration and Temporal client code come from GitOps comments only
  and are labelled model-only where they go further.
- The content of mctl-gitops#2456 and #2457 was not read. Temporal client authorization
  is treated as an unmet prerequisite.
- Whether a second provider or a non-Telegram surface consumes the adapter within the
  planning horizon is the main trigger for promoting option C. With `glovo.mctl.ai/mcp`
  chosen as a multi-tenant surface, this trigger needs re-evaluation by the owner.
