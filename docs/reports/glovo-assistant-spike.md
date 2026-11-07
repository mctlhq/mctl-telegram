# Spike: Glovo Assistant basket handoff and shared Temporal namespace tenancy

Issue: [mctlhq/mctl-telegram#1184](https://github.com/mctlhq/mctl-telegram/issues/1184).
Proposal: `platform-gitops/agents-state/mctl-telegram/proposals/issue-1184-spike-poc-glovo-assistant-basket-handoff/`.

This is a time-boxed, inert spike. It changes no production code path, flips no
flag and touches no GitOps file. MCTL never pays, never stores card data and never
reports an order as paid. Anything not observed is marked `UNVERIFIED`.

Decision: **`MOCK_ONLY_PENDING_CONNECTOR`**. Target architecture, once the blockers
below clear: **`GO_SHARED_AFTER_HARDENING`** (option B of
[ADR 0009](../adr/0009-assistant-temporal-tenancy.md)).

Multi-tenant production rollout is **BLOCKED** whatever the decision value, while the
Temporal frontend has no client authentication and authorizer.

## 1. Baseline

Read from the mctl-gitops checkout used by the proposal. Live cluster state was not
read in this spike, so "deployed" means "present in GitOps on main".

### Temporal inventory

| Item | Value | Path (mctl-gitops) | Status |
| --- | --- | --- | --- |
| Namespaces | `kuptsi` (retention 7 days), `mctl-agents` (30 days) | `infra-components/data/temporal/tenant-namespace-job.yaml` | deployed |
| Search attributes | `kuptsi`: `LeadId` Keyword. `mctl-agents`: `Service` Keyword, `IssueNumber` Int, `AgentVersion` Keyword | same | deployed |
| Assistant namespace | none | n/a | candidate (`mctl-assistants`) |
| Frontend client auth | none; the header of the policy states the network is the only boundary | `infra-components/data/temporal/networkpolicy.yaml` (#1810, #1818) | deployed |
| gRPC clients (port 7233) | namespace `mctl-api`; `admins` pods `admins-mctl-agents-worker`, `-exec`, `-implement`; `labs` pod `labs-kuptsi-app` | same | deployed |
| Task queues | `mctl-dev-loop` (`--role control`), `mctl-dev-loop-exec`, implementation role worker; image `ghcr.io/mctlhq/mctl-agents:1.117.0` | `services/admins/mctl-agents-worker/values.yaml` | deployed |
| mctl-api client | `TEMPORAL_ADDRESS temporal-frontend.temporal.svc.cluster.local:7233`, `TEMPORAL_NAMESPACE mctl-agents` | `bootstrap/templates/mctl-platform/mctl-api.yaml` | deployed |
| mctl-telegram | `AGENT_ENABLED`, `ASSISTANT_REGISTRY_ENABLED`, `HUMAN_INPUT_ENABLED` true; `workContext.tenant: mctl`; `MANAGED_RUNTIME_ENABLED` unset (code default false, `internal/config/config.go`) | `services/labs/mctl-telegram/values.yaml` | deployed |
| mctl-telegram as Temporal client | no; no `go.temporal.io` in `go.mod`, not in the NetworkPolicy | `go.mod` | n/a |

Consequence: any pod admitted by the NetworkPolicy can act on every Temporal
namespace, including `mctl-agents`. Every work item this deployment creates goes to
the single configured tenant `mctl`; that is the "silently assigned shared tenant"
risk, and the identity chain in the ADR refuses instead of defaulting to it.

### mctl-telegram assistant runtime (this repository)

- One assistant per account: `assistants/hr-recruiter/assistant.yaml`, installed
  through `internal/assistantinstall/service.go` and keyed by Telegram user ID.
- `agent_profiles.install_revision` already fences stale work as `install_changed`
  (`docs/assistants/spec.md`). The order snapshot reuses it.
- Inbound third-party DMs reach `internal/agent/listener/listener.go`. Owner commands
  come only as `/mctl ...` in Saved Messages (`internal/agent/control/router.go`).
  A Glovo command must enter through the owner channel, never the listener.
- `internal/agent/schedule/schedule.go` is working-hours only, not a job scheduler.
- Identity relay: `docs/contracts/mctl-api-work-context.md` (bot is `surface:telegram`,
  user relayed through `X-MCTL-Surface-Actor`).
- Egress: `internal/netsafe/netsafe.go`. Human input: `internal/humaninput`.
- Threat model to extend: `docs/agent-runtime/threat-model.md` (T3, T10, T12).

## 2. Duplicate map

| Concern | Owner |
| --- | --- |
| Catalog and install | mctl-telegram#1002 |
| Connector threat model, per-tool approval | #1048 |
| Managed worker | #1088 |
| Schedules | mctlhq/.github#318 |
| Commerce accounting | mctlhq/.github#173 |
| Tenant boundary | mctlhq/.github#309 |
| Approval and human input | mctl-agents#198, #333 |
| Temporal client auth | mctl-gitops#1810, #1818 |

This spike adds nothing that duplicates them.

## 3. Provider evaluation

| Provider path | Capability | Auth model | Status |
| --- | --- | --- | --- |
| Glovo Discover MCP | search only, no cart | not assessed | UNVERIFIED terms |
| `denya/glovo-skill` (unofficial) | prepares an authenticated basket over consumer HTTP/session APIs; no checkout | consumer session | UNVERIFIED terms; session persistence is a credential-theft risk |
| Partner APIs | unknown | unknown | UNVERIFIED |

Montenegro coverage, terms of service and basket continuity (does the basket appear
in the user's phone app) are all `UNVERIFIED`. No cookie or token was used or pasted.
Until a sanctioned basket API exists, the adapter stays a fake.

## 4. Risk matrix

Extends threat-model.md T3 (cross-job and cross-account access), T10 (credential
confusion) and T12 (late or stale writes).

| Threat | Mitigation | Evidence |
| --- | --- | --- |
| Cross-tenant list, query, signal | server-side scope check on `(tenant_id, owner_principal_id, order_id)`, uniform not-found | PoC T14 |
| Wrong or default tenant | typed refusal, never `workContext.tenant` | PoC T15 |
| Direct Temporal ingress | only mctl-api is a client; surface has no namespace or workflow parameter | PoC T16; BLOCKED on frontend auth |
| Credential or cart leak into history, logs | opaque refs only, canary leak check | PoC T17 |
| Menu text injection | structured sanitized fields only reach the LLM | PoC T1 |
| Stale install | `RevalidateScope` before every write | PoC T6, T9 |
| Duplicate fire or button | workflow ID per occurrence, RejectDuplicate, consent applied once | PoC T10, T12 |
| Blind retry of a write | read-back verify | PoC T11 |
| False "paid" claim | outcome stays `OUTCOME_UNKNOWN` | PoC T7, T13 |
| One provider or tenant degrading others | per-provider breaker, per-tenant limit | PoC T18 |
| SSRF through provider URLs | `internal/netsafe` in the real adapter | design only |

Real-phone continuity: `UNVERIFIED`. The UI falls back to "Open Glovo and review the
basket" with no claimed deep link.

## 5. Child issues (draft text, not PRs)

- mctl-api: order index keyed by tenant and principal; assistant install keyed by
  `(tenant_id, owner_principal_id, assistant)`; personal scope after .github#309;
  sole Temporal client for assistants.
- mctl-gitops: `mctl-assistants` namespace (7-day retention), Temporal client auth
  and authorizer, provider worker namespace, egress allowlist and NetworkPolicy.
- mctl-telegram: owner-channel Glovo commands and the basket UI.
- mctlhq/.github#318: schedule contract (workflow ID scheme in the contract).
- mctl-agents: reuse of human input for basket consent.

## 6. Open questions

Whether the live cluster matches GitOps; actual namespaces present in Temporal;
Glovo terms and Montenegro coverage; sanctioned basket API; real-phone continuity.

## 7. PoC evidence

`cd test/glovo-poc && go test ./...` runs offline in a separate Go module (the root
module gains no `go.temporal.io/sdk` dependency). It uses a fake provider on
loopback, an in-memory control plane, the Temporal SDK test environment, and
synthetic personas Alice (`tenant-alpha`), Bob (`tenant-beta`) and Carol
(`tenant-gamma`, no install). Tests T1 to T18 map to test names carrying the same
number.

Limits, stated plainly:

- The Temporal test environment does not enforce `WorkflowIDReusePolicy`. T10
  asserts the ID scheme and a mocked ledger in the control plane; server-side
  enforcement is not exercised.
- T16 is checked at the surface request decoder (unknown fields refused), not
  against a real API server.
- T17 scans every payload that crosses the data converter, the order logs and
  results. Search attributes are not used by the PoC workflow, so none are scanned.
- T18 exercises the breaker and limiter as units, not a live task queue.
- Frontend authentication, the authorizer and real task-queue isolation are not
  tested; they are the recorded BLOCKERS.
