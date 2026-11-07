# 0009. Assistant Temporal tenancy: a shared `mctl-assistants` namespace

Status: Proposed. Spike: [glovo-assistant-spike.md](../reports/glovo-assistant-spike.md)
(#1184). Nothing in this record is deployed.

## Context

Assistant orders (first candidate: the Glovo basket handoff, see
[glovo-checkout-handoff.md](../contracts/glovo-checkout-handoff.md)) need durable
workflows. The Temporal cluster has no client authentication; the NetworkPolicy is
the only boundary, and any admitted pod can reach every namespace
(`infra-components/data/temporal/networkpolicy.yaml` in mctl-gitops, #1810/#1818).
Existing namespaces are `kuptsi` and `mctl-agents`. mctl-telegram's deployment
assigns all work items to the single tenant `mctl`.

## Decision (candidate)

**Option B: one shared namespace per environment, `mctl-assistants`**
(`mctl-assistants-poc` for a disposable non-prod run), with isolation done in the
MCTL control plane:

- Only mctl-api (the Automation Control Plane) is a Temporal client for start,
  signal, query and list. Surfaces call mctl-api with an authenticated principal and
  an opaque `order_id`. mctl-api derives the workflow ID server-side
  (`glovo-order/<tenant_id>/<order_id>`) and checks
  `(tenant_id, owner_principal_id)` against its own order index first. Listing uses
  that index, never Temporal visibility queries built from client input.
- Queues: `assistants-control` (trusted worker) and `assistants-provider-glovo`
  (low-trust provider worker in its own Kubernetes namespace, candidate
  `assistants-provider`, provider-only egress allowlist with `netsafe` semantics, no
  Vault token, no access to DevLoop queues).
- Fairness: per-tenant concurrency and rate limits in the control workflow; a
  per-provider circuit breaker. Per-tenant task queues are the promotion step when
  one tenant's backlog measurably delays others. Per-personal-user queues are never
  the default.
- Retention 7 days. Histories hold only opaque IDs.

## Options compared

| | A: `mctl-agents` | B: shared `mctl-assistants` | C: namespace per tenant |
| --- | --- | --- | --- |
| Queues | mixed with `mctl-dev-loop*` | own control and provider queues | per tenant |
| K8s namespaces | existing workers | one provider worker namespace | one per tenant, plus fan-out |
| Retention | 30 days | 7 days | per tenant |
| Authorizer prerequisite | yes | yes | yes, less critical |
| Blast radius | DevLoop privileged queues and all DevLoop clients | all assistant orders, bounded by control-plane checks | one tenant |
| Cost | lowest | low | one bootstrap line, retention and search attributes per tenant in `tenant-namespace-job.yaml`, worker fan-out |

Option A is rejected: it mixes untrusted provider I/O with privileged queues, and
every DevLoop client could touch assistant orders. Option C is the high-assurance
fallback.

## Promotion from B to C

A compliance requirement, a hard auth or rate-limit boundary for a tenant, or
measured noisy-neighbour impact that per-tenant queues do not fix.

## Identity chain

```
telegram_user_id -> SurfaceIdentityLink (verified) -> owner_principal_id
  -> tenant membership -> tenant_id          | no_tenant / ambiguous_tenant
  -> install (tenant, owner, assistant)      -> assistant_install_id + install_revision
  -> glovo_connection (owner-bound secret)   -> glovo_connection_id | no_connection
```

Fail closed on any missing, revoked, expired or ambiguous link, with a typed reason.
The tenant is an explicit owner choice when the principal has several; it is never
the deployment's `workContext.tenant`. `personal:<principal>` is modelled but refused
until mctlhq/.github#309 defines it. Today's per-Telegram-account install stays; a
Glovo install is a separate record (follow-up for #1002).

## BLOCKER

Multi-tenant rollout is BLOCKED until all of: Temporal frontend client auth (mTLS or
JWT) with an authorizer scoping each client identity to its namespace and queue;
narrowed NetworkPolicy entries for the assistant workers; independent
tenant-isolation threat-model tests. The NetworkPolicy alone is not enough.

## Consequences

Isolation rests on mctl-api correctness until the authorizer exists. Shared
retention and search attributes need one registration job entry. A provider outage
is contained by the per-provider breaker, not by namespace separation.
