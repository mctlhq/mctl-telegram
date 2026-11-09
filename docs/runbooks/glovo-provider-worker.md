# Glovo provider worker (fake-provider only)

`provider/glovo` is a nested Go module that builds `cmd/glovo-provider-worker`
and the image `Dockerfile.glovo-provider-worker`
(`ghcr.io/mctlhq/mctl-telegram-glovo-provider-worker` is the assumed name; the
image is **not published** by any workflow).

**This code authorizes no GitOps, Vault, DNS, namespace, Temporal namespace or
deploy change.** The worker is not deployable until the gates below close.

## What it is

The provider side of the boundary in `docs/adr/0010-glovo-multitenant-connections.md`.
It polls only the Temporal namespace `mctl-assistants-provider-glovo`, task queue
`assistants-provider-glovo` (compiled constants; any other value is a startup
error). It holds one Temporal client, used only by its own poller, and never
signals, queries, lists, cancels, terminates or starts workflows (enforced by an
AST test). The only provider adapter is the in-process `fakestore`; the
`glovo_real` build tag deliberately fails to compile.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `FAKE_ONLY` | none, image sets `true` | Must be exactly `true` or the worker exits non-zero |
| `TEMPORAL_HOSTPORT` | `localhost:7233` | Temporal frontend |
| `TEMPORAL_NAMESPACE` | `mctl-assistants-provider-glovo` | Must equal the default |
| `TEMPORAL_TASK_QUEUE` | `assistants-provider-glovo` | Must equal the default |
| `TEMPORAL_TLS_CERT_FILE`, `TEMPORAL_TLS_KEY_FILE`, `TEMPORAL_TLS_CA_FILE` | unset | Optional TLS files (cert and key together) |
| `HEALTH_ADDR` | `:8081` | Internal probe and metrics listener |
| `GLOVO_PROVIDER_DISABLED` | `false` | Kill switch |
| `WORKER_STOP_TIMEOUT` | `25s` | Graceful stop bound (max `28s`, below a 30s pod grace) |

Setting any of `GLOVO_*TOKEN*`, `GLOVO_*SESSION*`, `GLOVO_*COOKIE*`,
`GLOVO_*PASSWORD*`, `GLOVO_API_*` or `GLOVO_BASE_URL` makes the worker refuse to
start; only the variable name is logged.

## Probes and metrics

`/livez` and `/healthz` report liveness. `/readyz` is true only while the
poller runs, the kill switch is off and the provider breaker is closed.
`/metrics` exposes `mctl_glovo_provider_*` series. No ingress is defined.

## Kill switch and rollback

`GLOVO_PROVIDER_DISABLED=true` refuses new mutations with `provider_disabled`
(readiness goes false; shutdown and local reads proceed). An open breaker
refuses with `provider_unavailable`. Rollback of any future deployment is
re-pinning the previous image digest. Rolling back this change is
`git revert -m 1 <merge>`.

## Required pod spec (documentation only)

- security context: `runAsNonRoot: true`, `runAsUser: 1000`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`
- resources: requests `100m` / `64Mi`, limits `500m` / `256Mi`
- network: default-deny egress except the Temporal frontend
- no Vault token, no service-account token, no DevLoop access

## Control bridge

`internal/bridge.ControlBridge` (`ResolveScope`, `ConsumeApproval`) is the only
route to tenant authority. Only a deterministic fake exists. The binary wires an
empty fake, so every request is refused until a production bridge exists. The
wire format (`internal/protocol/v1alpha1`) is provisional pending
mctl-agents#1043. Local refusal codes beyond ADR 0010: `approval_invalid`,
`approval_expired`, `approval_replayed`, `intent_mismatch`, `bridge_unavailable`,
`provider_disabled`, `provider_unavailable`, `tenant_busy`, `invalid_request`,
`write_unverified`, `write_failed`.

## Gates still blocking deployment

G2, G3 and G5 of ADR 0010 remain open: the production bridge
(mctl-agents#1043, mctl-api#953, mctl-api#954), real provider access, and
Temporal namespace RBAC (mctl-gitops#2469). Publishing and deploying this image
need separate approvals.

## Reuse map from `test/glovo-poc`

| PoC | Promoted to | Tests |
| --- | --- | --- |
| `fakeglovo` | `internal/fakestore` | T1-T3, loopback rule, session isolation |
| `workflows` | `internal/workflows`, `internal/activities` | T4-T9c, T11-T13, T17 (revoke now ends in `revoked`, cancel in `cancelled`) |
| `controlplane.DecodeRequest` (T16) | `internal/protocol/v1alpha1` | forbidden-key table |
| `controlplane` T10, T14, T15 | `internal/bridge/fake` semantics | activity refusal tests |
| `fairness` | `internal/fairness` | T18 |
| `leakcheck` | `internal/leakcheck` | canary converter and log, metric, result scans |

`controlplane.CP` itself (links, membership, handoff token minting) stays a
control-plane responsibility and is not promoted. `test/glovo-poc` is unchanged.
