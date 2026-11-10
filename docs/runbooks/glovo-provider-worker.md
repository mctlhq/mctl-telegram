# Glovo provider worker (fake-provider only, command bridge)

`provider/glovo` is a nested Go module that builds `cmd/glovo-provider-worker`
and the image `Dockerfile.glovo-provider-worker`
(`ghcr.io/mctlhq/mctl-telegram-glovo-provider-worker` is the assumed name; the
image is **not published** by any workflow).

**This code authorizes no GitOps, Vault, DNS, namespace or deploy change, and it
issues no credential.** The worker is not deployable until the gates below close.

## What it is

The provider side of the mctl-api command bridge (mctlhq/mctl-api#968,
`docs/bridge.md`). It holds **no Temporal credential and no Temporal SDK**: its
only control-plane I/O is an HTTP client for three routes of mctl-api. It polls
`POST /api/v1/bridge/commands/claim`, asks for a single-use write permit with
`POST /api/v1/bridge/commands/{id}/write-permit` before each mutating kind, runs
the effect against the in-process `fakestore`, and posts exactly one v1alpha1
result to `POST /api/v1/bridge/commands/{id}/result`. mctl-api alone decides
scope, tenant, owner and approval; the provider has no `ResolveScope` or
`ConsumeApproval` of its own. The `glovo_real` build tag deliberately fails to
compile.

Wire: the v1alpha1 schemas are byte copies from mctl-api `internal/bridge/schema`
(merge `14645f93`); the one v1alpha2 command, `place_order_fake`, and the
`claim/v1alpha2` envelope come from mctl-agents `docs/contracts/bridge/v1alpha2`.
Both are pinned by sha256 in `internal/protocol/v1alpha1/wire_test.go`. The wire
changes only through mctl-agents#1044, this module and mctl-api#957 together.

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `FAKE_ONLY` | none, image sets `true` | Must be exactly `true` or the worker exits non-zero |
| `MCTL_API_BASE_URL` | required | mctl-api origin only (scheme and host, optional port). `https`; `http` only for loopback |
| `MCTL_BRIDGE_CREDENTIAL_FILE` | required | File holding the bearer credential, re-read on every request |
| `BRIDGE_WORKER_IDENTITY` | `provider:glovo` | Must match `^provider:[a-z0-9-]{1,32}$`; a command for another audience is refused locally |
| `BRIDGE_CLAIM_MAX` | `4` | Claim batch, 1..10 |
| `BRIDGE_POLL_INTERVAL` | `2s` | Claim interval, 500ms..60s |
| `HEALTH_ADDR` | `:8081` | Internal probe and metrics listener |
| `GLOVO_PROVIDER_DISABLED` | `false` | Kill switch |
| `WORKER_STOP_TIMEOUT` | `25s` | Graceful stop bound (max `28s`, below a 30s pod grace) |

Setting any `TEMPORAL_*` variable makes the worker refuse to start (names only
are listed): a stale Temporal manifest must not go unnoticed. Setting any of
`GLOVO_*TOKEN*`, `GLOVO_*SESSION*`, `GLOVO_*COOKIE*`, `GLOVO_*PASSWORD*`,
`GLOVO_API_*` or `GLOVO_BASE_URL` also refuses to start. Errors never carry a
value or the credential path.

The credential is only ever sent as `Authorization: Bearer`. It is held in a type
whose string, JSON and log forms are `[redacted]`; `Authorization` and
`lease_token` are on the log redaction list.

## Egress

**Default-deny egress; egress only to the mctl-api origin** (documentation of the
pod spec below, not something this code enforces by itself). In code the HTTP
client refuses, before dialing, any request outside the configured origin or
outside `/api/v1/bridge/commands/`, follows no redirect and ignores proxy
environment variables. Each request has a 10s timeout and a 64 KiB response cap.

## Rate budget

mctl-api allows 120 requests per minute per principal across all three routes.
At the defaults (poll 2s is 30 claims per minute, batch 4, at most one permit
and one result per command) a steady 10 commands per minute uses about 50
requests per minute. A claim 429 waits at least `Retry-After`; backoff is
exponential with jitter up to 60s.

## Per-command behaviour

1. Parse against the schema chosen by `schema_version`, then strict-decode.
   v1alpha2 is accepted only for `place_order_fake`; any other combination, and
   any unknown `schema_version`, is refused locally. A `claim/v1alpha2` envelope
   is accepted; an unknown envelope version is a failed claim and nothing in it
   is parsed. A v1alpha2 command inside a v1alpha1 envelope is refused.
2. Pre-flight: `cancel_requested`, past `expires_at`, kill switch, open breaker,
   tenant concurrency.
3. `quote` and `read_status` never request a permit. `place_order_fake` and
   `cancel_order_fake` request exactly one permit, run exactly one fake effect
   keyed by `command_id`, read it back, and only then report `applied`.
4. A mutation whose `command_id` already has a local effect record came back after
   a reclaim. mctl-api has already turned `permitted` into `unknown`, and refuses
   `applied` unless the state is `permitted`, so the worker reports
   `failed_terminal`/`internal`/`unknown` with `error_detail=applied_prior_lease`
   and requests no permit.
5. The result is encoded once and schema-validated; every retry resends the same
   bytes. Two deadlines apply: the permit request and the effect stop at the
   lease deadline, `min(expires_at, claim time + 60s lease - 5s)`; result retries
   run until `expires_at`, because mctl-api accepts a same-token replay after the
   lease ran out. `lease_stale` stops both.

### Outcome map

The map is final within the frozen `result.schema.json` enums (posted to
mctl-api#957). It is generated from the single table in `internal/executor`
(`DUMP_OUTCOME_TABLE=<file> go test -run TestDumpTable ./internal/executor`) and
asserted equal to it by `TestRunbookMatchesExecutorTable`.

| Situation | outcome | error_code | provider_effect | Next step |
|---|---|---|---|---|
| quote / read_status ok | succeeded | none | none | submit |
| mutation applied under this lease's permit | succeeded | none | applied | submit |
| mutation re-delivered after reclaim, local effect record exists | failed_terminal | internal (`error_detail=applied_prior_lease`) | unknown | submit, no permit |
| schema-invalid / audience mismatch | failed_terminal | provider_rejected (`error_detail=schema_invalid`) | none | submit if envelope valid, else drop |
| cancel_requested=true (unreachable on mctl-api a9ca5814; defence) | cancelled | none | none | submit |
| kill switch / breaker open / tenant busy | failed_retryable | provider_unavailable | none | submit |
| fakestore 429 / transient read failure | failed_retryable | provider_unavailable | none | submit |
| unknown or revoked fake session, item unavailable, no order to cancel | failed_terminal | provider_rejected | none | submit |
| ambiguous write | failed_terminal | provider_unavailable | unknown | submit, never retry |
| permit write_fence_refused (403) | approval_refused | approval_refused | none | submit |
| permit write_fence_unavailable (503) | failed_retryable | internal (`error_detail=write_fence_unavailable`) | none | submit |
| permit permit_already_issued (409; owner decision 2026-11-09) | failed_terminal | internal (`error_detail=permit_already_issued`) | unknown | submit |
| permit not_mutating (409) | failed_terminal | internal (`error_detail=not_mutating`) | none | submit |
| permit 429 | failed_retryable | provider_unavailable | none | submit |
| permit 5xx (not the 503 fence) / transport | failed_retryable | provider_unavailable | none | submit |
| any call lease_stale / command_expired / command_cancelled | - | - | - | stop, no result |
| any call command_not_found (404) | - | - | - | stop, metric |
| result replayed:true | - | - | - | done |
| result already_completed (unreachable on a9ca5814; defence only) | - | - | - | done |
| result result_conflict | - | - | - | log code + metric, no resend |
| result invalid_document / binding_mismatch / result_inconsistent | - | - | - | log code + metric (bug), no resend |
| result 5xx / 429 / transport | - | - | - | resend the same bytes, backoff 250ms..8s (429: at least Retry-After), until expires_at |
| claim 429 | - | - | - | back off at least Retry-After |
| any call 401 (no code) | - | - | - | stop the command, readiness fails, claim backs off at cap |
| any other status/code, or unparseable body | - | - | - | fail closed: no effect, no new body, metric unmapped_responses_total{route} |

The rows labelled unreachable describe defence only: on mctl-api `a9ca5814` a
claimed command never carries `cancel_requested=true` and `already_completed` is
returned only by the control-side cancel path. Nobody should read them as tested
server behaviour.

## Probes and metrics

`/livez` and `/healthz` report liveness (process level). `/readyz` is true only
while the last successful claim is within a window of 3 poll intervals (at least
30s), the kill switch is off and the breaker is closed; it fails at once while
the bridge answers 404, 401 or 403. `/metrics` exposes `mctl_glovo_provider_*`
series with no id labels: `commands_total{kind,outcome,effect}`,
`permits_total{result}`, `results_total{status}`, `result_conflicts_total`,
`ambiguous_writes_total`, `claim_errors_total{code}`,
`commands_dropped_total{reason}` and `unmapped_responses_total{route}`. No
ingress is defined.

## Kill switch and rollback

`GLOVO_PROVIDER_DISABLED=true` answers every command with
`failed_retryable`/`provider_unavailable`/`none` without a permit (readiness goes
false). An open breaker does the same. Rolling back this change is
`git revert -m 1 <merge>`; nothing needs undoing in GitOps, Vault, Temporal or
mctl-api.

## Required pod spec (documentation only)

- security context: `runAsNonRoot: true`, `runAsUser: 1000`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`,
  `capabilities.drop: [ALL]`, `seccompProfile.type: RuntimeDefault`
- resources: requests `100m` / `64Mi`, limits `500m` / `256Mi`
- network: default-deny egress; egress only to the mctl-api origin
- no Vault token, no service-account token, no DevLoop access, no Temporal access

## Gates still blocking deployment

Deployment, publishing and any credential issue need separate approvals:
mctl-gitops#2457 (credential and the plaintext lease token column decision),
mctl-gitops#2506 and #2540, `MCTL_BRIDGE_ENABLED` and `MCTL_BRIDGE_PROVIDERS` in
mctl-api (the bridge ships dark and its production state was not observed), and
OPEN-986-6 (the real provider entry must declare v1alpha2 before the first
dispatch). A real adapter needs durable dedupe: the in-process effect record is
lost on restart, which is why `permit_already_issued` reports `unknown`.

## Stop conditions

Stop and page a human on: `result_conflicts_total` above zero,
`unmapped_responses_total` above zero, `ambiguous_writes_total` above zero,
repeated `claim_errors_total{code="refused"}`, or any credential appearing in a
log line.

## Reuse map

| Earlier work | Now | Tests |
| --- | --- | --- |
| `fakeglovo` (PoC) | `internal/fakestore` (plus `FAKE-1..3`, `PlaceOrderFake`, `CancelOrderFake`, `EffectOf`, `OrderStatus`, `Revoke`) | store and order-write tests |
| #1258 `workflows`, `activities`, `bridge`, `basket` | not ported; replaced by `internal/poller`, `internal/executor`, `internal/bridgeclient` | poller and executor tests |
| #1258 `protocol` `ProviderRequest` | replaced by the bridge wire in `internal/protocol/v1alpha1` | wire tests |
| `fairness`, `leakcheck`, `obs`, `health`, `fakeonly` | kept (`obs` lost its Temporal interceptor) | package tests |
