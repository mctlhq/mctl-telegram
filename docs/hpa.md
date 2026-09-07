# Horizontal Pod Autoscaler (HPA) guide for mctl-telegram

## Per-session memory estimate

Each live MTProto client pool entry allocates:

- **One TCP connection** to a Telegram data center (~4 KB socket buffer in the
  kernel; negligible in heap terms).
- **gotd auth-key material**: approximately 200 B per client (AES-IGE key blob +
  server salt).
- **Two goroutines**: `run()` and `gc()`. Go's default initial goroutine stack is
  8 KiB; both stay near that floor for idle clients. Combined: ~16 KiB.
- **gotd client struct and MTProto layer**: about 250 KB of heap per idle client
  (send/receive buffers, codec state, inbox channel, pending-requests map). This
  is the dominant cost.

**Measured RSS delta (benchmark, amd64, Go 1.25, 100 idle sessions):**

| Metric              | Value |
|---------------------|-------|
| Baseline RSS        | ~30 MB |
| RSS at 100 sessions | ~58 MB |
| Delta per session   | ~2.8 MB |

Use **3 MB per session** as a conservative planning figure (includes OS/runtime
overhead on top of the measured delta).

## Recommended TELEGRAM_MAX_SESSIONS per pod memory tier

| Pod memory limit | Usable for sessions* | Recommended TELEGRAM_MAX_SESSIONS |
|-----------------|---------------------|----------------------------------|
| 256 MiB         | ~140 MB             | 45                               |
| 512 MiB         | ~340 MB             | 110                              |
| 1 GiB           | ~820 MB             | 270                              |

\* Assumes ~30% of pod memory is reserved for the HTTP server, Prometheus
collector, DB connection pool, and OS runtime. Adjust the margin for your
workload profile.

The configured value is logged at startup:

```
{"level":"INFO","msg":"session pool cap configured","max_sessions":110}
```

and exposed as the Prometheus gauge `mctl_telegram_pool_capacity`.

## Kubernetes HPA stanza

The following HPA scales mctl-telegram replicas when the average fraction of
the session pool in use across pods exceeds 70%. It requires the
[Prometheus Adapter](https://github.com/kubernetes-sigs/prometheus-adapter)
to expose the custom metrics.

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: mctl-telegram
  namespace: mctl
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: mctl-telegram
  minReplicas: 1
  maxReplicas: 10
  metrics:
    - type: Object
      object:
        describedObject:
          apiVersion: apps/v1
          kind: Deployment
          name: mctl-telegram
        metric:
          name: mctl_telegram_client_pool_utilization
        target:
          type: Value
          value: "0.7"
```

The custom metric `mctl_telegram_client_pool_utilization` should be defined in
the Prometheus Adapter config as:

```yaml
rules:
  - seriesQuery: 'mctl_telegram_client_pool_size{namespace!="",pod!=""}'
    resources:
      overrides:
        namespace: { resource: namespace }
        pod: { resource: pod }
    name:
      matches: "mctl_telegram_client_pool_size"
      as: "mctl_telegram_client_pool_utilization"
    metricsQuery: >-
      mctl_telegram_client_pool_size{<<.LabelMatchers>>}
      /
      mctl_telegram_pool_capacity{<<.LabelMatchers>>}
```

The mctl-gitops kustomize base for this adapter configuration lives under
`platform-gitops/k8s/prometheus-adapter/`.

## Alerts

The three alerts below are live, defined as a `VMRule` in mctl-gitops at
`platform-gitops/infra-components/observability/vm-rules/mctl-telegram-ops.yaml`.
That directory is what ArgoCD reconciles, and it is the only path by which an
alert reaches this cluster. `deploy/alerts/mctl-telegram.rules.yaml` in this
repository holds the same expressions as a **non-deployed reference** — see the
header comment in it before editing anything there.

- **MctlTelegramPoolNearCapacity** (warning at >85%, critical at >95%) — fires
  when the session pool fills up and the cap is positive.
- **MctlTelegramFloodWaitSpike** (warning at >0.5 events/s, critical at >2
  events/s) — fires on sustained Telegram rate-limit pressure.
- **MctlTelegramOAuthPendingStuck** (warning) — fires when more than 100
  OAuth authorization flows remain in-flight for 15 minutes or longer.

`MctlTelegramPoolNearCapacity` is deployed but **cannot currently fire**, and
that is by design rather than a defect. Both of its rules carry
`and mctl_telegram_pool_capacity > 0`, and the gauge reads `-1` whenever
`TELEGRAM_MAX_SESSIONS` is 0 or unset, which is the case today. Deploying it
now means that setting a cap is a configuration change and not also an
alerting change. Until a cap is set, treat pool saturation as unmonitored: the
rule exists, it is simply not covering anything yet.

A one-off `kubectl apply` of the manifest here is not a deployment, and it does
not clean itself up either. The applied object carries no ArgoCD tracking
metadata, so ArgoCD neither adopts nor prunes it: it stays active
indefinitely, drifting silently from this file, and will later fire alongside
whatever gets ported properly. If you or anyone else ever applied one of these
by hand, find and delete it explicitly; do not expect a reconcile to remove
it.

Find the strays by the tracking metadata ArgoCD stamps on what it manages. In
this cluster that is the annotation `argocd.argoproj.io/tracking-id` — checked
on a managed rule, which carries the annotation and no
`app.kubernetes.io/instance` label, so filtering on the label would list every
managed rule as a stray:

```
kubectl get prometheusrule,vmrule -A -o json | jq -r '
  .items[]
  | select(.metadata.annotations["argocd.argoproj.io/tracking-id"] == null)
  | "\(.kind) \(.metadata.namespace)/\(.metadata.name)"'
```

Confirm the method before trusting the output —
`kubectl get cm argocd-cm -n argocd -o jsonpath='{.data.application\.resourceTrackingMethod}'`
— since under label tracking the key is `app.kubernetes.io/instance` instead.
Read the list before deleting anything: an object may be unmanaged for reasons
other than a stray `kubectl apply`.

The SLO-level burn-rate alerts (MCP tool availability, OAuth endpoint
availability, session borrow success rate) have already been ported, as
`mctl-telegram-slo.yaml`; see [docs/slo.md](slo.md).

## Notes

- When `TELEGRAM_MAX_SESSIONS` is unset or 0, `mctl_telegram_pool_capacity` is
  set to -1 (meaning "uncapped"). The HPA expression above will produce negative
  values in that case and the HPA target will not trigger — which is intentional.
  Enable the cap explicitly before enabling HPA.

- The FloodWait counter `mctl_telegram_flood_wait_events_total` is covered by
  the `MctlTelegramFloodWaitSpike` alert defined in
  `deploy/alerts/mctl-telegram.rules.yaml`.

- `mctl_oauth_pending_auth_size` is covered by the
  `MctlTelegramOAuthPendingStuck` alert defined in
  `deploy/alerts/mctl-telegram.rules.yaml`.

## Grafana dashboard

A pre-built operator dashboard is committed at
`deploy/grafana/mctl-telegram-beta.json`. Import it into Grafana via
**Dashboards > Import** and map the `DS_PROMETHEUS` input to your Prometheus
data source. The dashboard covers the same pool-utilization signal used by the
HPA (Session pool row) plus traffic, Telegram pressure, session lifecycle, OAuth,
and rate-limiting panels.

## Sticky routing for multi-replica deployments

### Problem

`internal/telegram/clientpool.go` (lines 60-91) maintains a per-process map
from `user_id` to a live `*telegram.Client` goroutine. This state is not shared
across pods: when the Kubernetes Deployment scales to two or more replicas, a
user whose requests land on different replicas triggers a fresh MTProto session
on each replica. Telegram treats each new session as a new device login and
fires a "New login" security notification — damaging user trust and raising red
flags for security-conscious users. In addition, pool memory grows in proportion
to (active users * replicas) instead of active users alone, undermining the
capacity planning described above.

### Two-layer solution

Sticky routing operates at two independent layers, both of which must be active
for multi-replica deployment to be safe:

> **Status:** Layer 2 (replica-identity observability) ships in this repository.
> Layer 1 (the ingress consistent-hash manifests) is **not** shipped here yet —
> it is tracked separately in issue #126 with a controller-acceptance gate,
> because the ingress Lua + Istio/Envoy config semantics are an error-prone area
> that needs its own design + review cycle. The description below documents the
> intended Layer-1 design.

**Layer 1 — Load-balancer consistent-hash routing** (tracked in issue #126):
An ingress-tier Lua snippet extracts the `sub` claim from the JWT payload
(`tg:<telegram_id>`), sets it as the `X-Mctl-Route-Key` request header, and
NGINX (or Envoy) performs ketama consistent-hash routing on that header value.
All requests for the same `sub` reach the same upstream pod. When a pod is added
or removed, only the minimum subset of users affected by the rehash moves;
unaffected users keep hitting their existing pod with no new session.

**Layer 2 — Replica identity observability** (this repository):
`mctl_telegram_replica_id{replica_id="..."}` is an info-type Prometheus gauge
(constant value 1) that appears on every pod's `/metrics` endpoint. Operators
cross-reference it with `mctl_telegram_client_pool_size` to verify that sticky
routing is in effect.

### Security analysis for payload-only JWT extraction at the routing tier

The JWT signature is **not** verified at the ingress tier. This is intentional:

- NGINX community edition and Envoy without the Istio JWT AuthN filter do not
  ship HS256 verification as a first-class feature. Adding it would require
  distributing `OAUTH_JWT_SIGNING_KEY` outside the pod boundary, increasing the
  attack surface for key exposure.
- The routing key carries **no authorization weight**. The application's auth
  middleware (`internal/auth/middleware.go`) re-verifies the full JWT signature
  on every request and rejects any tampered token before it reaches any handler.
- A client that edits its JWT payload to change the `sub` claim changes only
  which pod handles the request; the forged token is then rejected by that pod's
  own auth check. **No privilege escalation is possible.**

The ingress configuration **must** strip the `X-Mctl-Route-Key` header from
client requests before the Lua extraction step so that a client cannot inject a
routing key without a valid JWT.

### Downward API snippet for POD_NAME

Wire the `POD_NAME` environment variable via the Kubernetes downward API in the
Deployment spec so that the `mctl_telegram_replica_id` gauge and startup log
line carry a meaningful value:

```yaml
env:
  - name: POD_NAME
    valueFrom:
      fieldRef:
        fieldPath: metadata.name
```

`REPLICA_ID` takes precedence if set. If neither is set, the value falls back to
`"unknown"` and startup continues normally. A monitoring alert on
`mctl_telegram_replica_id{replica_id="unknown"}` can catch missing downward API
configuration.

### Verification

After deploying with sticky routing enabled, verify on each pod:

```bash
kubectl exec -n mctl <pod-name> -- \
  wget -qO- http://localhost:8080/metrics | grep mctl_telegram_replica_id
```

Expected output (one line per pod, each with a distinct `replica_id`):

```
mctl_telegram_replica_id{replica_id="mctl-telegram-7f9d-abc12"} 1
```

Cross-reference with the pool size gauge to confirm that each pod serves a
distinct, non-overlapping set of users:

```bash
kubectl exec -n mctl <pod-name> -- \
  wget -qO- http://localhost:8080/metrics | grep mctl_telegram_client_pool_size
```

### One-time "New login" events on pod restarts and rehashes

When a pod is restarted or when the consistent-hash ring rebalances after a
scale-out event, a subset of users is remapped to a different pod. Each remapped
user will experience a one-time "New login" Telegram security notification as
their MTProto session is re-established on the new pod. This is unavoidable
with in-process session state. After the rebalance stabilizes, sticky routing
prevents further spurious notifications.

Monitor `mctl_telegram_client_errors_total` for spikes after scale events as an
indirect indicator of session churn.

### Ingress manifests (deferred — issue #126)

The Layer-1 ingress reference manifests (NGINX `access_by_lua_block` consistent-hash
routing and the Istio EnvoyFilter equivalent) are **not** in this repository yet.
They are tracked in issue #126, which requires a controller-acceptance gate before
merge: the NGINX config must pass reload/admission, the EnvoyFilter must show up in
`istioctl proxy-config` after `istioctl analyze`, and a bearer-token request must
flow through without a Lua runtime error. Until that lands, run multi-replica
deployments only with an externally provided, validated consistent-hash ingress.
