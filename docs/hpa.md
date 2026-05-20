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

Add the following PrometheusRule to alert on sustained pool-full conditions:

```yaml
- alert: MctlTelegramPoolNearCapacity
  expr: |
    mctl_telegram_client_pool_size / mctl_telegram_pool_capacity > 0.85
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "mctl-telegram session pool above 85% capacity"
    description: >
      Pod {{ $labels.pod }} is at {{ $value | humanizePercentage }} of its
      TELEGRAM_MAX_SESSIONS cap. Consider increasing the replica count or
      raising TELEGRAM_MAX_SESSIONS if headroom permits.
```

## Notes

- When `TELEGRAM_MAX_SESSIONS` is unset or 0, `mctl_telegram_pool_capacity` is
  set to -1 (meaning "uncapped"). The HPA expression above will produce negative
  values in that case and the HPA target will not trigger — which is intentional.
  Enable the cap explicitly before enabling HPA.

- The FloodWait counter `mctl_telegram_flood_wait_events_total` can be used to
  alert on Telegram rate-limit pressure independently of session count.

- `mctl_oauth_pending_auth_size` tracks the number of in-flight OAuth
  authorization flows. A sustained non-zero value with no corresponding traffic
  suggests abandoned flows or an uptick in bot-scan traffic against
  `/oauth/authorize`.

## Grafana dashboard

A pre-built operator dashboard is committed at
`deploy/grafana/mctl-telegram-beta.json`. Import it into Grafana via
**Dashboards > Import** and map the `DS_PROMETHEUS` input to your Prometheus
data source. The dashboard covers the same pool-utilization signal used by the
HPA (Session pool row) plus traffic, Telegram pressure, session lifecycle, OAuth,
and rate-limiting panels.
