# Beta SLOs for mctl-telegram

This document defines the Beta-tier Service-Level Objectives (SLOs) for
mctl-telegram, the corresponding SLI PromQL expressions, the error-budget
policy, and the exclusions that govern how specific failure modes are
counted.

Deployed alert rules: the burn-rate alerts and the SLI recording rules this
document defines are deployed from `mctl-gitops`, at
`platform-gitops/infra-components/observability/vm-rules/mctl-telegram-slo.yaml`
(a `VMRule` — the cluster's alerting engine is VMAlert, and that file is what
ArgoCD reconciles). The tables in this document are the source of truth for
the numbers; that file is the only thing that changes what the cluster does.
So a threshold change is two steps in this order: edit the table here, then
open the `mctl-gitops` PR that makes the rule match it. Doing only the second
leaves this document asserting a number the cluster does not use, which is the
drift this section exists to prevent.

Deployed alert names: `MctlTelegramToolAvailability{Fast,Slow}Burn`,
`MctlTelegramOAuthAvailability{Fast,Slow}Burn`,
`MctlTelegramSessionBorrow{Fast,Slow}Burn`. Severities there read `critical` and
`warning` rather than the `page` / `ticket` used below, because that is the
convention every other rule in that cluster follows; the page semantics are
preserved by routing the three `FastBurn` alert names to the Telegram receiver
in Alertmanager.

Reference-only alert YAML:
[`deploy/alerts/mctl-telegram.rules.yaml`](../deploy/alerts/mctl-telegram.rules.yaml).
That file is **not deployed by anything** — see the header comment in it.

---

## SLI definitions

### MCP tool availability

Fraction of MCP tool invocations that complete with `status="ok"`.

```promql
sum(rate(mctl_tool_invocations_total{status="ok"}[28d]))
/
sum(rate(mctl_tool_invocations_total[28d]))
```

### MCP tool latency — read tools (p95 and p99)

p95 latency across all read-only tools:

```promql
histogram_quantile(0.95, sum by(le)(
  rate(mctl_tool_invocation_duration_seconds_bucket{
    tool=~"list_dialogs|get_unread_messages|get_messages|get_my_audit_log|prepare_pin_message|list_telegram_identities"
  }[5m])
))
```

p99 latency across all read-only tools (replace `0.95` with `0.99`).

### MCP tool latency — destructive/send tools (p95)

p95 latency across destructive tools:

```promql
histogram_quantile(0.95, sum by(le)(
  rate(mctl_tool_invocation_duration_seconds_bucket{
    tool=~"send_message|pin_message|disconnect_telegram_account|delete_telegram_account"
  }[5m])
))
```

### OAuth token-endpoint availability

Fraction of requests to `/oauth/token` and `/oauth/telegram/callback` that
return a non-5xx response:

```promql
1 - (
  sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback",status_code=~"5.."}[28d]))
  /
  sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback"}[28d]))
)
```

### Session borrow success rate

Fraction of `Pool.Borrow()` calls that succeed, excluding expected TTL
expirations (see [Exclusions](#exclusions)):

```promql
sum(rate(mctl_sessions_borrow_total{result="ok"}[28d]))
/
sum(rate(mctl_sessions_borrow_total{result=~"ok|error"}[28d]))
```

Counter: `mctl_sessions_borrow_total{result}` — label values: ok,
expired_idle, expired_absolute, error.

---

## Tool classification

| Tool | Kind |
|------|------|
| `list_dialogs` | read |
| `get_unread_messages` | read |
| `get_messages` | read |
| `get_my_audit_log` | read |
| `prepare_pin_message` | read |
| `list_telegram_identities` | read (admin) |
| `send_message` | destructive |
| `pin_message` | destructive |
| `disconnect_telegram_account` | destructive |
| `delete_telegram_account` | destructive |

Admin-only tools (`list_telegram_identities`, `set_telegram_access`,
`get_user_audit_log`, `revoke_telegram_session`) are excluded from the
latency SLO; their invocation frequency is too low to compute a meaningful
quantile.

---

## SLO targets

| SLO | Target | 30-day error budget |
|-----|--------|---------------------|
| MCP tool availability | 99.5% | 3 h 36 min |
| MCP tool latency p95 read | p95 < 2 s | N/A |
| MCP tool latency p99 read | p99 < 5 s | N/A |
| MCP tool latency p95 send | p95 < 4 s | N/A |
| OAuth token-endpoint availability | 99.9% | 43 min |
| Session borrow success rate | 99% | 7 h 12 min |

Latency SLOs use sustained-breach alerting rather than an error-budget model
because histogram bucket resolution does not support sub-second budget
accounting.

The 28-day range in SLI expressions is a standard approximation for a 30-day
rolling window (4 calendar weeks, Prometheus-cache-friendly).

---

## Multi-window burn-rate alert thresholds

Burn-rate alerts fire when the error rate is a multiple of the allowed
hourly error rate. Using the 99.5% tool-availability SLO (0.5% error budget)
as an example:

| Window | Burn multiplier | Alert threshold | Severity |
|--------|----------------|-----------------|----------|
| 1 h | 14.4x | 7.2% error rate | page |
| 6 h | 6x | 3.0% error rate | ticket |

OAuth availability SLO (0.1% budget):

| Window | Burn multiplier | Alert threshold | Severity |
|--------|----------------|-----------------|----------|
| 1 h | 14.4x | 1.440% error rate | page |
| 6 h | 6x | 0.600% error rate | ticket |

Session borrow success rate SLO (1% budget):

| Window | Burn multiplier | Alert threshold | Severity |
|--------|----------------|-----------------|----------|
| 1 h | 14.4x | 14.4% error rate | page |
| 6 h | 6x | 6.0% error rate | ticket |

The `for: 0m` convention is used on burn-rate alerts. The burn window itself
provides the statistical stabilization; adding a separate `for:` duration
would delay the alert by double and mask fast incidents.

---

## Error-budget policy

When the rolling-28-day SLI for any SLO drops below its target (budget
exhausted):

1. **Freeze non-critical feature merges.** Only PRs labeled `reliability`
   or `security` may merge. Bug fixes and hotfixes are exempt.

2. **Gate new production deploys.** A deploy may proceed only when the 6h
   burn rate for the affected SLO is below 1x (budget is not actively
   burning) at the time of the deploy.

3. **Restore policy.** Normal merge flow resumes once:
   - The rolling-28-day SLI returns to its target, AND
   - The remaining error budget is at least 50% (the burn rate has been
     below 1x for long enough to recover half the window).

---

## Exclusions

### Session TTL expirations

When `Pool.Borrow()` calls `db.Store.CheckSessionValid()` and the session has
exceeded its idle TTL (30 days) or absolute TTL (90 days), the store revokes
the row and returns `db.ErrSessionExpired` with reason `ReasonIdle` or
`ReasonAbsolute`. These exits are labeled:

- `mctl_sessions_borrow_total{result="expired_idle"}`
- `mctl_sessions_borrow_total{result="expired_absolute"}`

Both label values are **excluded from the session-borrow SLI denominator**.
TTL expiry is expected user-side state (the user has not used the service in
over 30 days), not a service failure. The SLI denominator is:

```promql
sum(rate(mctl_sessions_borrow_total{result=~"ok|error"}[28d]))
```

### FLOOD_WAIT retries that ultimately succeed

`borrowWithRetry()` in `internal/mcp/tools.go` retries up to 3 times when
Telegram returns a `FLOOD_WAIT_X` error, sleeping up to 60 seconds per
attempt. If the final attempt succeeds, `mctl_tool_invocations_total{status="ok"}`
is incremented. Only terminal FLOOD_WAIT failures (retries exhausted) count
as errors in the tool-availability SLI. Each FLOOD_WAIT event (including
those on retried attempts) is counted separately in
`mctl_telegram_flood_wait_events_total{tool}`.
