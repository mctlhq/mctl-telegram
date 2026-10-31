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

Each snippet below defines its ratio. The deployed 28-day compliance rules
compute these ratios, and the 1h and 6h error ratios the burn-rate alerts
read share their denominators, so a selector change here needs the same
change there. The rules aggregate with `sum by (job, namespace)` rather than
a bare `sum`, and fill an empty numerator with `0 *` the denominator, so a
window in which nothing matched the numerator records 0 instead of no value;
the comments in the rules file say why.

### MCP tool availability

Fraction of MCP tool invocations that complete with `status="ok"`, excluding
requests refused as the caller's mistake (see [Exclusions](#caller-errors)),
calls by a user with no connected account (see
[No active session](#no-active-session)) and the monitoring canary's own
calls (see [Canary traffic](#canary-traffic)):

```promql
sum(rate(mctl_tool_invocations_total{status="ok",traffic!="canary"}[28d]))
/
sum(rate(mctl_tool_invocations_total{status=~"ok|error",traffic!="canary"}[28d]))
```

Counter: `mctl_tool_invocations_total{tool,status,traffic}` — label values
for `status`: ok, error, caller_error, no_session; for `traffic`: user,
canary. The SLI selects `ok|error` by name, so these values are a contract:
a new one stays outside the SLI until it is added here and to the rules
deliberately. `traffic!="canary"` rather than `traffic="user"` so that a
series from a release before the label existed still counts as user
traffic.

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

Histogram: `mctl_tool_invocation_duration_seconds{tool}`. It has no
`traffic` label, so both latency SLOs include the canary's calls (see
[Canary traffic](#canary-traffic)).

### OAuth token-endpoint availability

Fraction of requests to `/oauth/token` and `/oauth/telegram/callback` that
return a non-5xx response:

```promql
sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback",status_code!~"5.."}[28d]))
/
sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback"}[28d]))
```

The numerator counts the non-5xx responses directly. The equivalent-looking
`1 - (5xx / total)` has no value when there were no 5xx at all, because a
selector that matches no series gives an empty result rather than zero: the
SLI would disappear exactly when OAuth is perfect.

Counter: `mctl_http_requests_total{method,route,status_code}`. It has no
`traffic` label, so this SLI includes the canary's requests (see
[Canary traffic](#canary-traffic)).

### Session borrow success rate

Fraction of `Pool.Borrow()` calls that succeed, excluding expected TTL
expirations, users with no connected account, Telegram replies over a
working session and the canary's own borrows (see
[Exclusions](#exclusions)):

```promql
sum(rate(mctl_sessions_borrow_total{result="ok",traffic!="canary"}[28d]))
/
sum(rate(mctl_sessions_borrow_total{result=~"ok|error",traffic!="canary"}[28d]))
```

Counter: `mctl_sessions_borrow_total{result,traffic}` — label values for
`result`: ok, expired_idle, expired_absolute, no_session, flood_wait,
call_error, error; for `traffic`: user, canary.

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

### Error-budget alerts

Each SLO with an error budget has an alert that fires once its
rolling-28-day SLI is below the target, which is the point at which the
policy above applies:

| Alert | Fires when | `for:` | Severity |
|-------|-----------|--------|----------|
| `MctlTelegramToolAvailabilityErrorBudgetExhausted` | `mctl_telegram:tool_availability:ratio_rate28d < 0.995` | 1h | warning |
| `MctlTelegramOAuthAvailabilityErrorBudgetExhausted` | `mctl_telegram:oauth_availability:ratio_rate28d < 0.999` | 1h | warning |
| `MctlTelegramSessionBorrowErrorBudgetExhausted` | `mctl_telegram:session_borrow_success:ratio_rate28d < 0.99` | 1h | warning |

They live in the `mctl-telegram-slo-budget` group of the same
`mctl-gitops` file as the burn-rate alerts. `for: 1h` keeps a ratio sitting
on the target from flapping at evaluation boundaries; a 28-day ratio moves
slowly, so it delays the signal very little. They are not routed to the
Telegram receiver: like the `SlowBurn` alerts they go to the default
receiver, which opens a ticket rather than paging.

The group is not merged before 2026-11-03. Until then the 28-day window
still holds samples recorded before the `flood_wait`/`call_error` split
(2026-10-06) and before `caller_error` existed, so the alerts would fire on
deploy for a state that has already been fixed. Each 28-day ratio is checked
against its target before the merge.

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
sum(rate(mctl_sessions_borrow_total{result=~"ok|error",traffic!="canary"}[28d]))
```

Selecting `ok|error` by name leaves out more than the TTL expirations:
`no_session`, `flood_wait` and `call_error` are outside it too (see below).
`traffic!="canary"` leaves out the canary's own borrows, for the reasons in
[Canary traffic](#canary-traffic).

### No active session

A call by a user who has no connected Telegram account — never connected,
or disconnected — fails with `db.ErrNoActiveSession` before Telegram is
called. `Pool.Borrow()` records it as
`mctl_sessions_borrow_total{result="no_session"}` and the tool layer as
`mctl_tool_invocations_total{status="no_session"}`, with
`reason="no_session"` on `mctl_tool_call_errors_total` and in the audit
row (it was `telegram_error`, which was wrong: Telegram was never asked).
Both are **excluded from both SLIs**, like a TTL expiry: it is user-side
state, not a service failure. The `audit_logs` row and the log line keep
`status=error`; the log line gains `slo_status=no_session`.

A disconnect that lands after `Pool.Borrow()` checked the session but
before the client loaded it counts the same way: the client fails with
`db.ErrNoActiveSession` before it connects to Telegram, and the borrow is
`no_session`.

A session check that could not be made (the store is unreachable) is not
`no_session`: it stays `error` and counts against the SLI.

Blind spot: a server bug that wrongly revokes sessions would move calls to
`no_session` instead of burning the SLI. That is caught where it starts —
`mctl_sessions_revoked_total{reason}` and the canary, which fails on
`no_session` — rather than by counting every disconnected user as an
outage.

Before mctl-telegram#974 these were `error`. Two disconnects of the
canary's own account (2026-10-23 and 2026-10-28/30) produced about 91% of
the 28-day tool errors and 83% of the borrow errors, and pulled the ratios
to 0.950 and 0.947.

### Canary traffic

The monitoring canary (`mctl-telegram-canary`, every 10 minutes) runs as the
accounts listed in `CANARY_TELEGRAM_IDS`. Every tool call and borrow made as
one of them carries `traffic="canary"`; everything else, including
background work and any call the server cannot place, is `traffic="user"`.
The label is derived from server config, never from the request, so it
cannot be used to move a call out of the SLI.

Canary traffic is **excluded from the tool-availability and session-borrow
SLIs**: every SLI selector on `mctl_tool_invocations_total` and
`mctl_sessions_borrow_total`, in this document and in the SLO rules file,
carries `traffic!="canary"`. The canary has its own success metric and alert
(`MctlTelegramCanaryFailing`); counted in the SLI as well, one canary outage
paged three ways, and because the canary was about a third of the 28-day
denominator its successes also flattered the SLI when real traffic was
degraded.

The OAuth SLI and the latency SLOs include the canary.
`mctl_http_requests_total` and `mctl_tool_invocation_duration_seconds` have
no `traffic` label, so there is nothing to select it out by. For OAuth that
is one request per canary run: the login-path probe's
`callback_unknown_state` step calls `/oauth/telegram/callback` with a state
the server never issued, gets the expected 200 and counts as a success. The
canary does not call `/oauth/token`.

### Telegram replies over a working session

Once the pool has handed out a connected client, an error returned by the
caller's function is labeled by what it says about the session:

- `mctl_sessions_borrow_total{result="flood_wait"}`: Telegram rate-limited
  the request (code 420, or `PEER_FLOOD`).
- `mctl_sessions_borrow_total{result="call_error"}`: Telegram answered and
  refused the request as the caller's mistake (code 400 or 403, such as an
  unknown peer or a missing permission).

Both are **excluded from the session-borrow SLI**. A reply from Telegram
shows the session works, so neither is a failure to provide one.
`borrowWithRetry()` calls `Pool.Borrow()` once per attempt, so a tool call
that succeeds after two flood-wait retries records two `flood_wait` and one
`ok`.

Everything else returned by the function stays `error` and counts against
the SLI: a session-auth rejection, a Telegram 5xx, a transport failure, a
cancelled or timed-out context, and any error that is not an MTProto reply.

Before 2026-10-06 all of these were `error`. Retried flood waits alone were
41 of 47 errors in 24 hours and fired `MctlTelegramSessionBorrowSlowBurn`
while 99% of tool calls succeeded. Sustained rate limiting is still visible
in `mctl_telegram_flood_wait_events_total{tool}`.

### Caller errors

A tool call that fails because the caller asked for something that cannot
be done is labeled
`mctl_tool_invocations_total{status="caller_error"}` and is **excluded
from both sides of the tool-availability SLI**. It covers:

- a Telegram reply refusing the request as the caller's mistake (code 400
  or 403, such as `CHANNEL_INVALID`, `PEER_ID_INVALID` or
  `CHAT_WRITE_FORBIDDEN`), including a peer the caller has no access hash
  for. This is the same definition as the session-borrow `call_error`
  above: `telegram.IsCallerRefusal` decides both;
- an argument, scope or tool-profile refusal that the failing code path
  itself named (`invalid_argument`, `scope_denied`, `profile_denied`), or
  the `identity missing scope` refusal. A reason guessed only from the error text is not trusted and
  stays `error`.

Everything else stays `error` and counts against the SLI: a session-auth
rejection (even one Telegram sends as a 400), `PEER_FLOOD` and any rate
limit that survives the retries, a Telegram 5xx, a transport failure, and a
store or handler failure.

Only the metric changes. The `audit_logs` row, the log line's `status` and
the trace keep `error`; the log line gains `slo_status=caller_error`.

The exclusion has one blind spot: a regression that turns every call into
a Telegram 400 would empty the SLI rather than burn it.
`MctlTelegramCallerErrorShareHigh` covers it by alerting when more than half
of an hour's tool calls (at least 20) are `caller_error`; see the runbook.

Before this split every failing call was `error`. Over four days in October
2026 all failed calls were caller refusals (unknown peers, missing
arguments, missing scope) and none was a server fault, yet the 28-day ratio
read 99.44%, under the 99.5% target.

### FLOOD_WAIT retries that ultimately succeed

`borrowWithRetry()` in `internal/mcp/tools.go` retries up to 3 times when
Telegram returns a `FLOOD_WAIT_X` error, sleeping up to 60 seconds per
attempt. If the final attempt succeeds, `mctl_tool_invocations_total{status="ok"}`
is incremented. Only terminal FLOOD_WAIT failures (retries exhausted) count
as errors in the tool-availability SLI. Each FLOOD_WAIT event (including
those on retried attempts) is counted separately in
`mctl_telegram_flood_wait_events_total{tool}`.
