# Runbook: `MctlTelegramCanaryFailing`

The mctl-telegram synthetic canary CronJob has been reporting
`mctl_telegram_canary_success = 0` for every scrape in the last 10
minutes and the condition has persisted for at least 5 minutes.

User-visible impact: end-to-end Telegram tooling is likely broken for
real users, even though individual components may be healthy.

## What the alert means

The canary CronJob (`deploy/canary/cronjob.yaml`, schedule
`*/2 * * * *`) runs `cmd/canary` against the production tg.mctl.ai
endpoint. Each run exercises:

1. `oauth_metadata` — `GET /.well-known/oauth-authorization-server`
2. `mcp_init` — MCP session initialization (`method: initialize`, obtains `Mcp-Session-Id`)
3. `list_dialogs` — MCP JSON-RPC call requiring a valid bearer token
4. `get_unread_messages` — optional MCP call (`CANARY_PROBE_UNREAD=true`)

A successful run pushes `mctl_telegram_canary_success=1`. Any step
failure pushes `0` and increments
`mctl_telegram_canary_step_failure_total{step=...}`.

## Triage

1. Identify the failing step:
   ```promql
   mctl_telegram_canary_step_failure_total > 0
   ```
   (Pushgateway replace semantics mean `rate()` is not useful here; use the
   instant value — 1 means the step failed in the last run.)
2. Inspect the most recent CronJob pod logs:
   ```sh
   kubectl -n labs get pods -l job-name --sort-by=.metadata.creationTimestamp | tail
   kubectl -n labs logs <pod-name>
   ```
   The canary logs each step with `slog` JSON and includes the HTTP
   status / RPC error inline.

## Likely causes by step

- **`oauth_metadata`** — `tg.mctl.ai` is down, OIDC issuer config is
  broken, or TLS cert expired. Cross-check with
  `mctl_telegram_up`-style readiness metrics for the server.
- **`mcp_init`** — MCP session initialization failed; the server returned
  a non-200 status or did not include an `Mcp-Session-Id` header. Usually
  indicates the MCP handler is unhealthy even though HTTP is up.
- **`list_dialogs`** — bearer token rotated or expired; MCP layer is
  unhealthy; `FLOOD_WAIT_*` from Telegram (the canary logs
  `flood_wait=true` in its slog output and increments
  `mctl_telegram_canary_step_failure_total{step="list_dialogs"}`).
- **`get_unread_messages`** — the test peer was deleted or
  re-permissioned; usually not user-facing, can be hidden by setting
  `CANARY_PROBE_UNREAD=false` on the CronJob while investigating.

## Mitigation

- **Token expiring / expired** — you should hear about this a week
  early: `mctl_telegram_canary_token_expires_in_seconds` reports the
  remaining lifetime on every run and `MctlTelegramCanaryTokenExpiring`
  fires under 7 days. Mint a new token via `POST
  /api/mcp/worker-token` (admin-scoped, requires `admin:users`; see
  `internal/workertoken`) and put it in the `mctl-telegram-canary`
  Secret's `bearer_token` key. The next CronJob run will pick it up;
  no CronJob or Deployment change is needed.

  The metric is **absent**, not zero, when the token carries no
  readable `exp` claim — an opaque or malformed credential leaves the
  series out entirely rather than publishing a 0 that would read as
  "already expired". A canary that is failing with no expiry series is
  therefore an auth problem, not an expiry one.

  The canary cannot renew itself yet; that is mctl-telegram#421.
- **Telegram FLOOD_WAIT** — back off; the canary will recover on its
  own once Telegram lifts the rate limit. Consider widening the
  CronJob `schedule` if it keeps recurring.
- **Server outage** — follow the mctl-telegram main runbook for the
  failing component (pool exhaustion, FLOOD_WAIT, OAuth pending —
  see related alerts).
- **Stop the canary while debugging** — suspend the CronJob:
  ```sh
  kubectl -n labs patch cronjob mctl-telegram-canary \
    --type merge -p '{"spec":{"suspend":true}}'
  ```
  Unsuspend after the underlying issue is resolved.

## Escalation

If the alert persists for more than 30 minutes and the failing step
is `oauth_metadata`, `mcp_init`, or `list_dialogs`, page the
mctl-telegram on-call — this represents a real user-visible outage.
