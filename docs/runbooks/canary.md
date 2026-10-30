# Runbook: `MctlTelegramCanaryFailing`

The mctl-telegram synthetic canary CronJob has been reporting
`mctl_telegram_canary_success = 0` for every scrape in the last 25
minutes and the condition has persisted for at least 5 minutes. With a
ten-minute probe interval that is roughly three consecutive failed runs,
so a single flap does not reach this alert.

User-visible impact: end-to-end Telegram tooling is likely broken for
real users, even though individual components may be healthy.

## What the alert means

The canary is deployed from mctl-gitops, not from this repository —
`services/labs/mctl-telegram/values.yaml` renders the CronJob
(`labs-mctl-telegram-canary`, schedule `*/10 * * * *`, running the same image
tag as the service itself), and
`infra-components/observability/vm-rules/mctl-telegram-canary.yaml` carries the
alert rules. Check those files for the current values rather than trusting the
numbers quoted here; this repository deliberately keeps no copy of either, and
the schedule has already changed once.

Each run of `cmd/canary` against the production tg.mctl.ai endpoint
exercises:

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
  `CANARY_PROBE_UNREAD=false` in the gitops values while investigating.

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

- **Renewal stopped working** — the canary renews its own token when
  less than a third of its lifetime remains (derived from the token's own
  `iat`/`exp`, so a 30-day token renews with 10 days left and a 90-day one
  with 30; `CANARY_TOKEN_RENEW_THRESHOLD` overrides it), by calling `POST /api/mcp/worker-token/renew` and patching the
  result back into the Secret. A failure there is deliberately **not** a
  red canary: the run continues on the still-valid token and only
  increments `mctl_telegram_canary_step_failure_total{step="token_renew"}`,
  so watch that series rather than `mctl_telegram_canary_success`:

  ```promql
  mctl_telegram_canary_step_failure_total{step="token_renew"} > 0
  ```

  The pod log carries the reason verbatim, including the server's own
  message. Two failures are worth naming:
  - `PATCH secret returned HTTP 403 ... is forbidden` — the ServiceAccount
    or its Role/RoleBinding is missing. Renewal is enabled by
    `CANARY_TOKEN_SECRET_NAME`; if that is set without the RBAC, every
    run past the threshold logs this.
  - `renewal window exhausted; an administrator must mint a new worker
    token` — the credential has hit its absolute ceiling of one year from
    the moment a human first minted it. Renewal deliberately cannot lift
    this; mint a fresh token through `POST /api/mcp/worker-token` as
    above. This is the one scheduled manual step that remains, and the
    expiry gauge plus `MctlTelegramCanaryTokenExpiring` give the usual
    week of warning before it bites.

  Renewal never changes identity or scopes — the endpoint copies both from
  the presented token — so a renewed canary keeps probing as the same
  account with the same read-only rights.
- **The canary's token itself leaked** (e.g. the `mctl-telegram-canary`
  Secret was exposed) — revoke it with the `revoke_worker_token` MCP tool
  (`admin:users` scope) by `jti` (from the most recent "worker token
  minted"/"worker token renewed" log line) or by the canary's `telegram_id`,
  then mint a fresh token and patch it into the Secret as above. See
  [Revoking a leaked worker token](../runbook.md#revokingaleakedworkertoken)
  in the main runbook for the full mechanics and the propagation-delay bound.
- **Telegram FLOOD_WAIT** — back off; the canary will recover on its
  own once Telegram lifts the rate limit. If it keeps recurring, widen the
  `schedule` in mctl-gitops — and resize the alert windows in the same change,
  since `MctlTelegramCanaryFailing`, `MctlTelegramCanaryStale` and
  `MctlTelegramCanaryAbsent` are all sized against the probe interval.
- **Server outage** — follow the mctl-telegram main runbook for the
  failing component (pool exhaustion, FLOOD_WAIT, OAuth pending —
  see related alerts).
- **Stop the canary while debugging** — suspend the CronJob. Note the
  deployed name is prefixed with the release: `labs-mctl-telegram-canary`,
  not `mctl-telegram-canary`.
  ```sh
  kubectl -n labs patch cronjob labs-mctl-telegram-canary \
    --type merge -p '{"spec":{"suspend":true}}'
  ```
  The object is managed by ArgoCD, so treat this as a short-lived measure: a
  subsequent sync can revert it. To stop the canary for longer than an
  investigation, set the suspend in mctl-gitops instead. Unsuspend after the
  underlying issue is resolved.

## Login-path probes

With `CANARY_LOGIN_PATH=true` the same run also walks the path a **new**
connector takes, up to the Telegram boundary (mctl-telegram#959). These
steps make no Telegram API call and log nobody in. They publish
`mctl_telegram_canary_login_path_success`, separately from
`mctl_telegram_canary_success`, and never change the Job's exit code. A
broken login path therefore alerts on its own metric and does not mark the
CronJob failed. Every login-path step is published on every run,
`mctl_telegram_canary_step_failure_total{step=...}` = 0 when it passed, so a
per-step alert can use `min_over_time` over a window. The gauge is absent, not 0, when the probes are disabled.
Every step runs even when an earlier one failed, so one run names every
broken hop.

| Step | Request | Passes only when |
| --- | --- | --- |
| `prm_root` | `GET /.well-known/oauth-protected-resource` | 200, `resource` = origin, `authorization_servers` non-empty |
| `prm_mcp` | `GET /.well-known/oauth-protected-resource/mcp` | 200, `resource` = origin + `/mcp` |
| `connect_page` | `GET /telegram/connect` | 200 with a link to this issuer's `/oauth/authorize` for `mctl_self_connect` |
| `authorize_redirect` | `GET /oauth/authorize` for `mctl_self_connect` (not followed) | 302 to `https://oauth.telegram.org` (`CANARY_TELEGRAM_OIDC_HOST`) with `client_id`, `redirect_uri` = origin + `/oauth/telegram/callback`, `response_type=code`, S256 PKCE, `state` |
| `callback_unknown_state` | `GET /oauth/telegram/callback` with a random state | 200 "link already used" page |
| `mcp_root` | unauthenticated `POST /` initialize | the app's 401: `Bearer realm="mctl-telegram"` naming the origin's protected-resource document |
| `edge_connector_ua` | unauthenticated `POST /mcp` as `Claude-User`, `ChatGPT-User`, `Perplexity-User` | the app's 401 for every one |

Likely causes:

- **`edge_connector_ua`**: Cloudflare is blocking a connector User-Agent
  again (the 2026-10-29 incident, mctl-gitops#2261). The log names which
  UA and what came back; a 403 with `server: cloudflare` is the edge, not
  the app. Check the zone's WAF and bot rules for tg.mctl.ai.
- **`mcp_root`**: MCP is no longer served on the bare origin (the
  2026-10-30 incident, mctl-telegram#957). Connectors configured with
  `https://tg.mctl.ai` complete OAuth and then fail with "action discovery
  failed". A 405 means the `/` routes lost POST.
- **`authorize_redirect`**: OIDC client config (`TELEGRAM_OIDC_*`) or the
  self-connect client changed. A 200 instead of the 302 usually means the
  reviewer chooser (`DEMO_REVIEWER_ENABLED`) is on.
- **`callback_unknown_state`** returning 5xx: the pending-auth store is
  failing. Look for `consume pending_auth failed` in the server log.
- **`prm_*` / `connect_page`**: a routing or `PUBLIC_BASE_URL` change; the
  error names the value that came back.

Each run leaves one abandoned pending authorization, which expires with the
code TTL, and logs one `oauth: callback request rejected
reason=unknown_state`. That log line carries neither the User-Agent nor the
state, so today nothing tells it apart from a real user's. The canary marks
its callback with a `state` starting `canary-` so that the funnel metrics in
mctl-telegram#960 can count it separately once the server records
something that identifies it. Every other login-path request sends
`User-Agent: mctl-telegram-canary/<version>`, except the
`edge_connector_ua` requests, which must look like the connectors.

## Escalation

If the alert persists for more than 30 minutes and the failing step
is `oauth_metadata`, `mcp_init`, or `list_dialogs`, page the
mctl-telegram on-call — this represents a real user-visible outage.
