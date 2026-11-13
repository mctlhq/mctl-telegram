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
  a non-200 status or did not include an `Mcp-Session-Id` header. A **401**
  here is an authentication problem: see "Canary authentication" below. Any
  other status usually means the MCP handler is unhealthy even though HTTP
  is up.
- **`list_dialogs`** — MCP layer is
  unhealthy; `FLOOD_WAIT_*` from Telegram (the canary logs
  `flood_wait=true` in its slog output and increments
  `mctl_telegram_canary_step_failure_total{step="list_dialogs"}`).
- **`get_unread_messages`** — the test peer was deleted or
  re-permissioned; usually not user-facing, can be hidden by setting
  `CANARY_PROBE_UNREAD=false` in the gitops values while investigating.

## Mitigation

- **Canary authentication** — since 0.138.1 the prod canary presents its
  projected Kubernetes ServiceAccount token (`CANARY_BEARER_TOKEN_FILE`,
  audience `tg.mctl.ai/canary`), not a minted worker token. kubelet issues and
  rotates it, so there is nothing to remint, renew or revoke, and a
  `revoke_worker_token` by the canary's `telegram_id` does not affect it. The
  server admits it through `internal/auth/k8ssa`, configured by `MCP_K8S_SA_*`
  in the gitops values. On a 401 at `mcp_init`, the server log line
  `auth failed ... err="kubernetes service account token: ..."` names the
  reason:
  - `signing keys: fetch jwks: ...`: the server cannot read the cluster JWKS
    (`/openid/v1/jwks`, e.g. an API server outage or NetworkPolicy egress). The
    token is refused, never let through, until the keys can be read.
  - an audience, subject or lifetime error: the CronJob's projected volume
    and `MCP_K8S_SA_AUDIENCE` / `MCP_K8S_SA_SUBJECT` disagree.
  - `token is not bound to a pod`: something other than a pod's projected
    volume produced the token.

  Moving the canary to another Telegram account means changing
  `CANARY_TELEGRAM_IDS`, `MCP_K8S_SA_TELEGRAM_ID` and the CronJob's
  `CANARY_TG_USER_ID` together; the server refuses to start if the SA's id is
  not a canary id.
- **The canary account was disconnected** (`list_dialogs` fails while
  `mcp_init` passes, and the server logs a revoked session for the canary's
  user). The account has to be re-linked: sign in at
  `/telegram/connect` as that account and finish the Telegram login, then
  mint a fresh worker token as above if the old one was revoked with it.
  `CANARY_TELEGRAM_IDS` on the server makes this hard to do by accident:
  for a listed account the manage-page Disconnect asks a second time and
  names the account as the canary, `POST /api/account/disconnect` and
  `DELETE /api/account` answer 409 unless `?confirm_canary=true` is given,
  and `disconnect_telegram_account`, `delete_telegram_account`,
  `revoke_telegram_session` and `set_telegram_access` with tier `none`
  refuse unless `confirm_canary: true` is passed. A confirmed override is in
  the audit log as the tool name with `:canary_override` appended, so
  `tool_name LIKE '%:canary_override'` finds who did it and when.
  Keep `CANARY_TELEGRAM_IDS` in step with the account the canary's token
  belongs to: after moving the canary to another account, update both in
  the same gitops change.
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
