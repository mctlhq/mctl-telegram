# mctl-telegram Operational Runbook

This runbook covers the Beta-tier alert playbooks for mctl-telegram. Each
section maps to one or more Prometheus alert rules defined in
`deploy/alerts/mctl-telegram.rules.yaml`.

Canary incidents are out of scope here; see
[docs/runbooks/canary.md](runbooks/canary.md).

---

## Table of contents

- [MctlTelegramNearCapacity — session pool near capacity](#mctltelegramnearcapacity)
- [MctlTelegramFloodWaitSpike — Telegram flood-wait rate spike](#mctltelegramfloodwaitspike)
- [MctlTelegramOAuthPendingStuck — OAuth pending authorizations stuck](#mctltelegramoauthpendingstuck)
- [JwtFailures — authentication failure spike](#jwtfailures)
- [TelegramClientErrors — Telegram client error rate spike](#telegramclienterrors)
- [RateLimitSpike — HTTP rate-limit event spike](#ratelimitspike)
- [SloBurnRate — SLO error-budget burn-rate alerts](#sloburnrate)
- [Canary](#canary)
- [Deployment compatibility boundaries](#deployment-compatibility)
- [Communication Agent operations](#communication-agent-operations)

---

<a id="deployment-compatibility"></a>
## Deployment compatibility boundaries

Both stable and preview mctl-telegram Deployments use Kubernetes
`strategy.type: Recreate`. Keep that invariant: an old server revision must
reach zero pods before a new revision starts. Stable and preview use separate
databases and secrets, so each environment crosses a schema boundary
independently.

This is a correctness requirement, not only an MTProto optimization. Some
security migrations intentionally do not dual-write legacy plaintext fields.
For example, the approval-code migration expires old plaintext capabilities
and writes only a keyed hash plus ciphertext. Old and new binaries therefore
must not overlap. Before promoting such a release:

1. verify the rendered Deployment strategy is `Recreate` and has no
   `rollingUpdate` field;
2. verify the old ReplicaSet has zero ready pods before accepting traffic on
   the new one;
3. do not use `kubectl rollout` overrides that restore `RollingUpdate`;
4. roll back by stopping the new revision before starting the old one, and
   assume pre-migration pending approvals may require fresh drafts.

The rolling guidance in generic secret-rotation procedures does not override
this workload-specific boundary.

---

<a id="communication-agent-operations"></a>
## Communication Agent operations

The communication agent has three independent containment controls:

- `AGENT_KILL_SWITCH=true` denies new agent actions at the server policy and
  executor layers.
- `agent_profiles.listener_enabled=false` stops Telegram ingestion for that
  account after the supervisor reconciles.
- `agent_profiles.autopilot_paused=true` denies autonomous replies for that
  account.
- worker Deployment replicas `0` stops model job processing.

No one control substitutes for the others. The closed state between test
windows is all four controls together: kill switch true, listener disabled,
autopilot paused, and worker replicas zero.

### Safe bootstrap and test-window procedure

1. Start dark: server deployed by exact commit SHA with
   `AGENT_ENABLED=true`, `AGENT_KILL_SWITCH=true`, and `Recreate`; worker
   replicas zero.
2. Verify the server pod is healthy, the database migration completed, and
   the preview/stable environment points only to its own database,
   encryption key, Telegram session, and worker credential.
3. Provision the account profile through the admin API with mode `observe`,
   `listener_enabled=false`, `autopilot_paused=true`, and an exact sender
   allowlist. Do not use an empty allowlist for a bounded test.
4. Mint an account-scoped `aud=agent` token with the shortest practical TTL,
   store it in the account's dedicated worker Secret, and ensure the model
   process itself does not receive that token. Never reuse one tenant's
   token in another worker.
5. Scale that account's worker to one replica and verify readiness with the
   queue empty. A replica is one worker process, not a request-parallelism
   setting: `100` replicas can claim up to 100 independent jobs, but does
   not guarantee 100-way throughput and can exhaust model quota, database
   connections, and Telegram/API budgets.
6. Open the bounded window in this order: set the listener on, confirm the
   pinned account is healthy, unpause autopilot, then set the global kill
   switch false by a reviewed deployment. Keep mode `observe` until every
   production gate in the canonical plan is complete.
7. Close immediately after evidence collection in the reverse safety order:
   set kill switch true, pause autopilot, disable the listener, then scale
   the worker to zero. Verify live pod/env state; a committed values file is
   not sufficient evidence.

The Telegram listener remains a single-replica responsibility until account
ownership/leader election exists. Worker replicas are horizontally safe at
the durable queue layer, including per-conversation ordering and stale-attempt
fencing, but each current Deployment is still tenant-scoped by one
`AGENT_API_TOKEN`. Do not build a shared worker by exposing an admin or
multi-tenant token to Claude; a shared pool requires job-scoped capabilities
or a trusted scheduler that injects exactly one tenant credential per
invocation.

### Configuration reference

| Variable/control | Default | Operational meaning |
|---|---:|---|
| `AGENT_ENABLED` | `false` | Mounts the Agent API and starts agent runtime components. It is not the emergency send cutoff. |
| `AGENT_KILL_SWITCH` | `false` | Global server-side deny gate. Production values must explicitly set it; dark starts use `true`. |
| `AGENT_RETENTION_DAYS` | `30` | Clears encrypted message-derived content after this many days. `0` means indefinite retention and is prohibited for production without a documented exception. |
| `AGENT_JOB_VISIBILITY` | `5m` | Time before a processing claim is treated as stale and requeued/dead-lettered. Must exceed the worst expected model turn. |
| `AGENT_APPROVAL_TTL` | `24h` | Maximum pending owner-approval lifetime. |
| `AGENT_PROFILE_PATH` | unset | One-time legacy YAML import only. Remove it after the encrypted DB import is verified. |
| `AGENT_PROFILE_OWNER_TG_ID` | `0` | Required only with the legacy import path; binds that file to one account. |
| `AGENT_TEST_CRASH_AFTER_RESERVE` | `false` | **TEST-ONLY.** Hard-exits the process (code 137) immediately after `send_random_id` is persisted and an action is CASed to `executing`, before the Telegram RPC — for the `random_id`/`RecoverStuck` crash-recovery drill. Every send handled by the pod is hit while set, not just a chosen one. Must never be `true` outside a deliberate, bounded drill window. |
| profile `listener_enabled` | `false` | Per-account Telegram ingest switch. |
| profile `autopilot_paused` | `true` on bootstrap | Per-account autonomous action pause. |
| profile `mode` | `observe` | `observe` always requires owner approval; `guarded` is production-gated. |
| worker `AGENT_API_TOKEN` | required | Tenant-scoped bearer capability. Current JWTs are stateless and cannot be revoked individually before expiry. |

### Dead-letter handling

`MctlAgentDeadLetter` means a job exhausted its configured attempts.
Contain the agent first if the cause is not already understood. Inspect only
metadata initially; message content may be private:

```sql
SELECT id, user_id, event_id, status, attempts, max_attempts,
       last_error, created_at, updated_at
FROM agent_jobs
WHERE status = 'dead_letter'
ORDER BY updated_at DESC
LIMIT 50;
```

Classify the cause before replay: permanent policy/input errors are not
replayed; quota/network/worker crashes may be replayable after remediation.
Confirm the source `incoming_events.body_encrypted` still exists and no
durable action/lead already completed the intent. Never manually send a
reply to compensate for an `executing` action: Telegram may have accepted
the original persisted `random_id`.

There is deliberately no public replay endpoint. A controlled operator
requeue is a database change and requires a ticket/evidence record:

```sql
BEGIN;
SELECT id, user_id, status, attempts, last_error
FROM agent_jobs
WHERE id = :job_id AND user_id = :user_id
FOR UPDATE;

UPDATE agent_jobs
SET status = 'pending', attempts = 0, next_run_at = CURRENT_TIMESTAMP,
    claimed_by = NULL, claimed_at = NULL, last_error = NULL,
    updated_at = CURRENT_TIMESTAMP
WHERE id = :job_id AND user_id = :user_id AND status = 'dead_letter';
COMMIT;
```

Require exactly one updated row. Keep mode `observe`, watch the attempt and
action rows, and close the test window if it dead-letters again.

### Agent alert response

- `MctlAgentDeadLetter` (warning): close unexplained test traffic, inspect
  job/attempt metadata, fix the cause, and use the controlled replay above
  only for a transient failure.
- `MctlAgentActionsExecutingStuck` (critical): set the global kill switch,
  pause the account, and disable its listener. Inspect the persisted action
  status, `send_random_id`, and Telegram-side outcome. Do not change the
  random ID or reconstruct a different body.

### Retention and deletion matrix

| Storage surface | Content | Retention | Deletion mechanism |
|---|---|---|---|
| `incoming_events` | Event/dedup metadata plus encrypted inbound body | Body: `AGENT_RETENTION_DAYS` (30d default); metadata tombstone: account lifetime | Body nulled by agent retention sweeper; row purged by hard account deletion |
| `conversation_messages` | Encrypted inbound/outbound context | `AGENT_RETENTION_DAYS` | Rows deleted by agent retention sweeper or hard account deletion |
| `agent_actions` | Policy/lifecycle metadata, encrypted draft and exact send body, encrypted approval capability | Terminal or inactive pre-send content: `AGENT_RETENTION_DAYS`; executing recovery content: until terminal; lifecycle tombstone: account lifetime | Old inactive pre-send actions are denied, then terminal content/capabilities are nulled; executing rows retain the exact body and random ID for safe recovery; row purged on hard deletion |
| `owner_notifications` | Encrypted owner summary/draft plus delivery metadata | Body: `AGENT_RETENTION_DAYS`; metadata: account lifetime | Body nulled by sweeper; row purged on hard deletion |
| `job_leads` | Recruiter/company/role/compensation details | Account lifetime or earlier user-requested deletion | Hard account deletion |
| `conversations` | Peer metadata, state, counters, timestamps | Account lifetime | Hard account deletion |
| `agent_jobs`, `agent_job_attempts` | Queue state, attempt timing, bounded error text, result IDs | Account lifetime; message body is not copied here | Hard account deletion |
| `agent_profiles` | Policy settings and per-tenant encrypted owner profile | Account lifetime | Hard account deletion; a content-free legacy-import tombstone may remain while the login identity remains |
| update/cursor/sent-marker tables | Telegram watermarks, Saved Messages cursor, dedup IDs | Account lifetime | Hard account deletion |
| `audit_logs` | Tool/action metadata and redacted errors; no message body/token/session | `AUDIT_RETENTION_DAYS` (90d default) | Audit sweeper; approved early-purge SQL if required |
| worker Claude session | No persisted conversation (`--no-session-persistence`) | Process lifetime | Process/pod exit |
| container logs | Redacted structured operational logs | Platform Loki policy, normally 14–30d | Platform log retention |
| database backups / PVC snapshots | Encrypted database pages and worker credential state | Platform backup policy | Natural backup expiry; selective row deletion cannot rewrite immutable historical snapshots |

`AGENT_RETENTION_DAYS=0` and `AUDIT_RETENTION_DAYS=0` mean “keep forever”,
not “delete immediately.”

### Delete one account's Communication Agent data

1. Set the global kill switch, pause and disable the target profile, and
   scale its worker Deployment to zero. Wait for in-flight claims to stop.
2. Delete the target worker Secret. Because current `aud=agent` JWTs are
   stateless, deletion stops new pod use but does not revoke a copied token;
   wait for its expiry or rotate the signing key in a separately reviewed,
   all-client migration. This limitation blocks a general shared-worker
   design.
3. Call authenticated `DELETE /api/account`. It atomically removes Telegram
   sessions and all user-scoped agent profiles, events, messages,
   conversations, leads, actions, notifications, jobs, attempts, cursors,
   watermarks, and sent-message markers. The stable login identity and
   audit history intentionally survive.
4. Verify zero rows for the internal `user_id` across those tables. Do not
   query by a raw Telegram ID in evidence or logs.
5. If the request also requires early audit erasure, delete
   `audit_logs WHERE user_id = :user_id` under an approved privacy ticket
   after the endpoint's own deletion audit row is written. This removes that
   user's complete hash chain; never edit individual audit rows.
6. Record the database-backup and log-retention expiry dates. Immutable
   backups are not selectively rewritten; access remains restricted until
   their normal expiry.

### Credential rotation

- Agent API token: scale the tenant worker to zero, mint a replacement with
  the shortest practical TTL, update only that tenant's Secret, start one
  replica, verify claims, then remove the old Secret. A suspected copied
  token requires signing-key rotation or waiting for expiry.
- Claude credential/state: scale to zero, revoke it at the provider, replace
  the dedicated credential volume/secret, start one replica, and verify the
  old credential fails. Never reuse the PR-review credential pool.
- Telegram session: disable listener and pause, disconnect/revoke the old
  session, complete OAuth for the replacement, then re-enable only after the
  account identity is verified.
- Encryption key: online/in-place rotation is not currently supported. Treat
  suspected compromise as an incident: close the agent window, revoke
  sessions and tokens, keep the old key isolated for recovery, and implement
  a separately reviewed dual-key re-encryption migration before replacing
  it. Never replace the key directly; existing ciphertext would become
  unreadable.

---

<a id="mctltelegramnearcapacity"></a>
## MctlTelegramNearCapacity — session pool near capacity

### Symptom

- Alert `MctlTelegramPoolNearCapacity` fires with severity **warning** when
  `mctl_telegram_client_pool_size / mctl_telegram_pool_capacity > 0.85` for
  5 minutes.
- Alert fires with severity **critical** when the ratio exceeds **0.95** for
  2 minutes.
- Both alerts only fire when `mctl_telegram_pool_capacity > 0`. When
  `mctl_telegram_pool_capacity == -1`, the cap is disabled and these alerts
  will not fire.

### Likely causes

- Organic user growth: more users are using Telegram tooling concurrently
  than the current cap can accommodate.
- A previous scale-down reduced pod count without adjusting
  `TELEGRAM_MAX_SESSIONS`, leaving fewer total pool slots.
- A session leak: clients that should be removed from the pool are not being
  cleaned up by the pool GC goroutine.
- Cap is too low for the actual memory headroom available in the pod.

### Diagnostic queries

Current pool utilization ratio:

```promql
mctl_telegram_client_pool_size / mctl_telegram_pool_capacity
```

Absolute pool size and capacity:

```promql
mctl_telegram_client_pool_size
mctl_telegram_pool_capacity
```

Session lifecycle counters (connected vs. revoked):

```promql
rate(mctl_sessions_connected_total[5m])
sum(rate(mctl_sessions_revoked_total[5m])) by (reason)
```

### Mitigation

1. **Check whether the cap is intentionally enabled.** If
   `mctl_telegram_pool_capacity == -1`, the pool is uncapped. Do not proceed
   to raise `TELEGRAM_MAX_SESSIONS` without first deciding on a cap. Set an
   explicit cap, then re-evaluate whether HPA or a higher `TELEGRAM_MAX_SESSIONS`
   is appropriate.

2. **Verify RAM headroom before raising `TELEGRAM_MAX_SESSIONS`.** Use the
   3 MB-per-session planning figure from [docs/hpa.md](hpa.md). Consult the
   `TELEGRAM_MAX_SESSIONS` table in that document for recommended values per
   pod memory tier (256 MiB → 45, 512 MiB → 110, 1 GiB → 270). Do not raise
   the cap past what the pod memory limit can safely accommodate.

3. **Scale out via HPA.** If the Prometheus Adapter HPA is configured,
   confirm it is reacting. A target of 70% utilization is recommended; see
   [docs/hpa.md](hpa.md) for the Kubernetes HPA stanza.

4. **Raise `TELEGRAM_MAX_SESSIONS` on the Deployment** (Recreate restart):
   ```sh
   kubectl -n mctl-telegram set env deployment/mctl-telegram \
     TELEGRAM_MAX_SESSIONS=<new-value>
   ```
   Only do this after confirming RAM headroom as above.

5. **Critical severity.** If the critical alert fired, scale out immediately.
   New connections will be rejected once the pool is full, causing tool
   invocation errors that will trigger the `MctlToolAvailabilityFastBurn`
   alert. See [SloBurnRate](#sloburnrate).

### Escalation

- **Warning**: investigate within 30 minutes. No immediate page.
- **Critical**: page the mctl-telegram on-call immediately. Pool exhaustion
  causes user-visible tool failures.
- Escalate to the platform team if pod memory limits cannot be increased and
  more replicas are not available.

### Postmortem trigger

Open a postmortem if:
- The critical alert fires and pool exhaustion causes tool errors that
  consume more than 10% of the monthly error budget.
- The pool hit 100% utilization (pool_size >= pool_capacity) for any
  measurable duration.

---

<a id="mctltelegramfloodwaitspike"></a>
## MctlTelegramFloodWaitSpike — Telegram flood-wait rate spike

### Symptom

- Alert `MctlTelegramFloodWaitSpike` fires with severity **warning** when
  `sum(rate(mctl_telegram_flood_wait_events_total[5m])) > 0.5` per second for
  2 minutes.
- Alert fires with severity **critical** when the rate exceeds **2 events/s**
  for 2 minutes.
- Each FLOOD_WAIT_X event from Telegram is counted even if the subsequent
  retry succeeds.

### Likely causes

- One or more MCP tools are generating excessive Telegram API calls, either
  due to a burst of user requests or a misbehaving client.
- A single high-volume user is invoking tools faster than Telegram's
  per-account rate limit allows.
- A load test or bot is targeting the MCP endpoint with no rate limiting on
  the client side.
- Telegram temporarily lowers rate limits during an incident on their side.

### Diagnostic queries

Identify which MCP tool is generating the most flood-wait events:

```promql
topk(5, sum by (tool) (rate(mctl_telegram_flood_wait_events_total[5m])))
```

Total flood-wait event rate across all tools:

```promql
sum(rate(mctl_telegram_flood_wait_events_total[5m]))
```

Correlate with tool invocation rate to find the offending tool:

```promql
sum(rate(mctl_tool_invocations_total[5m])) by (tool)
```

To identify the offending user, search structured slog logs (JSON) for
`flood_wait` events with the `user_id` field:

```sh
kubectl -n mctl-telegram logs -l app=mctl-telegram --since=10m \
  | grep -i flood_wait | jq -r '.user_id' | sort | uniq -c | sort -rn | head -20
```

> **Caveat — logs are incomplete for warning-level spikes.** The
> `mctl_telegram_flood_wait_events_total` metric is incremented on *every*
> `FLOOD_WAIT` inside `borrowWithRetry()`, but `borrowWithRetry()` itself emits
> no log line — a `flood_wait`-bearing entry only appears when retries are
> exhausted and the tool returns an error. Warning-level spikes that self-retry
> successfully therefore produce little or no log output. Use the metric (with
> its `tool` label) as the authoritative detection and per-tool signal; treat
> the log grep above as best-effort per-user attribution for error-level
> (exhausted-retry) events only.

### Mitigation

1. **Warning severity.** The `borrowWithRetry()` function retries up to 3
   times with up to 60 seconds sleep per attempt. Warning-level events may
   self-resolve without intervention.

2. **Identify the offending tool and user** using the queries above. If a
   single `user_id` is responsible, consider revoking their session or
   applying a stricter per-user rate limit.

3. **Reduce tool fan-out.** If the flood-wait is tied to a specific tool
   (e.g., `list_dialogs` called in tight loops), coordinate with the calling
   agent to add client-side backoff.

4. **Critical severity.** Tool invocations on the affected user's account
   will fail once retries are exhausted. Those failures count against the
   tool-availability SLO. Check [SloBurnRate](#sloburnrate).

5. If flood-wait pressure is coming from a bot scan, check
   [RateLimitSpike](#ratelimitspike) and consider IP-level blocking at the
   ingress layer.

### Escalation

- **Warning**: investigate within 1 hour if the rate does not self-resolve.
- **Critical**: page mctl-telegram on-call. Sustained critical-level
  flood-waits will exhaust tool-availability error budget.
- Escalate to Telegram if the flood-wait pattern is account-wide rather
  than isolated to specific tools — this may indicate a Telegram-side
  incident.

### Postmortem trigger

Open a postmortem if:
- A critical flood-wait spike lasts more than 30 minutes.
- The flood-wait spike causes tool-availability SLO fast-burn alert to fire.

---

<a id="mctltelegramoauthpendingstuck"></a>
## MctlTelegramOAuthPendingStuck — OAuth pending authorizations stuck

### Symptom

- Alert `MctlTelegramOAuthPendingStuck` fires with severity **warning** when
  `mctl_oauth_pending_auth_size > 100` for **15 minutes**.
- `mctl_oauth_pending_auth_size` is refreshed every minute by the OAuth
  server's background sampler.

### Likely causes

- **Sweeper goroutine stopped.** The OAuth server contains a background
  sweeper that removes expired pending auth flows. If the goroutine panicked
  or was not started, stale entries accumulate.
- **Telegram OIDC IdP is down.** Users start the authorization flow
  (`/oauth/authorize`) but Telegram cannot complete the callback
  (`/oauth/telegram/callback`), leaving flows in the pending map.
- **Bot scan against `/oauth/authorize`.** Automated scanners or bots
  initiating OAuth flows without completing them will grow the pending count.
- **Deployment with `UseDBForOAuth=true`.** In this mode pending flows are
  stored in the database. A stuck DB transaction or migration failure can
  prevent cleanup.

### Diagnostic queries

Current size of the pending auth map:

```promql
mctl_oauth_pending_auth_size
```

OAuth endpoint error rate (look for 5xx on the callback route):

```promql
sum(rate(mctl_http_requests_total{route="/oauth/telegram/callback",status_code=~"5.."}[5m]))
```

HTTP traffic to `/oauth/authorize` (detect bot scan):

```promql
sum(rate(mctl_http_requests_total{route="/oauth/authorize"}[5m])) by (status_code)
```

When `UseDBForOAuth=true`, run the following against the production database
to count recent pending flows:

```sql
SELECT COUNT(*) FROM oauth_pending_auth
WHERE created_at >= NOW() - INTERVAL '10 minutes';
```

### Mitigation

1. **Check pod logs for sweeper errors:**
   ```sh
   kubectl -n mctl-telegram logs -l app=mctl-telegram --since=20m \
     | grep -E 'oauth|sweeper|pending'
   ```

2. **Restart the pod** to clear the in-memory pending map. Trade-off: any
   users currently in the OAuth flow will have their flow interrupted and
   will need to restart the authorization.
   ```sh
   kubectl -n mctl-telegram rollout restart deployment/mctl-telegram
   ```

3. **If a bot scan is suspected**, check access logs for the
   `/oauth/authorize` route and coordinate with the platform team to apply
   IP-level blocking or CAPTCHA protection at the ingress.

4. **If Telegram IdP is down**, monitor Telegram's status page. The pending
   flows will time out naturally once the sweeper runs. The alert will clear
   once the map drains below 100 after the sweeper catches up.

5. **`UseDBForOAuth=true` mode:** After a pod restart, verify the DB count
   from the query above is decreasing. If rows are not being deleted, inspect
   DB connection health and migration state.

### Escalation

- **Warning**: investigate within 30 minutes. If a bot scan is identified,
  escalate to the platform/security team immediately.
- Escalate to the platform team if the OAuth server restart does not clear
  the count and the DB query shows no cleanup activity.

### Postmortem trigger

Open a postmortem if:
- The OAuth pending map grows to over 1 000 entries, suggesting active
  abuse or a prolonged sweeper outage.
- The stuck pending state prevents legitimate users from completing OAuth
  authorization for more than 30 minutes.

---

<a id="jwtfailures"></a>
## JwtFailures — authentication failure spike

### Symptom

- No dedicated alert rule fires for JWT failures by default, but a spike in
  `mctl_auth_failures_total` will surface in the SLO burn-rate alerts if
  failures reach tools that are counted in the tool-availability SLI.
- Operationally monitor: `rate(mctl_auth_failures_total[5m]) > 0` as an ad
  hoc query during incidents.
- `mctl_auth_failures_total` is labeled by `reason` and `provider`.

### Likely causes

- **`jwt_expired`**: Caller's token has expired. Normal at low rates;
  a spike indicates a misconfigured token TTL or a client not refreshing
  tokens.
- **`jwt_invalid_signature`**: The signing key used to generate the token
  does not match the key currently configured in the server. Often caused by
  a JWT secret rotation that was not propagated to all pods simultaneously.
- **`jwt_invalid_issuer`**: The `iss` claim in the token does not match the
  server's expected issuer value (`OAUTH_JWT_ISSUER` env var).
- **`jwt_missing_audience` / `jwt_wrong_audience`**: The `aud` claim is
  absent or does not match the server's audience (`OAUTH_JWT_AUDIENCE` env
  var).
- **`bearer_scheme_error`**: The `Authorization` header is malformed —
  missing the `Bearer ` prefix or the header is absent entirely.
- **`other`**: Catch-all for unexpected validation errors; check pod logs.
- **Provider context:** `provider` label values are `local-jwt`,
  `shared-hmac`, and `local-dev`.

### Diagnostic queries

Auth failure rate by reason and provider:

```promql
sum(rate(mctl_auth_failures_total[5m])) by (reason, provider)
```

Top failure reasons:

```promql
topk(5, sum(rate(mctl_auth_failures_total[5m])) by (reason))
```

Failure rate for JWT signature/expiry reasons specifically:

```promql
sum(rate(mctl_auth_failures_total{reason=~"jwt_invalid_signature|jwt_expired"}[5m])) by (provider)
```

### Mitigation

1. **`jwt_invalid_signature` spike** indicates a secret rotation issue.
   - For `local-jwt` provider: the server uses `OAUTH_JWT_SIGNING_KEY`
     (preferred) or `OAUTH_JWT_SECRET` (deprecated fallback). Ensure the
     new key is deployed to **all** pods before rotating the issuing
     service's key. Preserve the workload's `Recreate` strategy and complete
     the replacement before rotating the issuer.
   - For `shared-hmac` provider: `OAUTH_JWT_SECRET` must match between the
     token issuer and the mctl-telegram server. Redeploy both in the same
     release.

2. **`jwt_expired` spike**: investigate whether client token TTL
   configuration has changed, or whether a clock skew exists between token
   issuer and server. Check NTP sync on both sides.

3. **`jwt_invalid_issuer` / audience failures**: check `OAUTH_JWT_ISSUER`
   and `OAUTH_JWT_AUDIENCE` environment variables are consistent with the
   values embedded in issued tokens.

4. **`bearer_scheme_error` spike**: usually a misconfigured calling client.
   Identify the caller from pod logs (search for `bearer_scheme_error` in
   structured slog output) and fix the client's `Authorization` header
   construction.

5. **Sustained high failure rates** that cause 401 responses at scale do not
   count against any availability SLO: the tool-availability SLI excludes
   them (unauthenticated requests are rejected before a tool is invoked), and
   the OAuth burn-rate rules count only `status_code=~"5.."`, so authn-driven
   401s from the token endpoint never burn that budget either. Treat a 401
   spike as a client-misconfiguration or attack signal, not an SLO event;
   investigate the failure reason directly rather than waiting on burn alerts.

### Escalation

- If `jwt_invalid_signature` or `jwt_expired` spikes to >10% of all
   requests and a secret rotation is not in progress, page the
   mctl-telegram on-call — the key material may have been corrupted or
   leaked.
- Escalate to the security team if `jwt_invalid_signature` failures persist
  after confirming the deployed key is correct (possible token forgery
  attempt).

### Postmortem trigger

Open a postmortem if:
- A JWT secret rotation causes a user-visible outage lasting more than 5
  minutes.
- `jwt_invalid_signature` failures are confirmed to be caused by an
  unauthorized key (security incident).

---

<a id="telegramclienterrors"></a>
## TelegramClientErrors — Telegram client error rate spike

### Symptom

- No dedicated alert rule is wired by default; this metric is a raw signal
  used for triage during pool-related or flood-wait incidents.
- `mctl_telegram_client_errors_total` is a plain Counter with no labels. It
  counts every Telegram MTProto client goroutine exit with a non-context-canceled
  error.
- A rising rate indicates that live client goroutines are crashing or
  disconnecting unexpectedly.

### Likely causes

- Telegram data center connectivity issues causing MTProto connections to
  drop.
- MTProto authentication key invalidation (Telegram revoked the session
  server-side).
- Telegram server returning unhandled error codes that cause the `gotd/td`
  client goroutine to exit.
- Resource exhaustion on the pod (OOM, file descriptor limit) causing
  connection failures.
- Network policy change blocking egress to Telegram data centers (ports 443
  and 80 to `149.154.0.0/16` and `91.108.0.0/14`).

### Diagnostic queries

Rate of Telegram client errors:

```promql
rate(mctl_telegram_client_errors_total[5m])
```

Correlate with pool size (client errors reduce the pool):

```promql
mctl_telegram_client_pool_size
```

Session revocation rate (client errors often trigger revocations):

```promql
sum(rate(mctl_sessions_revoked_total[5m])) by (reason)
```

To retrieve the actual error category, inspect pod logs for the structured
slog warning emitted on each client exit:

```sh
kubectl -n mctl-telegram logs -l app=mctl-telegram --since=10m \
  | grep 'telegram client exited' \
  | jq -r '{user_id, err}'
```

The log line has the form:

```json
{"level":"WARN","msg":"telegram client exited","user_id":"...","err":"..."}
```

### Mitigation

1. **Isolated error for a single user**: the pool will remove the failed
   client and the user will receive an error on next invocation. This is
   self-healing; the client is re-established on the next `Borrow()` call.

2. **Sustained error rate affecting many users**: check pod logs for
   recurring `err` values. If the error is a Telegram connectivity issue
   (e.g., `EOF`, `connection reset by peer`), check network egress from the
   pod to Telegram data centers:
   ```sh
   kubectl -n mctl-telegram exec deploy/mctl-telegram -- \
     nc -zv 149.154.167.51 443
   ```

3. **Auth key invalidation (`AUTH_KEY_UNREGISTERED`)**: the session is
   permanently broken and must be revoked. The user must re-authorize via
   the OAuth flow. Check whether a bulk Telegram session invalidation
   occurred.

4. **OOM / fd exhaustion**: check pod memory usage and `kubectl describe`
   for OOMKilled events. Reduce `TELEGRAM_MAX_SESSIONS` or scale out.

### Escalation

- Escalate to the platform team if Telegram DC connectivity is interrupted
  for all pods simultaneously (network policy regression).
- Escalate to Telegram support if `AUTH_KEY_UNREGISTERED` errors affect
  a large fraction of sessions simultaneously (Telegram-side mass revocation).

### Postmortem trigger

Open a postmortem if:
- Telegram client errors cause a measurable reduction in `mctl_telegram_client_pool_size`
  (>5% of pool) and tool failures exceed the fast-burn SLO threshold.
- Connectivity to Telegram DCs is interrupted for more than 5 minutes.

---

<a id="ratelimitspike"></a>
## RateLimitSpike — HTTP rate-limit event spike

### Symptom

- No dedicated alert rule is wired by default. Monitor this metric during
  traffic incidents or bot-scan investigations.
- `mctl_rate_limit_events_total` counts HTTP 429 responses, labeled by
  `identity_kind`: `user` (authenticated — bucketed by `identityKey()`, which
  prefers the JWT subject, then the GitHub login, then the numeric user ID) or
  `anon` (unauthenticated — all such requests share a single global token
  bucket, not per-IP buckets).
- A spike in `anon` rate-limit events typically indicates a bot scan or DDoS
  attempt. A spike in `user` events indicates one or more authenticated
  callers exceeding per-user request budgets.

### Likely causes

- **`anon` spike**: bot scan, vulnerability scanner, or load test targeting
  the service from unauthenticated endpoints.
- **`user` spike**: a misbehaving or misconfigured MCP client sending too
  many requests. May also indicate an agent loop that is not respecting
  backoff signals.
- **`anon` spike coinciding with `mctltelegramoauthpendingstuck`**: bots
  targeting `/oauth/authorize` will generate both `anon` rate-limit events
  and pending OAuth flows. Check [MctlTelegramOAuthPendingStuck](#mctltelegramoauthpendingstuck).

### Diagnostic queries

Rate-limit event rate by identity kind:

```promql
sum(rate(mctl_rate_limit_events_total[5m])) by (identity_kind)
```

Overall HTTP request rate (for context):

```promql
sum(rate(mctl_http_requests_total[5m])) by (route, status_code)
```

Break the 429s down by identity kind (`anon` vs `user`):

```promql
sum(rate(mctl_rate_limit_events_total[5m])) by (identity_kind)
```

Note: 429 responses are not structured-logged with a `user_id`, and
`mctl_rate_limit_events_total` carries only the `identity_kind` label — it
cannot attribute a spike to a single user. To pin down a specific abusive
caller, correlate the request-path audit logs (which do carry `user_id`)
over the same window.

### Mitigation

1. **`anon` spike from a specific IP range**: coordinate with the platform
   team to apply IP-level blocking at the ingress (nginx / cloud load
   balancer WAF rules). Rate-limiting at the application layer is a last
   resort.

2. **`user` spike from a specific caller**: identify the offending
   `telegram_id` via `list_telegram_identities`. Contact the user or, if the
   behavior is abusive, revoke their session with the admin-only
   `revoke_telegram_session` MCP tool (requires the `admin:users` scope).
   There is no REST admin endpoint; it is an MCP `tools/call` against the
   `/mcp` endpoint (after the standard `initialize` handshake):
   ```sh
   curl -X POST https://tg.mctl.ai/mcp \
     -H "Authorization: Bearer <admin-token>" \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Mcp-Session-Id: <id from initialize>" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"revoke_telegram_session","arguments":{"telegram_id":<id>}}}'
   ```

3. **The rate limiter is protecting the Telegram pool.** High `anon` or
   `user` rate-limit events at the HTTP layer mean the pool is protected;
   do not lower the rate-limit thresholds without understanding the traffic
   source.

4. **Sustained `anon` flood coinciding with OAuth pending stuck**: prioritize
   fixing the bot scan first (ingress block) before restarting the OAuth
   server, to avoid the pending map refilling immediately after restart.

### Escalation

- Escalate to the platform/security team for any `anon` spike that persists
  for more than 10 minutes and cannot be attributed to a known load test.
- Escalate to the mctl-telegram on-call if legitimate authenticated users are
  being incorrectly rate-limited (confirmed via support reports or a `user`
  spike with no matching abuse pattern). Note: HTTP 429s are emitted by the
  pre-tool middleware and never increment `mctl_tool_invocations_total`, so a
  rate-limit spike does not register as tool-availability SLO burn — judge
  user impact from the 429 rate and reports, not the burn-rate alerts.

### Postmortem trigger

Open a postmortem if:
- An `anon` spike causes authenticated users to experience degraded
  availability due to shared infrastructure resource contention.
- Rate-limit configuration is found to be incorrect (e.g., thresholds too
  low, causing legitimate traffic to be throttled).

---

<a id="sloburnrate"></a>
## SloBurnRate — SLO error-budget burn-rate alerts

### Symptom

One or more of the following multi-window burn-rate alerts fire:

| Alert | Severity | Window | Threshold |
|-------|----------|--------|-----------|
| `MctlToolAvailabilityFastBurn` | page | 1h | error rate >7.2% |
| `MctlToolAvailabilitySlowBurn` | ticket | 6h | error rate >3.0% |
| `MctlOAuthAvailabilityFastBurn` | page | 1h | error rate >1.440% |
| `MctlOAuthAvailabilitySlowBurn` | ticket | 6h | error rate >0.600% |
| `MctlSessionBorrowFastBurn` | page | 1h | error rate >14.4% |
| `MctlSessionBorrowSlowBurn` | ticket | 6h | error rate >6.0% |

Fast-burn (page severity) means 14.4x the allowed burn rate — at that rate
the full 30-day error budget is exhausted in about 2 days (30d / 14.4 ≈ 50
hours). The 1h alert window is what makes it page-worthy: it catches the
burn early, long before the budget is gone. Slow-burn (ticket severity)
means 6x — the 30-day budget is exhausted in about 5 days (30d / 6).

### Likely causes

- **MctlToolAvailabilityFastBurn/SlowBurn**: Telegram client errors
  (see [TelegramClientErrors](#telegramclienterrors)), pool exhaustion
  (see [MctlTelegramNearCapacity](#mctltelegramnearcapacity)), or
  flood-wait retries exhausted (see [MctlTelegramFloodWaitSpike](#mctltelegramfloodwaitspike)).
- **MctlOAuthAvailabilityFastBurn/SlowBurn**: OAuth server errors (500s on
  `/oauth/token` or `/oauth/telegram/callback`). Check the OAuth pending
  state (see [MctlTelegramOAuthPendingStuck](#mctltelegramoauthpendingstuck))
  and JWT failures (see [JwtFailures](#jwtfailures)).
- **MctlSessionBorrowFastBurn/SlowBurn**: Session store errors, database
  connectivity failures, or session corruption. TTL expirations
  (`expired_idle`, `expired_absolute`) are excluded from the SLI
  denominator.

### Diagnostic queries

MCP tool availability error rate (1h window):

```promql
sum(rate(mctl_tool_invocations_total{status="error"}[1h]))
/
sum(rate(mctl_tool_invocations_total[1h]))
```

Tool error rate broken down by tool:

```promql
sum(rate(mctl_tool_invocations_total{status="error"}[5m])) by (tool)
```

OAuth endpoint 5xx rate (1h window):

```promql
sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback",status_code=~"5.."}[1h]))
/
sum(rate(mctl_http_requests_total{route=~"/oauth/token|/oauth/telegram/callback"}[1h]))
```

Session borrow error rate (1h window, excluding TTL expirations):

```promql
sum(rate(mctl_sessions_borrow_total{result="error"}[1h]))
/
sum(rate(mctl_sessions_borrow_total{result=~"ok|error"}[1h]))
```

Current sessions active:

```promql
mctl_sessions_active
```

### Mitigation

1. **Identify the root-cause alert.** A tool-availability burn is typically
   downstream of a Telegram-layer or pool-layer problem. Check the other
   sections in this runbook in the following order:
   - [MctlTelegramNearCapacity](#mctltelegramnearcapacity)
   - [MctlTelegramFloodWaitSpike](#mctltelegramfloodwaitspike)
   - [TelegramClientErrors](#telegramclienterrors)

2. **Halt non-critical rollouts during the incident.** Any in-progress
   deployment that is not a hotfix for the current incident must be paused:
   ```sh
   kubectl -n mctl-telegram rollout pause deployment/mctl-telegram
   ```
   Resume after the incident is resolved:
   ```sh
   kubectl -n mctl-telegram rollout resume deployment/mctl-telegram
   ```

3. **Fast-burn incidents: page if root cause not identified within 30 minutes.**
   If the root cause cannot be identified and mitigated within 30 minutes
   of the fast-burn alert firing, page additional on-call responders.

4. **Error budget exhausted: activate feature freeze.** When the 28-day
   rolling SLI drops below the SLO target, activate the error-budget policy
   from [docs/slo.md](slo.md):
   - Freeze all non-`reliability` and non-`security` PRs.
   - Gate production deploys: only proceed when the 6h burn rate is below 1x.
   - Resume normal flow once the SLI returns to target and the remaining
     budget is at least 50%.

5. **Slow-burn alerts (ticket severity)**: file a reliability ticket
   immediately. Root-cause investigation should begin within one business
   day.

6. **Session borrow burn**: check database connectivity and migration state.
   A schema migration that locks the `sessions` table will cause borrow
   errors for the duration of the lock.

### Escalation

- **Fast-burn page**: on-call must respond within 5 minutes. If root cause
  not identified within 30 minutes, escalate to the second on-call and
  notify the engineering manager.
- **Slow-burn ticket**: assign to the reliability rotation within one
  business day. No page required unless it escalates to fast-burn.
- Escalate to the platform team for infrastructure-layer issues (database
  outage, Kubernetes control-plane degradation).

### Postmortem trigger

Open a postmortem if:
- A fast-burn incident lasts more than 30 minutes, OR
- The incident consumes more than 10% of the monthly error budget for any
  SLO.

See [docs/slo.md](slo.md) for the full error-budget policy and recovery
criteria.

---

<a id="canary"></a>
## Canary

Canary incidents (alert `MctlTelegramCanaryFailing`) use separate canary-specific
metrics that are not part of the main server metrics registry. See
[docs/runbooks/canary.md](runbooks/canary.md) for the full canary runbook.
