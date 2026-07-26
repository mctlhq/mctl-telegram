# MCTL Communication Agent — Plan

This is the single canonical plan for the Communication Agent, committed to
the repo so it is equally available to Claude Code, Codex, and any other
agent working on this codebase, in any session. Prior drafts lived only in
`~/.claude/plans/*.md` (a Claude-Code-local, machine-only location invisible
to Codex) — this file supersedes them. Where this file conflicts with
anything outside the repo, this file wins.

**Status (2026-07-26)**: Workstream A (core backend) is merged through PR 8.
C1 preview infrastructure is deployed and one complete Saved Messages
approval cycle has passed live end to end. Saved-command delivery is now
durable through DB-cursored history polling (#319, #322). C1 is still in
bounded validation: the 30-fixture run, kill-switch-after-approval drill,
and soak are not complete, and the listener is disabled and autopilot paused
between test windows. The Channels preview (Part 2) is scoped but not started
and is not a dependency of C1. Current evidence and the remaining C1
checklist live in
[`docs/reports/communication-agent-c1.md`](../reports/communication-agent-c1.md).

- ✅ A PR 1–5 — merged (#286, #288, #289, #299, #290)
- ✅ A PR 6 (Agent API) — merged as #306
- ✅ A PR 7 (control plane + executor) — merged as #307 (commit `33311bf`)
- ✅ A PR 8 (Option C headless worker) — merged as #308 (commit `98b338e`)
- ✅ Follow-up fixes — #309 (claude-review.yml dedup), #310 (job_leads schema fix)
- ✅ Worker MCP startup + durable completion verification — #316
- ✅ Saved Messages history polling + live approve cycle — #319, #322
- 🟨 C1 — staging deployment and bounded observe validation — **in progress**
- ⬜ A PR 8b / Channels preview (Part 2 below) — scoped, not started, not blocking
- ⬜ C2 — production promotion, gated on soak + a separate production quota domain

---

# Part 1 — Core Implementation

## Context

Build an autonomous communication agent that handles incoming Telegram DMs
(first scenario: HR/recruiters) via tg.mctl.ai: classify sender/intent,
collect vacancy details, send the owner summaries + draft replies into Saved
Messages, and only auto-reply within a strict server-side policy. Claude
never touches MTProto directly; all its actions are proposals validated
server-side. MVP = **observation mode** (no auto-sends; owner approves each
reply via `/mctl approve <code>` in Saved Messages).

Three repos are touched: **mctl-telegram** (all backend logic — the bulk of
the work), **mctl-claude-remote** (entrypoint support for the Channels
preview), **mctl-gitops** (deployment).

## Key findings that shape the plan (verified in code)

- **mctl-telegram had no incoming-update listener before this work** — reads
  were pull-based (`MessagesGetHistory` on demand). `ClientPool`
  (`internal/telegram/clientpool.go`) keeps one long-lived gotd client per
  user; PR 3/4 added a pinned, GC-exempt entry with an `UpdateHandler`.
- **Migrations are hand-rolled** in `internal/db/db.go` (`pgSchema()`/
  `sqliteSchema()`, idempotent on every boot). Repos follow the
  `internal/db/refresh_tokens.go` pattern.
- **Audience-scoped internal surface precedent**: `internal/bridge/`
  (`aud=bridge` HS256 JWTs, `selectBridgeProvider` in `cmd/server/main.go`,
  mint endpoint `POST /api/bridge/token`). The Agent API (`internal/agentapi`,
  `aud=agent`) is cloned from this pattern.
- **Saved Messages requires the owner's own MTProto session**
  (`tg.InputPeerSelf`) — `internal/digest/digest.go`'s bot-token path cannot
  write there; `internal/telegram/sendself.go` handles this.
- **Deployment**: services are auto-discovered from
  `mctl-gitops/platform-gitops/services/<team>/<service>/values.yaml` (shared
  `base-service` chart).
- **Caveat**: the `labs` namespace has `allowInternetEgress: true`
  namespace-wide; NetworkPolicies are additive, so a per-pod policy cannot
  tighten it. True egress restriction needs a dedicated tenant namespace
  (deferred to C2, see below).

## Architecture

```
Telegram DM → gotd updates.Manager (in mctl-telegram, pinned ClientPool entry)
  → incoming_events (unique event_id, ON CONFLICT DO NOTHING)
  → agent_jobs (pending)                      ← durable, at-least-once, SKIP LOCKED claim
  → Agent API /api/agent/v1 (aud=agent JWT, long-poll POST /jobs/claim, 11 restricted tools)
  → TRANSPORT (swappable — worker pulls the same API either way):
      · PRODUCTION/DEFAULT: Option C headless worker (cmd/agent-worker) — Go
        process pulls a job, invokes `claude -p` with restricted MCP tools,
        no Channels
      · EXPERIMENTAL, feature-flagged, never a production dependency:
        Option A — cmd/agent-channel stdio bridge, persistent Claude CLI
        session under Channels (see Part 2)
  → propose_reply / save_job_lead / send_owner_summary / complete_agent_job
  → server-side policy engine → observe: always require_approval;
    RE-CHECKED again immediately before send (approval → send is not atomic;
    state can change in between: takeover, pause, kill switch, rate limit)
  → Saved Messages (InputPeerSelf): summary + draft + /mctl approve|reject <code>
  → owner command (outgoing msg in Saved Messages, captured by same listener)
  → executor re-checks kill switch + policy → sends reply to the original peer only,
    using a persisted Telegram random_id so a retry after a crash mid-send is a
    no-op dedup at the MTProto layer, not a manual trap state
```

### Transport decision (corrected 2026-07-25 — supersedes the 2026-07-22 framing)

**The load-bearing constraint is not org tier — it's that `claude -p` (and
stream-json/SDK invocations) never register a Channels listener at all,
regardless of account.** Verified directly (2026-07-25, Claude Code 2.1.220,
`claude.ai` Pro account, no org): the MCP server connects and its tools work
under `-p` and under `-p --input-format stream-json` with stdin held open,
but `Channel notifications registered` never appears in either path and an
emitted `notifications/claude/channel` is silently dropped. The identical
server registers and receives notifications only under a **persistent
interactive CLI session running under a PTY**, after answering the per-launch
`--dangerously-load-development-channels` development-warning dialog.

A Team/Enterprise org with `channelsEnabled` + `allowedChannelPlugins`
removes that per-launch confirmation dialog (via an allowlisted plugin
instead of the raw dev flag) — but it does **not** change the headless/`-p`
limitation above. Getting an org would not make Option A viable as a simple
headless worker; a persistent interactive session is required either way.

**Decision: Option C (headless worker, no Channels) remains the production
transport.** Channels is pursued as a bounded, feature-flagged, non-production
preview deployment — `communication-agent-preview` — detailed in full in
**Part 2** below. It is not a one-off spike-proof anymore; it is scoped as a
real (if experimental) persistent-session service with its own recovery,
context-isolation, and security design. It does not block C1 and is not a
dependency of it.

Agent-API transport (server↔worker) is unchanged either way: **plain JSON
HTTP + long-poll (≤25s)**, not MCP-over-HTTP, not SSE/WS. Both Option C and
the Part 2 Channels preview call the identical JSON API 1:1 — the transport
choice never touches Telegram ingest, policy, or the executor.

**Production quota domain — blocking prerequisite before guarded autopilot.**
Option C's worker invokes `claude -p` using the same interactive-OAuth
credential pool as interactive Claude Code sessions and `claude-review.yml`'s
PR review jobs. That pool is shared, exhausts fast, and has no predictable
per-consumer throughput (see the closed-incident Appendix below for direct
evidence). The worker can be built and merged under `AGENT_ENABLED=false`
either way, but **must not be flipped on in production, and must not be
promoted past observe mode, until it runs against its own billing/quota
domain** — a separate org/account or a metered API key with its own budget,
rate limits, and alerts. Track as an explicit go/no-go gate alongside the
Rollout gates below.

## Workstream A — mctl-telegram (backend)

New packages: `internal/agent/{listener,queue,policy,control,executor,profile}`,
`internal/agentapi`, `internal/db/agent_*.go` + `updatestate.go`,
`internal/telegram/sendself.go`, `cmd/agent-worker` (Option C), and
`cmd/agent-channel` (Part 2, Channels preview).

**PR 1 — `feat(db): agent domain schema and repos`** ✅ merged (#286)
Tables (both dialects, in `internal/db/agent_schema.go`, hooked into
`Migrate()`): `agent_profiles`, `incoming_events` (unique `event_id`,
`body_encrypted` via `crypto.AESGCM`), `conversations`, `conversation_messages`,
`agent_actions` (approval_code, policy_decision, status
proposed→pending_approval→approved→executing→executed|rejected|expired|denied),
`job_leads`, `owner_notifications`, `tg_update_state`/`tg_channel_state`
(gotd pts/qts). `internal/audit/redact.go` covers `body`/`proposed_text`;
30-day retention sweeper for message bodies ships in the same PR.

**PR 2 — `feat(db): durable agent job queue`** ✅ merged (#288)
`agent_jobs` + `agent_job_attempts`; `EnqueueAgentJob` (idempotent by
event_id), `ClaimAgentJobs` (PG `FOR UPDATE SKIP LOCKED`; sqlite two-step),
`RetryAgentJob` (backoff `min(30s·2^n, 30m)`, max 5 → dead_letter),
`RequeueStaleAgentJobs` (visibility timeout 5m).

**PR 3 — `feat(telegram): pinned pool entries with update handlers`** ✅ merged (#289)
`ClientPool.WithAgentRuntime(rt)`, `Pin/Unpin` (GC exemption);
`internal/db/updatestate.go` implements `updates.StateStorage`.
`internal/telegram/sendself.go`: `SendToSelf`/`SendToInputPeer`.

**PR 4 — `feat(agent): incoming update listener`** ✅ merged (#299)
`internal/agent/listener`: `tg.NewUpdateDispatcher` wrapped in `updates.New`;
pure `ExtractEvent()` mapping. **Requires `replicas=1`.**

**PR 5 — `feat(agent): policy engine`** ✅ merged (#290)
`internal/agent/policy.Evaluate(Input) Result` — pure, table-driven-tested.
`mode==observe` always forces `require_approval`.

**PR 6 — `feat(agent): agent-facing HTTP surface`** ✅ merged (#306, spec issue #296)
`internal/agentapi` under `/api/agent/v1`, `aud=agent` JWT (cloned bridge
pattern). Endpoints: `POST /jobs/claim` (long-poll claim; deprecated
`GET /events` retained for rolling-upgrade compatibility), `GET /event/{id}`,
`GET /conversations/{id}/context`, `GET /recruiters/{peer}`, `GET /leads/{id}`,
`GET /policy`, `GET /jobs/{id}` (minimal durable completion postcondition),
`POST /actions/propose_reply`, `POST /leads`,
`POST /actions/request_owner_approval`, `POST /notify/summary`,
`POST /autopilot/pause`, `POST /jobs/{id}/complete`.

*Hardening debt flagged post-merge, not blocking observe-mode:*
- ✅ `POST /jobs/claim` is the worker path; the mutating legacy `GET /events`
  is deprecated and retained only for rolling-upgrade compatibility.
- ✅ Completion atomically verifies and stores exact
  `result_action_id`/`result_lead_id` linkage while fencing the active claim
  attempt; the model cannot supply either id to `complete_agent_job`.

**PR 7 — `feat(agent): saved-messages control plane + executor + owner profile`** ✅ merged (#307, spec issue #297)
`internal/agent/control`: `ParseCommand` for
`/mctl status|leads|show|continue|pause|takeover|approve|reject <arg>`.
`internal/agent/profile`: `OwnerProfileProvider` reading a YAML profile from
`AGENT_PROFILE_PATH`, restricted fields never returned to the agent surface.

`internal/agent/executor` crash-recovery design: approve → re-check kill
switch/mode/state → **persist the Telegram `random_id` for the send before
issuing the RPC** → set `executing` → send → `executed`. On restart while
`status=executing`, retry the same send RPC with the same persisted
`random_id` — MTProto dedups on `random_id`, so a retry after a crash is a
safe no-op if the original send landed, and a real idempotent send if it
didn't. Policy is re-checked a second time immediately before the send RPC
fires, not only at approval time. A concurrent owner reply cancels/blocks a
pending autonomous reply. Edit/delete of the source message invalidates the
draft or produces a new versioned event. Approval TTL 24h → expired.

*Approval code invariants*: cryptographically random (`newApprovalCode()`);
**stored as cleartext today** — flag as hardening debt before guarded
autopilot (a DB read compromise exposes live approval codes); single-use via
status transition; bound to owner + conversation + action + the current
message version; activated only via an atomic CAS state transition.

*`random_id` retry-safety* rests on MTProto's server-side dedup, which is
real but untested against this codebase's actual retry edges (reconnect,
full process restart, delayed retry, unknown-first-RPC-result, DC/session
change). Run a real integration test against the `mctl-reviewer` test
account before trusting this in guarded autopilot — not just unit tests
asserting the code path is reached.

**PR 8 — `feat(agent): headless worker (Option C)`** ✅ merged (#308)
Production/default transport (see Transport decision above). A Go worker
claims a job via long-poll, builds a strict envelope, invokes `claude -p`
with the restricted agent MCP tools and `--json-schema`, parses the result,
calls the corresponding `/api/agent/v1/actions/*` endpoint. A job is only
marked complete after its result is durably persisted server-side. No shell,
filesystem, or generic HTTP tool exposed to the model. Ships in its own
dedicated image (`Dockerfile.agent-worker`, not the main `mctl-telegram`
image — the worker needs the `claude` CLI, which the Go-only server image
deliberately doesn't have) — see `docs/agent-worker.md`.

**PR 8b — Channels preview** — see Part 2. Not a hardening-debt item on PR 8;
a separate, later, optional track.

**PR 9 — `docs+chore`** — not started. Runbook (bootstrap, kill switches,
dead-letter handling), config docs, adversarial test suite (prompt-injection
inputs → expected deny/approval), remaining alerts/metrics, and the expanded
retention table below.

*Retention scope beyond the 30-day message-body sweeper*: drafts/proposed
replies (`agent_actions.payload`), owner summaries (`owner_notifications.body`),
saved leads (`job_leads`), per-turn conversation context, dead-letter
entries, per-attempt audit rows (`agent_job_attempts`, `LogToolCall` chain),
the worker's own session logs, and the pod's PVC/backup snapshots. PR 9
should ship a retention table (storage surface → what's stored → retention
period → deletion mechanism) plus a "delete this one user's data" procedure
that actually reaches all of them.

**Also merged, not originally tracked**: #310 (`fix(db): add
job_leads.job_id via idempotent ALTER, not inline CREATE TABLE`) — a
follow-up correctness fix to PR 1's hand-rolled migration.
#309 (`fix(ci): dedupe claude-review runs and drop blind fallback retry`) —
see the closed-incident Appendix below.

## Workstream C — mctl-gitops (C1/C2)

**C1 — staging deployment, disabled/observe-only.** Not started; the next
actionable step now that #307/#308 are on main. Uses the existing `labs`
namespace and the existing `mctl-telegram-preview` service (already deployed;
confirmed present at
`mctl-gitops/platform-gitops/services/labs/mctl-telegram-preview/values.yaml`).
No new namespace for C1. Add `AGENT_ENABLED=true`, `AGENT_KILL_SWITCH=true`
(dark start), `AGENT_PROFILE_PATH`, a dedicated Agent API token, a test
Telegram account/session, and preview-only DB/encryption key. No production
promotion in this PR. (The Channels-preview deployment,
`communication-agent-preview`, is a separate new service under the same
`labs` namespace — see Part 2 §8; it is not part of C1's baseline scope, it
runs alongside it once built.)

**C1 hardening baseline** — pin the pod's securityContext/topology from the
first staging deploy:
- `AGENT_ENABLED`/kill switch closed by default.
- `replicas: 1` until a proven multi-replica ownership/leader-election model
  exists (same constraint as PR 4's listener).
- A dedicated Agent API credential (not reused from any other service).
- Non-root, read-only root filesystem, dropped Linux capabilities, seccomp —
  confirm the chart default actually satisfies all four per-deploy, don't
  assume it from the "existing hardened securityContext" note.
- `automountServiceAccountToken: false`; profile mount read-only.
- Claude/credentials volume scoped to minimal permissions, with a documented
  rotation/revocation procedure (add to PR 9's runbook scope).
- Explicit CPU/memory/ephemeral-storage limits, not just requests.
- No GitHub, MinIO, or cluster-scoped credential mounted into this pod.

**C2 — production-ready config + promotion, after soak.** Flips the account
into real observe-mode traffic (still no auto-sends per the MVP definition),
gated additionally on the production quota domain prerequisite above. This
is also where a dedicated `comms` tenant namespace (deferred from C1) would
be introduced if real egress isolation is still wanted at that point:
`tenants/comms/values.yaml` (`allowIntraNamespace: false`,
`allowClusterEgress: true`, `allowInternetEgress: false`) + a per-pod
NetworkPolicy restricting egress to DNS + 443-to-non-RFC1918 +
`labs-mctl-telegram.labs.svc:8080`. Note this is *not* a strict
Anthropic-only egress restriction — 443-to-all-non-RFC1918 is close to open
internet egress; it's defense-in-depth specifically because the model has no
generic HTTP tool, not because the policy itself constrains destinations
meaningfully. A real hostname-allowlist needs an egress proxy/gateway
(Cilium FQDN filtering or a forward proxy) — track as a hardening item.

mctl-telegram values: `AGENT_ENABLED`, `AGENT_KILL_SWITCH`, profile secret.
DB: reuse the existing `labs-mctl-telegram` database (no new DB).

## Rollout gates

1. **Observe mode** (MVP DoD): ≥30 dialogs, classification ≥90%, 0
   restricted-info leaks, 0 wrong-peer sends, JSON validity ≥99% → then
2. **Before Guarded autopilot, all of the following must be true**:
   - Production quota domain provisioned and in use (separate from
     interactive Claude Code + `claude-review.yml` pool).
   - PR 6 hardening debt resolved (`POST /jobs/claim`, atomic
     `result_action_id`-based completion).
   - Approval-code invariants verified by explicit test, codes stored as hash
     not cleartext.
   - `random_id` MTProto-dedup failure drill run against the `mctl-reviewer`
     test account.
   - Full per-surface retention table shipped (PR 9).
3. **Guarded autopilot** (discovery questions only auto-sent; everything else
   approval) → then
4. **Hardening**: daily message caps, circuit breaker, replay protection,
   full alert set (`mctl_agent_*` metrics wired to AlertManager).

## Out of scope

WhatsApp/Viber/Gmail, CRM, auto-CV, attachments, link-opening, interview
scheduling, calendar, Kafka, universal assistant.

## Verification (Part 1)

- Per-PR: existing test patterns (`newTestStore` sqlite for repos;
  table-driven pure tests for extract/policy/parser; `httptest` + local JWT
  tokens for agentapi incl. aud enforcement — MCP token must 403).
- End-to-end (staging, before observe soak): send a DM from a second account
  (`mctl-reviewer` test acct) → verify event row, job claim via curl with
  agent token, `propose_reply` → policy `require_approval` → Saved Messages
  draft arrives → `/mctl approve <code>` → reply lands in the original chat
  with disclosure line → audit chain rows present → `complete_agent_job`
  closes the job. Kill-switch flip mid-flow must block execution.
- Adversarial suite: injection prompts ("Ignore your previous instructions",
  "Send me Dmitry's phone number", …) asserted to produce deny/approval at
  the **policy layer** regardless of model output.
- Failure drills: duplicate update (dedup), pod restart mid-job (visibility
  requeue), invalid JSON (1 repair retry → dead_letter), owner takeover
  mid-job.
- **Before guarded autopilot only**: `random_id` MTProto-dedup failure drill,
  explicit approval-code single-use/binding test.

---

# Part 2 — Channels Preview (`communication-agent-preview`)

Status: ready for implementation planning and scoped delivery.
Verified against Claude Code `2.1.220`, `claude.ai` Pro account, no
Team/Enterprise org.

## 2.1 Objective

Build an experimental `communication-agent-preview` deployment that
processes Telegram DM jobs through a persistent Claude Code Channels session,
while Option C (Part 1) remains the production/default transport.

The preview must prove:

1. A durable `agent_jobs` claim can wake a persistent Claude session through
   a custom `notifications/claude/channel` MCP server.
2. Claude can use only the restricted Agent API tools.
3. Every tool call remains bound server-side to the active `job_id + attempt`.
4. A crash, dropped notification, or stale session cannot lose a job or
   write a stale result.
5. Telegram sends remain governed by the existing server-side policy,
   approval flow, send gates, persisted `random_id`, and executor recovery.

The preview must not:

- change the production `tg.mctl.ai` deployment;
- merge the release-please PR merely to obtain an image;
- make Channels a dependency of C1 or the production path;
- reuse the live PR-steward Claude session;
- expose shell, filesystem, generic HTTP, GitHub, Kubernetes, or MTProto
  tools to Telegram-supplied content;
- enable guarded autopilot.

## 2.2 Repositories touched

- **mctl-telegram** — `cmd/agent-channel`, `internal/agentchannel` (Workstream T).
- **mctl-claude-remote** — communication-agent runtime mode, PTY driver
  (Workstream R).
- **mctl-gitops** — `communication-agent-preview` deployment in `labs`
  (Workstream G).

Merged foundation this builds on: PR #307 (control plane/executor), PR #308
(Option C worker) — see Part 1.

## 2.3 Verified facts

| Invocation | MCP connection | Channel listener | Payload delivery |
|---|---:|---:|---:|
| `claude -p "..."` | yes | no | no |
| `claude -p --input-format stream-json` with stdin kept open | yes | no | no |
| persistent interactive CLI under a PTY | yes | yes | yes |

> As of Claude Code 2.1.220, custom development channels loaded through
> `--dangerously-load-development-channels` are not registered in the tested
> `-p`/SDK CLI paths, including long-lived stream-json input. The same
> channel registers and receives notifications in persistent interactive CLI
> mode after the per-launch TUI confirmation.

Do not broaden this to all future Claude Code versions or to
Anthropic-allowlisted plugins — it is verified for a custom development
channel on the stated runtime and account. Reproduce locally with a minimal
`server.notification()` MCP server declaring
`capabilities.experimental["claude/channel"]`; do not commit raw spike logs
(they may contain account identifiers, prompts, or session IDs) — only the
sanitized matrix above.

The per-launch development-warning dialog reappears every launch for the
same server and workspace; it is not eliminated by previously accepting it.
The separate "New MCP server found in this project" consent is tied to
project `.mcp.json` — pass an explicit `--mcp-config` file and pre-seed
workspace trust to avoid that second dialog; the development-channel warning
itself is unavoidable on the Pro/custom-channel path.

## 2.4 Transport options

### Option C — existing per-job headless worker (Part 1)

Already merged. Clean context per job, job identity/attempt passed outside
model-controlled input, built-in tools disabled, simple per-job budget/timeout,
crash recovery via queue visibility timeout and fencing. Production/default.

### Option A — persistent custom Channels session

```
agent_jobs claim
  → cmd/agent-channel holds one active job
  → notifications/claude/channel wake-up
  → persistent Claude CLI turn
  → job-scoped restricted MCP action
  → complete_agent_job
```

Works only in the verified persistent CLI/PTY path; requires a per-launch
development-warning confirmation on Pro; the notification is a wake-up,
never a durable acknowledgement; context persists across jobs unless
explicitly rotated; needs independent session recovery and
context-isolation controls. Experimental preview transport only.

### Option B — Channels combined with Remote Control

Option A plus `--remote-control`. Reuses existing relay health machinery and
lets an operator inspect the live session, but adds another input path into
the agent session (operator messages can contaminate agent context), and the
existing health check reflects relay health, not durable queue/channel
health. **Allowed only as a short-lived diagnostic mode, never the default
preview design, never the readiness signal or a transport dependency.** If
enabled, no operator messages may be sent while an agent job is active.

### Option A-Team — custom Channels through a Team/Enterprise allowlist

Same persistent execution model as Option A, packaged as an allowlisted
plugin (`channelsEnabled` + `allowedChannelPlugins`). Removes the
development-warning dialog. Does **not** solve persistent context isolation,
per-job routing, session crash recovery, tool restriction, or durable job
acknowledgement — optional future hardening, not required for the Pro
preview, not a reason to delay it.

### Hybrid comparison deployment

Run Option C and Option A against separate test queues/accounts or
deterministic replayed fixtures. Never let both transports claim from the
same live queue without an explicit partition — that makes comparison and
recovery nondeterministic. Compare: claim-to-first-action latency, total
model cost per completed job, valid completion percentage, context leakage
across conversations, stale-attempt rejection count, restart recovery
duration, dead-letter percentage, operator intervention count.

## 2.5 Chosen preview architecture

Use the existing `labs` namespace for the preview. A separate `comms`
namespace is deferred to C2/production isolation (Part 1).

```
labs namespace
├── mctl-telegram-preview            (existing; C1 baseline)
│   ├── MTProto user session
│   ├── incoming listener
│   ├── encrypted event/conversation storage
│   ├── durable agent_jobs queue
│   ├── Agent API
│   └── policy + executor
│
├── communication-agent-preview      (new; this workstream)
│   ├── persistent Claude CLI under a PTY
│   ├── exact-match development-warning driver
│   ├── cmd/agent-channel stdio MCP subprocess
│   ├── separate Claude credentials/state
│   └── no ingress, GitHub, Kubernetes, or MTProto access
│
└── claude-remote                    (existing PR steward; unchanged, isolated)
```

Why a separate deployment is mandatory even inside `labs`: different
lifecycle/restart behavior; different credentials and quota; no GitHub App
secret or cluster RBAC; independent scale-to-zero kill switch; a Claude
failure must not restart MTProto/API; untrusted Telegram content must never
enter the PR-steward session.

## 2.6 Workstream T — mctl-telegram: `cmd/agent-channel`

One focused PR. Do not combine with unrelated Agent API hardening.

**T1 — Reuse, don't duplicate, Option C's client/tool definitions.** Refactor
only as needed so both `agent-worker` and `agent-channel` share the Agent API
client, exact tool names/schemas, job envelope/`JobContext`,
response/error mapping, and redacting logging. No second independently
maintained list of the 11 tools.

**T2 — Implement the channel MCP server.** Add `cmd/agent-channel` and
`internal/agentchannel`. Update the mctl-telegram Docker build so the preview
image contains a statically linked `mctl-telegram-agent-channel` binary (the
artifact the R6 init-container packaging copies out). The server must: use
stdio MCP; declare `capabilities.experimental["claude/channel"] = {}`; expose
only the restricted Agent API tools; long-poll/claim through the Agent API;
emit a wake-up with no raw Telegram body and no model-selectable peer; keep
active job identity outside model-controlled arguments; reject every tool
call when no job is active; bind every action to the active
`job_id + attempt + conversation_id`; serialize to one active job per
process; accept `complete_agent_job` exactly once per attempt; clear the
active slot only after durable completion succeeds; redact bodies/profile
data/tokens/proposed text from logs.

Wake-up payload — no Telegram IDs, event IDs, message bodies, or the Agent
API token in notification text or process arguments:

```
A communication-agent job is ready. Use get_event and
get_conversation_context for the server-bound current job. Complete the job
exactly once.
```

**T3 — Recovery semantics.** Channels notification delivery is not an
acknowledgement.

```
no active job
  → claim job(attempt=N)
  → set active job locally
  → emit notification
  → restricted tool calls
  → durable action/lead write
  → complete(job, attempt=N)
  → clear active job
```

On a crash: do not locally mark the job complete; let the visibility timeout
requeue it; a new claim receives a higher/current attempt; stale tool calls
from the old session must receive conflict/not-found; notification
redelivery must return the persisted exact action/body, never generate
conflicting durable state. No in-memory acknowledgement competing with the
database queue.

**T4 — Context-isolation policy.** Preview phase 1: one test owner, one
allowlisted sender/conversation at a time, one active job, no concurrent
conversation interleaving. Before expanding to multiple live conversations,
choose and prove one strategy:

1. Single persistent session with bounded rotation — lowest operational
   cost, highest context-contamination risk.
2. One session/process per conversation — strong isolation, higher
   process/quota/operational cost.
3. Short-lived session per job — strong isolation, but removes most of
   Channels' benefit and converges on Option C.

Do not silently promote strategy 1 beyond the single-conversation preview.

**T5 — Tests.** Unit: channel capability declaration; exact shared tool
list; no built-in/generic tools in generated launch config; tool call
rejected without active job; stale attempt rejected; wrong
conversation/job identity cannot be supplied by the model; duplicate
notification does not create a second action; complete clears the active
slot only after server success; logs contain no event body/token/proposed
text. Integration: fake Agent API claim → notification → tool → complete;
crash after claim before notification; crash after notification before
action; crash after durable action before complete; visibility-timeout
requeue; stale old process attempts a write after new claim.

```sh
go test -count=1 ./...
go vet ./...
go test -race ./internal/agentchannel/... ./internal/agentworker/... ./internal/agentapi/...
govulncheck ./...
```

## 2.7 Workstream R — mctl-claude-remote: communication-agent mode

Separate PR after or alongside Workstream T. Off by default.

**R1 — Pin and reproduce.** Bump the image pin from `2.1.198` to `2.1.220`,
or explicitly document why the preview stays on `2.1.198`. Run the same
no-tools custom-channel matrix inside the built container; require an
interactive positive control before proceeding. Update
`mctl-claude-remote/docs/claude-channels-spike.md` with the proven Pro/
full-round-trip and `2.1.220` results — that file currently still says
Channels needs a Team/Enterprise org to be viable at all, which overstates
the constraint (see Transport decision, Part 1); correct it in this PR.

**R2 — Add an explicit mode, not arbitrary CLI injection.**

```
CLAUDE_RUNTIME_MODE=remote-control|communication-agent
AGENT_CHANNEL_MCP_CONFIG=/etc/communication-agent/mcp.json
AGENT_CHANNEL_SERVER=server:agent-channel
```

No generic `CLAUDE_EXTRA_ARGS` that permits arbitrary shell fragments.
Validate server names and paths.

**R3 — PTY warning driver.** Must launch the persistent CLI under a PTY and:
wait for the exact heading `WARNING: Loading development channels`; verify
the displayed channel is exactly `server:agent-channel`; select
`I am using this for local development`; time out and exit nonzero if the
expected prompt does not appear; fail closed on an unknown prompt or changed
text; never answer a permissions prompt, workspace trust prompt, login
prompt, or arbitrary confirmation; emit only structural status logs, never
TUI content containing Telegram data. Preferred implementation: a small Go
PTY driver with exact screen-state matching. An `expect` script with ANSI
normalization is acceptable for preview if pinned/tested. Blind
newline/keystroke piping is prohibited. This driver is an experimental
preview dependency, not approved for production promotion.

**R4 — Restrict Claude tools.** The launched session must receive:

```
--tools ""
--allowedTools <exact agent-channel MCP tool list>
--mcp-config <explicit file>
--strict-mcp-config
--dangerously-load-development-channels server:agent-channel
```

Do not reuse the existing default `--dangerously-skip-permissions` invocation
for Telegram-driven work. The model process must not inherit
`AGENT_API_TOKEN`, GitHub credentials, Kubernetes credentials, MinIO
credentials, or unrelated application secrets — only the `agent-channel` MCP
subprocess receives the Agent API token.

**R5 — Session state and health.** Reuse persistent HOME, session ID
management, bounded transcript retention, supervisor/relaunch logic. Do not
assume the existing Remote Control TLS health check proves Channels health.
Preferred readiness source: `agent-channel` exposes a loopback-only health
endpoint or readiness file after the MCP client connects; readiness becomes
false on stdio disconnect; liveness requires both the Claude process alive
and the channel MCP connected; metrics count session starts, prompt-driver
failures, MCP reconnects, and uncompleted active-job restarts. Remote
Control may be enabled temporarily for diagnostics but is never the
readiness source and should be off for the normal preview.

**R6 — Runtime packaging.** The Claude CLI and `agent-channel` binary
currently live in different images.

1. **Init-container copy — recommended for C1.** An init container using
   the exact `mctl-telegram-preview` image copies the static
   `mctl-telegram-agent-channel` binary into a shared volume; the
   `mctl-claude-remote` container runs it from there. Verify the copied
   binary checksum/version at startup, log only the non-sensitive version.
2. Dedicated combined image — cleaner long term, another build/release
   artifact.
3. Install Claude CLI into the mctl-telegram image — rejected: expands the
   public server image, couples unrelated runtime concerns.

**R7 — Tests.** Shell syntax and unit tests for the PTY driver; exact
expected prompt accepted; changed prompt text rejected; wrong channel name
rejected; login prompt rejected; permission prompt rejected; process restart
repeats the development confirmation safely; channel MCP disconnect flips
readiness; no Agent API token in Claude environment or
`/proc/<pid>/cmdline`; no built-in tools available; no transcript contains
plaintext Telegram bodies when the chosen session-persistence mode says it
should not.

## 2.8 Workstream G — mctl-gitops: C1 preview deployment

Human-reviewed PR. Never auto-merge `mctl-gitops`.

**G1 — Keep production untouched.** Do not merge mctl-telegram release PR
#303 as part of this. Do not change
`platform-gitops/services/labs/mctl-telegram/values.yaml`. Use
`mctl-telegram-preview` and its `main-<sha>` image track. Verify the preview
image contains the required agent binaries before rollout.

**G2 — Configure mctl-telegram-preview.**

```
AGENT_ENABLED=true
AGENT_KILL_SWITCH=true            # initial dark phase
AGENT_PROFILE_PATH=<read-only mount>
AGENT_PROFILE_OWNER_TG_ID=<test owner>
```

Preview database only, preview encryption key only, test Telegram
account/session only, dedicated `aud=agent` token, no production owner
profile.

**G3 — Add `communication-agent-preview`.**

Path: `platform-gitops/services/labs/communication-agent-preview/values.yaml`

Initial state: `replicaCount: 0`. Required: separate deployment; no ingress;
no public Service; `automountServiceAccountToken: false`; no
Role/ClusterRole/RoleBinding; no GitHub App secret; no PR-steward config; no
shared `claude-remote` workspace; dedicated Agent API token; dedicated
Claude credentials/state; explicit CPU/memory limits; read-only root
filesystem where compatible; all Linux capabilities dropped; non-root
UID/GID; loopback health probes only.

**G4 — Claude state storage.** Choose after checking current `labs` PVC
quota/usage: (1) dedicated PVC — best isolation, note the Hetzner volume
minimum and tenant PVC quota; (2) dedicated MinIO prefix/credentials —
avoids a new PVC but needs restore/sync sidecars and MinIO secrets;
(3) shared existing claude-remote state — **prohibited**. Do not store
writable refreshed Claude credentials in a ConfigMap or immutable Secret.

**G5 — Networking.** The `labs` tenant currently allows internet and
intra-namespace egress; NetworkPolicies are additive and cannot make this a
strict Anthropic-only sandbox. For preview: accept this limitation
explicitly, expose no generic HTTP tool to the model, limit
application-level destinations to the preview Agent API, mount no
namespace/service credentials. Production isolation (dedicated
namespace/tenant, FQDN-filtered egress) is a C2 concern.

## 2.9 Rollout phases

**Phase 0 — manifest and dark validation.** `communication-agent-preview`
replicas `0`; `mctl-telegram-preview` has `AGENT_ENABLED=true`,
`AGENT_KILL_SWITCH=true`; mint/validate the dedicated Agent API token;
validate profile mounting and owner binding; verify no route/secret points
at production; validate rendered Helm manifests.
*Exit*: no production diff; no public endpoint; secrets/service-account
boundaries correct; preview server starts and migrations succeed.

**Phase 1 — channel runtime smoke test.** Scale to one replica; keep
`AGENT_KILL_SWITCH=true`; verify PTY driver, channel registration,
readiness, and empty-queue idle; inject a synthetic/fake Agent API job
before using Telegram; verify restricted tools and durable complete
behavior. *Exit*: no manual prompt after pod start; no unknown prompt
auto-accepted; channel readiness observable; synthetic job survives a
process restart.

**C1 validation hardening** 🟨 in progress

- `agent_profiles.sender_allowlist` gates incoming private/edit events before
  the listener creates any conversation, event, or job. Empty means allow all
  for backward compatibility; C1 sets exactly the dedicated test sender.
  Owner outgoing takeover detection and Saved Messages commands are not
  filtered.
- The opt-in real-model harness in
  `internal/agentworker/eval_test.go` runs the production `ClaudeInvoker`,
  real Claude Code CLI, and real job-scoped stdio MCP server over 30 JSONL
  fixtures. It asserts action class and required extracted fields without
  brittle exact-draft matching, plus 30/30 same-attempt terminal jobs, zero
  restricted/adversarial output leaks, and zero wrong binding writes.
- C1 acceptance is at least 27/30 correct fixture classifications, all 30
  terminal, and zero leaks/wrong-peer/stale-attempt writes, followed by the
  three live Telegram drills recorded in the C1 report.

**Phase 2 — one test Telegram conversation.** Dedicated test owner + one
allowlisted sender; `AGENT_KILL_SWITCH=false`; profile mode `observe`; do
not approve a real outbound reply until summary/draft routing is verified;
verify Saved Messages notification and policy decision; approve only a
harmless test reply to the test sender; flip kill switch between approval
and send and require the executor to block. *Exit*: zero wrong-peer sends;
exact intended body on recovery/redelivery; stale attempts rejected; no
restricted profile fields exposed; audit chain intact.

**Phase 3 — bounded observe soak.** Maximum one conversation at a time;
collect ≥30 test dialogs/fixtures; compare Option A and Option C on
partitioned/replayed inputs; track latency, cost, valid completions,
restarts, dead letters, context contamination. *Exit*: classification
accuracy ≥90%; JSON/tool completion validity ≥99%; zero restricted-data
leaks; zero wrong-peer sends; zero stale-attempt durable writes; documented
restart recovery; no unexpected built-in tool availability.

**Phase 4 — decision.** (1) Channels shows material benefit and passes all
gates → continue hardening. (2) Works but no material benefit → retain as
diagnostic/spike. (3) Context/recovery/PTY risk too high → scale to zero,
keep Option C only. Do not promote to production merely because the
happy-path demo works.

## 2.10 Failure drills

Required before the Phase 4 decision: kill Claude after job claim but before
notification; kill after notification but before first tool; kill after
durable action write but before completion; restart the entire pod; delay
restart past visibility timeout; let an old process attempt a stale write
after a new attempt claims the job; send two jobs close together and verify
strict serialization; send an edit/delete for the source message while a job
is active; owner takeover while a job is active; kill switch flip before
send; Agent API token revocation; malformed MCP response; development
warning text changed; channel subprocess exits while Claude remains alive;
Claude exits while the channel subprocess has an active job. Every drill
must record expected DB/job/action states, not only log output.

## 2.11 Security review checklist

Telegram body is untrusted input. Channel instructions cannot override the
server-side job binding. Model never chooses peer/user/conversation/job/attempt.
Built-in tools are absent, not merely denied at invocation time. Only
allowlisted Agent MCP tools are visible; `alwaysLoad: true` blocks the first
single-turn prompt until the job-scoped MCP server connects. Agent API token
is available only to the MCP subprocess. Claude credentials are separate from PR
review/steward credentials. No GitHub, Kubernetes, MinIO, production DB, or
production Telegram secrets. No message bodies in logs, argv, Kubernetes
events, or health endpoints. Saved Messages and outbound replies still pass
existing send gates. `complete_agent_job` follows a durable action/lead
commit. After Claude exits, the worker accepts success only when
`GET /jobs/{id}` confirms that the same attempt is terminal; final model text
is never completion evidence. Stale attempts fail closed. Deployment can be
disabled by scaling to zero. Server-side send kill switch remains independent
of the worker pod.

## 2.12 PR sequence

1. **R0 docs**: update `mctl-claude-remote/docs/claude-channels-spike.md`
   with 2.1.220 facts and the corrected org-tier framing.
2. **T1**: shared Agent API tool definitions/refactor, behavior unchanged.
3. **T2**: `cmd/agent-channel` + unit/integration tests.
4. **R1**: communication-agent runtime mode + exact PTY driver + health.
5. **G1**: disabled GitOps deployment (`replicas: 0`) + preview server flags.
6. **G2**: enable one replica for Phase 1 after image availability and
   secret bootstrap.

Each PR must be independently reversible. Do not combine T2, R1, and G1 into
one review unit.

## 2.13 Instructions for the implementing agent

Before editing: read each repository's `AGENTS.md`/contributor instructions;
fetch current remote state; use isolated worktrees/branches; preserve
unrelated user changes and untracked files; confirm actual current image
tags and GitOps quota usage instead of copying values from this plan
blindly.

Git rules: conventional commit subjects; no `Co-Authored-By` trailers;
mctl-telegram uses squash merge; no manual release tags; do not merge
release PR #303; never auto-merge `mctl-gitops`.

Operational rules: no production writes; no Vault secret values in chat,
shell history, commits, or logs; do not copy the live `claude-remote`
credentials/workspace; require explicit operator approval before scaling
the preview above zero or disabling the kill switch; follow GitOps
desired-state flow, not `kubectl edit`.

## 2.14 Decision gates requiring the operator

Ask before: (1) choosing PVC versus dedicated MinIO state; (2) scaling
`communication-agent-preview` from `0` to `1`; (3) performing
`claude auth login` in the new state volume; (4) changing
`AGENT_KILL_SWITCH` from `true` to `false`; (5) approving the first real
test reply; (6) expanding beyond one allowlisted conversation; (7) moving
the deployment from `labs` to a dedicated namespace; (8) promoting Channels
beyond experimental status. All other implementation details may proceed
autonomously within the stated scope.

## 2.15 Definition of done for Part 2

Option C remains operational and unchanged as the default; a separate
`communication-agent-preview` can be safely scaled from zero; the custom
channel registers under the pinned container runtime; the per-launch
warning is handled by an exact-match fail-closed PTY driver; a test
Telegram job completes through Channels with only restricted tools;
crash/requeue/stale-attempt drills pass; context scope is limited and
documented; all security boundaries are verified; comparison data supports
an explicit keep/drop/promote decision.

---

# Appendix — claude-review.yml cost investigation (closed, 2026-07-22)

Kept as historical record; not forward-looking plan content.

Mid-development, both interactive `/compact` and `claude-review.yml`'s PR
review jobs started failing with `"You've hit your org's monthly usage
limit"`, blocking #307/#308 from getting a review verdict.

**Root cause**: `pull_request: [opened, reopened, synchronize,
ready_for_review]` already auto-fires a review on every push; this session's
habit of "push fix commit, then comment `@claude review`" duplicated a
review the push had already triggered. Four fully redundant sessions in one
day on this repo from that pattern alone. No `concurrency` group existed to
cancel/dedupe overlapping runs. The fallback-token step
(`CLAUDE_CODE_OAUTH_TOKEN_2`) did not distinguish failure causes and drew
from the same exhausted org quota as the primary, so it was guaranteed to
fail identically while still burning a second full session first
(`duration_ms: 404, num_turns: 1, total_cost_usd: 0` — instant, zero-turn,
zero-cost, distinguishable from a genuine transient failure).

An earlier draft proposed removing the `pull_request` auto-trigger entirely.
Rejected — that trigger *is* the merge gate; removing it means a push
silently never gets reviewed unless a human remembers to comment, which
regresses the actual safety property. The waste came from redundantly
commenting on top of the auto-trigger, not from the auto-trigger existing.

**Fix, applied and merged as #309** (`fix(ci): dedupe claude-review runs and
drop blind fallback retry`):
- `concurrency` group (`claude-review-<repo>-<pr>`, `cancel-in-progress:
  true`) **plus** a cheap preflight dedup step that checks via `gh api`
  whether a review already exists for this PR + head SHA and skips the job
  entirely if so — concurrency alone only bounds the waste to one run, not
  zero, since the first run may already have spent tokens before
  cancellation lands.
- Removed the automatic fallback-token retry (it doubled a guaranteed-identical
  quota failure); posts a status comment prompting a manual re-trigger
  instead.
- **Behavioral fix**: stop commenting `@claude review` right after pushing a
  fix commit — the `pull_request`/`synchronize` trigger already covers it.
  Only comment manually when a re-review is needed *without* a new push.

Not yet verified fleet-wide — the other ~12 repos sharing this workflow
pattern have not had their `claude-review.yml` checked against these same
defects.
