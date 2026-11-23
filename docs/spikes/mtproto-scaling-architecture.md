# MTProto scaling architecture spike (#1282)

Status: PROPOSED research. Refs #1282 (not Closes). Docs only: no runtime,
test, schema, config, credential or permission change. Source inspection and
design only. The outcome is pending the owner; merging this file grants no
authority to implement anything in it.

Base: `origin/main` at `d10f33bf4c314e91523596b048abe903d85e1599`. Every
`path:line` below is at that SHA unless another is named.

Labels used throughout: OBSERVED (read in repository source at the SHA),
REPORTED (stated in a repository document, not re-measured here),
VENDOR-PARAPHRASE (the orchestrator's bounded paraphrase of a Telegram page
read on 2026-11-14; not a snapshot), DEP-UNVERIFIED (behaviour of a
dependency's internals; the dependency cache was out of scope, so it was not
read), UNKNOWN, NOT_RUN.

## 1. Scope and limits of this document

- It does not repeat the design already recorded in
  [ADR 0005](../adr/0005-session-pool-and-sticky-routing.md),
  [docs/hpa.md](../hpa.md) and [internal/bridge/DESIGN.md](../../internal/bridge/DESIGN.md).
  It cites them and adds what they leave open.
- No benchmark was run. No Telegram request was made. Every capacity number
  that is not already in a repository document is UNKNOWN or NOT_RUN.
- The issue numbers #1115, #145, #126, #568, #1108 are mapped from the task
  statement. The repository carries text for some of them (section 11); for
  the others the title and state are UNVERIFIED here, and the connector
  evidence the task allows must confirm them before anyone relies on the map.
- Facts about other repositories (mctl-gitops replica count, resource limits,
  probes) are only what this repository's docs say about them. Nothing from
  another checkout was read.

## 2. Evidence the spike rests on

Repository (OBSERVED unless marked):

| Fact | Where |
|---|---|
| One gotd client per `user_id`, in a per-process map, each with `run()` and `gc()` goroutines | `internal/telegram/clientpool.go:109-155,462-515` |
| Pool cap is a count of map entries; 0 means uncapped | `clientpool.go:113,473-477`; `internal/config/config.go:240-241,629` |
| Idle teardown after `IdleTimeout`, checked once a minute; pinned (listener) entries are exempt and heartbeat the DB row | `clientpool.go:596-627` |
| Every `Borrow` does one session-validity SELECT and one `last_used_at` UPDATE, plus a session load on a cold entry | `clientpool.go:253-274,326-329`; `internal/db/store.go:1749-1760,1811-1830`; `internal/telegram/sessionstore.go:27-46` |
| A pooled client can never create an auth key: no active row means `db.ErrNoActiveSession` | `sessionstore.go:17-46` |
| The first loaded row id is pinned for the client's life; revocation is by row id, never by user | `sessionstore.go:61-65`; `clientpool.go:423-460,539-594` |
| `Close`, `RemoveAtomic`, `revokeRejected`, idle GC and `Shutdown` all call `cancel()` and do not wait for `client.Run` to return | `clientpool.go:439-460,637-703,621-625` |
| `acquire` refuses only while `retiring[userID]` is set (async revoke) and counts only entries still in the map | `clientpool.go:466-477,556-575` |
| One shared api_id-wide token bucket (`TG_API_RATE_PER_SEC`, `TG_API_RATE_BURST`), default off, shared with the login client | `cmd/server/main.go:222-252`; `config.go:242-253,630-631` |
| `/healthz` and `/readyz` are the same handler and always return 200 | `cmd/server/main.go:504-505,996-1000` |
| Shutdown: `srv.Shutdown` with a 10 s context, then wait for the broadcast worker; `pool.Shutdown` is a deferred `cancel()` per entry | `main.go:248,940-946`; `clientpool.go:697-703` |
| `ConfirmStore` (10 min TTL, single-shot, in-memory), `MediaStore` (same TTL), `PeerCache` (10 min TTL plus dialog snapshots), all per process | `internal/mcp/confirm.go:12-45`; `internal/mcp/mediastore.go:25-39`; `internal/telegram/peercache.go:10-47` |
| Local Bridge `Hub`: in-process, one connection per user, 100 in-flight calls per daemon, ping every 25 s, 5 s pong deadline; relay rollout makes every daemon reconnect | `internal/bridge/hub.go:49,159-300`; `internal/bridge/DESIGN.md`; `docs/runbook.md:2841` |
| Production strategy is `Recreate` at one replica, required for correctness as well as MTProto | `docs/runbook.md:233-257,3171-3177`; ADR 0005 |
| `AUTH_KEY_DUPLICATED` is classified as a revoked-session code and revokes the loaded row | `clientpool.go:28-36`; `docs/troubleshooting.md:218-232` |
| A preview account was found rejected with `AUTH_KEY_DUPLICATED` after a Deployment-strategy change; a fresh OAuth reconnect cleared it | `docs/reports/communication-agent-c1.md:74-83,150-158` (REPORTED; the cause is not established there) |
| RSS reported as about 30 MB baseline and about 58 MB at 100 idle sessions, with a stated per-session figure of 2.8 MB and 3 MB used for planning. The document is internally inconsistent: (58 - 30) / 100 = 0.28 MB per session, ten times lower than the stated 2.8 MB. Which is right is UNKNOWN; neither is re-measured here | `docs/hpa.md:17-26` (REPORTED; amd64, Go 1.25, idle only) |
| About 40 users in the live-login study window | `docs/runbook.md:3667` (REPORTED) |
| Service availability targets: tool 99.5% (3 h 36 min per 30 days), OAuth 99.9% | `docs/slo.md:156-165` |
| Pool-full and flood-wait metrics exist; the pool cap is currently unset, so saturation is unmonitored | `internal/metrics/metrics.go:736-756`; `docs/hpa.md:120-126` |

Telegram (VENDOR-PARAPHRASE; not observed production behaviour):

- `/api/obtaining_api_id`: `api_id`/`api_hash` authorize an application; one
  `api_id` per phone number is currently issued; the published sample app id
  is for testing and is limited; client abuse is monitored. Nothing in it
  grants or denies fleet capacity or a rate.
- `/api/datacenter`: DC endpoints change and `help.getConfig` lists them; main
  queries go to the closest access point; the config includes `tmp_sessions`.
  This does not by itself define what concurrent use of one permanent key
  means. The exact rule is UNKNOWN until a specific source is read.
- `/api/errors`: errors are structured (numeric code and type); `FLOOD_WAIT_X`
  carries a wait; migration errors exist. No exhaustive rate formula.
- Published limits are incomplete. This document asserts no per-account or
  per-IP exclusivity, designs no rate-limit evasion and proposes no `api_id`
  pooling.

Dependency (DEP-UNVERIFIED): `gotd/td v0.163.0` (`go.mod:12`). How many TCP
connections a `telegram.Client` opens, whether it opens extra connections or
exported authorizations for other DCs or media, and how fast `Run` tears down
after cancel were not read. Section 6 treats these as unknowns to measure.

## 3. Identifiers that must not be conflated

| Term | What it is | Who holds it here | Scaling consequence |
|---|---|---|---|
| `api_id` / `api_hash` | Application credential for the whole deployment | `TG_API_ID`/`TG_API_HASH`, one pair, shared by every pooled client and the login client (`main.go:222-252`) | One shared budget and one abuse-monitoring identity. Adding replicas does not add credentials. Adding credentials is out of scope (no `app_id` pooling) |
| User authorization | A logged-in Telegram account | `telegram_accounts` row, sealed at rest (ADR 0001) | Survives restarts; revoked server-side by the user or Telegram |
| Permanent auth key | Per-DC key from the DH handshake; the authorization is bound to it | Session blob in the row, loaded by `SessionStore.LoadSession` | The unit that must have one live owner. Re-handshake creates a new login visible to the user (ADR 0005, `hpa.md:183-196`) |
| MTProto session (session id and salt) | Logical stream inside a key | Inside the gotd client | Two clients on one key are the case ADR 0005 avoids. Whether a given overlap yields `AUTH_KEY_DUPLICATED`, a new session, or nothing is UNKNOWN (section 6.3) |
| TCP connection | Transport carrying a session | Opened by `client.Run` | Counts against pod fds, memory and egress; not equal to a key or an authorization |
| Media/other-DC connection | Possible additional transport, possibly a different key per DC | DEP-UNVERIFIED | Must be counted per DC in the benchmark, not assumed to be one per user |

`AUTH_KEY_DUPLICATED` is therefore not modeled here as "any two TCPs". The
repository treats it as a terminal revocation signal (`clientpool.go:28-36`)
and has one REPORTED occurrence around a strategy change
(`communication-agent-c1.md:82`). Its exact trigger is UNKNOWN, and the design
below guards against the broader, safer condition "two live clients holding
one key at the same time", which the repository already treats as unsafe.

## 4. Current state, with assumptions

```
HTTP (chi)  --JWT-->  MCP tools --Borrow--> ClientPool{map user_id -> entry}
                         |                        |-- run(): client.Run(ctx)  -> Telegram (TCP/DC)
                         |                        |-- gc():  1/min idle check
                         |-- ConfirmStore, MediaStore, PeerCache (process memory)
                         |-- Hub (local-mode users) --websocket--> user daemon (key on user disk)
DB: telegram_accounts (sealed blob, revoked_at, last_used_at), audit chain
```

State owners (each is lost or duplicated if a second process serves traffic):

| State | Owner today | Failure with 2 processes | Needed for scale |
|---|---|---|---|
| MTProto client per user | `ClientPool.entries` (`clientpool.go:134-142`) | Two clients on one key | One verified owner per user (this spike) |
| Update stream (listener) | gotd `updates.Manager` run by the agent runtime via `entry.runFn`, pinned by `Pin` (`agentruntime.go:84-112`) | Two consumers, or none after a pin is lost | The owner must also own the listener; supervisor reconciles per process |
| Rate limiter, per-user holds | In process (ADR 0005) | Budget multiplied by replicas; holds invisible to the peer | Shared or per-owner, fail closed |
| `ConfirmStore` | In process, 10 min | A confirm on another replica returns not-found | Route by owner, or persist |
| `MediaStore` | In process, 10 min | Same, for `get_media` | Same |
| `PeerCache` / dialog snapshots | In process | Extra resolves only (`peercache.go:10-14`) | Nothing; correctness-neutral |
| Local Bridge `Hub` | In process, one daemon per user | Daemon connected to replica A, call lands on B: `ErrNoDaemonConnected` | Route by daemon connection, or a shared registry |
| OAuth pending flows | In process (ADR 0005) | Callback on another replica fails | Out of this spike's scope; listed for completeness |

Assumptions (stated so they can be corrected):
1. One replica, `Recreate`, as the runbook states; the live replica count and
   limits are not re-verified here.
2. Roughly tens of connected users today (REPORTED about 40 in one study).
   The 500/1000/5000 figures below are planning assumptions, not forecasts.
3. A tool call is bursty and user-driven, not a steady stream.
4. Local Bridge users are a separate population whose key is on their disk;
   they do not consume pool sessions.

Observed gaps that matter before any scale step:
- G1. `/readyz` is `/healthz`: always 200, blind to the database and the pool.
- G2. Teardown is cancel-only. After `Close`, `RemoveAtomic`, a rejected-key
  eviction or idle GC the entry leaves the map immediately, so `acquire` can
  build a replacement while the old `client.Run` is still unwinding. Within one
  process that is a possible brief overlap of two clients on one key
  (inference from the code; how long `Run` takes to stop is DEP-UNVERIFIED).
  The only mutual exclusion is `retiring`, which covers async revoke, not
  eviction. `TelegramClientPoolSize` is decremented at exit
  (`clientpool.go:563-565`), so a transient value above the cap is a usable
  overlap signal.
- G3. `Shutdown` cancels and returns; the process may exit before sockets
  close cleanly. With `Recreate` this is hidden because the new pod starts
  later.
- G4. `ErrPoolFull` counts map entries only, not exiting clients, so it
  under-counts live sockets during churn.
- G5. The shared limiter is per process and defaults off.
- G6. Sticky routing (`deploy/ingress/*`) is a performance hint keyed on an
  unverified JWT payload (`hpa.md:230-247`). It is not ownership.

## 5. Owner lifecycle design (applies to options B and C)

Goal: at most one live client per `user_id` across processes, with
fail-closed behaviour and a minimized, observable overlap window. This is a
goal, not a property the design is shown to achieve (see 6.1). This section
is design only, and PROPOSED pending the owner.

### 5.1 Lease record

One row per user (new table in a later, separately approved change):
`owner_id` (pod identity), `epoch` (bigint, strictly increasing),
`expires_at` (database time, not the pod clock), `state`
(`active | draining | released`). All transitions are compare-and-set on
`(user_id, epoch)` using `now()` from the database.

### 5.2 State machine

```mermaid
stateDiagram-v2
    [*] --> Unowned
    Unowned --> Acquiring: CAS insert/update, epoch+1
    Acquiring --> Active: lease row won; start client.Run
    Acquiring --> Unowned: CAS lost
    Active --> Active: renew before TTL/3 (CAS on epoch)
    Active --> Draining: revoke, rebalance, SIGTERM, or renew failed
    Draining --> Released: in-flight RPCs done or deadline; cancel; Run returned
    Released --> Unowned: row marked released (or expires)
    Active --> Fenced: renew CAS lost / epoch changed
    Fenced --> Released: cancel at once, no new RPC
    Active --> Dead: process dies
    Dead --> Unowned: takeover rule UNRESOLVED (6.1), expiry alone is not proof
```

Rules (PROPOSED, pending owner; none of these is shown sufficient, see 6.1):
- Start a new owner when the previous lease is `released` after an awaited
  `Run` exit. Taking over an EXPIRED lease without a confirmed exit of the old
  owner is an UNRESOLVED case (section 6.1); expiry plus a grace period is a
  heuristic, not a proof.
- A holder that cannot renew should stop issuing RPCs and cancel its client
  at a locally derived deadline, without needing the database. The deadline
  is derived as in 6.2, not by comparing database time with a monotonic clock.
- Every outgoing tool RPC checks "local deadline not passed" before it
  starts, and the caller maps a refused result to a retryable error. This
  reduces the chance of an RPC under an expired lease; it does not prevent it
  (6.1).

### 5.3 Normal handoff

```mermaid
sequenceDiagram
    participant W as New owner B
    participant D as Lease DB
    participant O as Old owner A
    participant T as Telegram
    W->>D: CAS acquire(user, epoch=N+1) rejected: A active
    W->>D: request drain (state=draining)
    D-->>O: A sees draining at next renew or notify
    O->>O: stop new RPCs, finish in-flight to deadline
    O->>T: cancel client.Run, wait for Run to return
    O->>D: release(epoch=N)
    W->>D: CAS acquire(epoch=N+1) wins
    W->>T: client.Run with the stored key
```

### 5.4 Failure cases

| Case | What the lease can do | What it cannot do | Missing guard to add before trusting it |
|---|---|---|---|
| Owner dies, or is believed dead | Expires after TTL | Distinguish "dead" from "paused, partitioned or slow". A successor started on expiry may overlap a live old owner | UNRESOLVED: safe takeover needs independent evidence that the old owner has terminated (6.1); no mechanism is proposed or approved here |
| Network partition from DB, Telegram still reachable | Nothing: the holder keeps an open socket | Stop an already-open Telegram socket. A database lease is advisory to the holder, not to Telegram | Local deadline (6.2) reduces but does not bound the window; overlap proxies (6.5) |
| Process pause across expiry (GC stop, SIGSTOP, VM or container freeze, CPU starvation) | Lease expires in the database | A cooperative local timer cannot fire while the process is paused. On resume, a stale socket and an in-flight RPC may act before the timer or the renew loop runs | UNRESOLVED (6.1) |
| Clock skew | Expiry is judged in database time | Make two pod clocks agree | Derive the local deadline per 6.2; alert on large renew latency |
| Stale release | CAS on epoch makes a late release by an old epoch a no-op | | Epoch in every write, including the audit row |
| Revoke (user disconnect, `RemoveAtomic`) | Move to draining; `RemoveAtomic` already holds a mutex across the DB revoke | Cancel is not awaited (G2) | Await `Run` exit before `released` |
| Drain on SIGTERM | Mark draining, stop acquiring | Existing `Shutdown` is cancel-only (G3) | Await `Run` exit within the 10 s shutdown budget or record that it did not |
| In-flight RPC at fence time | Fence rejects new RPCs | Recall an RPC already on the wire | Non-idempotent mutations (send, pin) already go through `ConfirmStore` single-shot; the fenced owner must not retry them elsewhere |
| Rollout | Lease keeps ownership single across old and new pods if both run | Replace `Recreate` safely on its own | See section 10, step 3 |

Observation points a later implementation could expose, read-only, with their
limits stated in 6.5: pool size, lease rows, teardown duration histogram
(cancel to `Run` return), renew latency and failures, refused-RPC events, CAS
conflicts.

## 6. What a lease cannot prove, and what stays unresolved

6.1 Limits of lease, timer and grace (FACT by construction unless marked).
- A lease is a database fact. A Telegram socket opened under an old epoch
  stays open until that process closes it.
- A cooperative local timer is code in the same process. If the process is
  paused across `expires_at` (GC stop-the-world, SIGSTOP, VM or container
  freeze, CPU starvation, a stalled node), the timer cannot run during the
  pause. On resume, the open socket and any RPC already queued or in flight
  can proceed before the timer callback or renew loop is scheduled. A
  successor may by then hold a newer epoch and a live client.
- A grace period based on measured p99 teardown is not a hard upper bound:
  p99 leaves the tail, and a pause is a separate, unbounded delay. Teardown
  measured on healthy cancels says nothing about a process that is not
  running.
- An RPC already on the wire cannot be recalled by anything in this design.
- Uncertain death: a missed renew is indistinguishable from a dead owner, a
  slow owner and a partitioned owner. Expiry is therefore not evidence that
  the old owner has stopped.
- Consequence: lease plus timer plus grace do NOT by themselves prove at most
  one live Telegram client per user. This document claims no such proof.
- Status: safe takeover of an expired lease is UNRESOLVED unless termination
  of the old owner (process exit, socket closed, or equivalent) is
  independently established. No fencing or termination mechanism is proposed
  as approved here; whether one exists, and what it costs, is an open owner
  question. Clean handoff (release after awaited `Run` exit, 5.3) is the only
  path in this document with an explicit termination event, and it does not
  cover crashes or pauses.
- Possible outcomes of this gap are UNKNOWN (HYPOTHESIS only): a brief
  duplicate client may be harmless, may cause errors, or may revoke the key
  (`AUTH_KEY_DUPLICATED` is a terminal revocation signal in this repository).

6.2 Deriving a local deadline conservatively (PROPOSED).
- Database absolute time and a pod monotonic clock must not be compared
  directly: they have different origins and the monotonic clock is not
  meaningful across processes.
- Instead the holder records a monotonic instant `t_send` immediately before
  sending an acquire or renew request, and the response gives the lease
  duration `TTL` (a relative value, not an absolute timestamp). The local
  deadline is `t_send + TTL - margin`. Using `t_send`, not the response time,
  makes the deadline conservative: it counts the full request latency
  against the holder. `margin` must cover monotonic drift over `TTL`; its
  value is NOT_RUN.
- A renew that fails or returns late never extends the deadline. Only a
  successful response measured from its own `t_send` does.
- This yields a conservative bound only while the process is actually
  running. It does nothing for 6.1 pause cases, and does not make takeover
  safe.

6.3 Two overlap windows exist even in a clean handoff: the old owner's
cancel-to-`Run`-return time, and the new owner's connect time. Both must be
measured (NOT_RUN). What Telegram does on overlap is UNKNOWN from the
repository and is not inferred from vendor text. An isolated, owner-approved
single-account test in a later wave could observe it; this spike authorizes
none.

6.4 Grace value: NOT_RUN. Any grace is a heuristic that shortens the window
for a healthy old owner. It is not a guarantee and is not used as proof.

6.5 What the overlap observations can and cannot show (PROPOSED).
- A lease row shows who the database believes owns a user. It does not show
  open sockets.
- The aggregate pool gauge shows entries or clients per pod. It does not
  identify which user, and summing across pods does not establish per-user
  overlap.
- Per-user cross-pod socket overlap is therefore NOT directly observable from
  a lease row plus an aggregate gauge. Proxies: a per-user, per-pod "client
  running" indicator joined with the lease owner at the same time; a pool
  size above cap during local teardown (G2); a CAS conflict count; a
  refused-RPC count. Each is a proxy.
- Blind spots: a stale, expired owner whose pod is paused or partitioned
  and cannot report; a pod that crashed and reports nothing; scrape
  intervals longer than the overlap window; the other-DC and media
  connections (DEP-UNVERIFIED); and clients Telegram still sees as connected
  after the pod's own view has closed them.
- A zero overlap reading is therefore evidence of absence only for the
  sampled, reporting pods.

## 7. Separate the health and availability planes

| Plane | Question | Today | Needed |
|---|---|---|---|
| Liveness | Is the process alive | `/healthz` 200 | Keep |
| Readiness | May the process receive traffic | `/readyz` identical to liveness (G1) | PROPOSED, needs its own owner approval because it changes routing: DB reachable, migrations applied, not draining. Must not depend on Telegram |
| Authenticated MCP availability | Can an authenticated caller list tools and call non-Telegram tools | Covered by tool SLI (`slo.md`) | Unchanged |
| Session availability | Can this user's key be borrowed now | `mctl_sessions_borrow_total` results incl. `no_session`, `flood_wait`, `call_error` | Add `not_owner`, `fenced`, `draining` results |
| Degraded | Service up, some sessions unavailable | Implicit | Explicit: pool full, owner moving, lease store down (read-only tools may continue) |

Readiness must never go false because one user's Telegram session is bad;
otherwise one tenant drains the fleet. Telegram flood waits are session or
account scope, not readiness.

## 8. Options compared

A. Stateless HTTP tier + a single MTProto owner process.
- HTTP replicas hold no keys; they forward Telegram work to one owner over
  an internal RPC. State (`ConfirmStore`, `MediaStore`) lives on the owner, so
  it stays correct. HTTP can scale and roll without touching sockets.
- The owner is still a single point of failure and a rollout blackout for
  Telegram work (relates to #1108). Ceiling is one pod's memory and one egress
  identity. This is the smallest step.

B. Sharded session workers.
- Consistent hash of `user_id` to N workers, each owning its shard's keys,
  stores and listeners. HTTP tier is stateless and routes by owner lookup.
- Ownership by lease (section 5). Scales sockets and memory linearly.
  Costs: a routing tier, a lease store, resharding handoffs, per-worker
  listener supervision, shared or per-shard limiter.

C. Co-located owners + verified routing (HTTP and MTProto in one pod, routed
to the owner pod).
- Fewest moving parts to build from today's binary. Routing is verified by
  the lease, not trusted from a header.
- Sticky routing alone is NOT ownership: it is keyed on an unverified payload
  (`hpa.md:230-247`) and says only where to try first. Ownership is the lease.
  A request that reaches a non-owner must be forwarded or refused with a
  typed retryable error, never served by opening a second client.
- Cost: every pod keeps HTTP and MTProto coupled, so HTTP rollout and session
  handoff are the same event.

| | A | B | C |
|---|---|---|---|
| Removes rollout blackout for non-Telegram HTTP | yes | yes | partly |
| Removes rollout blackout for Telegram work | no | yes (handoff) | yes (handoff) |
| Scales sockets/memory past one pod | no | yes | yes |
| Needs lease and fence | no (one owner) | yes | yes |
| Moves `ConfirmStore`/`MediaStore` | no | yes, per shard | yes, per owner |
| Keeps Local Bridge custody | yes | yes, bridge sessions stay off the pool | yes |
| Build size | smallest | largest | middle |

Local Bridge custody is preserved in all three: a `mode='local'` user's key
is on their machine, the pool never opens it (`DESIGN.md`; `server.go:65-75`),
and the owner abstraction applies only to `hosted` users. The `Hub` has the
same one-process limit and needs its own decision (route by daemon
connection) before any HTTP fan-out in A or C; this spike does not move it.

## 9. Capacity: assumptions versus measurements

No new measurement exists. REPORTED in `hpa.md:17-26`: 30 MB baseline, 58 MB
at 100 idle sessions, and a per-session figure that does not match them.

The 3 MB figure below is an UNVALIDATED conservative scenario only. It is not
measured capacity and not a proven upper bound: the source document is
inconsistent (2.8 MB stated, 0.28 MB by its own arithmetic, section 2), idle
only, and excludes active calls, media, listeners and extra-DC state, so real
per-client memory could exceed it.

| Scenario | Connected users (assumption) | Concurrently live clients (assumption, not measured) | Memory at 3 MB scenario figure | Verdict |
|---|---|---|---|---|
| 500 | 500 | UNKNOWN | about 1.5 GB if all live | The 1 GiB tier cap of 270 would bind (`hpa.md:30-34`); idle GC lowers live count by an unmeasured amount |
| 1000 | 1000 | UNKNOWN | about 3 GB if all live | Exceeds the largest documented tier |
| 5000 | 5000 | UNKNOWN | about 15 GB if all live | Not one pod under any documented tier |
| Pinned listeners | Subset | Always live | Counts in full | Listener users do not idle out |

The product of users and 3 MB is an arithmetic scenario, not a bound and not
a prediction. Idle-only RSS also ignores active-call memory, media buffers (a
768Mi stopgap exists, `runbook.md:3499`), update-stream load for listeners,
and gotd extra-DC state.

| Dimension | Known | UNKNOWN / NOT_RUN |
|---|---|---|
| Sockets per DC | Not observed | Sockets per client, per DC, media vs main, at 100/500/1000 live (DEP-UNVERIFIED) |
| Memory | Idle figure REPORTED inconsistently (2.8 vs 0.28 MB per session) | Which idle figure is right; under active calls, listeners, media, at 500+ |
| Goroutines | Two per client by construction (`clientpool.go:512-513`); gotd adds more (DEP-UNVERIFIED) | Total per live client |
| CPU | | Handshake CPU per cold start; steady-state per call |
| Bursts and fairness | One global mutex `p.mu` guards the map and is held during the DB revoke in `revokeRejected` and `RemoveAtomic` | Mutex contention at burst; one tenant's DB stall blocking others |
| Lease DB amplification | Today: 2 DB statements per `Borrow`, plus a pin heartbeat per minute per listener | Added renew traffic: roughly one write per live client per renew interval; unquantified at 1000+ against a pool of 10 open connections (`db.go:50-56`) |
| Egress and login throttling | Shared limiter exists, default off | Real rate that triggers `FLOOD_WAIT`; login burst behaviour (`runbook.md:2530-2535` notes a login burst can flood-wait the shared id) |
| Latency, success | SLO targets only | Cold-start and handoff latency; success during handoff |
| Headroom cost | | Cost of redundant or standby capacity |

## 10. Recommendation

Every step below is PROPOSED and pending the owner. A sequence is suggested,
not decided. None of it is authorized by this document.

Step 0a (passive telemetry, no behaviour change): instrument and decide.
- Add read-only metrics: per-user client-running indicator, pool size above
  cap, cancel-to-`Run`-return duration, socket and goroutine counts per
  client, DB statements per Borrow. Read their limits in 6.5.
- Capture the section 9 measurements from the existing single replica. This
  turns UNKNOWN cells into data without a load test. Rollout of even this
  change restarts the pod and is itself a blackout under `Recreate`.

Step 0b (readiness change, separate approval): make `/readyz` distinct from
`/healthz` (DB reachable, not draining). This is not passive. It changes
routing and rollout behaviour: a wrongly failing probe removes the only pod
from service. It needs its own owner approval, its own rollback and must not
be bundled with 0a.

Step 1 (PROPOSED smallest zero-downtime change for non-Telegram traffic):
option A for HTTP only. Keep one MTProto owner and `Recreate` for it, and
split a stateless HTTP tier so that a web/OAuth/static rollout no longer
blacks out those paths. An HTTP-only split does NOT remove the MTProto-owner
rollout blackout: every owner rollout still stops the one pod holding all
keys and Telegram work is unavailable until the new one starts. It does not
change key ownership and does not touch `api_id`. It addresses only the part
of #1108 that is not Telegram work.

Step 2 (gated on step 0 data and an owner decision): fix the teardown gaps G2
and G3 in the single owner: await `Run` exit before an entry is considered
gone and before `acquire` may rebuild, and make `Shutdown` wait within its
budget. This is a prerequisite for any lease, and is useful alone.

Step 3 (separately gated scale path, blocked on the UNRESOLVED takeover
limitation in 6.1 for any crash or pause case): lease, epoch and local
deadline (section 5), then option C for co-located owners with verified routing, because it
reuses the existing binary and the sticky manifests as a hint only. Move to
option B only if step 0 data shows one pod's memory or one egress identity is
the limit. Replace `Recreate` last, only after the overlap gauge has stayed at
zero under a handoff test the owner approves.

### Counter-evidence and no-go conditions

- The REPORTED `AUTH_KEY_DUPLICATED` occurrence shows that a strategy change
  alone coincided with a dead preview session; any step that allows overlap
  must be rolled out with the overlap gauge as a stop signal.
- No-go for steps 3 and beyond if: teardown time is unbounded or unmeasurable;
  the overlap gauge is non-zero in a controlled handoff; the lease store is
  not on the readiness path; a request can be served by a non-owner.
- No-go for any design that depends on additional `api_id`s, per-IP spreading
  to avoid limits, or a claimed exclusivity not shown in a primary source.
- If a primary source later shows a stricter concurrency rule for a key, the
  effect is UNKNOWN. It may be more than a change of timer margins: it may
  invalidate the lease design or the option choice, and would require
  re-review of this whole document.
- No-go for step 3 takeover of expired leases until termination of the old
  owner can be independently established (6.1).

### Rollback

- Step 0 and 1: revert the change; behaviour returns to one pod, `Recreate`.
- Step 2: revert; teardown returns to cancel-only.
- Step 3: set owners back to one holder (lease table ignored), restore
  `Recreate`, stop the new revision before starting the old one as the
  runbook requires (`runbook.md:253-254`). Pending confirmations may be lost
  (`confirm.go:17-20` already says this is by design).

## 11. Existing issue dependency map

| Issue | Role here | Source of the claim |
|---|---|---|
| #1115 lease/fencing | Section 5 and 6 | Task statement; no repository text at the SHA |
| #145 and #126 routing | Sticky ingress reference manifests (`hpa.md:203-204`: #141 closing #126); #145 not found in the repository | Partly OBSERVED, #145 UNVERIFIED |
| #568 statelessness | Retiring the legacy MCP session path is a code change that belongs to #568 | `docs/cloudflare-portal-compat.md:68,180`; `internal/mcpprobe/inprocess_test.go:217-228` |
| #1108 rollout blackout | DB connect retry shortened to cut rollout dead time; Telegram-work blackout remains | `cmd/server/main.go:70-76`; `docs/plans/gate-889-managed-soak.md:75-76` |
| #1282 | This spike | Task statement |

Ordering: step 0 has no dependency; step 1 depends on #568 (statelessness of
the HTTP tier); step 2 is a prerequisite of #1115; step 3 depends on #1115
and on #145/#126 routing; #1108 is reduced by step 1 and closed only by step 3.

## 12. Provisional implementation allowlist, tests and mutations

Provisional only. No new epic, child issue or contract is approved by this
document; the owner decides whether any of it becomes work.

Files a later change would likely touch:
- `cmd/server/main.go` (readiness, shutdown wait)
- `internal/telegram/clientpool.go` (await `Run` exit, owner gate)
- new `internal/telegram/lease*.go` and a schema addition in `internal/db`
- `internal/metrics/metrics.go` (read-only gauges and histograms)
- `internal/mcp/server.go`, `confirm.go`, `mediastore.go` (owner-aware state)
- `docs/hpa.md`, `docs/runbook.md`, ADR 0005 supersession note

Tests a later change would need: lease CAS races (two acquirers, stale
release, epoch bump); local deadline refusal without DB; teardown-awaited
before rebuild; `acquire` blocked while an old `Run` is unwinding; readiness
false on DB loss and true on Telegram loss; confirm/media routed to the owner;
Local Bridge users never entering the lease path.

Changes a later change would perform: add one lease table; add metrics;
change `Recreate` only at step 3. No schema, config or secret change is
made by this spike.

### 12.1 Proposed mutation checks (not run; no code or mutation exists)

Each row names a guard a later implementation would have, the temporary
mutation (remove or weaken the guard), and the negative test that must FAIL
under it. A guard with no failing test is untested. The run procedure would
be: commit, mutate, run the named test, expect failure, restore.

| Guard removed | Negative test that must fail | Failure shown |
|---|---|---|
| Epoch compare-and-set on acquire and renew (plain upsert instead) | Two concurrent acquirers for one user, then renew with the losing epoch | Both believe they own, or the loser's renew succeeds |
| Awaited `Run` exit before release and before `acquire` may rebuild (cancel-only, as today) | Test client whose `Run` blocks after cancel; assert no second client starts and no release is written until it returns | A second client starts while the first is still unwinding |
| Stale-release guard (release not conditioned on epoch) | Owner A at epoch N is superseded by epoch N+1, then A's late release arrives | The newer owner's row is released or cleared |
| Expired-lease RPC gate (no deadline check before an RPC) | Fake clock past the local deadline; issue a tool RPC | RPC reaches the fake transport instead of a retryable refusal |
| Wrong-owner routing check (serve on any pod) | Request for a user whose lease names another pod | A client is opened locally instead of a forward or typed refusal |

Limits: the expired-lease gate test uses a fake clock and cannot reproduce a
real process pause (6.1); passing it does not show the pause case is safe.

## 13. Proposed isolated benchmark and read-only telemetry (needs later approval)

Nothing below is run or authorized now.

Passive telemetry on the existing replica (step 0a; readiness, step 0b, is a
separate approval): the metrics in section 10, plus process fd count, goroutine count, `p.mu` wait, DB statements
per Borrow, and pool size over time. No new Telegram traffic.

Isolated benchmark (later approval, owner-chosen accounts and environment):
- Use the repository's synthetic personas for fixtures; no real account id in
  committed files.
- Phase 1: idle sockets, memory, goroutines at 10/50/100/250 live clients
  against a Telegram test environment if one is approved, otherwise a fake
  transport; report per-DC sockets.
- Phase 2: handoff test for one test account only: measure cancel-to-`Run`
  return, and observe what Telegram returns during a deliberately bounded
  overlap. Abort on the first `AUTH_KEY_*` signal.
- Phase 3: DB amplification with a lease table at 500/1000 simulated holders.
- Report UNKNOWN/NOT_RUN for anything not run. No result becomes a capacity
  claim without the raw numbers attached.

## 14. Evidence gaps and pending decisions

Acceptance checklist (INCOMPLETE; every box open; #1282 is not closed by this
document and nothing here may be read as closing it):

- [ ] Vendor primary verification: Telegram pages read in full and quoted
  from a snapshot, specifically the rule for concurrent use of one permanent
  key. Current material is a VENDOR-PARAPHRASE. A stricter rule than assumed
  may invalidate the design, not only change margins.
- [ ] Dependency internals: `gotd/td v0.163.0` connection model, per-DC
  keys, and `Run` teardown behaviour read from source or measured.
- [ ] gitops live configuration: replica count, strategy, limits and probes
  in mctl-gitops confirmed from that repository.
- [ ] Issue-status evidence: titles and state of #1115, #145, #126, #568,
  #1108 confirmed from the tracker.
- [ ] Safe-takeover question (6.1) answered by the owner.
- [ ] `docs/hpa.md` memory figure inconsistency resolved by measurement.

Evidence gaps:
1. Exact Telegram rule for concurrent use of one permanent key (UNKNOWN; needs
   a specific source on `/api/auth` and `/api/datacenter` beyond the excerpts).
2. gotd connection model, per-DC key use and teardown time (DEP-UNVERIFIED;
   cache not read).
3. Live replica count, limits and probes in mctl-gitops (needs connector
   evidence).
4. Titles and state of #1115, #145, #568 beyond what the repository carries.
5. Whether Telegram's `FLOOD_WAIT` budget is per account, per `api_id` or per
   IP for this workload (UNKNOWN).

Pending owner decisions:
1. Is step 0a passive telemetry approved to run on the existing replica, and
   separately, is the step 0b readiness change approved?
2. Is the HTTP/MTProto split (step 1) wanted before the lease work, or is the
   `Recreate` blackout accepted at current SLO targets?
3. Is a Telegram test environment or single test account approved for the
   handoff observation in section 13?
4. Does the Local Bridge `Hub` need its own owner design now, or is it
   deferred?
