# Threat model: own / external agent runtime (T4)

Status: v1, 2026-11-02. Issue #1046 (P4.5 of #1002). This document describes the code as it is. It changes no behaviour.

Companion documents: the API reference [`docs/contracts/agent-job-api.md`](../contracts/agent-job-api.md), the worker guide [`docs/agent-worker.md`](../agent-worker.md), the tier table in [`docs/assistants/spec.md`](../assistants/spec.md), [ADR 0002](../adr/0002-send-gate.md) and [ADR 0008](../adr/0008-managed-runtime.md).

`go test ./docs/...` fails when a route is added to or removed from `agentapi.Server.Register` unless this document still names it (see [Route coverage](#route-coverage)).

## Invariant

An external runtime may reason. It never gets authority to bypass MCTL execution policy. The only path to an effect is:

    claim -> external model -> propose -> MCTL policy -> MCTL send

The runtime holds no Telegram credential and no Telegram session material. Every state-changing call re-runs the server-side policy engine (`policy.Evaluate`) whatever credential made it, and every send is made by MCTL's executor behind the send gate (ADR 0002), never by the runtime.

## Credential boundary

| Runtime | Credential | Status |
|---|---|---|
| Own / external (T4) | The existing account-scoped `aud=agent` token from `POST /api/agent/token`, plus the `aud=agent-job` token the server mints for each job at claim. | Implemented. This document is about it. |
| Managed (P5) | A claim-only `aud=agent-pool` credential, then job-bound `aud=agent-job`. | **Implemented behind `MANAGED_RUNTIME_ENABLED`** (#1090, [ADR 0008](../adr/0008-managed-runtime.md)). The pool identity can call `POST /jobs/claim` only (`requireNotPool` elsewhere). Residual risk: the pool token can claim the jobs of every managed account, so it is the widest credential in the agent API; revoke it by `jti` if it leaks. |

Own and managed runtimes are different trust boundaries. The own credential path is not changed by the managed model.

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Telegram content: event bodies, sender metadata, conversation history | `incoming events`, `conversation messages` | Private user data. |
| Owner profile view | `OwnerProfileProvider.PublicProfile` | Facts about the owner that may be said to a stranger. |
| Owner notes inside `instructions` | The rendered prompt in the claim envelope | Free text the owner wrote for the assistant. |
| Leads and records | `agent leads` per conversation | Counterparty data (company, role, pay). |
| The ability to cause a send | `POST /actions/propose_reply` and the executor | A wrong message cannot be unsent. |
| Runtime and job credentials | Bearer tokens | Anyone who holds one acts as the runtime. |
| Account budget and cost ledger | `cost_usd` on the job row | Spend attribution. |
| Audit integrity | The hash-chained audit log (ADR 0003) | Evidence of who did what. |

## Actors

- **Runtime operator.** Honest, possibly careless: logs a prompt, leaves a token in a shell history.
- **Compromised runtime host.** An attacker who runs code where the worker runs and can read its environment.
- **The model.** Prompt-injected through inbound Telegram text it is asked to read.
- **Model provider.** Receives everything the runtime sends to the model. MCTL does not choose it for an own runtime.
- **Network attacker.** Can observe or replay traffic if TLS is absent.
- **Another account's runtime.** Holds valid credentials for a different account.

## Trust boundaries

    MCTL server  |  runtime process  |  model provider

The runtime and the provider are outside MCTL's control. **Everything the API returns to the runtime must be assumed to reach the model provider.** MCTL enforces its rules at the server side of the first boundary only.

## Read exposure

What a runtime can read, per route, with the credential that reaches it and what the server strips or checks. "Account" is the `aud=agent` token, "job" the `aud=agent-job` token. For the job token, `enforceBinding` and the per-route checks named below apply; for the account token they are no-ops (`jobBound(id)` is false).

| Route | Returns | Reached by | Binding check and stripping |
|---|---|---|---|
| `GET /events` | Same as `POST /jobs/claim` (legacy alias, `Deprecation`/`Sunset` headers). | Account | Claim route: `requireAccountToken` refuses the job token. |
| `POST /jobs/claim` | `jobEnvelope`: job id, event ids, conversation id, rendered `instructions` (catalog prompt plus owner notes), tool aliases, `install_revision`, a job token. | Account | `requireAccountToken`. |
| `GET /event/{eventID}` | Message body, sender and chat ids, metadata. | Account, job | Job: the event must be in the job's `SourceEventIDs` (`handleGetEvent`). |
| `GET /conversations/{id}/context` | Conversation row, up to 100 messages, the conversation's leads. | Account, job | Job: `enforceBinding` on the conversation id. Account: any conversation of the account. |
| `GET /conversations/{id}/leads` | Leads of one conversation. | Account, job | `enforceBinding`. |
| `GET /leads/{id}` | One lead. | Account, job | Job: the lead's conversation must be the token's (`handleGetLead`). |
| `GET /recruiters/{peer}` | The owner profile view: `never` fields and the restricted section are removed, `after_owner_engaged` fields only once the owner has engaged with the peer. | Account, job | Job: the peer must be the conversation's peer (`handleRecruiterProfile`). Account: cold-sender view only. |
| `GET /policy` | The account's policy configuration (mode, limits, intents, hours, kill switch). | Account, job | Account-level data; advisory. `policy.Evaluate` is the authority. |
| `GET /jobs/{id}` | Job id, status, attempt, result ids. | Account, job | Job: `enforceBinding` on the job id. |

The runtime never sees Telegram session material, other accounts' data, or the restricted and `never` profile fields.

## Threats and mitigations

Each mitigation names the code that enforces it. The write routes appear here: `POST /actions/propose_reply`, `POST /leads`, `POST /actions/request_owner_approval`, `POST /notify/summary`, `POST /autopilot/pause`, `POST /jobs/{id}/complete` and `POST /jobs/{id}/cost`.

### T1 Credential theft

- **Account token.** Lifetime 30 days by default, 90 days at most (`defaultAgentTokenTTL`, `maxAgentTokenTTL` in `tokenhandler.go`). It carries no `jti`. Reach: see [Blast radius](#blast-radius-of-the-account-scoped-token). Mitigation: `POST /api/agent/token` is admin-only; revocation is blanket by Telegram id.
- **Job token.** Minted by `mintJobToken`. Its TTL ends at `ClaimedAt + jobVisibility` (`AGENT_JOB_VISIBILITY`, code default 5 minutes). It is bound to one job, attempt and conversation, and signs the tool set. A stolen job token is useful for minutes and for one job.
- Revocation cache staleness is bounded by `MaxRevocationCacheTTL` (15 s).
- The job-token TTL figure above is the code default. The gitops values for `labs/mctl-telegram` and `labs/mctl-telegram-preview` do not set `AGENT_JOB_VISIBILITY`, so the default presumably applies, but the live pod environment was **not observed**: the figure is unconfirmed until read from the running service.

### T2 Replay

- A job token past its attempt is refused by the attempt fence in `CompleteAgentJob` and by the `install_revision` fence (`policy.DenyInstallChanged`).
- `InsertAgentAction` is idempotent per `(job_id, action_type)`, so a replayed propose does not create a second action.
- No route extends a token's lifetime.
- Bearer tokens are not sender-constrained: a captured token can be replayed from anywhere until it expires or is revoked. Accepted, see [Residual risks](#residual-risks).

### T3 Cross-job and cross-account access

- Job token: `enforceBinding` (`binding.go`) on propose, save lead, approval, summary, pause, context, get lead, job status, complete and cost; the job/event check in `handleGetEvent`; the peer check in `handleRecruiterProfile`; the lead-conversation check in `handleGetLead`; `requireAccountToken` on claim.
- Every store query is scoped by `id.UserID`, so no token reads another account's rows.
- **`enforceBinding` is a no-op for the account token.** For a holder of it, job binding is voluntary: it can name any job, conversation or lead of its own account.

### T4 Tool widening

The tool set comes from the signed `job_tools` claim of the job token and never from the request (`toolGate`, `toolSet` in `toolgate.go`). A route serving a tool outside the set answers 403 `tool_not_allowed` (`tools.Endpoints`). With the account token the set is the account's installed definition (`accountTools`), or every tool when no catalog is configured.

### T5 Policy bypass

No route sends. `POST /actions/propose_reply` records an action after `policy.Evaluate`; only MCTL's executor sends it, after the send gate (ADR 0002) and its own restricted-field check (`MatchRestricted`). `POST /actions/request_owner_approval` and `POST /notify/summary` reach the owner, not the peer. The deny codes, the kill switch (`GlobalKill`) and the owner's mode apply to every credential alike.

### T6 Prompt injection causing disclosure

Inbound text can steer the model. The server does not rely on the model: the profile view strips restricted and `never` fields before the model sees them (`PublicProfile`); `MatchProtected` and `intent_never` refuse a reply that would carry or answer them; in guarded mode a reply the policy does not allow waits for the owner. A manipulation alert is replaced by a fixed notice server-side so the model's wording is not forwarded. These are measured by the C1 suite.

### T7 Claiming and never completing

A claim is a lease: `RequeueStaleAgentJobs` returns a stale job to the queue after the visibility window, and `RouteUnclaimed` forwards never-claimed jobs to the operator. A runtime that hoards claims cannot hold a conversation hostage indefinitely.

### T8 Cost misreporting

`POST /jobs/{id}/cost` is worker-only and not a tool. For an own runtime it affects only the reporter's own account. The managed ledger is server-authoritative (ADR 0008).

### T9 Denial of service

Request bodies are capped at 1 MiB (`maxRequestBodyBytes`), the claim long-poll is bounded (`defaultLongPollTimeout`, 20 s), and a claim returns at most 10 jobs.

### T10 Credential confusion

Audiences are distinct: the agent mount accepts `aud=agent` and `aud=agent-job` only (`selectAgentProvider`, `selectAgentJobProvider`); a bridge token or a regular MCP token does not authenticate here. The job provider requires `aud=agent-job` (`AudienceRequired`).

### T11 Compromised runtime host or model provider

Everything the API returned reaches them: event bodies, context, the owner profile view, leads, the policy and the owner notes in `instructions`. What they cannot get: Telegram session material, other accounts' data, the restricted and `never` profile fields, or a way to send. A compromised host also holds its account token for its remaining lifetime (T1). Mitigations are those above, plus blanket revocation by Telegram id.

### T12 Late or stale writes

A write for a job that is no longer claimed under that attempt is refused 409 and changes nothing (`Queue.CompleteWithResult`, the live status/attempt gate in `InsertAgentAction`). The conformance runner exercises this (`cmd/agent-conformance`).

## Blast radius of the account-scoped token

As of today, a holder of an `aud=agent` token:

- lives 30 days by default and up to 90 (`defaultAgentTokenTTL`, `maxAgentTokenTTL`);
- carries no `jti`, so it cannot be revoked individually; the only revocation is blanket by Telegram id (`derivedAudiences` in `internal/auth/localjwt/issuer.go` contains `agent`; `needsRevocationCheck` looks it up), cached for at most `MaxRevocationCacheTTL` (15 s);
- can claim jobs of the account (`POST /jobs/claim`), which also returns the instructions with the owner notes;
- can read the context, leads and events of **any** conversation of the account, not only the one it claimed;
- can call every per-job route for **any** job of the account, because `enforceBinding` does nothing for it;
- can propose replies, save leads, ask for owner approval, send owner summaries and pause autopilot, all through policy;
- cannot send, cannot read another account, and cannot read Telegram session material.

## Residual risks

Each is accepted, has an owner and a trigger for revisiting it. The owner column names the owning role of the slice.

| Risk | Why accepted | Owner | Revisit when |
|---|---|---|---|
| Bearer tokens are not sender-constrained (no DPoP or mTLS). | Out of scope of #1046; the job token lives minutes. | Platform owner | A token is stolen in practice, or sender-constrained tokens are scheduled. |
| The account-scoped token is wide, long-lived and has no `jti`. | Changing the own credential path is out of scope; the deployed first-party worker depends on it. | Platform owner | An external runtime is onboarded for an account other than the owner's own. |
| Owner notes and the engaged profile view reach a model provider MCTL does not choose. | They are the instructions and the facts the assistant needs. This document records the exposure and does not change it. | Platform owner | The provider list for an own runtime is constrained, or owner-note visibility is revisited. |
| The job-token TTL (5 minutes) is the code default, not read from the running service. | No live read was available. | Maintainer of this document | Before the figure is quoted outside this repository. |
| Without a job-token signer the claim has no `job_token` and `ClaudeInvoker` falls back to the account token. | Compatibility for deployments without a signer. | Platform owner | A deployment without a signer is found in production. |

## Route coverage

The test `docs/agent_job_api_test.go` drives `Server.Register` with a recording router. It requires every registered route to appear in this document as `METHOD path` in code formatting, and requires the contract's route table to match the registered routes exactly. The sixteen routes are: `GET /events`, `GET /event/{eventID}`, `GET /conversations/{id}/context`, `GET /conversations/{id}/leads`, `GET /recruiters/{peer}`, `GET /leads/{id}`, `GET /policy`, `GET /jobs/{id}`, `POST /actions/propose_reply`, `POST /leads`, `POST /actions/request_owner_approval`, `POST /notify/summary`, `POST /autopilot/pause`, `POST /jobs/claim`, `POST /jobs/{id}/complete` and `POST /jobs/{id}/cost`.

## Conformance

`cmd/agent-conformance` runs the C1 suite against a worker binary or deployment, so an author can show that it completes jobs, respects the job binding and tool set and leaks nothing before it is connected to a real account. See the contract's [Conformance](../contracts/agent-job-api.md#conformance) section.
