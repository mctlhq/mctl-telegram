# Agent job API v1 (current behaviour)

**Source of truth: the code.** This is a reference for `/api/agent/v1` as `internal/agentapi` behaves today. It describes, and does not change, the server. Where this text and the code differ, the code wins and this file is corrected in the same change. `go test ./docs/...` fails when the route table below and `agentapi.Server.Register` differ.

Who it is for: an account owner who runs their own worker (tier T4 in [`docs/assistants/spec.md`](../assistants/spec.md)) and wants to build one without reading mctl-telegram's source. First-party worker: [`docs/agent-worker.md`](../agent-worker.md). What an external worker can read and do, and the blast radius of its credential: [`docs/agent-runtime/threat-model.md`](../agent-runtime/threat-model.md).

All paths are relative to the mount `/api/agent/v1` (for example `/api/agent/v1/jobs/claim`). Bodies are JSON. Request bodies are limited to 1 MiB (`maxRequestBodyBytes`), unknown fields are rejected (`decodeStrict`), and authentication is `Authorization: Bearer <token>`.

## Authentication

An own / external runtime uses **the existing account-scoped `aud=agent` token**. It is minted by `POST /api/agent/token`, which is admin-only (`admin:users`), with `sub=tg:<telegram id>`. The default lifetime is 30 days and the maximum 90 days. It carries no `jti`; the only revocation is blanket revocation by Telegram id. It can claim, and it can call every per-job route for any job of the account (the binding checks below do nothing for it).

Job-level binding comes from the **`aud=agent-job` token** the server mints for each job at `POST /jobs/claim`, where a job-token signer is configured. It is bound to one job, attempt and conversation, signs the job's tool set (`job_tools`), and expires at `claim time + AGENT_JOB_VISIBILITY` (code default 5 minutes). A worker should give the model only this token, never the account token. When the server has no signer, `job_token` is absent from the claim and the worker has only its account token.

**Managed runtime: planned, not implemented.** A pooled platform runtime is designed to use a claim-only `aud=agent-pool` credential and then job-bound `aud=agent-job` (#1090, [ADR 0008](../adr/0008-managed-runtime.md)). This is design intent. No `agent-pool` audience exists in the code, no route in this document accepts one, and nothing here changes for it.

Audiences are distinct. A bridge token or a regular MCP token does not authenticate on this mount.

### Credential matrix

"Account" is `aud=agent`, "Job" is `aud=agent-job`. "Binding" is what the server checks for a job token; it is skipped for an account token.

| Route | Account | Job | Binding for a job token |
|---|---|---|---|
| `POST /jobs/claim`, `GET /events` | yes | refused 403 | `requireAccountToken` |
| `GET /event/{eventID}` | yes | yes | event must be in the job's source events |
| `GET /conversations/{id}/context` | yes | yes | conversation id |
| `GET /conversations/{id}/leads` | yes | yes | conversation id |
| `GET /recruiters/{peer}` | yes | yes | peer must be the conversation's peer |
| `GET /leads/{id}` | yes | yes | lead's conversation |
| `GET /policy` | yes | yes | none (account-level data) |
| `GET /jobs/{id}` | yes | yes | job id |
| `POST /actions/propose_reply` | yes | yes | conversation, job, attempt |
| `POST /leads` | yes | yes | conversation, job, attempt |
| `POST /actions/request_owner_approval` | yes | yes | conversation, job, attempt |
| `POST /notify/summary` | yes | yes | conversation, job, attempt |
| `POST /autopilot/pause` | yes | yes | none |
| `POST /jobs/{id}/complete` | yes | yes | job, attempt |
| `POST /jobs/{id}/cost` | yes | yes | job, attempt |

A request value of zero or absent means "not named" and is not compared; a job token supplies its own conversation when the body omits it. Every refusal by binding is `403 {"error":"credential is bound to another conversation"}`.

## Route table

| Method | Path | Tool (`tools.Endpoints`) | Purpose |
|---|---|---|---|
| `GET` | `/events` | none | Deprecated alias of `POST /jobs/claim`. Carries `Deprecation` and `Sunset` (2026-12-31) headers and a `Link` to the successor. |
| `GET` | `/event/{eventID}` | `get_event` | One inbound event. |
| `GET` | `/conversations/{id}/context` | `get_conversation_context` | Conversation, recent messages, leads. |
| `GET` | `/conversations/{id}/leads` | `get_lead` | Leads of a conversation. |
| `GET` | `/recruiters/{peer}` | `get_recruiter_profile` | The owner's profile as the agent may see it. |
| `GET` | `/leads/{id}` | `get_lead`, `get_conversation_context` | One lead. |
| `GET` | `/policy` | `get_policy` | The account's policy configuration. |
| `GET` | `/jobs/{id}` | none | Job status. |
| `POST` | `/actions/propose_reply` | `propose_reply` | Propose a reply for policy. |
| `POST` | `/leads` | `save_job_lead` | Create or update a lead. |
| `POST` | `/actions/request_owner_approval` | `request_owner_approval` | Ask the owner to decide. |
| `POST` | `/notify/summary` | `send_owner_summary` | Tell the owner something. |
| `POST` | `/autopilot/pause` | `pause_autopilot` | Pause or resume autopilot. |
| `POST` | `/jobs/claim` | none | Long-poll claim of the next job. |
| `POST` | `/jobs/{id}/complete` | `complete_agent_job` | Finish a job. |
| `POST` | `/jobs/{id}/cost` | none | Worker-only cost report. |

A route with a tool is gated (`toolGate`): when the caller's tool set holds none of the route's tools the answer is `403 {"error":"tool_not_allowed","tool":"<tool>"}`. For a job token the set is the signed `job_tools`; for an account token it is the installed definition's tools, or every tool when no catalog is configured. A tool set that cannot be resolved is `503 {"error":"tool set unavailable"}`. Routes marked "none" are never gated.

## Lifecycle

1. **Claim.** `POST /jobs/claim` with the account token. The server holds the request up to 20 s and answers `{"jobs":[...]}`; an empty array means nothing was due, not an error. Repeat.
2. **Read.** `GET /event/{eventID}`, `GET /conversations/{id}/context`, `GET /recruiters/{peer}`, `GET /policy`, `GET /leads/...` with the job token.
3. **Act.** `POST /leads`, then one of `POST /actions/propose_reply`, `POST /actions/request_owner_approval`, `POST /notify/summary`, or `POST /autopilot/pause`. A reply is only proposed: policy decides, and MCTL, not the worker, sends it.
4. **Complete.** `POST /jobs/{id}/complete` once, with the attempt from the claim.
5. **Verify and report.** `GET /jobs/{id}` to confirm the exact attempt reached a terminal status, and `POST /jobs/{id}/cost` with the observed model spend. Both may arrive after the job is terminal.

## Claim envelope

`POST /jobs/claim?limit=N` (default 1, at most 10; a non-positive or non-numeric `limit` is 400) returns each job as:

| Field | Type | Meaning |
|---|---|---|
| `job_id` | int | Job identity. |
| `event_id` | string | The head event; read it with `GET /event/{eventID}`. |
| `conversation_id` | int | Omitted when unset. |
| `attempt` | int | The claim identity. Echo it on every write and on complete. |
| `deadline` | string, RFC 3339 | Advisory: when the claim is due for reclaim. The sweeper enforces it, not the API. |
| `job_token` | string | The `aud=agent-job` credential. Omitted without a signer. |
| `turn_id`, `source_event_ids` | string, []string | A coalesced turn: every event, in arrival order. |
| `instructions` | string | The system prompt: catalog prompt plus the owner's notes. Omitted without a catalog. |
| `assistant`, `assistant_digest` | string | `name@version` and its digest, for logs. |
| `tools` | []string | The job's tools by the names the definition uses (canonical or alias). |
| `install_revision` | int | The install revision the claim was made under. The job's work is refused once it moves. |

Claim errors: `503` `assistant disabled in the registry`, `assistant registry unreachable, lifecycle unknown`, `assistant fork may not run: forks are off, or the mode is guarded`; `500` `assistant instructions unavailable`, `claim failed`.

## Routes

### Reads

- `GET /event/{eventID}`: `200 {"event_id","kind","chat_tg_id","sender_tg_id","message_id","body","meta","created_at"}`; `404 event not found`.
- `GET /conversations/{id}/context?limit=N` (default 20, at most 100): `200 {"conversation":{...},"messages":[{"direction","body","created_at"}],"leads":[...]}`; `404 conversation not found`.
- `GET /conversations/{id}/leads`: `200 {"leads":[...]}`.
- `GET /leads/{id}`: `200` one lead; `404 lead not found`.
- `GET /recruiters/{peer}`: `200` a JSON object, the owner's profile with the restricted section and `never` fields removed, and `after_owner_engaged` fields only once the owner has engaged with the peer. `501 owner profile not configured`, `404 owner profile not configured for this account`.
- `GET /policy`: `200 {"mode","autopilot_paused","max_autonomous_turns","max_msgs_per_minute","max_reply_chars","intent_allowlist","intent_denylist","working_hours","global_kill"}`. Advisory: `policy.Evaluate` is the authority on every write.
- `GET /jobs/{id}`: `200 {"job_id","status","attempt","result_action_id","result_lead_id"}`; `404 job not found`. Status is one of the job statuses; `completed`, `failed` and `ignored` are terminal.

### Writes

- `POST /actions/propose_reply`: body `{"conversation_id","job_id","attempt","intent","text"}`. `text` is required. Policy runs; the response is `200 {"action_id","decision","reasons","status","approval_code"}`, where `decision` is `allow`, `require_approval` or `deny` and `status` is `approved`, `pending_approval` or `denied`. A denial is a `200` with `decision: deny` and its reasons, not an error status. The same job proposing again returns the stored action (idempotent per job and action type).
- `POST /leads`: body `{"conversation_id","lead_id","job_id","attempt","company","role","recruiter_name","recruiter_tg_id","compensation","status","detail"}`; `200 {"lead_id"}`.
- `POST /actions/request_owner_approval` and `POST /notify/summary`: body `{"conversation_id","job_id","attempt","intent","text"}`; `text` is required. `200 {"action_id","notification_id","decision"}`, or `200 {"suppressed":true,"reason"}` for a repeated manipulation alert within its window. An `intent` of `assistant_manipulation` on a summary is replaced server-side by a fixed notice.
- `POST /autopilot/pause`: body `{"paused": bool}`; an empty body or omitted field means `true`. `200 {"autopilot_paused"}`.
- `POST /jobs/{id}/complete`: body `{"attempt","status","note","result_action_id","result_lead_id"}`. `status` is `completed`, `failed` or `ignored`. `completed` must link an exact persisted result (`result_action_id` or `result_lead_id`) that belongs to this job and account. `200 {"completed":true}`.
- `POST /jobs/{id}/cost`: body `{"attempt","cost_usd"}`; `attempt` must be positive and `cost_usd` not negative. `200 {"recorded":true}`. Worker-only: it is not a tool and the model must not be able to call it.

## Binding, fencing, deadlines, retries

- **Attempt fence.** A job is claimed under an attempt number. Writes that name a job must carry the current attempt. A write after the job was reclaimed (visibility timeout) or finished is `409 job is no longer claimed under that attempt` (complete, cost) or `409 job is no longer the active attempt for this account` (leads, propose). Treat a 409 as "stop": the result is no longer yours.
- **Install fence.** `install_revision` in the claim is the install revision the job started under. A proposal made after the owner changed the install is denied with `install_changed`.
- **Source fence.** A proposal for a turn whose source message was edited or deleted is denied with `source_message_superseded`.
- **Deadline.** `deadline` is advisory. After the visibility window the sweeper requeues the job under a new attempt; never-claimed jobs are routed to the operator. Finish within the window or accept that the job will be re-run.
- **Idempotency.** Writes tied to a job are idempotent per job and action type: repeating a propose, approval or summary returns the stored result rather than creating another. Complete is not repeated: a second complete is `409`. Retry a request only after a network failure, with the same body.
- **Long poll.** A claim holds up to 20 s. A client timeout below that sees spurious failures; the first-party client allows more.
- **No TTL extension.** Nothing extends a token's lifetime.

## Errors (current)

Errors are `{"error": "<text>"}` with an HTTP status. The text is free prose except for the policy and tool-gate codes below. **There is no `code` field and the texts are not a stable enum**; branch on the status, not the text. This section records what the code writes; it adds nothing.

| Status | When | Typical `error` text |
|---|---|---|
| 400 | Malformed body, unknown field, bad id, missing required field | `invalid request body`, `invalid job id`, `invalid conversation id`, `invalid lead id`, `invalid peer id`, `conversation_id required`, `text required`, `limit must be a positive integer`, `status must be completed, failed, or ignored`, `attempt must be positive`, `cost_usd must not be negative`, `job_id does not exist for this account`, `job_id does not belong to conversation_id` |
| 401 | No or unacceptable credential | `authentication required` |
| 403 | Binding or credential mismatch; tool outside the set | `credential is bound to another conversation`; `tool_not_allowed` (with `"tool"`) |
| 404 | Not found for this account | `job not found`, `conversation not found`, `lead not found`, `event not found`, `owner profile not configured for this account`, `agent profile not configured for this account` |
| 409 | Fenced write | `job is no longer claimed under that attempt`, `job is no longer the active attempt for this account`, `cannot mark job completed without an exact persisted result id`, `result does not belong to this job and account` |
| 500 | Server fault | `lookup failed`, `propose failed`, `save failed`, `complete failed`, `request failed`, `claim failed` |
| 501 | Owner profile provider absent | `owner profile not configured` |
| 503 | Registry or tool set unavailable | see Claim errors; `tool set unavailable` |

### Policy deny codes

A refused proposal is a `200` with `decision: deny`. Its machine code is a `policy.DenyCode`, a closed set: `global_kill`, `user_mismatch`, `mode_off`, `mode_unrecognized`, `autopilot_paused`, `conversation_taken_over`, `conversation_closed`, `conversation_paused`, `conversation_state_unrecognized`, `sender_blocked`, `action_type_unrecognized`, `peer_mismatch`, `no_disclosure_text`, `empty_reply`, `reply_too_long`, `reply_contains_url`, `reply_contains_credentials`, `reply_contains_never_field`, `intent_never`, `audience_excluded`, `install_changed`, `source_message_superseded`, `tool_not_allowed` and the fallback `unknown`. `tool_not_allowed` is also the `error` of a gated route's 403.

## Deprecations

- `GET /events` (alias of claim): sunset 2026-12-31.
- `POST /jobs/{id}/complete` without a result id is accepted only while the server runs with legacy completion enabled, and then carries `Deprecation` and `Sunset` headers.

## Conformance

`cmd/agent-conformance` runs the C1 suite against a worker you did not link into it. It serves a loopback fake of this API, issues a token that stands for the account-scoped `aud=agent` token, returns one fixture per claim with a per-job token, and scores the run with the existing gates: classification at the suite threshold (hr-recruiter@0.1.0: at least 29 of 32), every fixture terminal, and no leak, binding violation or wrong auto-send. The harness token and the job tokens exist only inside the fake; no server reads them.

```bash
go build -o agent-conformance ./cmd/agent-conformance
./agent-conformance --worker-cmd ./agent-worker --report c1.json   # exec the worker
./agent-conformance --listen :8099                                  # or start it yourself
```

The fake is stricter than the server for the account token: a request that names no job (no job id in the path or the body, or a body `job_id` of zero), such as `GET /policy`, cannot be attributed to a fixture and is refused with `409` when zero or several jobs are open, and that fails the run. The server accepts such a request. A worker should send its job token, which carries the job.

The worker command gets `AGENT_API_BASE_URL` and `AGENT_API_TOKEN` and inherits the rest of the environment (model credentials are yours). With `--listen` the tool prints both values and waits. The run ends with a drain: after the last fixture is terminal it waits for the worker's status reads and cost reports (`--settle-quiet`, `--settle-max`), releases a long-polling worker, stops it (`--stop-grace`), shuts the server down gracefully and only then scores. The JSON report is bound to `harness_version`, `suite_digest` and `definition_digest` and holds no model text. Exit status is 0 on pass, 1 on fail, 2 on a setup error. A `settle_timeout` is reported and does not change the verdict.

`AGENT_CONFORMANCE=1 go test ./internal/agentworker -run TestC1Conformance` runs the first-party worker through it. Plain `go test ./...` skips that and spends no model quota.
