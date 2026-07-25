# Communication agent: headless worker (Option C)

`cmd/agent-worker` is the production transport for the communication agent
(see the Communication Agent plan's Architecture/Transport decision). It
replaced an originally-scoped Claude Code Channels bridge, which turned out
not to be viable in production without a Team/Enterprise `allowedChannelPlugins`
org policy mctlhq's account doesn't have (research-preview instability plus a
per-launch confirmation dialog with no non-interactive bypass otherwise).

## Relationship to the agent API

Every piece of communication-agent state and every side effect (sending a
reply, saving a lead, notifying the owner) lives behind
`/api/agent/v1` (package `internal/agentapi`, shipped in A-PR6/#296). That API
is the actual authority: every state-changing call re-runs the server-side
policy engine (`internal/agent/policy`) regardless of what called it.
`agent-worker` is one of (eventually) two transports that call it —
the other being the experimental, feature-flagged Channels adapter
(A-PR8b) — and the two are interchangeable from the API's point of view.
Nothing about ingest, policy, or the executor (A-PR7/#297) is aware of which
transport is in use.

## Job loop

1. `run()` (the default entrypoint) long-polls `GET /events` for the next
   due job. The server holds the connection open for up to ~20s per poll, so
   this is a tight loop with no client-side sleep on the happy path — a
   `PollEvents` failure backs off exponentially (2s → 60s) and resets on the
   next success.
2. For each claimed job, the worker builds a fresh `claude -p` invocation
   (`internal/agentworker.ClaudeInvoker.Run`) scoped to exactly that job:
   - `--mcp-config` describes one MCP server (`agent`) whose command is this
     same binary, re-invoked with `--mcp-serve`. The job's identity
     (`job_id`, `attempt`, `event_id`, `conversation_id`) is passed to that
     subprocess entirely through its own env — never as a tool argument the
     model could supply or get wrong (see `JobContext`'s doc comment in
     `internal/agentworker/mcpserver.go`).
   - `--strict-mcp-config` so no other locally configured MCP server leaks
     in, and `--allowedTools` names exactly the 11 `mcp__agent__*` tools —
     no `Bash`, `Read`, `Write`, `WebFetch`, or any other built-in tool is
     ever available to this invocation. The tool surface is exactly the
     JSON API surface, by construction.
   - `--output-format json` so the worker can tell a real failure
     (`is_error: true`, e.g. an internal SDK error or a hit `--max-budget-usd`
     cap) apart from an ordinary "nothing to do" turn.
3. The model does all of its actual work through those 11 tools — each one
   is a thin proxy onto the matching `/api/agent/v1` endpoint
   (`propose_reply`, `save_job_lead`, `request_owner_approval`,
   `send_owner_summary`, `pause_autopilot`, `get_event`,
   `get_conversation_context`, `get_recruiter_profile`, `get_lead`,
   `get_policy`, `complete_agent_job`). The worker process itself never
   parses or acts on the model's final text — only the tool calls have any
   effect, and only `complete_agent_job` (itself just another API call)
   marks the job done.
4. A worker crash, or a model turn that never calls `complete_agent_job`,
   needs no special recovery here: the job stays claimed until its
   `deadline` and is requeued by the existing visibility-timeout sweeper
   (`internal/sweeper.AgentJobs`, A-PR2/#288); repeated failures eventually
   dead-letter it. `POST /jobs/{id}/complete` itself refuses to mark a job
   `completed` unless a durable result (an `agent_actions` row or a saved
   lead) already exists for it (`agentapi.handleJobComplete`) — so even a
   model that calls `complete_agent_job` without having done anything first
   gets a 409, not a silently-lost job.

## Configuration

| Env var | Required | Meaning |
|---|---|---|
| `AGENT_API_BASE_URL` | yes | Full `/api/agent/v1` root, e.g. `https://labs-mctl-telegram.labs.svc:8080/api/agent/v1`. |
| `AGENT_API_TOKEN` | yes | Long-lived worker bearer token, minted via `POST /api/agent/token` (`aud=agent`, admin-scoped — see `internal/agentapi/tokenhandler.go`). Never logged; passed to the spawned `--mcp-serve` subprocess's env, never to the model's own process env. |
| `AGENT_CLAUDE_BIN` | no | Override the `claude` binary path/name (default: `claude` on `$PATH`). |
| `AGENT_SYSTEM_PROMPT` | no | Extra system prompt for the communication-agent persona/policy. |
| `AGENT_MAX_BUDGET_USD` | no | Per-job `--max-budget-usd` cap. |

`AGENT_JOB_ID`, `AGENT_JOB_ATTEMPT`, `AGENT_JOB_EVENT_ID`, `AGENT_JOB_CONV_ID`
are internal — set only by the parent worker process on the `--mcp-serve`
subprocess it spawns per job, never configured by an operator.

## Deployment note

This binary requires the `claude` CLI itself (and its own Anthropic
credentials) to be present in its runtime environment — the main
`mctl-telegram` image (Go-only alpine, `ENTRYPOINT ["mctl-telegram"]`) has
neither, so `cmd/agent-worker` does **not** ship there. It has its own
dedicated image, built from `Dockerfile.agent-worker` at the repo root
(`node:22-slim` + a pinned `@anthropic-ai/claude-code` + this binary, no
`git`/`gh`/`kubectl`/PR-steward tooling), published as
`ghcr.io/mctlhq/{component_name}` by the platform's `deploy-service`
workflow — for C1, `component_name=communication-agent-worker-preview` — see
`docs/plans/communication-agent.md` Part 1, C1. Claude credential bootstrap
(`claude auth login`, persistence) for that deployment is tracked in the
same plan section, the same way `mctl-claude-remote` documents its own
one-time bootstrap for its unrelated PR-steward deployment.

## Testing

`internal/agentworker` has full unit coverage without ever invoking the real
`claude` CLI or spending API budget: `client_test.go` uses `httptest` against
the agent API's wire shapes, `mcpserver_test.go` exercises every tool
handler against a fake `agentAPI`, and `claudeinvoker_test.go` swaps in a
fake shell script for `ClaudeBin` to assert on the exact CLI invocation
(flags, `--mcp-config` contents, tool allowlist) without touching the
network.
