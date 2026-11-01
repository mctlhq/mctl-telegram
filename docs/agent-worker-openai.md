# OpenAI-compatible agent-worker runner

`cmd/agent-worker` keeps `AGENT_RUNNER=claude` as its default. The managed-runtime path can select the in-process OpenAI-compatible runner with `AGENT_RUNNER=openai`; both runners use the same job-scoped tool handlers and the same durable completion check.

This document is additive while #1091 remains a draft behind the #1046 gate. The operator-facing table is intended to be folded into `docs/agent-worker.md` before the PR leaves draft.

| Env var | Required for `openai` | Meaning |
|---|---:|---|
| `AGENT_RUNNER` | yes | `claude` or `openai`; unset remains `claude`. |
| `AGENT_MODEL` | yes | OpenAI-compatible provider model name. |
| `AGENT_OPENAI_BASE_URL` | yes | Base URL immediately above `/chat/completions` (normally the configured Cloudflare AI Gateway compatibility endpoint). |
| `AGENT_OPENAI_API_KEY` | yes | Provider API key. Sensitive; never logged. |
| `AGENT_GATEWAY_TOKEN` | no | Cloudflare AI Gateway bearer token. Sensitive; sent as `cf-aig-authorization`. |
| `MODEL_INPUT_USD_PER_MTOK` | yes | Input list price in USD per million tokens; finite and non-negative. |
| `MODEL_OUTPUT_USD_PER_MTOK` | yes | Output list price in USD per million tokens; finite and non-negative. |
| `AGENT_MAX_TURNS` | no | Maximum provider turns per job; default `12`. |
| `AGENT_OPENAI_MIN_INTERVAL` | no | Minimum process-wide interval between provider requests, as a Go duration such as `6s`; the limiter is state on the single `OpenAIRunner` instance, not a package global. |
| `AGENT_MAX_BUDGET_USD` | no | Per-job USD cap. For OpenAI-compatible models the runner computes it from provider token usage and the two configured prices. |

The existing `AGENT_API_BASE_URL`, `AGENT_API_TOKEN`, `AGENT_CREDENTIAL_DOMAIN_ID`, worker concurrency, health and metrics settings remain unchanged. `AGENT_API_TOKEN` is used by the poll loop only. An OpenAI job refuses to run without the claim's narrow `job_token`; every tool call, cost report and terminal-state verification for that job uses a fresh `Client` authenticated with that job token.

## Provider request contract

The runner sends non-streaming `POST {AGENT_OPENAI_BASE_URL}/chat/completions` with `tool_choice: auto` and the `mcplib.Tool.InputSchema` values produced by the shared `buildToolSet` without schema rewriting. Requests set:

- `Authorization: Bearer <AGENT_OPENAI_API_KEY>`;
- `cf-aig-authorization: Bearer <AGENT_GATEWAY_TOKEN>` when configured;
- `cf-aig-collect-log: false`;
- `cf-aig-skip-cache: true`.

A non-2xx provider response is represented only by HTTP status and parsed `Retry-After`. Its body is drained for connection reuse but is never retained, decoded, returned in an error, or logged because a provider error body may echo message/tool content.

429 and 5xx responses are retried with `Retry-After` or bounded exponential backoff. All waits use the job context, whose deadline is set by `Worker.runJob`; retries therefore cannot run past the claim deadline. Exhausted 429 retries map to the existing usage-limit error/metric class.

## C1 evaluation

The opt-in C1 harness accepts `AGENT_C1_EVAL_RUNNER=openai`. It uses the real `OpenAIRunner`, the real shared tool handlers and the fake Agent API used by the existing guarded eval harness. Provider credentials are read from the same OpenAI env variables above; `AGENT_OPENAI_MIN_INTERVAL` can be used for Hetzner pacing. Normal CI never sets `AGENT_C1_EVAL=1`, so it performs no paid/network model calls.
