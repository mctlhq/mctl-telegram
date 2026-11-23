# Agent platform compatibility matrix

This is the per-host record of how each MCP host reaches the OAuth 2.1 server
at `https://tg.mctl.ai/mcp`, whether production admits it, and whether anyone
has seen it work. It is the documentation slice D1 of
[mctlhq/mctl-telegram#784](https://github.com/mctlhq/mctl-telegram/issues/784).

## Status legend

- `works`: a cited run completed sign-in, token issuance and at least one tool
  call against tg.mctl.ai.
- `works with caveats`: completed, but with a stated limitation or on a
  sibling service rather than tg.mctl.ai.
- `not tested`: anything else. An allowlist entry alone means `not tested`.

## Source of the allowlist column

The "Allowlist entry today" cells were read from mctl-gitops
`platform-gitops/services/labs/mctl-telegram/values.yaml` at gitops revision
`a481332` on 2026-10-27. The Gemini/Google, Grok, Notion, Rayrun and Hermes
Agent rows were added on 2026-11-21 against revision `8d082583b`. That file is authoritative; this table is a dated
snapshot. The settings involved are `OAUTH_ALLOWED_IMPLICIT_HOSTS`,
`OAUTH_CIMD_ALLOWED_HOSTS`, `MCP_CLIENT_PROFILES` and
`OAUTH_DCR_REDIRECT_URIS`.

## Matrix

| Host | Registration path | Allowlist entry today | Status | Evidence | Date observed |
| --- | --- | --- | --- | --- | --- |
| Claude (hosted connector) | CIMD (`claude.ai`); DCR only while CIMD is not advertised | implicit `claude.ai`, `claude.com`; CIMD `claude.ai` | works | Owner-observed on 2026-11-22 against tg.mctl.ai: sign-in, token issuance and tool calls completed ([record](https://github.com/mctlhq/mctl-telegram/pull/1393)). Earlier, the CIMD proof was recorded against mctl-api, not tg.mctl.ai: [mctl-gitops#2039](https://github.com/mctlhq/mctl-gitops/pull/2039), inventory in [#784](https://github.com/mctlhq/mctl-telegram/issues/784). | 2026-11-22 |
| Claude Code | DCR with a loopback redirect | none needed: loopback redirects are always accepted | works | Owner-observed on 2026-11-22 against tg.mctl.ai: sign-in, token issuance and tool calls completed ([record](https://github.com/mctlhq/mctl-telegram/pull/1393)). Earlier, on 2026-10-27, read-only tool calls succeeded from a Claude Code session during the [#784 E2 run](https://github.com/mctlhq/mctl-telegram/issues/784#issuecomment-6450452592), with the connection path not recorded. | 2026-11-22 |
| ChatGPT | CIMD (`chatgpt.com`, which also covers Codex) | implicit `chatgpt.com`; CIMD `chatgpt.com` | works | Owner-observed on 2026-11-22 against tg.mctl.ai: sign-in, token issuance and tool calls completed ([record](https://github.com/mctlhq/mctl-telegram/pull/1393)). Earlier, the CIMD proof was on mctl-api ([mctl-gitops#2039](https://github.com/mctlhq/mctl-gitops/pull/2039)). MCP Apps are deferred to [#650](https://github.com/mctlhq/mctl-telegram/issues/650). | 2026-11-22 |
| Cursor | DCR with the hosted callback on `www.cursor.com`; the `cursor://` scheme is refused | implicit `www.cursor.com`, `cursor.com` | not tested | Allowlisted only. Production saw 464 rejected registrations on 2026-09-21..23 before the hosts were admitted; no sign-in is verified; tracked in [#1385](https://github.com/mctlhq/mctl-telegram/issues/1385). | not observed |
| VS Code | CIMD (`vscode.dev`) | CIMD `vscode.dev` | not tested | Allowlisted only. No run is recorded. | not observed |
| Gemini and Google (Gemini custom connectors, Antigravity) | DCR; callbacks under `oauth-redirect*.googleusercontent.com` scoped to the `user_bound_custom-mcp-` path prefix | implicit `oauth-redirect.googleusercontent.com`, `oauth-redirect-sandbox...`, `oauth-redirect-test...` (path-prefix scoped), `antigravity.google` | not tested | Allowlisted only (Gemini hosts since 0.139.0). No sign-in is verified; tracked in [#1386](https://github.com/mctlhq/mctl-telegram/issues/1386). | not observed |
| Grok | DCR from `grok.com` | implicit `grok.com` and `ALLOWED_ORIGINS` (admitted by [mctl-gitops#2870](https://github.com/mctlhq/mctl-gitops/pull/2870), merged 2026-11-21) | works | Owner-observed on 2026-11-22 against tg.mctl.ai: sign-in, token issuance and tool calls completed ([record](https://github.com/mctlhq/mctl-telegram/pull/1393)). Before admission, production refused 11 registrations on 2026-11-12..21, all `redirect_host_not_allowed`. The matrix-run issue is [#1381](https://github.com/mctlhq/mctl-telegram/issues/1381). | 2026-11-22 |
| Notion | DCR from `app.notion.com` | none yet; admission in progress (mctl-gitops follow-up to [#2870](https://github.com/mctlhq/mctl-gitops/pull/2870)) | not tested | Production refused 2 registrations on 2026-11-16, both `redirect_host_not_allowed`. Verification tracked in [#1382](https://github.com/mctlhq/mctl-telegram/issues/1382). | not observed |
| Rayrun | DCR from `ray.run` | none yet; admission in progress (mctl-gitops follow-up to [#2870](https://github.com/mctlhq/mctl-gitops/pull/2870)) | not tested | Production refused 1 registration on 2026-11-15, `redirect_host_not_allowed`. Verification tracked in [#1383](https://github.com/mctlhq/mctl-telegram/issues/1383). | not observed |
| Hermes Agent | CIMD since 2026-11-22: client_id `https://agentspodium.com/oauth/mcp/clients/<pod>/<server>.json`, one redirect URI `https://agentspodium.com/oauth/mcp/cb/<pod>/<server>` on a host AgentsPodium owns (confirmed by AgentsPodium by email) | path-scoped CIMD entry `agentspodium.com/oauth/mcp/clients/<pod>/` for one test pod only, plus a `client_id` profile binding to `core-readonly` with a two-scope ceiling | works with caveats | Owner-observed on 2026-11-22..23 against tg-preview and tg.mctl.ai from one Hermes pod: admission, sign-in, token issuance and every read tool completed under `core-readonly`; `send_message` is absent from the catalog. Hermes requests every advertised scope unless `oauth.scope` is set in the agent's config, so a read-only test must set `oauth.scope: "telegram:dialogs:read telegram:messages:read"` and the server must hold a ceiling for that client_id. The Hermes sign-in window is about a minute: a Telegram confirmation after that returns `OAuth flow expired` on the pod's callback. Not yet covered: a run past the first hour (several Hermes processes share one token store and one-time refresh rotation can revoke the family, per AgentsPodium). Other pods are not admitted. Verification tracked in [#1384](https://github.com/mctlhq/mctl-telegram/issues/1384) and [#1402](https://github.com/mctlhq/mctl-telegram/issues/1402). | 2026-11-23 |
| Windsurf | unknown (DCR assumed) | none | not tested | No allowlist entry and no run. | not observed |
| Town | CIMD document published at `https://www.town.com/.well-known/oauth-client-id`; DCR via a `www.town.com` callback. Which one Town uses is not confirmed. Site: [town.com](https://www.town.com/). | implicit `www.town.com`, `town.com`; CIMD `www.town.com`; profile binding to `core-reply` | works | Owner-observed on 2026-11-22 against tg.mctl.ai: sign-in, token issuance and tool calls completed under the restricted `core-reply` profile ([record](https://github.com/mctlhq/mctl-telegram/pull/1393)). Earlier (2026-10-23): DCR was rejected with `invalid_redirect_uri` until mctl-gitops#2023; the CIMD document resolves; the `MCP_CLIENT_PROFILES` binding to `core-reply` parses. Still not confirmed: whether Town uses CIMD or DCR. See [#784](https://github.com/mctlhq/mctl-telegram/issues/784) and the [admission runbook](../runbooks/admitting-an-agent-platform.md). | 2026-11-22 |
| MCP Inspector | DCR with a loopback redirect | none needed: loopback redirects are always accepted | not tested | Not run against tg.mctl.ai. Only the in-process probe exists: see the `in-process-current-main` cell in [cloudflare-portal-compat.md](../cloudflare-portal-compat.md). | not observed |
| Cloudflare MCP portal | byte-exact redirect URI, automatic DCR mode | `OAUTH_DCR_REDIRECT_URIS`: two URIs, `<portal servers-callback>` and `<dashboard oauth-callback ...>` | not tested | Mirrors `PENDING-OPERATOR` in [cloudflare-portal-compat.md](../cloudflare-portal-compat.md); the `direct-deployed` and `cloudflare-portal` cells are not run. | not observed |

## Notes

- `antigravity.google` is on `OAUTH_ALLOWED_IMPLICIT_HOSTS`. It is
  allowlisted and not tested; it is covered by the Gemini and Google row.
- `localhost` and `127.0.0.1` on the implicit list are redundant: the server
  accepts loopback redirects regardless of that list. Custom schemes such as
  `cursor://` are refused.
- The Cloudflare portal's per-account dashboard callback URL is deliberately
  not reproduced here; it lives only in gitops.

## How to update a row

Admit the host following
[Admitting an agent platform](../runbooks/admitting-an-agent-platform.md), run
the verification steps, then change the row in the same pull request that
records the evidence: a link to a test, PR, canary run or dated observation,
and the date in `YYYY-MM-DD` form.
