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
`a481332` on 2026-10-27. That file is authoritative; this table is a dated
snapshot. The settings involved are `OAUTH_ALLOWED_IMPLICIT_HOSTS`,
`OAUTH_CIMD_ALLOWED_HOSTS`, `MCP_CLIENT_PROFILES` and
`OAUTH_DCR_REDIRECT_URIS`.

## Matrix

| Host | Registration path | Allowlist entry today | Status | Evidence | Date observed |
| --- | --- | --- | --- | --- | --- |
| Claude (hosted connector) | CIMD (`claude.ai`); DCR only while CIMD is not advertised | implicit `claude.ai`, `claude.com`; CIMD `claude.ai` | works with caveats | CIMD proof was recorded against mctl-api, not tg.mctl.ai: [mctl-gitops#2039](https://github.com/mctlhq/mctl-gitops/pull/2039), inventory in [#784](https://github.com/mctlhq/mctl-telegram/issues/784). No tg.mctl.ai host run is recorded. The README claim that Claude is the tested client awaits a recorded host run. | 2026-10-23 |
| Claude Code | DCR with a loopback redirect | none needed: loopback redirects are always accepted | works with caveats | Same as the Claude row: no tg.mctl.ai host run is recorded; see [#784](https://github.com/mctlhq/mctl-telegram/issues/784). | 2026-10-23 |
| ChatGPT | CIMD (`chatgpt.com`, which also covers Codex) | implicit `chatgpt.com`; CIMD `chatgpt.com` | works with caveats | CIMD proof was on mctl-api ([mctl-gitops#2039](https://github.com/mctlhq/mctl-gitops/pull/2039)); no tg.mctl.ai run is recorded. MCP Apps are deferred to [#650](https://github.com/mctlhq/mctl-telegram/issues/650). | 2026-10-23 |
| Cursor | DCR with the hosted callback on `www.cursor.com`; the `cursor://` scheme is refused | implicit `www.cursor.com`, `cursor.com` | not tested | Allowlisted only. Production saw 464 rejected registrations on 2026-09-21..23 before the hosts were admitted; no sign-in is verified. | not observed |
| VS Code | CIMD (`vscode.dev`) | CIMD `vscode.dev` | not tested | Allowlisted only. No run is recorded. | not observed |
| Windsurf | unknown (DCR assumed) | none | not tested | No allowlist entry and no run. | not observed |
| Town | CIMD document published at `https://www.town.com/.well-known/oauth-client-id`; DCR via a `www.town.com` callback. Which one Town uses is not confirmed. | implicit `www.town.com`, `town.com`; CIMD `www.town.com`; profile binding to `core-reply` | not tested | Proven: DCR was rejected with `invalid_redirect_uri` until mctl-gitops#2023; the CIMD document resolves; authorize reaches the Telegram sign-in; the `MCP_CLIENT_PROFILES` binding to `core-reply` parses. Not proven: a completed token, a tool call, and the CIMD-or-DCR choice. See [#784](https://github.com/mctlhq/mctl-telegram/issues/784) and the [admission runbook](../runbooks/admitting-an-agent-platform.md). | 2026-10-23 |
| MCP Inspector | DCR with a loopback redirect | none needed: loopback redirects are always accepted | not tested | Not run against tg.mctl.ai. Only the in-process probe exists: see the `in-process-current-main` cell in [cloudflare-portal-compat.md](../cloudflare-portal-compat.md). | not observed |
| Cloudflare MCP portal | byte-exact redirect URI, automatic DCR mode | `OAUTH_DCR_REDIRECT_URIS`: two URIs, `<portal servers-callback>` and `<dashboard oauth-callback ...>` | not tested | Mirrors `PENDING-OPERATOR` in [cloudflare-portal-compat.md](../cloudflare-portal-compat.md); the `direct-deployed` and `cloudflare-portal` cells are not run. | not observed |

## Notes

- `antigravity.google` is on `OAUTH_ALLOWED_IMPLICIT_HOSTS`. It is
  allowlisted, not in scope of this matrix, and not tested.
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
