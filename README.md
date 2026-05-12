# mctl-telegram

Go remote MCP server exposing Telegram user-account access (via `gotd/td` MTProto) as MCP tools — `list_dialogs`, `get_unread_messages`, `send_message` — for Claude.ai and any MCP-compatible client.

Status: **bootstrap** — only `/healthz` and `/readyz` endpoints implemented. Telegram and MCP layers land in subsequent milestones.

## Endpoints (current)

| Path       | Purpose                          |
|------------|----------------------------------|
| `/healthz` | Liveness probe — returns `ok` 200 |
| `/readyz`  | Readiness probe — same response   |

## Local run

```
go run ./cmd/server
curl -s localhost:8080/healthz
```

## Deployment

Image: `ghcr.io/mctlhq/mctl-telegram:<semver>` (no `v` prefix).
GitOps values: `mctl-gitops/platform-gitops/services/labs/mctl-telegram/values.yaml`.
Public hostname: `https://telegram.mctl.ai`.
