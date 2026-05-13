# mctl-telegram

Go remote MCP server exposing Telegram user-account access (via `gotd/td` MTProto) as MCP tools — `list_dialogs`, `get_unread_messages`, `send_message` — for Claude.ai and any MCP-compatible client.

Status: **functional MVP** (0.2.0). Three tools, OAuth-protected, draft-by-default send gate. Telegram session is per-operator and persisted encrypted.

## Endpoints

| Path                                       | Purpose                                                                                              |
|--------------------------------------------|------------------------------------------------------------------------------------------------------|
| `/healthz`, `/readyz`                      | Probes — `ok` 200.                                                                                   |
| `/.well-known/oauth-protected-resource`    | RFC 9728 metadata declaring `api.mctl.ai` as the authorization server.                               |
| `/mcp`                                     | MCP Streamable HTTP endpoint. Auth: `Authorization: Bearer <JWT-from-api.mctl.ai>`.                  |

## MCP tools

| Tool                  | Annotations          | Notes |
|-----------------------|----------------------|-------|
| `list_dialogs`        | `readOnly`           | inputs: `limit` (≤200, default 50), optional `query`. peer id format `user:<id>` / `chat:<id>` / `channel:<id>`. |
| `get_unread_messages` | `readOnly`           | inputs: optional `peer`, `limit` (≤200). only unread. |
| `send_message`        | `destructive`        | inputs: `peer`, `text`, optional `mode` ∈ `{draft, send}`. Default `draft`. Real send requires all of: server `ALLOW_SEND=true`, identity has `telegram:messages:send` scope, `mode=send`. Otherwise returns dry-run preview with `dry_reason`. |

## Local development

```bash
# 1. Build & run the server
ADDR=:8080 \
AUTH_MODE=local-dev AUTH_REQUIRED=false \
OPERATOR_GITHUB_LOGIN=your-github-handle \
DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
go run ./cmd/server

# 2. First-time login (registers an app at https://my.telegram.org first)
TG_API_ID=12345 TG_API_HASH=hexhexhex... \
DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
OPERATOR_GITHUB_LOGIN=your-github-handle \
go run ./cmd/login --phone +1...

# 3. Smoke test via MCP inspector or curl
curl -s -X POST localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"local","version":"0"}}}'
```

## Production environment

Required `env` (set via Helm `values.yaml` + ExternalSecret pulling from Vault):

| Key                       | Source                                          |
|---------------------------|-------------------------------------------------|
| `AUTH_MODE`               | `shared-hmac` (recommended) or `own-oauth` (M6) |
| `AUTH_REQUIRED`           | `true`                                          |
| `OAUTH_JWT_SECRET`        | Vault `secret/platform/oauth-jwt-secret`        |
| `TG_API_ID`, `TG_API_HASH`| Vault `secret/platform/mctl-telegram/api`       |
| `ENCRYPTION_KEY`          | Vault `secret/platform/mctl-telegram/encryption` (32-byte hex) |
| `DATABASE_URL`            | `postgres://...` (provisioned via `mctl_provision_database`) |
| `ALLOW_SEND`              | `false` until bake-in completes                 |

## Claude.ai connector registration

1. Verify the well-known is reachable:
   ```bash
   curl https://labs-mctl-telegram.mctl.ai/.well-known/oauth-protected-resource
   ```
2. In Claude.ai → Settings → Connectors → Add custom connector:
   * Remote MCP URL: `https://labs-mctl-telegram.mctl.ai/mcp`
   * Authentication: OAuth (the connector will discover `api.mctl.ai` from the well-known and prompt for GitHub login).
3. After GitHub auth, the access token issued by `api.mctl.ai` is automatically used on every MCP request. `mctl-telegram` verifies it via shared HMAC.

## Deploy

This service is part of the `mctlhq` platform. Image builds and gitops commits are centralized in [`mctlhq/mctl-gitops`](https://github.com/mctlhq/mctl-gitops). For a new version:

```bash
# tag, push, then dispatch
git tag X.Y.Z && git push origin X.Y.Z
mctl deploy -t labs -n mctl-telegram -r mctlhq/mctl-telegram -g X.Y.Z \
  --host labs-mctl-telegram.mctl.ai --port 8080 \
  --env AUTH_MODE=shared-hmac --env AUTH_REQUIRED=true --env ALLOW_SEND=false
```

* Image: `ghcr.io/mctlhq/mctl-telegram:<semver>` (no `v` prefix)
* GitOps values: `mctl-gitops/platform-gitops/services/labs/mctl-telegram/values.yaml`
* Public hostname: `https://labs-mctl-telegram.mctl.ai`

## Security

See [SECURITY.md](SECURITY.md) — covers shared-HMAC coupling, send-gate invariants, and reporting channel.
