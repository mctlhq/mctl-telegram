# mctl-telegram

Go remote MCP server exposing Telegram user-account access (via `gotd/td` MTProto) as MCP tools — `list_dialogs`, `get_unread_messages`, `get_messages`, `send_message`, `pin_message`, and account controls — for Claude.ai and any MCP-compatible client.

Status: **experimental / beta** (v0.x). Seven tools, OAuth-protected, draft-by-default send gate. Telegram session is per-operator and persisted encrypted. APIs and tool schemas may change before v1.0.

## Security and privacy model

mctl-telegram holds a **server-side** Telegram MTProto session on your behalf. This means the server can technically read your Telegram data while processing your requests — it is the one making MTProto calls to Telegram. We minimize what is stored (encrypted session blob only) and what is logged (no message text, no phone numbers), but you are trusting both the operator of this deployment and the integrity of this code.

See [SECURITY.md](SECURITY.md) for the full threat model, cryptographic invariants, send-gate design, and reporting channel.

**Do not expose this server publicly without OAuth, HTTPS, and a trusted deployment boundary.**

## Endpoints

| Path                                       | Purpose                                                                                              |
|--------------------------------------------|------------------------------------------------------------------------------------------------------|
| `/healthz`, `/readyz`                      | Probes — `ok` 200.                                                                                   |
| `/.well-known/oauth-protected-resource`    | RFC 9728 metadata declaring the authorization server for this deployment.                            |
| `/mcp`                                     | MCP Streamable HTTP endpoint. Auth: `Authorization: Bearer <JWT>`.                                   |

## MCP tools

| Tool                          | Annotations       | Notes |
|-------------------------------|-------------------|-------|
| `list_dialogs`                | `readOnly`        | Inputs: `limit` (≤200, default 50), optional `query`. Peer id format: `user:<id>` / `chat:<id>` / `channel:<id>`. |
| `get_unread_messages`         | `readOnly`        | Inputs: optional `peer`, `limit` (≤200). Returns only unread messages. |
| `get_messages`                | `readOnly`        | Full message history for a specific peer, not just unread. |
| `send_message`                | `destructive`     | Inputs: `peer`, `text`, optional `mode` ∈ `{draft, send}`. Default `draft`. Real send requires all of: server `ALLOW_SEND=true`, identity has `telegram:messages:send` scope, per-account `send_enabled=true`, and `mode=send`. Otherwise returns dry-run preview with `dry_reason`. |
| `pin_message`                 | `destructive`     | Inputs: `peer`, `message_id`, `unpin` (bool). |
| `disconnect_telegram_account` | `destructive`     | Soft-revokes your session — marks it revoked and tears down the in-memory MTProto client. |
| `delete_telegram_account`     | `destructive`     | Hard-deletes the encrypted session blob and all per-account metadata from the server. |

## Quick start (local dev)

```bash
# 1. Build & run the server (auth bypassed for local dev)
ADDR=:8080 \
AUTH_MODE=local-dev AUTH_REQUIRED=false \
OPERATOR_GITHUB_LOGIN=your-github-handle \
DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
go run ./cmd/server

# 2. First-time login (register an app at https://my.telegram.org first)
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

## Self-hosted deployment

### Prerequisites

- Telegram API credentials: register an app at <https://my.telegram.org> to get `TG_API_ID` and `TG_API_HASH`.
- A Telegram bot for the OIDC login flow: create one via BotFather and note its numeric id and token.
- A Postgres database (or SQLite for single-node deployments).
- An HTTPS endpoint reachable by your MCP clients.

### Configuration

Copy `.env.example` to `.env` and fill in the values:

```bash
cp .env.example .env
$EDITOR .env
```

Key variables:

| Variable                      | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| `AUTH_MODE`                   | `local-jwt` — server signs its own tokens (recommended for self-hosting)    |
| `AUTH_REQUIRED`               | `true` in production; `false` only for local dev                            |
| `OAUTH_JWT_SIGNING_KEY`       | HS256 signing key for access tokens; see below                              |
| `TELEGRAM_OIDC_CLIENT_ID`     | Login bot's numeric Telegram id (from BotFather; not secret)                |
| `TELEGRAM_OIDC_CLIENT_SECRET` | OIDC client secret for the login bot                                        |
| `TELEGRAM_LOGIN_BOT_TOKEN`    | Bot token — used only for the new-client welcome digest                     |
| `TG_API_ID`                   | Telegram API id from my.telegram.org                                        |
| `TG_API_HASH`                 | Telegram API hash from my.telegram.org                                      |
| `ENCRYPTION_KEY`              | 32-byte hex key for encrypting session blobs at rest                        |
| `DATABASE_URL`                | `postgres://...` or `file:./mctl-telegram.db?_pragma=journal_mode(WAL)`     |
| `ALLOW_SEND`                  | `false` by default; set `true` only after validating the send gate          |
| `PUBLIC_BASE_URL`             | External HTTPS base URL, e.g. `https://tg.example.com`                     |
| `OAUTH_ACCESS_TOKEN_TTL`      | optional, default `1h`                                                      |
| `OAUTH_REFRESH_TOKEN_TTL`     | optional, default `720h` (30 days)                                          |

> `OAUTH_JWT_SECRET` is a deprecated alias of `OAUTH_JWT_SIGNING_KEY`. It is
> still accepted as a fallback but logs a warning at startup. Use
> `OAUTH_JWT_SIGNING_KEY` for new deployments.

### JWT signing key

In `local-jwt` mode mctl-telegram signs its own access tokens (HS256). The signing key **must persist across restarts** and **must be dedicated to this service** — if it changes, every previously issued token fails verification.

Generate a key:

```bash
# 64 random bytes, base64-encoded — store this in a secret manager or .env
openssl rand -base64 64
```

Set it as `OAUTH_JWT_SIGNING_KEY` in your environment. In local development any non-empty string works.

### Token lifetimes and refresh

Access tokens are intentionally short-lived (`OAUTH_ACCESS_TOKEN_TTL`, default 1h). Clients renew them silently with the OAuth 2.1 `refresh_token` grant: the `/oauth/token` endpoint accepts `grant_type=refresh_token` and returns a new access token plus a rotated refresh token, with no Telegram sign-in interaction. Refresh tokens are opaque, stored SHA-256-hashed, and rotated on every use; replaying an already-rotated token revokes the whole token family.

### Docker

```bash
# Build
docker build -t mctl-telegram .

# Run (pass env from a file)
docker run --rm -p 8080:8080 --env-file .env mctl-telegram
```

Image published to `ghcr.io/mctlhq/mctl-telegram:<semver>` (no `v` prefix).

### Docker Compose

A `docker-compose.yml` is included for a self-contained local deployment with Postgres:

```bash
cp .env.example .env
$EDITOR .env          # fill in TG_API_ID, TG_API_HASH, keys
docker compose up -d
```

Services started: `app` (mctl-telegram on port 8080) and `db` (Postgres 16).

For Beta-tier service-level objectives, error-budget policy, and burn-rate alert definitions, see [docs/slo.md](docs/slo.md).

## Connecting to Claude.ai

1. Start mctl-telegram and confirm the well-known is reachable:
   ```bash
   curl https://<your-host>/.well-known/oauth-protected-resource
   ```
2. In Claude.ai → Settings → Connectors → Add custom connector:
   * Remote MCP URL: `https://<your-host>/mcp`
   * Authentication: OAuth (the connector discovers the authorization server from the well-known metadata).
3. Complete the Telegram login flow in the browser; the issued access token is used automatically on every MCP request.

## Operations: Canary account

The synthetic canary probe (`cmd/canary`) verifies the live service end-to-end. It requires a dedicated Telegram test account — **not the operator's personal account** — to avoid false-positive FLOOD_WAIT interference.

### Setting up the canary account

1. Create a fresh Telegram account for the canary. Note its numeric user id.

2. Complete the browser-based setup flow by visiting `GET /telegram/connect` while signed in as the canary. This links the session to an authenticated identity in the database.

3. Issue a read-only bearer token with the `set_telegram_access` admin MCP tool:

   ```
   set_telegram_access(tg_user_id="<canary-account-id>", scopes="telegram:dialogs:read,telegram:messages:read")
   ```

   The token must carry exactly `telegram:dialogs:read,telegram:messages:read` and must **not** include `telegram:messages:send`.

4. Pass `tg_user_id` and `bearer_token` to the canary probe via environment variables or a Kubernetes Secret.

5. Schedule the canary to run every two minutes against your deployment.

The canary pushes three Prometheus metric families to a Pushgateway:

- `mctl_telegram_canary_success` — 1 if all probes passed, 0 if any failed.
- `mctl_telegram_canary_duration_seconds` — wall-clock time of the run.
- `mctl_telegram_canary_step_failure_total{step=}` — per-step failure counters.

An alert rule template is provided in `deploy/alerts/canary.rules.yaml`.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, code style, and the PR process.

## Security

See [SECURITY.md](SECURITY.md) — covers the send-gate invariants, session encryption, and the reporting channel.
