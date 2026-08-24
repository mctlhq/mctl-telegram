# mctl-telegram

Go remote MCP server exposing user-authorized Telegram account access (via `gotd/td` MTProto) as MCP tools — dialogs, messages, preview-gated sends, pin controls, audit logs, and account/admin controls — for ChatGPT Apps, Claude.ai, and any MCP-compatible client.

Status: **Apps SDK readiness track** (v0.x). Fourteen MCP tools, OAuth-protected, preview-only sending by default, reviewer/demo login mode, and production-facing docs/metadata intended for ChatGPT Apps review. Telegram session is per-user and persisted encrypted. APIs and tool schemas may change before v1.0.

mctl-telegram is an independent project, not an official Telegram app or Telegram API partner. It operates only on the Telegram account that the user explicitly connects and controls; users remain responsible for complying with Telegram's terms.

## Security and privacy model

mctl-telegram holds a **server-side** Telegram MTProto session on your behalf. This means the server can technically read your Telegram data while processing your requests — it is the one making MTProto calls to Telegram. We minimize what is stored (encrypted session blob only) and what is logged (no message text, no phone numbers), but you are trusting both the operator of this deployment and the integrity of this code.

See [SECURITY.md](SECURITY.md) for the full threat model, cryptographic invariants, send-gate design, and reporting channel.

**Do not expose this server publicly without OAuth, HTTPS, and a trusted deployment boundary.**

## Endpoints

| Path                                       | Purpose                                                                                              |
|--------------------------------------------|------------------------------------------------------------------------------------------------------|
| `/healthz`, `/readyz`                      | Probes — `ok` 200.                                                                                   |
| `/.well-known/oauth-protected-resource`    | RFC 9728 metadata declaring the authorization server for this deployment.                            |
| `/mcp`                                     | MCP Streamable HTTP endpoint. Auth: `Authorization: Bearer <JWT>`. 401 responses include `WWW-Authenticate` pointing to `/.well-known/oauth-protected-resource/mcp` (RFC 9728 discovery). |

## MCP tools

| Tool                          | MCP annotations | Notes |
|-------------------------------|----------------------|-------|
| `list_dialogs`                | `readOnly=true`, `destructive=false`, `openWorld=true` | Reads Telegram dialogs (audit row is internal observability). Inputs: `limit` (≤200, default 50), optional `query`. |
| `get_unread_messages`         | `readOnly=true`, `destructive=false`, `openWorld=true` | Reads unread Telegram messages (audit row is internal observability). Inputs: optional `peer`, `limit` (≤200). When `peer` is omitted, DMs and chats/groups (including megagroup/supergroups) fill `limit` before broadcast channels. |
| `get_messages`                | `readOnly=true`, `destructive=false`, `openWorld=true` | Reads recent message history for a specific peer (audit row is internal observability). |
| `send_message`                | `readOnly=false`, `destructive=true`, `openWorld=true` | Inputs: `peer`, `text`. Preview-only by default: sends for real only when the gate is fully open (server `ALLOW_SEND=true`, identity has `telegram:messages:send` scope, per-account `send_enabled=true`). Otherwise returns `sent=false` with `dry_reason`; no message is delivered. |
| `send_media`                  | `readOnly=false`, `destructive=true`, `openWorld=true` | Inputs: `peer`, `media_type` (`photo`/`video`/`document`/`animation`), exactly one of `file_url`/`file_base64`, optional `caption`/`file_name` (required for `document`+`file_base64`). Same preview-only gate as `send_message`; a denied call never fetches `file_url` or decodes `file_base64`. `animation` is always sent as a distinct type from `video`, never relabeled. `file_url` goes through an SSRF-guarded fetcher (HTTPS-only; loopback/link-local/private-range addresses refused, including on redirect hops). Both sources are capped by `MEDIA_UPLOAD_MAX_BYTES` (default 20 MiB). |
| `prepare_pin_message`         | `readOnly=false`, `destructive=false`, `openWorld=false` | Creates a local one-shot confirmation record for a later `pin_message` call. |
| `pin_message`                 | `readOnly=false`, `destructive=true`, `openWorld=true` | Pins or unpins a Telegram message after a matching confirmation id. |
| `get_my_audit_log`            | `readOnly=true`, `destructive=false`, `openWorld=false` | Returns the authenticated user's own audit rows. |
| `disconnect_telegram_account` | `readOnly=false`, `destructive=true`, `openWorld=false` | Soft-revokes your session and tears down the in-memory MTProto client. |
| `delete_telegram_account`     | `readOnly=false`, `destructive=true`, `openWorld=false` | Hard-deletes the encrypted session blob and per-account metadata from this server. |
| `list_telegram_identities`    | `readOnly=true`, `destructive=false`, `openWorld=false` | Admin-only: lists signed-in Telegram identities and access state, with audit metadata. |
| `set_telegram_access`         | `readOnly=false`, `destructive=true`, `openWorld=false` | Admin-only: grants or revokes the local client access tier for a Telegram user. |
| `set_account_send`            | `readOnly=false`, `destructive=true`, `openWorld=false` | Admin-only: enables or disables the per-account real-send gate. |
| `get_user_audit_log`          | `readOnly=true`, `destructive=false`, `openWorld=false` | Admin-only: reads another Telegram user's audit rows, with audit metadata. |
| `revoke_telegram_session`     | `readOnly=false`, `destructive=true`, `openWorld=false` | Admin-only: revokes a user's active MTProto session on this server. |

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
| `ALLOWED_ORIGINS`             | optional; comma-separated Origin allowlist for `/mcp` (DNS-rebinding protection). No-Origin requests always pass; defaults to the `PUBLIC_BASE_URL` origin |
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

A refresh token (and its whole rotation family) can be revoked on demand with `POST /oauth/revoke` (RFC 7009; advertised as `revocation_endpoint` in `/.well-known/oauth-authorization-server`). Access tokens are not individually revocable within their TTL — see [SECURITY.md](SECURITY.md) for that trade-off.

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

## Connecting to ChatGPT Apps (Draft → review-ready)

> Note: mctl-telegram does **not** require an `OPENAI_API_KEY` server-side.
> ChatGPT connects to your MCP endpoint using OAuth bearer tokens issued by
> this service.

1. In ChatGPT, open **Settings → Apps** and select your draft app (enable Developer Mode first if required).
2. Set the MCP server URL to the public endpoint: `https://<your-host>/mcp` (OAuth auth).
3. Ensure these public pages are reachable over HTTPS:
   - Landing: `https://<your-host>/`
   - Docs: `https://<your-host>/docs`
   - Security: `https://<your-host>/security`
   - Privacy: `https://<your-host>/privacy`
4. Verify OAuth discovery:
   - Fetch `https://<your-host>/.well-known/oauth-protected-resource` (always served on your host).
   - Follow the `authorization_servers` URL it advertises and confirm that server's `/.well-known/oauth-authorization-server` resolves. In the default `local-jwt` mode this is your own host; in `shared-hmac`/`shared-hmac-legacy` mode discovery points at `https://api.mctl.ai`, so do **not** expect that document on `<your-host>`.
5. Run a live handshake (`initialize`) and at least one read-only tool call with MCP Inspector or ChatGPT Developer Mode before submitting.

### Quick connect to the hosted endpoint (`tg.mctl.ai`)

If you are using the shared hosted deployment, configure:

- Landing page: `https://tg.mctl.ai/`
- MCP connector URL: `https://tg.mctl.ai/mcp`

Submission notes:
- Keep real sends gated (`ALLOW_SEND=false` on tg.mctl.ai blocks all real sends until opt-in gates are enabled).
- If you enable real sends later, keep the per-account `send_enabled` gate and confirmation flow documented in `/security`.
- Prepare the dashboard submission package with the privacy policy URL, MCP/tool information, screenshots, and test prompts/responses.

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
