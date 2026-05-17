# Security policy

## Supported versions

Only the latest release and the `main` branch receive security fixes. Older tagged releases are not backported.

## Reporting a vulnerability

Email **dmitri+security@mctl.ai** with vulnerability reports. Please **do not** open public GitHub issues for security vulnerabilities. We respond within 72 hours and disclose fixes in the CHANGELOG once a release ships.

When reporting, please **do not include** Telegram session strings, OAuth tokens, API credentials, phone numbers, chat IDs, or private message content in your report.

## Threat model

`mctl-telegram` brokers two trust relationships per user:

| Boundary | Trusted credential | Lives |
|---|---|---|
| Inbound HTTP (Claude.ai → `/mcp`) | OAuth JWT issued by `mctl-telegram` (`AUTH_MODE=local-jwt`) or `api.mctl.ai` (`AUTH_MODE=shared-hmac-legacy`) | Bearer header, per-request |
| OAuth identity (Claude.ai → `/oauth/authorize`) | Telegram Login Widget HMAC payload (SHA256(bot_token) → HMAC-SHA256(data-check-string)) | Form submission, single-use |
| Outbound MTProto (`gotd/td` → Telegram) | Encrypted session blob | Postgres `telegram_accounts.session_encrypted` |

Compromise of any one compromises only the affected operator's account — not other users — provided the per-user session encryption key is unique. There is no inter-user data sharing path inside the service.

## Telegram-native OAuth (`AUTH_MODE=local-jwt`, the default)

The Claude.ai connector authenticates via a self-hosted OAuth 2.1 authorization server. The user-facing identity provider is the [Telegram Login Widget](https://core.telegram.org/widgets/login), which Telegram signs with HMAC-SHA256 keyed by `SHA256(bot_token)`. Once the widget HMAC verifies, mctl-telegram mints its own HS256 JWT signed by `OAUTH_JWT_SIGNING_KEY` and returns it to Claude.ai via the authorization-code grant.

Notes:

* `OAUTH_JWT_SIGNING_KEY` is a dedicated mctl-telegram signing key (Vault `secret/platform/mctl-telegram/oauth`) — there is no cross-service coupling. The deprecated `OAUTH_JWT_SECRET`, historically wired to mctl-api's shared secret, is still accepted as a fallback but logs a startup warning. The key must persist across pod restarts: if it changes, every previously issued token fails signature verification.
* PKCE-S256 is mandatory. Plain or missing `code_challenge` is rejected at `/oauth/authorize`.
* Authorization codes are single-use, 10-minute TTL, and bound to (`client_id`, `redirect_uri`, `code_challenge`). The `/oauth/token` endpoint deletes the code on first redemption.
* Access tokens are short-lived (`OAUTH_ACCESS_TOKEN_TTL`, default 1h). Clients renew them with the `refresh_token` grant — see "Refresh tokens" below.
* Implicit (unregistered) client_ids are accepted only when the `redirect_uri` host appears in `AllowedImplicitHosts` (default: `claude.ai`, `claude.com`, `localhost`, `127.0.0.1`) and the scheme is `https://` (or `http://` for loopback per RFC 8252 §7.3). This prevents the OAuth flow from being abused as an open redirector.
* Scope assignment is identity-based: Telegram ids in `TG_LOGIN_ADMINS` are granted full `platform-admins` scopes; everyone else authenticates but receives an empty scope set, failing every per-tool gate.
* `TELEGRAM_LOGIN_BOT_TOKEN` is sensitive on the same tier as `OAUTH_JWT_SIGNING_KEY`: it lets an attacker forge widget callbacks. Stored in Vault `secret/platform/mctl-telegram/login` and never logged.

### Refresh tokens

The `/oauth/token` endpoint supports `grant_type=refresh_token` so a client can renew an expired access token without re-running the Telegram Login Widget flow. Refresh-token handling is hardened as follows:

* **Opaque, not JWT.** A refresh token is 256 bits of CSPRNG output — it carries no claims and is meaningless without the server-side row.
* **Stored hashed.** Only the SHA-256 digest is persisted (`oauth_refresh_tokens.token_hash`); the plaintext never reaches the database.
* **Rotated on every use.** Each refresh issues a new refresh token and revokes the presented one. Tokens are bound to (`client_id`, `user_id`, `telegram_id`); a `client_id` mismatch is rejected.
* **Reuse detection.** Every token in a rotation lineage shares a `family_id`. Presenting an already-rotated token revokes the entire family — a stolen-token replay cannot outlive the legitimate client's next refresh.
* **Bounded lifetime.** Absolute expiry is `OAUTH_REFRESH_TOKEN_TTL` (default 30 days); a background sweeper deletes expired rows.

## Legacy coupling: shared `OAUTH_JWT_SECRET` with mctl-api (`AUTH_MODE=shared-hmac-legacy`)

The legacy `shared-hmac` (alias `shared-hmac-legacy`) auth mode validates JWTs by re-implementing mctl-api's HMAC-SHA256 verifier and reading the **same** `OAUTH_JWT_SECRET` from Vault (`secret/platform/oauth-jwt-secret`). It is retained for one minor release so existing Claude.ai connector sessions survive the rollout to `local-jwt`:

* **Impact**: compromise of the `mctl-telegram` pod's secret material is equivalent to compromise of `mctl-api`'s — an attacker can mint valid platform tokens.
* **Mitigation today**: rotate `OAUTH_JWT_SECRET` for **both** services in the same change. Failing to do so will lock out users on whichever side is stale.
* **Plan**: drop `shared-hmac-legacy` in mctl-telegram 0.8.0.

## Cryptographic invariants

* `ENCRYPTION_KEY` MUST be 32 random bytes, hex-encoded (64 chars). Refuses to start with any other length.
* MTProto session blobs are AES-256-GCM sealed (nonce = `gcm.NonceSize()` random bytes per session) before reaching disk.
* Audit log NEVER contains: full `text` of sent messages, decoded phone digits, 2FA password, MTProto session bytes, JWT secret, or encryption key. Slog-handler redaction strips these keys before any line reaches stdout.

## Send-gate (defense in depth)

Real Telegram sends require **all** of:

1. Server flag `ALLOW_SEND=true` (Helm values).
2. Identity has `telegram:messages:send` scope (group → scope map in `internal/auth/sharedhmac/verifier.go`).
3. `telegram_accounts.send_enabled = true` for that operator (set out-of-band).
4. Tool call argument `mode=send` (default is `draft`).

Any condition false → response is a dry-run preview containing the proposed text and the failing-condition reason in `dry_reason`. `mode=draft` never reaches the Telegram API.

## Authentication-required mode

* `AUTH_REQUIRED=false` is for local development only. The deployed pod MUST set `AUTH_REQUIRED=true` and `AUTH_MODE=local-jwt` (or the legacy `shared-hmac-legacy`).
* `local-dev` provider returns a fixed `Identity` with platform-admin scopes and is gated by `AUTH_MODE=local-dev`. It MUST NOT be reachable from any non-localhost interface in production.

## Rate limiting

Per-identity token bucket, default 30 requests/minute, capped at the same burst. Anonymous traffic (`/healthz`, `/readyz`, `/.well-known/*`) is exempt and rate-limited only at the ingress level.
