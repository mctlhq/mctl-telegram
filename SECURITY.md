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
| Inbound HTTP (Claude.ai → `/mcp`) | OAuth JWT issued by `api.mctl.ai` | Bearer header, per-request |
| Outbound MTProto (`gotd/td` → Telegram) | Encrypted session blob | Postgres `telegram_accounts.session_encrypted` |

Compromise of either compromises only the affected operator's account — not other users — provided the per-user session encryption key is unique. There is no inter-user data sharing path inside the service.

## Known coupling: shared `OAUTH_JWT_SECRET` with mctl-api (M2 → M3)

The current `shared-hmac` auth mode validates JWTs by re-implementing mctl-api's HMAC-SHA256 verifier and reading the **same** `OAUTH_JWT_SECRET` from Vault (`secret/platform/oauth-jwt-secret`). This is an MVP-stage coupling:

* **Impact**: compromise of the `mctl-telegram` pod's secret material is equivalent to compromise of `mctl-api`'s — an attacker can mint valid platform tokens.
* **Mitigation today**: rotate `OAUTH_JWT_SECRET` for **both** services in the same change. Failing to do so will lock out users on whichever side is stale.
* **Long-term fix (planned)**: add RS256 + `/oauth/jwks` to `mctl-api`; switch `mctl-telegram` to JWKS verification. Tracked at `mctlhq/mctl-api` (not yet filed).

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

* `AUTH_REQUIRED=false` is for local development only. The deployed pod MUST set `AUTH_REQUIRED=true` and `AUTH_MODE=shared-hmac` (or future `own-oauth`).
* `local-dev` provider returns a fixed `Identity` with platform-admin scopes and is gated by `AUTH_MODE=local-dev`. It MUST NOT be reachable from any non-localhost interface in production.

## Rate limiting

Per-identity token bucket, default 30 requests/minute, capped at the same burst. Anonymous traffic (`/healthz`, `/readyz`, `/.well-known/*`) is exempt and rate-limited only at the ingress level.
