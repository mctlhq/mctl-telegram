# Security policy

## Supported versions

Only the latest release and the `main` branch receive security fixes. Older tagged releases are not backported.

## Reporting a vulnerability

Email **dmitri+security@mctl.ai** with vulnerability reports. Please **do not** open public GitHub issues for security vulnerabilities. We respond within 72 hours and disclose fixes in the CHANGELOG once a release ships.

When reporting, please **do not include** Telegram session strings, OAuth tokens, API credentials, phone numbers, chat IDs, or private message content in your report.

## Threat model

`mctl-telegram` brokers the following trust relationships per user:

| Boundary | Trusted credential / state | Lives |
|---|---|---|
| Inbound HTTP (ChatGPT / Claude / MCP client → `/mcp`) | OAuth JWT issued by `mctl-telegram` (`AUTH_MODE=local-jwt`) or `api.mctl.ai` (`AUTH_MODE=shared-hmac-legacy`) | Bearer header, per-request |
| OAuth identity (client → `/oauth/authorize`) | Telegram OIDC `id_token` (JWKS-validated, Authorization Code + PKCE) | Server-to-server token exchange, single-use |
| Outbound MTProto (`gotd/td` → Telegram) | Encrypted session blob | Postgres `telegram_accounts.session_encrypted` |
| Communication Agent ingestion | Per-user listener state, encrypted message/event rows, queue jobs, and policy state | Postgres agent tables; only for profiles with the listener enabled |

Compromise of any one user's credentials or session should compromise only that user's account, not another user's, provided the per-user key derivation and user-scoped database predicates remain intact. There is no intended cross-user data-sharing path inside the service.

## Communication Agent safety boundary

The Communication Agent extends the service beyond request/response MCP calls. For accounts where the listener is explicitly enabled, the server keeps a Telegram update listener connected and can durably ingest relevant private-message updates.

The safety boundary is **server-side code and persisted state, not the model prompt or model output**:

* The listener maps supported Telegram updates into deterministic event IDs and atomically commits the event, queue job, and conversation activity timestamp. A partial event-without-job commit is not accepted.
* Persistence or command-routing failures are returned to `gotd`'s update manager. The stored Telegram watermark is not advanced, allowing reconnect and gap recovery to retry the update.
* Ordinary Saved Messages notes are ignored. Only explicit `/mctl ...` control commands are retained and routed.
* A genuine owner reply, including a media-only reply, moves the conversation to `taken_over`. A taken-over, paused, closed, blocked, or otherwise invalid conversation is denied by policy. This state is sticky — it does not expire on its own — and is only cleared by an explicit `/mctl continue <conversation id>` command, which also resets the conversation's autonomous-turn budget.
* Programmatic `send_message` and `send_media` calls record the Telegram-assigned message ID so their outgoing update echo is not mistaken for a human takeover.
* Disabling the listener removes the runtime account and unpins/stops its Telegram client rather than waiting for idle garbage collection.
* The server-side policy engine fails closed for unknown modes, states, or action types. It denies when the global kill switch is active, the agent is off/paused, the sender is blocked, the peer mismatches, required disclosure is missing, or proposed content violates structural safety checks.
* `observe` mode requires owner approval for replies. `guarded` mode may allow only allowlisted actions that pass every policy check and budget/rate constraint; otherwise approval is required or the action is denied.
* Approval actions use compare-and-set state transitions. An action that reached `executing` is not automatically retried after a crash, because a duplicate Telegram message is considered worse than a missed send.

The listener itself receives and queues updates; enabling the listener alone does not bypass the existing Telegram send gate.

## Communication Agent data at rest and retention

Unlike read-only MCP tool results, Communication Agent processing requires durable message state:

* `incoming_events` and `conversation_messages` can contain third-party Telegram message bodies.
* `agent_actions` can contain proposed reply payloads and policy metadata.
* Message bodies and action payloads are AES-256-GCM sealed with the owning user's derived key before storage.
* Agent content is user-scoped in every repository getter.
* The daily retention sweeper removes stored agent message content older than `AGENT_RETENTION_DAYS` (default **30 days**). Setting the value to `0` keeps rows indefinitely and should be treated as an explicit privacy trade-off.
* Audit rows use their separate `AUDIT_RETENTION_DAYS` policy (default 90 days) and do not contain message bodies.

## Telegram-native OAuth (`AUTH_MODE=local-jwt`, the default)

The connector authenticates via a self-hosted OAuth 2.1 authorization server. The user-facing identity provider is [Telegram's OpenID Connect provider](https://oauth.telegram.org): `/oauth/authorize` redirects the browser to `oauth.telegram.org` with an Authorization Code + PKCE request, and `/oauth/telegram/callback` exchanges the returned code for an `id_token` validated against Telegram's JWKS (signature, `iss`, `aud`, `nonce`, expiry). mctl-telegram is thus an OIDC federation broker — an OAuth 2.1 Authorization Server to the MCP client, and an OIDC Relying Party to Telegram. Once the `id_token` verifies, mctl-telegram mints its own HS256 JWT signed by `OAUTH_JWT_SIGNING_KEY` and returns it via the authorization-code grant.

Notes:

* `OAUTH_JWT_SIGNING_KEY` is a dedicated per-deployment signing key — there is no cross-service coupling. The deprecated `OAUTH_JWT_SECRET` is still accepted as a fallback but logs a startup warning. The key must persist across restarts: if it changes, every previously issued token fails signature verification.
* PKCE-S256 is mandatory on the MCP-client leg. Plain or missing `code_challenge` is rejected at `/oauth/authorize`. The broker runs a second, independent PKCE pair plus a `nonce` on the Telegram leg; the two legs share no secrets and are bound to distinct fields of the pending-authorization record.
* Authorization codes are single-use, 10-minute TTL, and bound to (`client_id`, `redirect_uri`, `code_challenge`). The `/oauth/token` endpoint deletes the code on first redemption.
* Access tokens are short-lived (`OAUTH_ACCESS_TOKEN_TTL`, default 1h). Clients renew them with the `refresh_token` grant.
* Implicit client IDs are accepted only when the `redirect_uri` host appears in the implicit-host allowlist and the scheme is `https://` (or loopback `http://` per RFC 8252). This prevents the OAuth flow from being abused as an open redirector. The same allowlist is applied to every `redirect_uri` supplied at RFC 7591 dynamic registration, so a client cannot smuggle in a phishing destination by registering first. The list is set with `OAUTH_ALLOWED_IMPLICIT_HOSTS` (comma-separated hostnames); unset, it defaults to `claude.ai, claude.com, chatgpt.com, localhost, 127.0.0.1`. Setting it replaces that default rather than extending it. Loopback hosts are accepted regardless of the list.
* Scope assignment is identity-based: Telegram IDs in `TG_LOGIN_ADMINS` are granted platform-admin scopes; other identities receive only their configured access tier.
* `TELEGRAM_OIDC_CLIENT_SECRET` is sensitive on the same tier as `OAUTH_JWT_SIGNING_KEY` and is never logged.
* **Access tokens are not individually revocable within their TTL.** An access token is a self-contained, bearer-valid JWT: `/mcp` accepts it purely from signature, issuer, and expiry, with no per-token denylist or storage lookup. The only way to invalidate an issued-but-unexpired access token early is rotating `OAUTH_JWT_SIGNING_KEY`, which invalidates every user's access tokens at once — there is no way to kill a single leaked access token in isolation. The accepted mitigation is keeping `OAUTH_ACCESS_TOKEN_TTL` short (see the `#398` 24h ceiling); a leaked access token is only ever live for that window. This is a deliberate, reviewed trade-off, not an oversight — see "Refresh tokens" below for the token that *is* individually revocable.

### Refresh tokens

The `/oauth/token` endpoint supports `grant_type=refresh_token` so a client can renew an expired access token without repeating Telegram sign-in.

* **Opaque, not JWT.** A refresh token is 256 bits of CSPRNG output.
* **Stored hashed.** Only its SHA-256 digest is persisted.
* **Rotated on every use.** Each refresh revokes the presented token and issues a replacement.
* **Reuse detection.** Replaying an already-rotated token revokes the entire token family.
* **Bounded lifetime.** Absolute expiry is `OAUTH_REFRESH_TOKEN_TTL` (default 30 days); a background sweeper deletes expired rows.
* **Explicitly revocable.** `POST /oauth/revoke` (RFC 7009, advertised as `revocation_endpoint` in `/.well-known/oauth-authorization-server`) lets a caller revoke a refresh token's whole family on demand — the same family-revoke mechanism reuse detection already uses internally, now reachable without waiting for a reuse event. This is how an operator cuts off a leaked *refresh* token without rotating `OAUTH_JWT_SIGNING_KEY` for every user; it does not affect any access token already issued from that family (see above).

## Legacy mode: `AUTH_MODE=shared-hmac-legacy`

The legacy mode validates JWTs signed by an external authorization server using a shared `OAUTH_JWT_SECRET`.

* **Impact:** the services share secret material; compromise of either may allow minting tokens for both.
* **Mitigation:** rotate the shared secret for both services simultaneously. Use `AUTH_MODE=local-jwt` for new deployments.
* **Plan:** `shared-hmac-legacy` will be removed in a future minor release.

## Cryptographic and logging invariants

* `ENCRYPTION_KEY` MUST be 32 random bytes, hex-encoded (64 chars). Production refuses an invalid length.
* MTProto session blobs, Communication Agent message bodies, and action payloads are AES-256-GCM sealed before reaching disk, using a per-user derived key.
* Audit logs and process logs NEVER contain full message bodies, decoded phone digits, 2FA passwords, MTProto session bytes, bearer tokens, JWT secrets, or encryption keys. The slog redaction handler strips sensitive keys before a line reaches stdout.
* The deployment operator and anyone who compromises the running pod can access plaintext while the service processes or decrypts user data. Hosted mode is not zero-knowledge.

## Send gate (defense in depth)

Real Telegram sends through `send_message` or `send_media` require **all** of:

1. Server flag `ALLOW_SEND=true`.
2. Identity has `telegram:messages:send` scope.
3. `telegram_accounts.send_enabled = true` for that operator.
4. Per-peer send rate limit not exhausted.

The tool exposes no trusted client-controlled bypass for these gates. Any condition false returns a dry-run result (`sent=false`) with a `dry_reason`; no send RPC reaches Telegram. Media dry-runs do not fetch a URL or decode base64 content.

## Authentication-required mode

* `AUTH_REQUIRED=false` is for local development only. A deployed pod MUST set `AUTH_REQUIRED=true` and a production auth mode.
* `local-dev` returns a fixed platform-admin identity and MUST NOT be reachable from a non-localhost production interface.
* This posture is enforced, not just documented: `cmd/server/bootguard.go`'s `checkBootGuard` runs at the start of `main()` and fatally exits before the database is opened or the listener is bound whenever `AUTH_MODE=local-dev`/`AUTH_REQUIRED=false` or a missing `ENCRYPTION_KEY` is paired with a non-loopback `ADDR` or `ENV=production`.

## Rate limiting

The default per-identity token bucket is 30 requests/minute with the same burst. Write paths also apply per-peer limits. Anonymous health, readiness, public content, and well-known endpoints are limited at the ingress layer.