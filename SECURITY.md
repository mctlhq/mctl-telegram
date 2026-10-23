# Security policy

## Supported versions

Only the latest release and the `main` branch receive security fixes. Older tagged releases are not backported.

## Reporting a vulnerability

Email **security@mctl.ai** with vulnerability reports. Please **do not** open public GitHub issues for security vulnerabilities. We respond within 72 hours and disclose fixes in the CHANGELOG once a release ships.

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

## Telegram-native OAuth (`AUTH_MODE=local-jwt`)

`local-jwt` is the mode for any real deployment, and the one tg.mctl.ai runs. It is not the code default: an unset `AUTH_MODE` means `local-dev`, which the boot guard below refuses outside local development.

The connector authenticates via a self-hosted OAuth 2.1 authorization server. The user-facing identity provider is [Telegram's OpenID Connect provider](https://oauth.telegram.org): `/oauth/authorize` redirects the browser to `oauth.telegram.org` with an Authorization Code + PKCE request, and `/oauth/telegram/callback` exchanges the returned code for an `id_token` validated against Telegram's JWKS (signature, `iss`, `aud`, `nonce`, expiry). mctl-telegram is thus an OIDC federation broker — an OAuth 2.1 Authorization Server to the MCP client, and an OIDC Relying Party to Telegram. Once the `id_token` verifies, mctl-telegram mints its own HS256 JWT signed by `OAUTH_JWT_SIGNING_KEY` and returns it via the authorization-code grant.

Notes:

* `OAUTH_JWT_SIGNING_KEY` is a dedicated per-deployment signing key — there is no cross-service coupling. The deprecated `OAUTH_JWT_SECRET` is still accepted as a fallback but logs a startup warning. The key must persist across restarts: if it changes, every previously issued token fails signature verification.
* PKCE-S256 is mandatory on the MCP-client leg. Plain or missing `code_challenge` is rejected at `/oauth/authorize`. The broker runs a second, independent PKCE pair plus a `nonce` on the Telegram leg; the two legs share no secrets and are bound to distinct fields of the pending-authorization record.
* Authorization codes are single-use, 10-minute TTL, and bound to (`client_id`, `redirect_uri`, `code_challenge`). The `/oauth/token` endpoint deletes the code on first redemption.
* Access tokens are short-lived (`OAUTH_ACCESS_TOKEN_TTL`, default 1h). Clients renew them with the `refresh_token` grant.
* Implicit client IDs are accepted only when the `redirect_uri` host appears in the implicit-host allowlist and the scheme is `https://` (or loopback `http://` per RFC 8252). This prevents the OAuth flow from being abused as an open redirector. The same allowlist is applied to every `redirect_uri` supplied at RFC 7591 dynamic registration, so a client cannot smuggle in a phishing destination by registering first. The list is set with `OAUTH_ALLOWED_IMPLICIT_HOSTS` (comma-separated hostnames); unset, it defaults to `claude.ai, claude.com, chatgpt.com, localhost, 127.0.0.1`. Setting it replaces that default rather than extending it. Loopback hosts are accepted regardless of the list.
* Pre-registered clients (`OAUTH_PREREGISTERED_CLIENTS`, a JSON array of `client_id` plus exact `redirect_uris`) are seeded at startup for a counterpart that cannot perform RFC 7591 registration. They bypass the implicit-host allowlist and nothing else: the `redirect_uri` is matched byte-for-byte by the same comparison used for dynamically registered clients, the backslash, userinfo and `https`-except-loopback shape checks all still apply, a fragment is refused, and PKCE-S256 remains mandatory. This is deliberately the narrower tool — onboarding one counterpart by widening `OAUTH_ALLOWED_IMPLICIT_HOSTS` would loosen redirect acceptance for every unregistered client, whereas an exact registration trusts that callback for exactly one `client_id`. No `client_secret` field exists: the server is public-client only and this variable does not change that. A malformed value, a duplicate `client_id`, a collision with a built-in client or an unrecognised field aborts startup rather than being ignored.
* Client ID Metadata Documents (CIMD, `OAUTH_CIMD_ACCEPT=true`, off by default) let an agent platform use an https URL as its `client_id`. The server fetches the JSON document at that URL and takes the redirect URIs from it, so the platform's own domain vouches for its callbacks and its host does not join the implicit-host allowlist. Only hosts on the mandatory `OAUTH_CIMD_ALLOWED_HOSTS` list are fetched. The fetch reaches public addresses only, follows no redirect, ignores proxy variables, caps the body at 64 KiB and is rate-limited per host. Documents are cached for their `Cache-Control` lifetime, clamped to between 30 seconds and 24 hours. A document that names a `client_secret`, a `token_endpoint_auth_method` other than `none` or `private_key_jwt`, or no usable redirect URI is refused, and a refused CIMD client never falls back to the DCR or implicit-client path. A `private_key_jwt` client (RFC 7523) must send a signed client assertion on every token request: ES256 or RS256 as its document declares, keys fetched from a `jwks_uri` on the `client_id`'s own host under the same allowlist, `iss` and `sub` equal to the `client_id`, `aud` equal to the issuer or the token endpoint, at most five minutes of lifetime, and a `jti` that is recorded until expiry and refused on replay across replicas. A `none` client that sends an assertion is refused. The document is resolved again at both token grants, so removing a host from the allowlist stops that client's refreshes as well. That is the lever for cutting a CIMD client off: turning `OAUTH_CIMD_ACCEPT` off stops new authorizations, but with no resolver nothing is consulted at refresh, so existing refresh-token families keep rotating until their absolute lifetime. The per-host fetch budget keeps half of its slots for client_ids whose document has validated before, so requests with fresh paths on an allowlisted host cannot stop a known document from being refetched. Use exact hosts in production. A `.suffix` entry trusts every subdomain under it, including the choice of redirect host in its documents, and lets a caller pick hosts to fill the per-host rate map, which refuses other untracked hosts for a minute. A document or key set that cannot be fetched is answered as a retryable `503 server_error`, never as `invalid_client`. Discovery announces CIMD and `private_key_jwt` only when `OAUTH_CIMD_ADVERTISE=true`: a client that prefers CIMD switches to it once announced and gets no DCR fallback if its host is off the allowlist (mctl-telegram#773).
* Dynamic registration for a gateway (`OAUTH_DCR_REDIRECT_URIS`, a comma-separated list of exact redirect URIs, empty by default) lets a counterpart that must register itself — the Cloudflare MCP portal in automatic mode — do so without its callback hosts joining the implicit-host allowlist. A `POST /oauth/register` whose `redirect_uris` are **all** on the list is accepted; one that names a listed URI together with anything else is refused with `invalid_redirect_uri`, even if the other URI would pass the implicit-host check; one that names no listed URI takes the unchanged implicit-host path. Matching is byte-for-byte, with the same shape checks and fragment refusal as pre-registered clients applied to the list at startup. Such a registration gets a `client_id` derived from its redirect set, so repeating it returns the same client and the rows it can create are bounded by the list; its `client_name` is always the server-assigned `Cloudflare MCP portal` (the caller's name is ignored, since a pinned `client_id` is derivable from public callbacks and the name feeds refresh-token records and broadcast audiences); it is kept past the registration TTL and outside the registration cap, and at `/oauth/authorize` each `redirect_uri` must still be on the current list, so removing an entry revokes it. PKCE-S256 and the public-client contract are unchanged, and the granted scope follows the same rule as every other client: an authorization request naming no scope gets the full entitlement, one naming scopes gets exactly those.
* Scope assignment is identity-based: Telegram IDs in `TG_LOGIN_ADMINS` are granted platform-admin scopes; other identities receive only their configured access tier.
* A grant is bounded by the request. When `/oauth/authorize` carries a `scope` parameter, the token endpoint issues the intersection of the identity's entitlement with the scopes named — never more — so a client that asked for `telegram:dialogs:read telegram:messages:read` cannot send, whatever its user could do. The two implicit-privileged scopes, `admin:users` and `admin:users:read`, are outside negotiation: they cannot be requested and are granted by membership alone, so they are unaffected by the parameter. An omitted `scope` keeps the pre-#607 behaviour and grants the full entitlement (RFC 6749 §3.3). Refresh preserves or shrinks that bounded grant and never widens it, including for an identity promoted after the first exchange.
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
* **Revoked on account deletion.** `delete_telegram_account` and `DELETE /api/account` revoke every refresh-token family of the user in the delete transaction (`revoked_reason = account_deleted`); a failed revocation fails the delete. Disconnect does not revoke, by design: it ends the Telegram session but keeps the client's OAuth grant. Access tokens already issued live until their TTL, as for every revocation.
* **Worker tokens and Local Bridge devices are revoked on account deletion too.** The same transaction records a blanket worker-token revocation for every Telegram id the user's tokens can carry (`users.telegram_login_id`, the legacy `tg:<id>` login, and the session's `telegram_user_id`) and marks every Local Bridge device revoked (`account_deleted`). That covers worker tokens, device credentials and the bridge tokens derived from them, since all carry their original issue time; a revoked device cannot claim a new credential lineage. Rejection takes effect within the revocation cache's refresh interval (at most 15 seconds). A failed revocation fails the delete.

## Legacy mode: `AUTH_MODE=shared-hmac-legacy`

The legacy mode validates JWTs signed by an external authorization server using a shared `OAUTH_JWT_SECRET`.

* **Impact:** the services share secret material; compromise of either may allow minting tokens for both.
* **Mitigation:** rotate the shared secret for both services simultaneously. Use `AUTH_MODE=local-jwt` for new deployments.
* **Gate:** `AUTH_MODE=shared-hmac-legacy` refuses to start unless `AUTH_ALLOW_SHARED_HMAC_LEGACY=true`. The shorter `AUTH_MODE=shared-hmac` alias still boots so a known deployment is not cut off, but it is the same verifier and the same shared-secret risk.
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
3. `telegram_accounts.send_enabled = true` for that account (owner sets this via `set_send_consent` or `/telegram/connect/manage`).
4. Per-peer send rate limit not exhausted (20 per hour to one peer), checked after the first three.
5. No PEER_FLOOD write pause on the account. When Telegram answers any call from the account with `PEER_FLOOD` (its anti-spam verdict on the account), the call is not retried and writes that use the send budget are refused for one hour (`audit.PeerFloodHold`), for the background executor as well as MCP tools. The pause is held in memory per replica and does not survive a restart; deletes and other cleanup are not paused.

The account configured as the demo/reviewer account (`DEMO_REVIEWER_*`) is checked ahead of every other condition. Its writes are refused with an error, never a preview, except `send_message` and `send_reply` to a test chat listed in `DEMO_REVIEWER_WRITE_PEERS`, and those still need every condition above. The list fails closed: when it is empty or unset, the reviewer can deliver nothing. Every other write tool (`send_media`, `edit_message`, `delete_messages`, `forward_messages`, `set_reaction`, `pin_message`, and the account, operator and broadcast tools) stays refused for that account. A tool added without an explicit decision is refused too (`internal/mcp/reviewer.go`).

The tool exposes no trusted client-controlled bypass for these gates. Apart from the reviewer refusal above, which is an error, any condition false returns a dry-run result (`sent=false`) with a `dry_reason`; no send RPC reaches Telegram. Media dry-runs do not fetch a URL or decode base64 content.

## Authentication-required mode

* `AUTH_REQUIRED=false` is for local development only. A deployed pod MUST set `AUTH_REQUIRED=true` and a production auth mode.
* `local-dev` returns a fixed platform-admin identity and MUST NOT be reachable from a non-localhost production interface.
* This posture is enforced, not just documented: `cmd/server/bootguard.go`'s `checkBootGuard` runs at the start of `main()` and fatally exits before the database is opened or the listener is bound whenever `AUTH_MODE=local-dev`/`AUTH_REQUIRED=false` or a missing `ENCRYPTION_KEY` is paired with a non-loopback `ADDR` or a deployment tier not recognized as local development. The guard fails closed on `ENV`: it allowlists the known local tiers (`local`, `dev`, `development`, `test`, `ci`, …), so `prod`, `staging`, `production` or any other spelling is treated as a real deployment.
* **Known gap — `ENV` must be set on real deployments.** An *unset* `ENV` is allowlisted as local (it is the default in `internal/config` and what a bare `go run ./cmd/server` sees), and config alone cannot tell "a developer never set `ENV`" from "ops never wired `ENV`". A deployment that leaves `ENV` unset **and** binds `ADDR` to loopback (e.g. behind an in-pod reverse proxy or sidecar) will therefore still boot with the local-dev auth bypass and/or unencrypted session storage — the loopback bind is the only remaining control. Always set `ENV` in deployment manifests; the allowance is intentional and pinned by `TestCheckBootGuardUnsetEnvOnLoopbackIsIntentionallyAllowed` in `cmd/server/bootguard_test.go`.

## Rate limiting

The default per-identity token bucket is 30 requests/minute with the same burst; it applies to authenticated requests. Write paths also apply per-recipient limits, per Telegram account (shared by every connector and worker token of that account): 20 sends, forwards, edits, reactions or pins per hour to one recipient, and a separate 60 per hour for cleanup (deleting messages, removing a reaction, unpinning). The recipient key folds the spellings of one target (`@Alice` and `alice`, `user:42` and `42`) but does not resolve a username to its numeric id, so those two remain separate budgets. The buckets are in process memory and reset when the pod restarts; they are an anti-flooding guard, not a durable quota.

Unauthenticated endpoints are limited per source IP only where the service does it itself: `POST /oauth/register` (`OAUTH_REGISTER_RATE_PER_MIN`, default 10/minute), the demo-reviewer sign-in, and Local Bridge activation. `/oauth/authorize`, `/oauth/token`, health, readiness, public pages and well-known documents have no per-IP limit, in the service or in the deployment's ingress configuration.