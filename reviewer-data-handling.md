# Data Handling — Reviewer Package

Source-of-truth for privacy and data-handling statements submitted to the ChatGPT App Directory
and the Claude connector directory. Statements here are grounded in the shipped source and verified
against `internal/db/store.go`, `internal/crypto/aesgcm.go`, `internal/audit/redact.go`, and
the live `privacy.html` / `security.html` pages at `tg.mctl.ai/privacy` and `tg.mctl.ai/security`.

---

## A — What we store

| Location | Contents |
|---|---|
| `users` table | Telegram user ID (subject from sign-in), display name, username. No phone number, no email. |
| `telegram_accounts` table | AES-256-GCM ciphertext of the MTProto session blob + non-sensitive metadata: `connected_at`, `expires_at`, `last_used_at`, `revoked_at`. Plaintext session bytes are never written to disk. |
| `audit_logs` table | Tool name, redacted peer reference (handles and phone-like digits masked by `audit.ScrubText()`), status (`ok`/`error`), redacted error string if any, timestamp, SHA-256 hash chain for tamper detection. **No message content.** |
| Process memory (transient) | Plaintext MTProto session and message data for the duration of a single tool call. Freed when the goroutine returns; never written to any storage layer. |
| Structured logs (stdout → Loki) | JSON log lines from `slog`, with sensitive keys replaced by `[redacted len=N]` before the line reaches stdout (handled by `internal/audit/redact.go`). Retained per platform Loki policy (typically 14–30 days). |

---

## B — What we do not store

- **Message bodies** — text, media captions, media files. Messages are fetched live from Telegram only when the authenticated user invokes a tool. They are returned to the caller and not written to any database, log, or file.
- Phone numbers (seen during interactive login, never persisted).
- Telegram 2FA passwords or verification codes.
- Raw MTProto session bytes (only the AES-GCM ciphertext lives in Postgres).
- OAuth JWT secrets, encryption keys, or derived per-user subkeys.
- `Authorization: Bearer` header values.
- IP addresses (not persisted by this service; platform ingress may log at L4/L7).

---

## C — Session encryption

- **Algorithm:** AES-256-GCM with a per-user subkey derived via HKDF-SHA256.
  Derivation: `subkey = HKDF(master, salt=user_id_be64, info="mctl-telegram-session-v2", L=32)`.
  Each user has a cryptographically independent key; compromise of one session does not expose others.
- **Master key:** stored in HashiCorp Vault. Injected into the runtime via a Kubernetes ExternalSecret
  as an environment variable (`ENCRYPTION_KEY`). The key is not committed to source code or GitOps
  configuration.
- **Nonce:** random 12-byte GCM nonce, unique per write, stored with the ciphertext.
- Legacy v1 blobs (single global key) are migrated to per-user v2 in-place on first read.

---

## D — Access scoping

Every MCP tool extracts the caller's identity exclusively from the validated OAuth JWT bearer token
(`auth.From(ctx)`). No tool accepts a user ID as a caller-supplied parameter. Read tools
(`list_dialogs`, `get_unread_messages`, `get_messages`) query only the authenticated user's Telegram
session. Cross-user message access is not possible through the tool interface. All database queries
include a `WHERE user_id = <auth_identity>` clause enforced in the application layer.

---

## E — Admin access

Admin users (identified by the `admin:users` scope, granted to the `TG_LOGIN_ADMINS` allowlist set
at deployment time) **can**:

- View audit log metadata (tool name, redacted peer, status) for any user via `get_user_audit_log`.
- Revoke any user's active MTProto session via `revoke_telegram_session`.
- Grant or revoke a user's local access tier via `set_telegram_access`.
- Enable or disable real-send for a user's account via `set_account_send`.

Admin users **cannot**:

- Read message bodies — they are never stored anywhere.
- Decrypt session blobs without the master `ENCRYPTION_KEY` (a separate runtime credential).
- Access phone numbers or 2FA credentials — never stored.
- Access any MCP tool that is not explicitly gated by `admin:users` scope.

---

## F — Account deletion and revocation

| Action | What happens |
|---|---|
| `disconnect_telegram_account` (self-service) | Soft-delete: sets `revoked_at`, closes the in-memory MTProto client atomically. Row stays in DB but is permanently unusable. |
| `delete_telegram_account` (self-service) | Hard-delete: removes all rows in `users` and `telegram_accounts` for the caller. Encrypted session ciphertext is destroyed. |
| Audit log retention on delete | Audit rows survive hard-delete by design — they provide a tamper-evident record that the account existed and what tools were called. They contain no message content. |
| Idle TTL | Sessions auto-expire after 30 days of inactivity (`last_used_at` check). |
| Absolute TTL | Sessions expire 90 days after connect time (`expires_at`). |
| Audit log retention | 90 days, then removed by the sweeper (configurable via `AUDIT_RETENTION_DAYS`; set to 0 to keep indefinitely). |

HTTP equivalents: `POST /api/account/disconnect`, `DELETE /api/account`,
`GET /api/account/audit`, `GET /api/account/audit/verify`.

---

## G — Operator trust boundary (honest statement)

> The application does not persist message contents. Messages are fetched live from Telegram only
> when the authenticated user invokes a tool. Access is scoped to the authenticated user, and no
> tool permits cross-user message access.
>
> Telegram session secrets are encrypted at rest using AES-256-GCM with per-user derived keys.
> The master encryption key is stored in HashiCorp Vault and not committed to source code or
> GitOps configuration. Infrastructure operators with privileged access to both the database and
> the encryption key could theoretically decrypt stored session blobs. This is the inherent trust
> boundary of any hosted service that handles user credentials on the user's behalf, and it is
> explicitly documented at https://tg.mctl.ai/security.

---

## H — Third-party data sharing

- **Telegram (transport + identity):** requests are forwarded to Telegram's MTProto API using the
  authenticated user's own session, on the user's behalf. Telegram sees the same traffic any
  Telegram client would generate. Identity comes from a Telegram sign-in flow handled by this
  server directly.
- No analytics, advertising, or third-party tracking.
- No data sold or shared with other parties.
- No data sent to OpenAI, Anthropic, or other AI providers by this server.
- OAuth-flow pages serve inline CSS only under a strict Content-Security-Policy and contact no
  external hosts.

---

## I — OIDC login scope

- Scopes requested at login: `openid profile` only.
- The `telegram:bot_access` scope (which previously triggered an "Allow messages" toggle) was
  removed in version 0.41.0. Users grant only basic identity and profile access during the OIDC
  login step.

---

## J — Prompt-injection boundary

Read tools (`get_unread_messages`, `get_messages`) wrap every Telegram message body in:

```
<telegram-content origin="telegram" peer="<redacted>" untrusted="true">…</telegram-content>
```

Adversarial closing-tag literals inside a message body are escaped so a sender cannot break out of
the untrusted block. A top-level `notice` field repeats the same guidance in prose. This gives an
LLM a clear data-vs-instructions boundary.

---

## Reference pages

| Page | URL |
|---|---|
| Privacy policy | https://tg.mctl.ai/privacy |
| Security model | https://tg.mctl.ai/security |
| Terms of service | https://tg.mctl.ai/terms |
| Public docs | https://tg.mctl.ai/docs |
| Source code | https://github.com/mctlhq/mctl-telegram |
| Security contact | security@mctl.ai |
| Privacy contact | privacy@mctl.ai |
