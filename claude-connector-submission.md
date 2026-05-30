# Claude Connector Directory — Submission Packet

Source-of-truth for the Anthropic remote-MCP directory submission form
(<https://clau.de/mcp-directory-submission>). This file is checked into the repo so the form
answers are version-controlled. **Secrets (the reviewer password) are NOT stored here** — supply
them directly in the form or via `mcp-review@anthropic.com`.

References:
- Submission requirements: <https://claude.com/docs/connectors/building/submission>
- Pre-submission checklist: <https://claude.com/docs/connectors/building/review-criteria>
- Testing notes: <https://claude.com/docs/connectors/building/testing>

## Server metadata
| Field | Value |
|---|---|
| Name | mctl-telegram |
| Server URL | `https://tg.mctl.ai/mcp` |
| Tagline | Manage your own Telegram account from Claude |
| Categories | Productivity / Communication |
| Transport | Streamable HTTP |
| Auth | OAuth 2.1 — PKCE (S256) + Dynamic Client Registration (RFC 7591) |
| Resources | none |
| Prompts | none |
| Allowed link URIs | none (no `ui/open-link` used) |
| Logo | `https://tg.mctl.ai/favicon.svg` (SVG; favicon also at `/favicon.ico`) |
| Privacy policy | `https://tg.mctl.ai/privacy` |
| Terms of service | `https://tg.mctl.ai/terms` |
| Public documentation | `https://tg.mctl.ai/docs` |
| GA date | _TBD — set by submitter_ |

### Description
mctl-telegram lets a user access and manage **their own** Telegram account from Claude after
explicit OAuth authorization. It supports reading recent chats, summarizing messages, drafting
replies, **preview-only sending by default**, confirmed pin actions, audit review, and account
disconnect/delete controls. It is an **independent project — not an official Telegram app or
Telegram API partner**, and Telegram message content is treated as untrusted user-generated data.

Existing Telegram MCP tools are mostly local/self-hosted with broad surfaces. mctl-telegram is
intentionally narrower and safer for hosted review: 9 user-facing tools + 5 admin-only
operator controls (14 total), each tool is read XOR write, no contact management, no media
upload, no admin group operations. Write operations
require explicit confirmation steps; per-peer rate limits prevent AI-driven flooding; send is
disabled by default. Users can cryptographically verify their audit log via hash chain.

## Tools (14)
Each tool is read **XOR** write (no tool mixes safe + unsafe operations). Capability is by
`destructiveHint`. Every tool has a `title` and explicit `readOnlyHint`/`destructiveHint`/
`openWorldHint`.

| Tool | Capability | Purpose |
|---|---|---|
| `list_dialogs` | read | List the connected account's Telegram dialogs (optional query filter). |
| `get_unread_messages` | read | Return unread messages, optionally for one peer. |
| `get_messages` | read | Return recent message history for a specific peer. |
| `send_message` | write | Send a message. **Preview-only by default**: real send requires `ALLOW_SEND=true` + `telegram:messages:send` scope + per-account `send_enabled=true`; otherwise returns `sent=false` dry-run. |
| `prepare_pin_message` | read | Create a local one-shot confirmation id for a later `pin_message` (no Telegram mutation). |
| `pin_message` | write | Pin/unpin a message after a matching confirmation id. |
| `get_my_audit_log` | read | Return the authenticated user's own audit rows. |
| `disconnect_telegram_account` | write | Soft-revoke the caller's session and tear down the in-memory MTProto client. |
| `delete_telegram_account` | write | Hard-delete the encrypted session blob and per-account metadata. |
| `list_telegram_identities` | read (admin) | Admin: list signed-in identities and access state. |
| `set_telegram_access` | write (admin) | Admin: grant/revoke a user's local access tier. |
| `set_account_send` | write (admin) | Admin: enable/disable a user's real-send gate. |
| `get_user_audit_log` | read (admin) | Admin: read another user's audit rows. |
| `revoke_telegram_session` | write (admin) | Admin: revoke a user's active MTProto session. |

## Test account (for reviewers)
- **Auth path:** the OAuth `/authorize` page exposes a password-gated **reviewer login** that
  authenticates as a single pre-provisioned demo Telegram identity — **no phone/SMS/2FA needed**.
  Enabled via `DEMO_REVIEWER_*` server config during review.
- **Username + flow:** provided in the form. **Password:** supply in the form directly (never
  committed). The demo account has a pre-seeded MTProto session and `send_enabled=false`, so every
  `send_message` stays a dry-run preview.
- **Admin note:** the reviewer demo account holds `admin:users` (it is in the server `TG_LOGIN_ADMINS`
  allowlist), so the 5 admin tools are deliberately reviewable. They are operator/self-host
  administration controls, gated behind the `admin:users` scope — not general consumer surface.
- **Connect fresh:** establish a **new** connection via the reviewer login. The `admin:users` scope
  (and the 5 admin tools) is granted at connection time, so a freshly connected reviewer session has
  it; reusing a stale token issued before the account was made admin would not. A normal first-time
  reviewer connection gets it automatically.

## Security
- OAuth 2.1 with mandatory PKCE (S256) and RFC 7591 Dynamic Client Registration.
- `.well-known/oauth-protected-resource` and `.well-known/oauth-authorization-server` published.
- **Origin-header validation** on `/mcp` (DNS-rebinding protection): requests with no Origin pass
  (server-to-server clients send none); a present Origin must be on the `ALLOWED_ORIGINS` allowlist.
- Telegram session blobs encrypted at rest (AES-256-GCM); audit log redacts message text, phone
  numbers, session bytes, and secrets.
- **Two-step write confirmation:** `send_message` returns a dry-run preview before anything
  reaches Telegram; `pin_message` requires a `confirmation_id` from a prior `prepare_pin_message`.
- **Per-peer rate limiting:** 20 send/pin actions per peer per hour — prevents AI-driven flooding.
- **Tamper-evident audit chain:** SHA-256 hash chain on `audit_logs`; users can verify at
  `GET /api/account/audit/verify`.
- **Local Bridge mode (beta):** keeps MTProto session entirely on the user's device — no session
  bytes on the server for users who want a stronger trust model.
- Egress note: Anthropic's docs list outbound CIDR `160.79.104.0/21`; only relevant behind a
  firewall/conditional-access policy. The custom connector already connects successfully, so no
  egress change is required.

## Data handling

Full package: `reviewer-data-handling.md` —
https://github.com/mctlhq/mctl-telegram/blob/main/reviewer-data-handling.md

### Form field: Privacy / data handling
```
mctl-telegram stores only the minimum data required to operate the connector: Telegram identity
metadata (user ID, display name, username), an AES-256-GCM encrypted MTProto session blob,
session metadata, and audit metadata. Message bodies and media are fetched live from Telegram
only when the authenticated user invokes a tool and are not persisted in the database, logs,
audit logs, or files. Audit logs contain only tool name, redacted peer reference, status,
timestamp, and tamper-evidence hash-chain data. Users can revoke or delete their Telegram
account connection using MCP tools. The hosted service is not zero-knowledge: infrastructure
operators with privileged access to both the database and the master encryption key could
theoretically decrypt stored session blobs.

Additional reviewer data-handling package:
https://github.com/mctlhq/mctl-telegram/blob/main/reviewer-data-handling.md
```

### Form field: External services
```
The connector communicates with Telegram's MTProto API on behalf of the authenticated user.
No analytics, advertising, telemetry, or data broker services are used. Tool results are
returned to the MCP client selected by the user.
```

### Form field: Authentication
```
OAuth 2.1 with mandatory PKCE (S256) and RFC 7591 Dynamic Client Registration. Each MCP tool
derives caller identity from the validated OAuth JWT bearer token server-side. No tool accepts
a caller-supplied user ID parameter.
```

### Form field: Write actions
```
Read tools and write tools are separate. Read tools are annotated readOnlyHint=true. Tools that
modify Telegram state (send, pin, revoke, delete, admin actions) are annotated destructiveHint
or equivalent. Real message sending is additionally gated by: server-level ALLOW_SEND flag,
per-user send_enabled flag, and the telegram:messages:send scope. No tool argument bypasses
the send gate.
```

### Operator trust boundary (reviewer notes)
> The application does not persist message contents. Messages are fetched live from Telegram only
> when the authenticated user invokes a tool. Access is scoped to the authenticated user, and no
> tool permits cross-user message access.
>
> Telegram session secrets are encrypted at rest using AES-256-GCM with per-user derived keys.
> The master encryption key is stored in HashiCorp Vault and not committed to code or
> configuration. Infrastructure operators with privileged access to both the database and the
> encryption key could theoretically decrypt stored session blobs. This is the inherent trust
> boundary of any hosted service that handles user credentials on the user's behalf, and it is
> explicitly documented at https://tg.mctl.ai/security.

**OIDC scope:** login requests `openid profile` only. The `telegram:bot_access` scope (which
previously surfaced an "Allow messages" toggle) was removed in 0.41.0.

## Policy narrative — Telegram is a third party
This is a **user-authorized client to the user's own Telegram account** over Telegram's official
MTProto API (`api_id`/`api_hash` from my.telegram.org). It is **not a scraper, not a relay, and not
an unofficial pass-through**: it acts only on the single account the user explicitly connects, and
the user remains responsible for complying with Telegram's terms. Non-affiliation copy is live on
the public landing/demo/privacy pages.

## Pre-submission checklist

**Repository**
- [ ] `reviewer-data-handling.md` on `main` with accurate claims
- [ ] No public page uses "we cannot access messages" or "E2EE" in hosted-service context
- [ ] All form privacy fields use "not persisted" framing, not "cannot access"

**MCP endpoint**
- [ ] Server reachable over HTTPS from Claude custom connector
- [ ] OAuth callback for Claude registered and working
- [ ] Token endpoint supports `application/x-www-form-urlencoded`
- [ ] OAuth discovery docs (`.well-known/*`) public and not WAF-blocked

**Tool metadata**
- [ ] All 14 tools have a `title` field
- [ ] Read tools (`list_dialogs`, `get_unread_messages`, `get_messages`,
      `get_my_audit_log`, `list_telegram_identities`, `get_user_audit_log`): `readOnlyHint=true`
- [ ] Write/destructive tools: `destructiveHint=true` or equivalent
- [ ] `prepare_pin_message`: `readOnlyHint=false`, `destructiveHint=false` (creates a local
      confirmation record — a side effect, but not a Telegram mutation)
- [ ] No tool mixes read + write operations
- [ ] Tool descriptions are narrow, non-promotional, accurate
- [ ] Errors are actionable, not generic 500s

**Send gates**
- [ ] `ALLOW_SEND=false` default documented
- [ ] Per-user `send_enabled` gate documented
- [ ] `telegram:messages:send` scope requirement documented
- [ ] No tool argument bypasses send gate

**Test account**
- [ ] Realistic sample dialogs (no real personal data)
- [ ] Has unread messages for testing
- [ ] `send_enabled=false` so every `send_message` is dry-run preview
- [ ] `admin:users` scope so all 14 tools are reviewable
- [ ] Reviewer credentials provided in the form (not committed here)

**Submission**
- [ ] Exercise all 14 tools via MCP Inspector before submitting
- [ ] Re-test as a custom connector in Claude after OriginGuard release (0.41.0)
- [ ] Confirm privacy/terms/docs/logo URLs resolve over HTTPS
- [ ] Set the GA date
- [ ] Paste form field text from the "Form field:" sections above
