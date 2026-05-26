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
- **Admin note:** the reviewer demo account intentionally holds `admin:users`, so the 5 admin tools
  are deliberately reviewable. They are operator/self-host administration controls, gated behind
  the `admin:users` scope — not general consumer surface.

## Security
- OAuth 2.1 with mandatory PKCE (S256) and RFC 7591 Dynamic Client Registration.
- `.well-known/oauth-protected-resource` and `.well-known/oauth-authorization-server` published.
- **Origin-header validation** on `/mcp` (DNS-rebinding protection): requests with no Origin pass
  (server-to-server clients send none); a present Origin must be on the `ALLOWED_ORIGINS` allowlist.
- Telegram session blobs encrypted at rest (AES-256-GCM); audit log redacts message text, phone
  numbers, session bytes, and secrets.
- Egress note: Anthropic's docs list outbound CIDR `160.79.104.0/21`; only relevant behind a
  firewall/conditional-access policy. The custom connector already connects successfully, so no
  egress change is required.

## Policy narrative — Telegram is a third party
This is a **user-authorized client to the user's own Telegram account** over Telegram's official
MTProto API (`api_id`/`api_hash` from my.telegram.org). It is **not a scraper, not a relay, and not
an unofficial pass-through**: it acts only on the single account the user explicitly connects, and
the user remains responsible for complying with Telegram's terms. Non-affiliation copy is live on
the public landing/demo/privacy pages.

## Pre-submission checklist
- [ ] Exercise all 14 tools via MCP Inspector.
- [ ] Re-test as a custom connector in Claude after the OriginGuard release (confirm no regression).
- [ ] Provide populated reviewer test-account credentials in the form.
- [ ] Confirm privacy/terms/docs/logo URLs resolve over HTTPS.
- [ ] Set the GA date.
