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
| `prepare_pin_message` | prep (`readOnlyHint=false`, `destructiveHint=false`) | Create a local one-shot confirmation id for a later `pin_message`. No Telegram mutation, but it writes a local confirmation record, so it is not annotated read-only. |
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
  committed). The demo account has a pre-seeded, populated MTProto session and `send_enabled=false`,
  so every `send_message` stays a dry-run preview.
- **Step-by-step setup (unfamiliar reviewer):**
  1. In Claude → Settings → Connectors, **Add custom connector** with URL `https://tg.mctl.ai/mcp`.
  2. Complete the OAuth flow.
  3. On the `/authorize` page choose **reviewer login** and enter the provided username/password.
  4. Confirm you are connected as the demo identity **@mctlhq** (`8745115872`).
  5. Run the recommended user-tool flow (list chats → read/summarize → draft → send → pin → audit).
  6. Sends are **dry-run/preview-only** for this account (nothing is delivered).
- **Permission boundary (expected behavior):** the reviewer demo account is a **normal client-tier
  user**, NOT an admin. The **9 user-facing tools work**; the **5 admin tools** (`list_telegram_identities`,
  `set_telegram_access`, `set_account_send`, `get_user_audit_log`, `revoke_telegram_session`) are
  gated behind the `admin:users` scope and will return a **clean "authorization denied / missing scope
  admin:users"** response for the reviewer — **that is the correct, expected behavior**, demonstrating
  the scope boundary. Their successful behavior is operator/self-host administration, verifiable with
  operator credentials on request.

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

### Server-side data access — explicit disclosure (remote mode)
> **This is a remote, hosted MCP server. It stores the user's encrypted Telegram MTProto session
> server-side, and the backend can technically access the Telegram chats and messages available to
> the authorized account when fulfilling a user-requested tool call.** We do not claim the service
> "cannot access your messages" in remote mode. Message *contents* are not persisted — they are
> fetched live from Telegram only during a tool call and returned to the user's MCP client — but the
> capability to read them exists by construction.
>
> **Mitigations:** access is user-scoped (no tool permits cross-user access); sessions are encrypted
> at rest (AES-256-GCM, per-user derived keys, master key in HashiCorp Vault, not in code/config); a
> tamper-evident hash-chained audit log records every tool call; users can revoke/delete at any time;
> and the data is **never used for training, never sold, and never accessed outside the user's own
> requests**. Infrastructure operators with privileged access to both the DB and the Vault key could
> theoretically decrypt session blobs — the inherent trust boundary of any hosted credential service,
> documented at https://tg.mctl.ai/security. (A future **Local Bridge** keeps the session on the
> user's own device — that is the only mode where the server cannot access messages.)

**OIDC scope:** login requests `openid profile` only. The `telegram:bot_access` scope (which
previously surfaced an "Allow messages" toggle) was removed in 0.41.0.

## Policy narrative — API ownership / Telegram is a third party
This is a **user-authorized client to the user's own Telegram account** over Telegram's official
MTProto API. Explicitly:
- mctl-telegram is a **user-authorized client for the user's own Telegram account** — not a scraper,
  relay, or unofficial pass-through; it acts only on the single account the user explicitly connects.
- It uses **Telegram's official MTProto client API** with `api_id`/`api_hash` from my.telegram.org.
- It does **not** claim to be Telegram or an official Telegram app/partner (non-affiliation copy is
  live on the public landing/demo/privacy pages).
- The **service domain is `tg.mctl.ai`**, and **all OAuth + MCP endpoints** (`/mcp`, `/authorize`,
  `/token`, `/register`, `/.well-known/*`) are served under that domain we own.
- **Data access is user-scoped and requires explicit user authorization** (OAuth 2.1); the user
  remains responsible for complying with Telegram's terms.
- **Third-party connection:** Telegram / MTProto.

## Compliance attestations (for the Data & Compliance form fields)
- **Health data:** No. Does not request, process, or intentionally access health data.
- **Prohibited use cases:** Does **not** transfer money, cryptocurrency, or financial assets; does
  **not** generate images, video, or audio via AI models.
- **Claude-side data:** Does **not** access Claude memory, chat history, conversation summaries, or
  user files.
- **Allowed link URIs:** Does **not** use `ui/open-link`; **allowed link URIs: none**. No third-party
  (Telegram) domains are listed.
- **MCP Apps assets:** Remote MCP server with **no** `ui/open-link` / interactive UI components /
  MCP-App widgets → MCP-App carousel screenshots are **not applicable**.

## Architecture decision — Remote now, MCPB (local) later
This directory submission is the **Remote MCP connector** (custom-connector over Streamable HTTP),
chosen for **Claude web + mobile + hosted** support. Remote means the encrypted Telegram session is
stored server-side (disclosed above). A **privacy-first Local Bridge / MCPB Desktop variant** — where
the Telegram session stays **on the user's device** — is tracked **separately** and would submit via
the MCPB path with its own README `privacy_policies` + open-source requirements. Not part of this
submission.

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

**Test account (fully populated)**
- [ ] Several dialogs incl. ≥1 private chat and ≥1 group/supergroup/channel (no real personal data)
- [ ] Has **unread** messages for testing; enough history to exercise list/get/summarize flows
- [ ] `send_enabled=false` so every `send_message` is dry-run preview
- [ ] Reviewer account is **non-admin (client tier)** — 9 user tools work; the 5 admin tools return a
      clean scope-denied (`admin:users`) = expected boundary; admin-tool success shown with operator creds
- [ ] Reviewer credentials provided in the form (not committed here)

**Submission**
- [ ] Re-test as a custom connector in Claude after OriginGuard release (0.41.0)
- [ ] Confirm privacy/terms/docs/logo URLs resolve over HTTPS
- [ ] Set the GA date
- [ ] Paste form field text from the "Form field:" sections above

### Manual gate: live Developer Mode / connector verification

This is the only non-automated submission gate.

Before submitting to the Claude Connector Directory, run all documented test cases against the live
connector using the provided reviewer credentials — as a custom connector in Claude (or via MCP
Inspector / ChatGPT Developer Mode).

Reason: without a real OAuth login and real tool calls, we cannot fully verify that:
- the submitted examples match the currently deployed runtime;
- the reviewer demo account receives the expected (client-tier) scopes;
- the 9 user-facing tools are callable and the 5 admin tools return a clean scope-denied for the
  reviewer (the expected permission boundary);
- dry-run/preview-only send behavior is shown correctly;
- error messages are actionable (no raw 500 / opaque Telegram errors).

Do not submit until this manual pass is completed and recorded.

(Everything else — endpoint, `.well-known` discovery, OriginGuard, artifact↔runtime annotation
parity, deploy state — is already verified by code/CI/curl/logs. Re-run this gate after any redeploy
that could change tool behavior or the demo account.)
