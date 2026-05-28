# ChatGPT App Directory — Submission Package

Source-of-truth for form fields and reviewer notes for the ChatGPT App Directory submission.
**Secrets (reviewer password) are NOT stored here** — supply them directly in the form.

---

## Reviewer note

Include this in the submission's reviewer comments or notes field:

```
mctl-telegram is a hosted MCP connector for a user's own Telegram account. It authenticates
users via OAuth and uses the authenticated user's Telegram MTProto session to perform
user-requested actions. It is an independent project — not an official Telegram app or
Telegram API partner.

The connector is designed for data minimization. Telegram message bodies are fetched live only
when the authenticated user invokes a tool. Message bodies may be returned to ChatGPT as tool
results for the requested action, but they are not persisted by mctl-telegram in the database,
logs, audit logs, or files.

Stored data is limited to Telegram identity metadata (user ID, display name, username),
encrypted MTProto session data, session metadata, and audit metadata. Audit logs contain only
tool name, redacted peer reference, status, timestamp, and tamper-evidence hash-chain data.

Telegram sessions are encrypted at rest using AES-256-GCM with per-user derived keys. The
hosted service is not zero-knowledge: infrastructure operators with privileged access to both
the database and the master encryption key could theoretically decrypt stored session blobs.
This trust boundary is documented explicitly at https://tg.mctl.ai/security.

Read tools and write tools are separated. Write operations require explicit confirmation
steps: send_message returns a dry-run preview (sent=false, dry_reason field) before anything
reaches Telegram; pin_message requires a matching confirmation_id from a prior
prepare_pin_message call. Real sending is further gated by server configuration, per-user
send_enabled flag, and the telegram:messages:send scope. Per-peer rate limits (20 actions/
peer/hour) prevent AI-driven message flooding. The test account has send_enabled=false, so
every send_message invocation during review is a dry-run preview.

Users who require a stronger trust model can use Local Bridge mode (beta), which keeps the
MTProto session entirely on the user's own device — no session bytes stored on the server.

Existing Telegram MCP tools are mostly local/self-hosted with broad surfaces (80+ tools,
contact management, media upload, admin group operations). mctl-telegram is intentionally
narrower: 9 user-facing tools + 5 admin-only operator controls (14 total), no contact management, no media upload, no admin group
operations, each tool is read XOR write. Users can cryptographically verify their audit log
has not been tampered with (GET /api/account/audit/verify).

Additional reviewer data-handling package:
https://github.com/mctlhq/mctl-telegram/blob/main/reviewer-data-handling.md
```

---

## Form field: Privacy / data handling

```
mctl-telegram stores only the minimum data required to operate the connector: Telegram identity
metadata, encrypted Telegram session data, session metadata, and audit metadata. Message bodies
and media are not persisted. Messages are fetched live from Telegram only when the authenticated
user invokes a tool and are returned to ChatGPT only as needed to complete the user-requested
action. Audit logs contain no message content.

The hosted service is not zero-knowledge: infrastructure operators with privileged access to
both the database and the master encryption key could theoretically decrypt stored session
blobs. This trust boundary is documented at https://tg.mctl.ai/security.
```

## Form field: Data recipients / third parties

```
mctl-telegram communicates with Telegram's MTProto API on behalf of the authenticated user.
The server does not use analytics, advertising, telemetry, or data broker services. Tool results
are returned to the ChatGPT client selected by the user. mctl-telegram does not send stored data
to OpenAI outside the user-initiated MCP tool call flow.
```

## Form field: User controls / data deletion

```
Users can disconnect their Telegram account using disconnect_telegram_account (soft-revokes the
stored session, closes the in-memory MTProto client). Users can delete their Telegram account
connection using delete_telegram_account (removes user and session rows). Audit metadata may be
retained for 90 days as a tamper-evident operational record and contains no message bodies.
HTTP equivalents: POST /api/account/disconnect, DELETE /api/account.
```

## Form field: Write actions / mutations

```
Tools that modify Telegram state are separated from read-only tools and marked as write or
destructive actions. Real message sending is disabled unless all required gates are enabled:
server-level send permission (ALLOW_SEND), per-user send_enabled flag, and the
telegram:messages:send scope. No tool argument bypasses the send gate. The review test account
has send_enabled=false, so every send_message call during review returns a dry-run preview with
sent=false and a dry_reason field.
```

---

## Pre-submission checklist

**Repository**
- [ ] `reviewer-data-handling.md` on `main` with accurate claims
- [ ] `chatgpt-app-submission.json` tool annotations correct (`readOnlyHint`, `destructiveHint`)
- [ ] No public page uses "we cannot access messages" or "E2EE" in hosted-service context

**MCP endpoint**
- [ ] Server reachable over HTTPS
- [ ] OAuth discovery documents resolve (`/.well-known/oauth-authorization-server`,
      `/.well-known/oauth-protected-resource`)
- [ ] OAuth callback for ChatGPT Dev Mode registered and working
- [ ] Token endpoint supports `application/x-www-form-urlencoded`
- [ ] `ALLOWED_ORIGINS` includes `https://chatgpt.com`, `https://chat.openai.com` in prod
      (release-gated: requires 0.41.0 + OriginGuard prod deploy)

**Tool metadata**
- [ ] All 14 tools have a `title` field
- [ ] Read tools: `readOnlyHint=true`
- [ ] Write/destructive tools: `destructiveHint=true`
- [ ] No tool mixes read + write operations
- [ ] `send_message` description mentions preview-only default
- [ ] All test cases in `chatgpt-app-submission.json` are verified against current runtime

**Test account**
- [ ] Realistic sample dialogs (no real personal data)
- [ ] Has unread messages for testing
- [ ] `send_enabled=false` (every `send_message` is dry-run preview)
- [ ] `admin:users` scope so all 14 tools are reviewable
- [ ] Reviewer credentials provided in the form (not committed)
- [ ] Reviewer prompt examples and expected outputs are current

**Submission**
- [ ] Exercise all 14 tools in ChatGPT Dev Mode before submitting
- [ ] Confirm privacy/terms/docs URLs resolve over HTTPS
- [ ] Set the GA date
- [ ] Paste reviewer note from above into the notes field
- [ ] Paste form field text from above into the corresponding form fields

---

## Key URLs

| Resource | URL |
|---|---|
| MCP endpoint | `https://tg.mctl.ai/mcp` |
| Privacy policy | `https://tg.mctl.ai/privacy` |
| Security model | `https://tg.mctl.ai/security` |
| Terms of service | `https://tg.mctl.ai/terms` |
| Public docs | `https://tg.mctl.ai/docs` |
| Reviewer data-handling package | `https://github.com/mctlhq/mctl-telegram/blob/main/reviewer-data-handling.md` |
| Support | support@mctl.ai |
