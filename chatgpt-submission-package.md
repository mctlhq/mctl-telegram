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

Please establish a fresh connection via the provided reviewer login. The submitted test cases use
only repeatable, reviewer-safe user workflows that the normal client-tier demo account can run on
ChatGPT web and mobile. Admin tools are operator/self-host controls guarded by the `admin:users`
scope; they are documented as capabilities but intentionally not part of the submitted pass/fail
test matrix. Account disconnect/delete and pin/unpin are also excluded from the submitted test
matrix because they are stateful/destructive and can make repeated reviewer runs non-reproducible.

Compliance attestations: Health data — No (not requested/processed/accessed). Does not transfer
money, cryptocurrency, or financial assets; does not generate images, video, or audio via AI models.
Does not access ChatGPT/Claude memory, chat history, conversation summaries, or user files. Does not
use ui/open-link; allowed link URIs: none (no third-party domains). No interactive UI components, so
app-carousel screenshots are not applicable.

Server-side data access (remote mode): this hosted server stores the user's encrypted Telegram
MTProto session server-side and can technically access the authorized account's chats/messages when
fulfilling a user-requested tool call. Message contents are not persisted; data is never used for
training, never sold, and never accessed outside the user's own requests; access is user-scoped,
encrypted at rest, audit-logged, and user-revocable. We do not claim the service "cannot access
messages" in remote mode.

Users who require a stronger trust model can use Local Bridge mode (beta), which keeps the
MTProto session entirely on the user's own device — no session bytes stored on the server.

Existing Telegram MCP tools are mostly local/self-hosted with broad surfaces (80+ tools,
contact management, media upload, admin group operations). mctl-telegram is intentionally
narrower: 9 user-facing tools + 5 admin-only operator controls (14 total), no contact management,
no media upload, no admin group operations, each tool is read XOR write. Users can
cryptographically verify their audit log has not been tampered with
(GET /api/account/audit/verify).

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
- [ ] Submitted test cases cover only repeatable reviewer-safe user flows
- [ ] Admin/destructive/stateful tools are documented but not submitted as reviewer pass/fail cases

**Test account (fully populated)**
- [ ] Several dialogs incl. ≥1 private chat and ≥1 group/supergroup/channel (no real personal data)
- [ ] Has **unread** messages + enough history for list/get/summarize flows
- [ ] `send_enabled=false` (every `send_message` is dry-run preview)
- [ ] Reviewer account is **non-admin (client tier)** and can run every submitted positive case
- [ ] Reviewer credentials provided in the form (not committed)
- [ ] Reviewer prompt examples and expected outputs are current

**Submission**
- [ ] Confirm privacy/terms/docs URLs resolve over HTTPS
- [ ] Set the GA date
- [ ] Paste reviewer note from above into the notes field
- [ ] Paste form field text from above into the corresponding form fields

### Manual gate: ChatGPT Developer Mode verification

This is the only non-automated submission gate.

Before submitting to the ChatGPT App Directory, run all documented test cases in ChatGPT Developer
Mode using the provided reviewer credentials.

Reason: without a real OAuth login and real tool calls through ChatGPT, we cannot fully verify that:
- the submitted examples match the currently deployed runtime;
- the reviewer demo account receives the expected (client-tier) scopes;
- every submitted positive case is callable with the non-admin reviewer account;
- dry-run/preview-only send behavior is shown correctly;
- error messages are actionable (no raw 500 / opaque Telegram errors).

Run the full submitted matrix twice: once on ChatGPT web and once on ChatGPT mobile. Record, for
each case: platform, prompt, actual tools called, final visible response, pass/fail status, and any
mismatch. Do not submit until both passes are completed and recorded.

Current web check, 2026-06-04:
- PASS: `list_dialogs` for recent chats/unread counts.
- PASS: `get_unread_messages` for unread Telegram messages.
- PASS: `list_dialogs` + `get_messages` for reading recent messages from an available chat.
- PASS: email boundary prompt. No mctl-telegram tool call; response says email is unsupported.
- PASS: calendar boundary prompt. No mctl-telegram tool call; response says calendar scheduling is
  unsupported.
- PASS: Telegram login-code boundary prompt. No mctl-telegram tool call; response refuses to use or
  process the one-time code and directs the user to the secure login flow.
- PASS: Telegram voice-call boundary prompt. No mctl-telegram tool call; response says voice calls
  are unsupported.
- PASS: WhatsApp boundary prompt. No mctl-telegram tool call; response says WhatsApp is unsupported.
- Removed from submitted matrix: dry-run `send_message` prompt. ChatGPT web chose to draft without
  calling `send_message`, so the submitted expected tool sequence was not reproducible.
- Removed from submitted matrix: `get_my_audit_log`. The tool redacts peers and message bodies, but
  the current reviewer account audit history includes stale destructive/admin test tool names and an
  old `@example_support` error, which can confuse pass/fail review.
- Reworded negative prompts as explicit mctl-telegram capability-boundary questions so ChatGPT does
  not route them to unrelated connectors such as Gmail or Calendar.

Current web check, 2026-06-05:
- FAIL before code fix: `get_unread_messages` returned a Telegram service message containing a
  login code and login IP metadata. This should not be submitted as-is.
- Fix prepared locally: hosted MCP and local bridge read outputs now redact Telegram login,
  verification, confirmation, security, one-time, 2FA/two-factor codes and `IP:` values before
  wrapping message text as untrusted Telegram content.
- Required before resubmit: release/deploy the redaction fix, reconnect or refresh the reviewer
  ChatGPT app session if needed, then rerun the full web and mobile matrix. The demo/video should be
  recorded only after the deployed runtime shows `[redacted]` instead of raw login secrets.

(Everything else — endpoint, OAuth discovery, OriginGuard, artifact↔runtime annotation parity,
deploy state — is already verified by code/CI/curl/logs. Re-run this gate after any redeploy that
could change tool behavior or the demo account.)

### Submitted test-case policy

The submitted `chatgpt-app-submission.json` test cases deliberately avoid:
- hardcoded Telegram peers or message ids such as `@example_support`, `message 42`, or raw numeric
  Telegram ids;
- admin/operator-only success cases;
- `disconnect_telegram_account` and `delete_telegram_account`, because they break the reviewer
  session for later runs;
- `prepare_pin_message` and `pin_message`, because they are stateful and depend on live chat admin
  rights;
- `send_message` dry-run examples, because ChatGPT may satisfy "draft" wording without invoking the
  send tool;
- `get_my_audit_log`, because audit output depends on previous reviewer-account activity and is
  therefore not a stable pass/fail example.

Admin and destructive tools remain in the runtime tool descriptors because they are real
capabilities, but they are not part of the OpenAI reviewer pass/fail test matrix.

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
