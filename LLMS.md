# LLMS.md — mctl-telegram MCP Remote Server Overview

> `mctl-telegram` is a hosted Go MCP (Model Context Protocol) remote server exposing user-authorized Telegram account access (via `gotd/td` MTProto) for ChatGPT, Claude.ai, and any MCP client.

## Core Capabilities

- **Hosted URL**: `https://tg.mctl.ai/mcp` (OAuth 2.1 PKCE + Dynamic Client Registration). Connect from ChatGPT (Developer Mode custom connector; not an App Directory listing), Claude.ai, Cursor, or any MCP client.
- **Read-only by default**: a newly connected account has `send_enabled=false`; write tools return previews until the owner opts in with `set_send_consent`.
- **Data Minimization & Encryption**: Message bodies are fetched live for user-requested tool calls and are not persisted for ordinary MCP use (Communication Agent accounts store encrypted content, see `/privacy`). MTProto session blobs are encrypted at rest with AES-256-GCM under per-user HKDF keys.
- **Archived submission packets** (historical): `docs/archive/chatgpt-submission-package.md`, `docs/archive/claude-connector-submission.md`.

## Tool Surface (37 MCP tools)

The authoritative, generated list with schemas and annotations is `docs/tool-descriptors.json`.

### Read (10)
`list_dialogs`, `get_unread_messages`, `get_messages`, `search_messages`, `prepare_get_media`, `get_media`, `get_my_identity`, `get_my_audit_log` (tamper-evident hash-chain), `get_my_send_status`, `get_my_notification_preferences`.

### Write (9)
`prepare_send_message`, `send_message`, `send_media`, `edit_message`, `delete_messages`, `forward_messages`, `set_reaction`, `prepare_pin_message`, `pin_message`. Sends and pins are gated: server `ALLOW_SEND`, the `telegram:messages:send` scope, and per-account `send_enabled`; otherwise a preview (`sent=false`, `dry_reason`) is returned.

### Own account (5)
`set_send_consent`, `set_my_notification_preferences`, `revoke_local_bridge_device`, `disconnect_telegram_account`, `delete_telegram_account`. All require the `account:manage` scope, which worker and device credentials never carry.

### Admin, `admin:users` scope (9)
`list_telegram_identities`, `get_user_audit_log`, `set_telegram_access`, `set_account_send`, `set_account_mode`, `revoke_telegram_session`, `provision_local_account`, `mint_worker_token`, `revoke_worker_token`.

### Broadcast operators, `admin:broadcast` scope (4)
`prepare_broadcast`, `list_broadcasts`, `get_broadcast`, `cancel_broadcast`. No tool can approve a broadcast; a human approves in the browser.

## Package Architecture

- `cmd/server/`: Main server entrypoint serving `/mcp`, `/privacy`, `/terms`, `/docs`.
- `internal/mcp/`: MCP server implementation, tool definitions, and schema annotations (snapshot in `docs/tool-descriptors.json`).
- `internal/telegram/`: `gotd/td` MTProto client lifecycle and session management.
- `internal/auth/`: OAuth 2.1 server, PKCE verification, and token handlers.
- `internal/crypto/`: Per-user AES-256-GCM session blob encryption.

## Testing Commands

```bash
go test ./... -v                 # Run full Go test suite
go test ./internal/mcp -v        # Test MCP tool handlers and dry-run guarantees
```
