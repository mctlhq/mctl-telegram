# LLMS.md — mctl-telegram MCP Remote Server Overview

> `mctl-telegram` is a hosted Go MCP (Model Context Protocol) remote server exposing user-authorized Telegram account access (via `gotd/td` MTProto) for ChatGPT Apps, Claude.ai, and any MCP client.

## Core Capabilities & Submission Package

- **Hosted URL**: `https://tg.mctl.ai/mcp` (OAuth 2.1 PKCE + Dynamic Client Registration).
- **Submission Packages**:
  - `chatgpt-submission-package.md`: Reviewer notes, privacy attestations, and submission form inputs for ChatGPT App Directory.
  - `claude-connector-submission.md`: Metadata, tool annotations, and safety criteria for Anthropic Claude Remote MCP Directory.
- **Data Minimization & Encryption**: Message bodies are fetched live for user-requested tool calls, never persisted in DB/logs. MTProto session blobs are encrypted at rest with AES-256-GCM.

## Tool Surface (14 MCP Tools)

### User Tools (9)
- `list_dialogs`: List account dialogs with optional query filter.
- `get_unread_messages`: Retrieve unread messages per peer.
- `get_messages`: Retrieve recent message history.
- `send_message`: Send message (**Preview-only dry-run by default** unless `send_enabled=true`).
- `prepare_pin_message`: Generate one-shot confirmation ID for pin.
- `pin_message`: Pin/unpin message using confirmation ID.
- `get_my_audit_log`: Cryptographic tamper-evident hash-chain audit log for user actions.
- `disconnect_telegram_account`: Soft-revoke session and stop MTProto client.
- `delete_telegram_account`: Hard-delete per-user session blob.

### Admin Tools (5)
- Operator controls guarded by `admin:users` scope (`admin_list_users`, `admin_get_user`, `admin_set_user_send_enabled`, etc.).

## Package Architecture

- `cmd/server/`: Main server entrypoint serving `/mcp`, `/privacy`, `/terms`, `/docs`.
- `internal/mcp/`: MCP server implementation, 14 tool definitions, and schema annotations.
- `internal/telegram/`: `gotd/td` MTProto client lifecycle and session management.
- `internal/auth/`: OAuth 2.1 server, PKCE verification, and token handlers.
- `internal/crypto/`: Per-user AES-256-GCM session blob encryption.

## Testing Commands

```bash
go test ./... -v                 # Run full Go test suite
go test ./internal/mcp -v        # Test MCP tool handlers and dry-run guarantees
```
