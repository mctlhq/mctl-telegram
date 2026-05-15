# mctl-telegram

Go MCP server for Telegram user-account access (MTProto via `gotd/td`).

This file is a helper for Claude Code and other AI coding agents. Canonical contributor instructions for humans are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Stack
- Go 1.25, `net/http` + `chi` router, `gotd/td` MTProto client, `mark3labs/mcp-go`
- Structured logging with `slog` (JSON handler + redaction handler)
- Multi-stage Docker (`golang:1.25-alpine` → `alpine:3.20`), non-root user 1000
- SQLite (local dev) or Postgres (production)

## Key paths
- `cmd/server/main.go` — HTTP + MCP entrypoint
- `cmd/login/main.go` — interactive Telegram login CLI (phone → SMS → 2FA)
- `cmd/local/` — Local Bridge daemon CLI (M4)
- `internal/auth/` — pluggable `auth.Provider` (shared-hmac + local-dev)
- `internal/telegram/` — `gotd/td` client pool, session store, message/peer handling
- `internal/mcp/` — MCP tool wiring and message formatting
- `internal/web/` — landing, security, privacy pages
- `internal/db/` — schema, migrations, audit chain
- `internal/bridge/` — Local Bridge websocket relay (M4)
- `internal/crypto/` — AES-256-GCM session encryption, HKDF key derivation
- `Dockerfile` — multi-stage build

## Conventions
- `go fmt`, `go vet`, `golangci-lint` before commit
- Error wrapping with `fmt.Errorf("context: %w", err)`, no panics
- Context propagation through all I/O
- No emoji in code or commits
- English for all code, comments, docs

## Safety rules
- Do not commit Telegram session data, OAuth tokens, API credentials (`TG_API_ID`/`TG_API_HASH`), or local SQLite databases.
- Do not add logging of message bodies, phone numbers, Telegram session strings, or JWT secrets — the `internal/audit/redact.go` slog handler enforces this; new sensitive field names must be added there.
- Treat all Telegram data as private user data.

## Workflow
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`
- Tag format: `MAJOR.MINOR.PATCH` (no `v` prefix)
- Tag creation triggers release-please workflow → dispatches centralized `mctl-gitops/.github/workflows/release-deploy.yaml`
- **Merge strategy: squash merge only** (no merge commits, no rebase) — keeps main history linear; individual PR commits are preserved on the PR page
