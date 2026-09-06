# mctl-telegram

Go MCP server for Telegram user-account access (MTProto via `gotd/td`).

This file is a helper for Claude Code and other AI coding agents. Canonical contributor instructions for humans are in [CONTRIBUTING.md](../CONTRIBUTING.md).

## Stack
- Go 1.26, `net/http` + `chi` router, `gotd/td` MTProto client, `mark3labs/mcp-go`
- Structured logging with `slog` (JSON handler + redaction handler)
- Multi-stage Docker (`golang:1.26.6-alpine` → `alpine:3.20`), non-root user 1000
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
- Test fixtures must use synthetic Telegram identifiers — never a real account's
  numeric id, first name or @handle, including your own. This repository is public,
  and a fixture is committed forever. Reuse one of the personas already in the
  tests — `Alice`, `Bob`, `Carol`, `Dana` — rather than inventing another, and
  before picking a numeric id run `git grep <id>` to see what it already means.
  An id may carry different labels in different places and often does: in
  `internal/db` the same id is the exempt-account subject and is labelled
  `Exempt` or `Op` by the test that uses it, while in `internal/oauth` the same
  id is `Dana`/`dana_tg` almost everywhere and `Admin` at a single site. Those
  role labels are not personas, and reusing an id for a role is
  fine — the stores are independent and nothing couples them. What must never
  recur is the thing this rule exists for: a real person's name, handle or
  numeric id in a fixture. `.github/CODEOWNERS` is the one deliberate
  exception, because the login there is review routing rather than test data.

## Workflow
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`
- Tag format: `MAJOR.MINOR.PATCH` (no `v` prefix)
- Tag creation triggers release-please workflow → dispatches centralized `mctl-gitops/.github/workflows/release-deploy.yaml`
- **Merge strategy: squash merges** (`gh pr merge <N> --squash --delete-branch`) — one clean
  conventional commit per PR on `main`. This keeps the graph linear and gives release-please a
  single changelog line per PR instead of a duplicated wall of text. The repo's squash format is
  configured to `PR_TITLE` + blank body, so the PR title MUST be a conventional-commit subject
  (e.g. `fix(telegram): ...`). Branch-protection "require up to date" no longer forces noisy
  `Merge branch 'main' into ...` bubbles, because squash discards branch history on merge.
  - This repo only (switched 2026-05-30). Other mctlhq repos still use merge commits until/unless
    the convention is rolled out org-wide.
