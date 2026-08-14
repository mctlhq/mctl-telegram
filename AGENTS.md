# mctl-telegram

Go MCP server for Telegram user-account access (MTProto via `gotd/td`).

This file is a helper for Codex and other AI coding agents. Canonical contributor instructions for humans are in [CONTRIBUTING.md](CONTRIBUTING.md).

## Stack
- Go 1.26, `net/http` + `chi` router, `gotd/td` MTProto client, `mark3labs/mcp-go`
- Structured logging with `slog` (JSON handler + redaction handler)
- Multi-stage Docker (`golang:1.26.6-alpine` → `alpine:3.20`), non-root user 1000
- SQLite (local dev) or Postgres (production)

## Key paths
- `cmd/server/main.go` — HTTP + MCP entrypoint
- `cmd/login/main.go` — interactive Telegram login CLI (phone → SMS → 2FA)
- `cmd/local/` — Local Bridge daemon CLI (M4)
- `internal/auth/` — pluggable `auth.Provider` (local-jwt default prod OAuth, shared-hmac-legacy, local-dev; Telegram OIDC under `telegramoidc`)
- `internal/telegram/` — `gotd/td` client pool, session store, message/peer handling
- `internal/mcp/` — MCP tool wiring and message formatting
- `internal/web/` — landing, security, privacy pages
- `internal/db/` — schema, migrations, audit chain
- `internal/bridge/` — Local Bridge websocket relay (M4)
- `internal/crypto/` — AES-256-GCM session encryption, HKDF key derivation
- `Dockerfile` — multi-stage build
- `Dockerfile.agent-worker` — dedicated runtime image for `cmd/agent-worker`
  (Node.js + pinned Claude Code CLI), separate from the main Go-only image
- `docs/plans/communication-agent.md` — canonical Communication Agent plan
  (status, architecture, rollout gates, Channels preview); the single source
  of truth for both Claude and Codex, supersedes any local `~/.claude/plans/*`
  draft

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
- Release flow: pushes to `main` run `release-please`, which maintains a release PR; merging that release PR creates the tag + GitHub release and dispatches the centralized `mctl-gitops/.github/workflows/release-deploy.yaml`. Do **not** create or push tags by hand (see `RELEASE.md`).
- **Merge strategy: squash merges** (`gh pr merge <N> --squash --delete-branch`) — one clean
  conventional commit per PR on `main`, for a linear graph and a single changelog line per PR. The
  repo's squash format is `PR_TITLE` + blank body, so the PR title MUST be a conventional-commit
  subject (e.g. `fix(telegram): ...`). This repo only (switched 2026-05-30); other mctlhq repos
  still use merge commits unless rolled out org-wide.
