# Contributing to mctl-telegram

Thank you for considering a contribution. This document covers dev setup, code conventions, and the PR process.

## Development setup

Requirements:
- Go 1.26+
- Telegram API credentials for MTProto testing — register at <https://my.telegram.org/apps>
- Optional: `golangci-lint` for linting

Run the server locally:

```bash
ADDR=:8080 \
AUTH_MODE=local-dev AUTH_REQUIRED=false \
OPERATOR_GITHUB_LOGIN=your-github-handle \
DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
go run ./cmd/server
```

First-time Telegram login (after registering an app at my.telegram.org):

```bash
TG_API_ID=12345 TG_API_HASH=hexhexhex... \
DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
OPERATOR_GITHUB_LOGIN=your-github-handle \
go run ./cmd/login --phone +1...
```

Run checks before pushing:

```bash
go fmt ./...
go vet ./...
go test ./...
golangci-lint run   # optional but appreciated
```

## Code conventions

- `fmt.Errorf("context: %w", err)` for error wrapping — no panics
- Context propagation through all I/O
- Structured logging via `slog` — add new sensitive field names to `internal/audit/redact.go`
- No emoji in code or commit messages
- English for all code, comments, and documentation

## Security and privacy rules

- Do not commit Telegram session data, OAuth tokens, API credentials, or local SQLite databases
- Do not add logging of message bodies, phone numbers, session strings, or JWT secrets
- All Telegram data must be treated as private user data

If you find a security vulnerability, please report it privately — see [SECURITY.md](SECURITY.md).

## Pull request process

1. Open an issue first for large or breaking changes.
2. Keep PRs focused — one logical change per PR.
3. Include tests or explain why tests are not applicable.
4. Update README or inline docs when behavior changes.
5. Ensure `go vet ./...` and `go test ./...` pass.
6. Maintainers may use automated review tools before merging.

## Commit style

Use conventional commits:

- `feat:` new behavior
- `fix:` bug fix
- `docs:` documentation only
- `refactor:` internal restructuring, no behavior change
- `test:` test additions or fixes
- `chore:` build, deps, config
- `ci:` workflow changes
- `security:` security-relevant fixes

Subject line under 72 characters. Body explains the *why*, not the *what*.

## Versioning and tags

- Semantic versioning: `MAJOR.MINOR.PATCH`
- No `v` prefix on tags: `0.5.0`, not `v0.5.0`
- APIs and tool schemas may change before v1.0
