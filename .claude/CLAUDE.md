# mctl-telegram

Go MCP server for Telegram user-account access (MTProto via gotd/td).

## Stack
- Go 1.25, net/http + chi router (planned), `gotd/td` (planned), `mark3labs/mcp-go` (planned)
- Structured logging with `slog` (JSON handler)
- Multi-stage Docker (golang:1.25-alpine -> alpine:3.20), non-root user 1000

## Conventions
- `go fmt`, `go vet`, `golangci-lint` before commit
- Error wrapping with `fmt.Errorf("context: %w", err)`, no panics
- Context propagation through all I/O
- No emoji in code/commits unless explicitly requested
- English for all code, comments, docs

## Key Paths
- `cmd/server/main.go` — HTTP + MCP entrypoint
- `internal/auth/` — pluggable auth.Provider (planned)
- `internal/telegram/` — gotd/td client pool (planned)
- `internal/mcp/` — MCP tool wiring (planned)
- `Dockerfile` — multi-stage build

## Workflow
- Conventional commits: `feat:`, `fix:`, `chore:`, `docs:`, `refactor:`, `test:`, `ci:`
- Tag format: `MAJOR.MINOR.PATCH` (no `v` prefix)
- Tag creation triggers release-please workflow → dispatches centralized `mctl-gitops/.github/workflows/release-deploy.yaml`
