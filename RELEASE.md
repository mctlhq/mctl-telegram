# Release process

Releases are managed by [release-please](https://github.com/googleapis/release-please). The tag and GitHub Release are created automatically — do not push tags manually.

## Steps

1. Ensure all checks pass on `main`:
   ```bash
   go fmt ./...
   go vet ./...
   go test ./...
   golangci-lint run
   ```

2. Merge changes to `main` using conventional commits (`feat:`, `fix:`, `chore:`, etc.). release-please reads commit history to determine the next version.

3. release-please auto-creates or updates a "chore: release X.Y.Z" PR. Review it, update `CHANGELOG.md` if needed, and merge.

4. On merge of the release PR, release-please creates the tag and GitHub Release, then dispatches the centralized build + deploy pipeline in `mctl-gitops`.

## Versioning

- `MAJOR` — breaking changes to tool schemas or auth behavior
- `MINOR` — new tools or non-breaking additions
- `PATCH` — bug fixes, dependency updates, docs
- Tags use no `v` prefix: `0.6.0`, not `v0.6.0`
- Stay on `0.x.y` until tool schemas and deployment model are stable
