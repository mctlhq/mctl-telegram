# Release process

1. Ensure all checks pass on `main`:
   ```bash
   go fmt ./...
   go vet ./...
   go test ./...
   golangci-lint run
   ```

2. Update `CHANGELOG.md` with the changes for this release.

3. Tag and push:
   ```bash
   git tag X.Y.Z
   git push origin X.Y.Z
   ```
   Tags use no `v` prefix: `0.6.0`, not `v0.6.0`.

4. The `release-please` workflow picks up the tag and dispatches the centralized build + deploy pipeline in `mctl-gitops`.

5. Create a GitHub Release from the tag with the relevant CHANGELOG section as the body.

## Versioning

- `MAJOR` — breaking changes to tool schemas or auth behavior
- `MINOR` — new tools or non-breaking additions
- `PATCH` — bug fixes, dependency updates, docs
- Stay on `0.x.y` until tool schemas and deployment model are stable
