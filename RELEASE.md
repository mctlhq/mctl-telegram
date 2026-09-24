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

## Tool surface evidence

`docs/tool-descriptors.json` is the canonical descriptor of every MCP tool the server registers (full surface: all tools, MCP Apps on). `TestToolDescriptorsSnapshotMatchesRegistry` holds it to the registry byte for byte, so any change to a tool's name, schema, annotations or text must regenerate it in the same pull request:

```bash
go test ./internal/mcp -run TestToolDescriptorsSnapshotMatchesRegistry -update-descriptors
```

While reviewing the release PR, diff the surface against the previous release. This is the deterministic source a product update may cite (issue-440): added, removed, schema-changed, annotation-changed (with each changed hint named) and text-changed tools, each kept separate. A rename shows up as one removal plus one addition.

```bash
go run ./cmd/tooldiff \
  -old <(git show <previous-tag>:docs/tool-descriptors.json) -from <previous-tag> \
  -new docs/tool-descriptors.json -to "$(git rev-parse HEAD)"
```

The command only prints JSON. It drafts, approves and publishes nothing. Releases before the snapshot existed have no file to diff against.

Every user-visible change in that diff needs a curated product update in `docs/product-updates/` (see its README): an added or removed tool, or a schema or annotation change, fails CI on the pull request that makes it until an approved entry claims it. CI runs the same check anyone can run locally:

```bash
go run ./cmd/productupdates gate
```

The check is the `product-updates` job in `build.yml`. Branch protection on `main` requires it, next to `test` and `docker` (set in the repository settings, not by this file). The baseline is the latest release tag whose tree carries `docs/tool-descriptors.json`. Until one exists, the gate requires nothing and only validates the feed; an entry's citation is reported as unverified, because there is no diff to hold it to. After a release, entries whose `evidence.from` is the previous baseline are history. New entries cite the new release. The gate reads no `CHANGELOG.md` and publishes nothing.

## Versioning

- `MAJOR` — breaking changes to tool schemas or auth behavior
- `MINOR` — new tools or non-breaking additions
- `PATCH` — bug fixes, dependency updates, docs
- Tags use no `v` prefix: `0.6.0`, not `v0.6.0`
- Stay on `0.x.y` until tool schemas and deployment model are stable
