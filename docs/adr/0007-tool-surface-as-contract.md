# 0007. The tool surface is a reviewed contract

Status: Accepted

## Context

For an MCP client, the tool list is the API: names, input schemas,
descriptions and annotations such as `readOnlyHint` and `destructiveHint`
decide what a model will call and whether a client asks the user first. A
change to an annotation can turn a confirmed write into an unconfirmed one
without any code that looks dangerous. Clients and users also need to hear
about such changes, and an announcement that claims a change the release
does not contain is its own kind of bug.

## Decision

- The full tool surface is committed as a snapshot,
  `docs/tool-descriptors.json` (schema `mctl-telegram.tool-descriptors/v1`).
  A test fails when the registered tools differ from it; the snapshot is
  regenerated with `go test ./internal/mcp -update-descriptors`
  (`internal/mcp/descriptors.go`).
- A release gate compares the snapshot at HEAD with the one in the latest
  release that has one (`cmd/productupdates`, CI job `product-updates`,
  0.69.0, #440). Every added or removed tool and every schema or annotation
  change must be claimed by an approved entry in `docs/product-updates/`,
  and no entry may claim a change the diff does not show.
- Announcing an entry to users is a second, separate approval: it goes
  out through the broadcast flow, approved by a human in a browser
  ([0002](0002-send-gate.md)).
- The CI image build checks that the feed shipped in the image matches
  `docs/product-updates/`.

## Consequences

- A change to the surface is visible in review as a diff to one file,
  rather than being spread across Go code.
- Release notes for clients are derived from evidence, so they cannot
  drift from what shipped.
- Every surface change costs an extra file in the pull request. That is
  the intended friction.

## Alternatives

- **Generate the list at runtime only.** Nothing to review, and nothing to
  compare against the last release.
- **Hand-written release notes.** The tool counts in this repository's own
  documents once disagreed with each other (14, 7 and 37); the snapshot is
  what made the true number checkable.
