# Product updates

The canonical feed of user-facing product updates (issue #440). One reviewed
YAML file per update, named `<id>.yaml`. The database only records what has been
published and in which digest. What an update says lives here, next to the
tool snapshot it cites (`docs/tool-descriptors.json`).

## The two approvals

1. **Content.** The pull request that adds or edits the file. Its merge is the
   review: an entry lands with `status: approved` and a named human in
   `provenance.reviewed_by`.
2. **Sending.** A campaign built from approved entries is approved separately,
   on the broadcast page. Nothing here sends anything.

A model may help word an update (`provenance.assisted_by`). It cannot approve
one: the reviewer is never a bot account and never the assisting model.

## Release gate

`go run ./cmd/productupdates gate` runs in CI on every pull request. It diffs
`docs/tool-descriptors.json` at HEAD against the latest release tag that carries
a snapshot (the *baseline*) and fails unless:

- every added or removed tool, and every schema or annotation change, since the
  baseline is claimed by exactly one **approved** entry whose `evidence.from`
  is the baseline. A draft covers nothing;
- every change such an entry claims is really in the diff, and every tool it
  names exists at HEAD or was removed. An update cannot state a change the tool
  surface does not show;
- no entry cites a release newer than the baseline.

Text-only changes may be claimed but need not be. A rename shows up as a
removal plus an addition: both must be covered, and one `changed_behavior`
entry may claim the pair. A release that changes no tool requires nothing.
Entries for older baselines are history and are only schema-checked.
`CHANGELOG.md` is not an input.

## Schema (`mctl-telegram.product-update/v1`)

```yaml
schema: mctl-telegram.product-update/v1
id: send-message-silent        # stable, [a-z0-9-], equals the file name
kind: changed_behavior         # new_tool | changed_behavior | deprecation | maintenance | security
title: Send messages silently  # <= 120 characters, user-facing
summary: >-                    # <= 1000 characters, user-facing
  send_message takes a silent flag that delivers without a notification.
locale: en                     # v1 is English only
delivery: next_digest          # next_digest | immediate | docs_only
high_value: false              # immediate is only for security, maintenance or high_value
tools: [send_message]          # affected tool identifiers
surfaces: [chatgpt, claude]    # optional
evidence:
  from: 0.69.0                 # the baseline release the diff is taken against
  changes:                     # the diff items this entry covers
    - {tool: send_message, change: schema}   # added | removed | schema | annotations | text
  links:                       # optional https sources; required when there are no changes
    - https://github.com/mctlhq/mctl-telegram/pull/123
release: 0.70.0                # optional, once the version is known
status: approved               # draft | approved
provenance:
  author: alice
  assisted_by: claude-opus     # optional
  reviewed_by: alice           # required when approved; may be the author
created_at: "2026-09-24"
reviewed_at: "2026-09-24"      # required when approved
```

The notification category is derived from `kind` and is never written:
`security` → security, `maintenance` → maintenance, everything else →
`product_updates` (opt-in). A digest is built for one category only, so opt-in
content never reaches people who did not opt in.
