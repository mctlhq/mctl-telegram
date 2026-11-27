# Telegram dashboard

Extends the flag-gated MCP App (`MCP_APPS_ENABLED`, the same switch as the
triage prototype in [mcp-apps-spike.md](mcp-apps-spike.md)). There is no
second service and no second credential path. The dashboard is another
`ui://` resource on the existing MCP server, `ui://mctl-telegram/dashboard`,
rendered by the host in the same sandboxed iframe and talking only over
`postMessage`.

## Template model

Documents use schema id `tg-dashboard/v1`
(`internal/dashboard/schema.json`). A template names a grid, a poll
interval (15–300 seconds; there is no push), up to eight data sources, and
up to 24 tiles. The server validates every custom template with that JSON
Schema and then with an allowlist the schema cannot express on its own:
data sources may name only `list_dialogs`, `list_folders`, `list_topics`,
`get_unread_messages`, `get_messages`, and `search_messages`, and tile
actions may name only `mark_read` and `save_draft`. `send_message`,
`delete_messages`, and every other write are rejected at save time.

The real A2UI renderer is not embedded. The App's CSP allows no origin, and
the document is not allowed to load script. A small in-document renderer
covers the fixed component catalog (`kpi`, `message_list`, `dialog_cards`,
`folder_board`, `topic_cards`, `search_digest`, `banner`).

## Built-ins and custom templates

Five built-ins ship in `internal/dashboard/templates/`: `unread_pulse`,
`groups_tiles`, `folders_board`, `forum_topics`, `watchlist_digest`. They
are code, not rows. Custom templates are stored per account in
`dashboard_templates` (at most 20, each at most 24 KiB). The iframe has no
`localStorage`. Built-in ids cannot be overwritten or deleted.

The model sees `list_dashboard_templates`, `get_dashboard_template`,
`save_dashboard_template` (`dry_run` validates without writing), and
`delete_dashboard_template`. The editor in the App is the same save path.

## Writes

An iframe click is not authorization. `prepare_dashboard_action` issues a
one-shot confirmation bound to the exact `mark_read` or `save_draft`
arguments and reports the same gate that tool will run. It does not call
Telegram. `mark_read` and `save_draft` consume the id when one is supplied,
before their own gate, and a mismatched, reused, or foreign id is refused.
The gate still decides: a valid confirmation does not mark a chat read or
save a draft when the gate is closed. Omitting the id leaves those two
tools on their previous path.

These tools, and the dashboard resource, are registered only while
`MCP_APPS_ENABLED` is on. They are disabled on the shared portal allowlist,
the same choice as `prepare_send_message`.

## Dialog fields

`list_dialogs` now also returns, from the `messages.getDialogs` reply it
already fetched: `top_message_id`, `unread_mentions_count`, `pinned`,
`muted`, `archived`, `is_broadcast`, `is_megagroup`, `is_forum`. `type`
stays `user`, `chat`, or `channel`. A broadcast channel and a supergroup
are both `channel`; the new flags distinguish them. Zero and false values
are omitted so older clients see the same JSON for a dialog that has none
of the flags.

## Data gaps and follow-ups

- A folder listing still scans the 200 most recent dialogs and 100 archived
  ones. `folder_scan.complete=false` is shown on the board as an incomplete
  list. Scanning the rest is a separate change.
- There is no push. The App polls at the template's `refreshIntervalSec`.
- Sponsored messages arrive only on message reads that include a broadcast
  channel (`get_unread_messages`, `get_messages`), in `sponsored`, never
  mixed into `messages`. The App renders them in a separate block labelled
  with the item's own `label` (`Sponsored` or `Recommended`). `list_dialogs`
  does not carry them. `sponsored_unavailable` is shown as unknown, not as
  "no ads".
- `search_messages` with several peers is fanned out by the App, at most
  five calls. A wider fan-out needs a server-side batch.
- `mark_read` and `save_draft` are still refused for Local Bridge accounts
  by those tools themselves. Prepare does not override that.
- A daemon older than this build omits the new dialog fields. Absence means
  false or zero.
