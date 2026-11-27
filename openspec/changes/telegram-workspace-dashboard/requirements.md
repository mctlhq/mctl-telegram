# Telegram Workspace opener requirements

Status is proposed. [Implementation issue #1482](https://github.com/mctlhq/mctl-telegram/issues/1482) supports [operator issue #650](https://github.com/mctlhq/mctl-telegram/issues/650).

- `telegram_dashboard` SHALL be a discoverable read-only tool with no required arguments, an authorized bounded snapshot, a semantic text result and a nested `_meta.ui.resourceUri` binding. Opening and refreshing SHALL require no LLM call.
- One server-owned immutable HTML bundle per Workspace release SHALL hydrate from the standard tool-result notification, support the standard lifecycle and retain the same digest across permitted routes and hosts.
- The Workspace SHALL show overview, inbox/history, permitted search and own-account/security status, including refresh time and explicit unavailable/partial states. It SHALL label scoped or sampled counts and show only observed Telegram data.
- The UI SHALL render Telegram data as untrusted text, adapt to host theme and negotiated display modes, and expose keyboard-accessible navigation. Only the isolated read profile SHALL be used for live validation. App requests SHALL retain existing authenticated identity, authorization and audit.
- Existing tools and their schemas SHALL preserve behavior. This proposal grants no deployment, flag enablement, account mutation or send.

Acceptance includes standard-host synthetic tests, independent security and contract review, and separately captured native and headless results under #650 when isolation passes.
