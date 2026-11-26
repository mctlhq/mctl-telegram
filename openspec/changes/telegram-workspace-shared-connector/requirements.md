# Telegram Workspace on the shared connector

- The authenticated tool list at `https://tg.mctl.ai/mcp` offers `telegram_dashboard`. Its existing registration opens a native view in ChatGPT.
- The Workspace publishes a fixed set of read-only App calls. The host refuses iframe calls to all other tools before proxying.
- Existing grants, OAuth discovery, tool schemas, scopes, write consent, rate limits and confirmations continue to work.
- Independent security and contract review and GitOps approval precede activation. Issue #650 owns sanitized real-host evidence and the release verdict.
