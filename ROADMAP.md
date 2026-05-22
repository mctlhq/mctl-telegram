# Roadmap

This document describes the current direction for mctl-telegram. It is a living document — priorities may shift.

## Near term

- Stabilize the seven MCP tools and lock their schemas for v1.0
- In-browser Telegram connect flow (`/telegram/connect`) — replace the CLI-only login
- Self-hosting guide (Docker Compose + standalone deployment without the mctlhq platform)
- Expand test coverage for auth, tool handlers, and session lifecycle
- Audit log retention sweeper (90-day window, tracked as M2)
- RS256 + JWKS at `mctl-api` — remove shared-HMAC coupling (tracked as M3)

## Later

- Multi-account support (multiple Telegram accounts per identity)
- Local Bridge mode hardening (M4) — beta is available today (MTProto session lives on the user's machine; the server acts as a relay only); remaining work is production-readiness and broader client support
- Per-tool scope granularity improvements
- Optional admin dashboard

## Out of scope

- Bypassing Telegram rate limits or API restrictions
- Accessing chats without a valid user authorization
- Automation for spam, mass messaging, or scraping
- Unofficial Telegram client features not supported by `gotd/td`
