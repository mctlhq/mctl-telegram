# Changelog

## [0.2.0](https://github.com/mctlhq/mctl-telegram/compare/0.1.0...0.2.0) (2026-05-14)


### ⚠ BREAKING CHANGES

* **scopes:** admins group is read-only by default (M2.6, BREAKING)

### Features

* add landing page at / with browser-GET redirect from /mcp ([8707dfd](https://github.com/mctlhq/mctl-telegram/commit/8707dfde953f0bb6374b17d58bfd222b95ea5ec6))
* **audit:** tamper-evident hash-chain on audit_logs (M3.1) ([1515049](https://github.com/mctlhq/mctl-telegram/commit/15150492f492dedce9c55f7589df84e92dc1e591))
* **audit:** tamper-evident hash-chain on audit_logs (M3.1) ([f52cc3a](https://github.com/mctlhq/mctl-telegram/commit/f52cc3a9d4692accf8227f25038a14cca4bc059a))
* **audit:** user-visible audit log via MCP tool + HTTP endpoint (M2.1) ([5a3c827](https://github.com/mctlhq/mctl-telegram/commit/5a3c827cc154de293774f69088119157131d2296))
* **audit:** user-visible audit log via MCP tool + HTTP endpoint (M2.1) ([ed1df07](https://github.com/mctlhq/mctl-telegram/commit/ed1df074196a9a14f58aeae04f686f051ccb1525))
* **auth:** JWT audience claim enforcement with phased rollout ([089f5b5](https://github.com/mctlhq/mctl-telegram/commit/089f5b5aeda8e2af9a71c7dfffaa3894b551480e))
* **auth:** JWT audience claim enforcement with phased rollout (M1.4) ([590a779](https://github.com/mctlhq/mctl-telegram/commit/590a779607f5b129d56d6a916bdaee78022c4f9b))
* **bridge:** Local Bridge scaffolding — protocol, hub, schema, stub CLI (M4 partial) ([4cf4b53](https://github.com/mctlhq/mctl-telegram/commit/4cf4b53ff44daa6b30318a7890bdd882fdb2a07b))
* **bridge:** Local Bridge scaffolding — protocol, hub, schema, stub CLI (M4 partial) ([efc75b9](https://github.com/mctlhq/mctl-telegram/commit/efc75b90dd151a3a7ea447945c5eebef46aea90a))
* **crypto:** per-user HKDF session keys with lazy v1-&gt;v2 migration ([76a2e26](https://github.com/mctlhq/mctl-telegram/commit/76a2e2602983bb328e089a9a3b9abfaf0a791355))
* **crypto:** per-user HKDF session keys with lazy v1-&gt;v2 migration (M1.3) ([2d7b091](https://github.com/mctlhq/mctl-telegram/commit/2d7b091e58f9029189f21435108476363c9a2a55))
* M1-M3 — gotd/td + MCP tools + auth + crypto + Postgres-ready ([5c31c95](https://github.com/mctlhq/mctl-telegram/commit/5c31c9573f25cbc32f208c3db4687044f9434661))
* **mcp:** add get_messages tool for full conversation history ([e7502ce](https://github.com/mctlhq/mctl-telegram/commit/e7502ce88f0689aa93bdbf91f026b12e3bf2e443))
* **mcp:** add pin_message tool (pin/unpin messages in groups/channels) ([84b705b](https://github.com/mctlhq/mctl-telegram/commit/84b705b10615638698a2b1f19ecfd2c3b9237eff))
* **mcp:** two-step prepare→confirm for send/pin (M2.3) ([05da6ca](https://github.com/mctlhq/mctl-telegram/commit/05da6cabd9a0303fb9c81f7bde3a34cc94a1048c))
* **mcp:** two-step prepare→confirm for send/pin (M2.3) ([eb3f166](https://github.com/mctlhq/mctl-telegram/commit/eb3f1666c049100b2855d455da2973998d8c61f2))
* **mcp:** wrap Telegram message text in untrusted-content tags (M3.2) ([bf2f6b0](https://github.com/mctlhq/mctl-telegram/commit/bf2f6b09eab0c92c90d51a18da1d288c219c9c9f))
* **mcp:** wrap Telegram message text in untrusted-content tags (M3.2) ([6fc8361](https://github.com/mctlhq/mctl-telegram/commit/6fc8361a2c1380b3904d313811b30f36133ee3c6))
* **ratelimit:** per-(identity, peer) write cap for prepare_* (M2.4) ([a7c10f0](https://github.com/mctlhq/mctl-telegram/commit/a7c10f0bfc74dda5344803d0d03d127fdc1f9001))
* **ratelimit:** per-(identity, peer) write cap for prepare_* (M2.4) ([64d43ce](https://github.com/mctlhq/mctl-telegram/commit/64d43cef3d2766c1ae0143e8bb93c138c1da7bc9))
* **scopes:** admins group is read-only by default (M2.6, BREAKING) ([8a90297](https://github.com/mctlhq/mctl-telegram/commit/8a902970ef78ba2853a39c9dd86e2f8cfedea0d9))
* self-service disconnect/delete + enforce send_enabled gate ([075d05f](https://github.com/mctlhq/mctl-telegram/commit/075d05f8603001910dec30d89fa49746fac37099))
* self-service disconnect/delete + enforce send_enabled gate (M1.1+M1.2) ([5f86095](https://github.com/mctlhq/mctl-telegram/commit/5f8609509992332741f452bc562edb54d49088e6))
* **sweeper:** audit-log retention sweeper + AUDIT_RETENTION_DAYS (M2.5) ([a224caf](https://github.com/mctlhq/mctl-telegram/commit/a224caf5a3e2fb455d729be37d71f248c511808d))
* **sweeper:** audit-log retention sweeper + AUDIT_RETENTION_DAYS (M2.5) ([207021b](https://github.com/mctlhq/mctl-telegram/commit/207021b9baccc2a9b48ffd3bbe84039168e2e0d0))
* **ttl:** session TTL (idle 30d + absolute 90d) with hourly sweeper (M2.2) ([42e68ac](https://github.com/mctlhq/mctl-telegram/commit/42e68ac3f0d6ad786435b99e243422b55b211259))
* **ttl:** session TTL (idle 30d + absolute 90d) with hourly sweeper (M2.2) ([9c51d36](https://github.com/mctlhq/mctl-telegram/commit/9c51d36cad14754866b079eab803cb1d1c294faa))
* **web:** add Telegram-style SVG favicon ([b8d4437](https://github.com/mctlhq/mctl-telegram/commit/b8d4437da69849388a893b6ba6b7cf30ca3306be))
* **web:** honest-disclosure landing + /security + /privacy ([d583a87](https://github.com/mctlhq/mctl-telegram/commit/d583a8776c36d73b03c426a67d229a692ad643e0))
* **web:** honest-disclosure landing + /security + /privacy (M1.5+M1.6) ([253b069](https://github.com/mctlhq/mctl-telegram/commit/253b0690bdcc0e26e4fb914bc27d49e132e60c8a))


### Bug Fixes

* **account:** close pool before DB revoke/delete (codex P1) ([f6f4744](https://github.com/mctlhq/mctl-telegram/commit/f6f474494ad3419247283f86a8c7d6584b1fbeed))
* **auth:** map admins group to full telegram scopes ([6e248e7](https://github.com/mctlhq/mctl-telegram/commit/6e248e79911c30280f83c0480aa502f2fdb4cafa))
* **auth:** reject malformed aud claims (codex P2) ([d553722](https://github.com/mctlhq/mctl-telegram/commit/d553722b72c0a2c04878466fe526ebcf0eceb56f))
* **db:** CAS-bound lazy migration UPDATE (codex P1) ([ea33e6c](https://github.com/mctlhq/mctl-telegram/commit/ea33e6cf8822c381cccb90095752ce305a58cbcb))
* **pool:** atomic pool eviction + DB revoke (codex P1 round 3) + audit GET ([e27594b](https://github.com/mctlhq/mctl-telegram/commit/e27594ba93e54058f8e4301f562dab18e0f31252))
* **telegram:** populate From field in get_messages and get_unread_messages ([a899e6d](https://github.com/mctlhq/mctl-telegram/commit/a899e6d1ff8279b10b0da7a0c6c823b0aa2164c6))
* **telegram:** remove pool entry under mutex on Close (codex P1) ([04739d3](https://github.com/mctlhq/mctl-telegram/commit/04739d326909395998d51d97eddcb7c907c10eed))

## 0.1.0 (2026-05-13)

### Features

* initial scaffold — Go HTTP server with `/healthz` and `/readyz` returning 200
* multi-stage Dockerfile (golang:1.25-alpine -> alpine:3.20, non-root)
* release-please + centralized mctl-gitops release-deploy wiring
