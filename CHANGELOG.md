# Changelog

## [0.19.0](https://github.com/mctlhq/mctl-telegram/compare/0.18.0...0.19.0) (2026-05-19)


### Features

* **oauth:** allow chatgpt.com redirect_uri in implicit-host allowlist ([dea99a8](https://github.com/mctlhq/mctl-telegram/commit/dea99a8d6050f67ffb3dc0ba29d8493fe6362512))
* **oauth:** allow chatgpt.com redirect_uri in implicit-host allowlist ([fbb925f](https://github.com/mctlhq/mctl-telegram/commit/fbb925f1f77391828c3ecf64ca44a097f7f978b0))

## [0.18.0](https://github.com/mctlhq/mctl-telegram/compare/0.17.0...0.18.0) (2026-05-18)


### Features

* **agents:** issue-59-add-observability-and-alerting-for-mctl ([#61](https://github.com/mctlhq/mctl-telegram/issues/61)) ([bb767b1](https://github.com/mctlhq/mctl-telegram/commit/bb767b162d81d4e6cb5151ace65b4021fe7918d5))

## [0.17.0](https://github.com/mctlhq/mctl-telegram/compare/0.16.1...0.17.0) (2026-05-18)


### Bug Fixes

* address codex review on partial-session PR ([4cc0cbc](https://github.com/mctlhq/mctl-telegram/commit/4cc0cbcfd18e23df7de60439636be028c94da599))
* detect unauthorized sessions and log MCP tool calls ([800f45c](https://github.com/mctlhq/mctl-telegram/commit/800f45cf06aaafedf91dbe107c04b34e5a17451a))
* detect unauthorized sessions and log MCP tool calls ([6cc2d83](https://github.com/mctlhq/mctl-telegram/commit/6cc2d83bd312e1bfdcecad908dd56f48ad1599eb))
* distinguish revoked sessions from unfinished ones ([8f21094](https://github.com/mctlhq/mctl-telegram/commit/8f21094ba30c7fcdb75d9ea1fd65c66ce272ef7c))
* **oauth:** clarify 2FA screen and add show-password toggle ([421f8a4](https://github.com/mctlhq/mctl-telegram/commit/421f8a449f958378075bede787ca0dc30896b094))
* **oauth:** clarify 2FA screen and add show-password toggle ([ccde0d1](https://github.com/mctlhq/mctl-telegram/commit/ccde0d1c4625647c2fd328d8158ae0d959e081b8))

## [0.16.1](https://github.com/mctlhq/mctl-telegram/compare/0.16.0...0.16.1) (2026-05-18)


### Bug Fixes

* **oidc:** tolerate Telegram's secp256k1 JWKS key ([#57](https://github.com/mctlhq/mctl-telegram/issues/57)) ([ffa7ede](https://github.com/mctlhq/mctl-telegram/commit/ffa7ede758e94cab72c3aa2beff45126996f05a9))

## [0.16.0](https://github.com/mctlhq/mctl-telegram/compare/0.15.0...0.16.0) (2026-05-18)


### ⚠ BREAKING CHANGES

* **oauth:** requires TELEGRAM_OIDC_CLIENT_ID and TELEGRAM_OIDC_CLIENT_SECRET; TELEGRAM_LOGIN_BOT_USERNAME is removed and TELEGRAM_LOGIN_BOT_TOKEN is now used only for the daily digest. The login bot must have OpenID Connect enabled in BotFather.

### Features

* **auth:** scaffold Telegram OIDC relying party (dormant) ([#54](https://github.com/mctlhq/mctl-telegram/issues/54)) ([e426aab](https://github.com/mctlhq/mctl-telegram/commit/e426aab2e4f23580f6798eb1b54874aeebd99757))
* **oauth:** migrate login from legacy widget to Telegram OIDC ([#56](https://github.com/mctlhq/mctl-telegram/issues/56)) ([5f49593](https://github.com/mctlhq/mctl-telegram/commit/5f49593ab0d6710244770e7d3cb86fcd26a916a3))

## [0.15.0](https://github.com/mctlhq/mctl-telegram/compare/0.14.0...0.15.0) (2026-05-17)


### Features

* **oauth:** add refresh-token grant and dedicate the JWT signing key ([#51](https://github.com/mctlhq/mctl-telegram/issues/51)) ([b255958](https://github.com/mctlhq/mctl-telegram/commit/b255958a53053e7e710631fdf22bdcf2f339eb64))

## [0.14.0](https://github.com/mctlhq/mctl-telegram/compare/0.13.0...0.14.0) (2026-05-17)


### Features

* **web:** redesign landing page on the mctl design system ([#49](https://github.com/mctlhq/mctl-telegram/issues/49)) ([944524f](https://github.com/mctlhq/mctl-telegram/commit/944524fcdecc30b1d823ebd75a1f25f607b8f6d9))

## 0.1.0 (2026-05-13)

### Features

* initial scaffold — Go HTTP server with `/healthz` and `/readyz` returning 200
* multi-stage Dockerfile (golang:1.25-alpine -> alpine:3.20, non-root)
* release-please + centralized mctl-gitops release-deploy wiring
