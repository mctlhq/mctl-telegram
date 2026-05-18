# Changelog

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
