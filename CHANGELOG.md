# Changelog

## [0.23.0](https://github.com/mctlhq/mctl-telegram/compare/0.22.0...0.23.0) (2026-05-20)


### Features

* **agents:** issue-87-grafana-dashboard-for-beta-operations ([dbbbd10](https://github.com/mctlhq/mctl-telegram/commit/dbbbd1014e92e72b802813a84c6d204125cf93ca))
* **agents:** issue-93-unified-connect-wizard-oidc-enable-acces ([e3dc686](https://github.com/mctlhq/mctl-telegram/commit/e3dc686820005e099c30d9612519154c6102809c))
* **ops:** add Grafana dashboard for beta operations ([f82f47f](https://github.com/mctlhq/mctl-telegram/commit/f82f47fc18cd2e9a01f0dbf580b0bfca154a094c))
* **web:** unified connect wizard with OIDC permissions step and audit trail ([1afa5da](https://github.com/mctlhq/mctl-telegram/commit/1afa5daef999fbfd50a077dd3cc127ba920daa3e))


### Bug Fixes

* **connect-wizard:** address P1/P2 review findings ([630dc5f](https://github.com/mctlhq/mctl-telegram/commit/630dc5f97d0a3a90aee44ccb37143ab62397cdbf))
* **connect-wizard:** complete wizard step indicator on code and password screens ([3feaa1b](https://github.com/mctlhq/mctl-telegram/commit/3feaa1bd49572653f048506e68372954e50e6bad))
* **connect-wizard:** derive Secure cookie flag + clear cookie on disconnect ([6c1a022](https://github.com/mctlhq/mctl-telegram/commit/6c1a022b1d513f7564d48c378b7aafcfc30e407c))
* **connect-wizard:** preserve wizard mode on empty-code re-render ([1c8ef15](https://github.com/mctlhq/mctl-telegram/commit/1c8ef15001bd62ec3cea891daa94ba69c2317907))
* **connect-wizard:** unblock CI + address P2/P3 review findings ([d3eceb4](https://github.com/mctlhq/mctl-telegram/commit/d3eceb4ae4460a4edbcfc58d6f8d494dc53486c0))
* **grafana:** rename __requires__ to __requires (P1 follow-up) ([ac23e7a](https://github.com/mctlhq/mctl-telegram/commit/ac23e7a3bf56ee2863223ba911b54f50ba77c7e7))
* **grafana:** rename dashboard import key to __inputs (P1 follow-up to [#95](https://github.com/mctlhq/mctl-telegram/issues/95)) ([4717277](https://github.com/mctlhq/mctl-telegram/commit/471727778c57e853cbac59e20877fad7095fd299))
* **grafana:** rename dashboard import key to __inputs (P1 follow-up to [#95](https://github.com/mctlhq/mctl-telegram/issues/95)) ([e096870](https://github.com/mctlhq/mctl-telegram/commit/e09687042c18e9ce0bd9283d242f6190e60e1b3f))

## [0.22.0](https://github.com/mctlhq/mctl-telegram/compare/0.21.0...0.22.0) (2026-05-20)


### Features

* **agents:** issue-67-build-browser-based-telegram-account-onb ([d2826e4](https://github.com/mctlhq/mctl-telegram/commit/d2826e42db4652becadeb16c865d70883e53aa26))
* **agents:** issue-69-improve-mobile-responsiveness-of-tg-mctl ([4c2ccaa](https://github.com/mctlhq/mctl-telegram/commit/4c2ccaa05f871f5b8bb35abe1b7749ffc68b883e))
* **agents:** issue-70-add-user-friendly-error-message-catalog ([dd28a43](https://github.com/mctlhq/mctl-telegram/commit/dd28a43f23b7c746112ff55420f4951ae3828313))


### Bug Fixes

* address P1/P2/P3 review findings in ExchangeConnect and validateClient ([fd85b79](https://github.com/mctlhq/mctl-telegram/commit/fd85b7989ee4fe9cf4d051fbdff49f60bb0191ab))
* **mcp:** swap slog field names: message=rpcErr.Message, code=rpcErr.Code ([6a9b3bb](https://github.com/mctlhq/mctl-telegram/commit/6a9b3bb4b2420c0a849a2f5669635b2cbf8096fa))
* **web:** reorder media queries largest-to-smallest (768→640→480) ([91aa239](https://github.com/mctlhq/mctl-telegram/commit/91aa239896ca5630375b7cf3e8ae5d8517a540e0))

## [0.21.0](https://github.com/mctlhq/mctl-telegram/compare/0.20.1...0.21.0) (2026-05-19)


### Features

* **agents:** issue-68-redesign-tg-mctl-ai-landing-page-for-cli ([1eae213](https://github.com/mctlhq/mctl-telegram/commit/1eae2133f8f504c946b7f36ff3fc262903985cfa))
* **web:** redesign landing page, add /docs route, fix stale auth copy ([9009776](https://github.com/mctlhq/mctl-telegram/commit/9009776e6aef6b087c569d2f9cef9fca3c4e89a8))


### Bug Fixes

* **telegram:** nil-safe SessionStore when Store is nil (test harness) ([61bf4ed](https://github.com/mctlhq/mctl-telegram/commit/61bf4edc5e88001c2c844bc734ca21486f984af1))
* **web:** correct docs.go comment four-&gt;three ([1573fe4](https://github.com/mctlhq/mctl-telegram/commit/1573fe44f7ba8731f9b3c734a9874f1d4657d68a))
* **web:** fix duplicate Telegram bullet in privacy, remove debug comment in landing ([ddf4c12](https://github.com/mctlhq/mctl-telegram/commit/ddf4c129e9cb1f20149f489dddfba9499d8e56cb))

## [0.20.1](https://github.com/mctlhq/mctl-telegram/compare/0.20.0...0.20.1) (2026-05-19)


### Bug Fixes

* **oauth:** drop admin:users from public scopes_supported ([1a2680d](https://github.com/mctlhq/mctl-telegram/commit/1a2680d139521a1d7937cf2b6e9065ccacaa06c7))
* **oauth:** drop admin:users from public scopes_supported ([153beb3](https://github.com/mctlhq/mctl-telegram/commit/153beb312651e1abebba532ca275dca3762f880a))

## [0.20.0](https://github.com/mctlhq/mctl-telegram/compare/0.19.0...0.20.0) (2026-05-19)


### Features

* **agents:** issue-66-scalability-audit-and-hardening-for-100 ([c497eb4](https://github.com/mctlhq/mctl-telegram/commit/c497eb4aaf777cea8431e6a6251dde34b4c04b3c))
* **scalability:** issue-66-scalability-audit-and-hardening-for-100 ([6ddfd1b](https://github.com/mctlhq/mctl-telegram/commit/6ddfd1b0657e0b6bee8194309fbf914bfc6698f1))


### Bug Fixes

* **oauth:** address P1/P2 review findings for DB-backed OAuth paths ([c70319c](https://github.com/mctlhq/mctl-telegram/commit/c70319cf282850638b811711163cc35262925355))
* **oauth:** address P2 findings — FLOOD_PREMIUM_WAIT and evict-insert comment ([e46f0b0](https://github.com/mctlhq/mctl-telegram/commit/e46f0b0a2fc9a38d7d6870108d5e297eff655086))
* **oauth:** fix TOCTOU in Consume* methods and evict live-row mismatch ([79386e7](https://github.com/mctlhq/mctl-telegram/commit/79386e78217a3301d772d974ab985c5fecfe4077))

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
