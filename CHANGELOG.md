# Changelog

## [0.26.1](https://github.com/mctlhq/mctl-telegram/compare/0.26.0...0.26.1) (2026-05-22)


### Bug Fixes

* **web:** make all pages mobile-responsive ([eec51ee](https://github.com/mctlhq/mctl-telegram/commit/eec51eef98e84b0051a12435f7ce696d6b50acef))
* **web:** make all pages mobile-responsive ([45f3fdb](https://github.com/mctlhq/mctl-telegram/commit/45f3fdb9efc8ccc436672120ebb973d8bfa84d05))

## [0.26.0](https://github.com/mctlhq/mctl-telegram/compare/0.25.0...0.26.0) (2026-05-22)


### Features

* **web:** restore light/dark theme toggle in shared chrome ([e21d7d8](https://github.com/mctlhq/mctl-telegram/commit/e21d7d863ccaebb87e37e1ea68384f69dd72ef87))
* **web:** restore light/dark theme toggle in shared chrome ([8c91110](https://github.com/mctlhq/mctl-telegram/commit/8c911105884976a791781df3d31f866d3e5b26e0))

## [0.25.0](https://github.com/mctlhq/mctl-telegram/compare/0.24.0...0.25.0) (2026-05-22)


### Features

* **web:** unify visual style across all pages via shared chrome ([6ebc8cf](https://github.com/mctlhq/mctl-telegram/commit/6ebc8cfc8167aeef0327c948eb4d2361eafb9677))
* **web:** unify visual style across all pages via shared chrome ([99d12a3](https://github.com/mctlhq/mctl-telegram/commit/99d12a3976259cb94c5cd919da2f9d8a0df2f00b))


### Bug Fixes

* **metrics:** add 2s/4s latency buckets for SLO p95 accuracy ([de56c7b](https://github.com/mctlhq/mctl-telegram/commit/de56c7bffa1c5231f7241550854934ebc5b687bf))
* **web:** address P3 review nits — stale comment + lite color-scheme ([c7651f1](https://github.com/mctlhq/mctl-telegram/commit/c7651f12d714413d5ac7514a1fc9adbbbd71483c))
* **web:** theme always follows OS, drop stale mctl-theme preference ([2684d8b](https://github.com/mctlhq/mctl-telegram/commit/2684d8b1202dddf5cf4f953a7c997177e923ca81))

## [0.24.0](https://github.com/mctlhq/mctl-telegram/compare/0.23.1...0.24.0) (2026-05-21)


### Features

* add Beta SLOs, burn-rate alerts, and session borrow counter ([f3d6240](https://github.com/mctlhq/mctl-telegram/commit/f3d62400e79eaea2712bcb86af694de2ea953e32))
* add Beta SLOs, burn-rate alerts, and session borrow counter ([#88](https://github.com/mctlhq/mctl-telegram/issues/88)) ([f9e29ce](https://github.com/mctlhq/mctl-telegram/commit/f9e29ce2fb6ecd202d1e225662c3c6b7a9621f63))
* add PrometheusRule manifest for production alerts ([#86](https://github.com/mctlhq/mctl-telegram/issues/86)) ([ec3b116](https://github.com/mctlhq/mctl-telegram/commit/ec3b11687b09125a9f4ecf01e84fecdb8801cb9a))
* **agents:** issue-86-ship-prometheusrule-manifests-for-produc ([e5b61fd](https://github.com/mctlhq/mctl-telegram/commit/e5b61fdd8c42fc6b3b1e57f27c45ec4ab1893eff))
* **agents:** issue-90-beta-capacity-profile-load-test-tuned-co ([d6fd303](https://github.com/mctlhq/mctl-telegram/commit/d6fd303b8c530866aae371d0d8edf74d455a29e1))
* **agents:** issue-92-operational-runbook-for-beta-top-n-incid ([62af604](https://github.com/mctlhq/mctl-telegram/commit/62af6044f738826da0fe09334421c9d0d3ca09d3))
* **db,config:** add configurable DB pool knobs and load-test binary ([ef47b02](https://github.com/mctlhq/mctl-telegram/commit/ef47b02d981479fed1b15077baa95bce050526f5))
* **web:** make landing page LLM-provider agnostic ([4ebc096](https://github.com/mctlhq/mctl-telegram/commit/4ebc0961d8c5cd4bb2aa8b1b1bee33e84750879e))
* **web:** make landing page LLM-provider agnostic ([8058bf4](https://github.com/mctlhq/mctl-telegram/commit/8058bf4804d39edd158284908b091b0eceeeae93))


### Bug Fixes

* **alerts:** add upper-bound guards on warning variants + humanize ([87cd94e](https://github.com/mctlhq/mctl-telegram/commit/87cd94e6f0af01b5f37eab1d496107c0b58e5a96))
* **auth:** unknown AUTH_MODE is now a fatal startup error ([5872cbc](https://github.com/mctlhq/mctl-telegram/commit/5872cbce8beb6d9c597b013f491acaa4cc6833fc))
* **grafana:** coalesce absent error series to zero in SLO panels ([2e992c6](https://github.com/mctlhq/mctl-telegram/commit/2e992c69e2f4c8f5d9c18222c1e15a10c151ef6e))
* **load-test:** count isError results, warn on metrics non-200, delta flood-wait ([060112d](https://github.com/mctlhq/mctl-telegram/commit/060112dbedf512c2049fe2626c5adb76fc174169))
* **load-test:** guard send_message, fix SSE extraction + poller timing ([40f6850](https://github.com/mctlhq/mctl-telegram/commit/40f68504e5c8b6885349f57fa56eb671ae4f96a6))
* **load-test:** MCP initialize handshake + token/draft correctness ([c587f98](https://github.com/mctlhq/mctl-telegram/commit/c587f980dc5b8444cb13a9f73e23c5da69c53b31))
* **oss:** remove internal infra references from SECURITY.md, CLI, issue template ([9b0489d](https://github.com/mctlhq/mctl-telegram/commit/9b0489d3a30b46ef7faef0c8f3a0b71eb2332d2e))
* **oss:** remove internal infra references from SECURITY.md, local CLI, issue template ([10f8034](https://github.com/mctlhq/mctl-telegram/commit/10f80343716f01bc68004a5f40bec5e97cda9dd8))
* point alert runbook_url at existing docs/hpa.md#alerts ([a007129](https://github.com/mctlhq/mctl-telegram/commit/a00712948ed17312a50a68cd0dc01b4676106eeb))
* **web:** address P3 review nits on landing page ([bb917fb](https://github.com/mctlhq/mctl-telegram/commit/bb917fb89fbe11a0bf2d7f192a7d86d482db9c7f))

## [0.23.1](https://github.com/mctlhq/mctl-telegram/compare/0.23.0...0.23.1) (2026-05-21)


### Bug Fixes

* **canary:** address P3 review findings ([f5e6cac](https://github.com/mctlhq/mctl-telegram/commit/f5e6cac0cba4c7c7a19c4c4e889e95e46511008a))
* **canary:** initialize MCP session before tools/call ([11b2795](https://github.com/mctlhq/mctl-telegram/commit/11b2795e6a37417706af354724df0ed3a7f869d1))
* **canary:** initialize MCP session before tools/call ([5f0ca47](https://github.com/mctlhq/mctl-telegram/commit/5f0ca47ad3a9fbf3966282626667a1f06765e07a))
* **web:** remove accent color picker from navbar ([1e13883](https://github.com/mctlhq/mctl-telegram/commit/1e13883285d130b8749e68b2b9668e10bc48c702))

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
