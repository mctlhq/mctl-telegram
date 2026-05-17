# Changelog

## [0.14.0](https://github.com/mctlhq/mctl-telegram/compare/0.13.0...0.14.0) (2026-05-17)


### Features

* **web:** redesign landing page on the mctl design system ([#49](https://github.com/mctlhq/mctl-telegram/issues/49)) ([944524f](https://github.com/mctlhq/mctl-telegram/commit/944524fcdecc30b1d823ebd75a1f25f607b8f6d9))

## 0.1.0 (2026-05-13)

### Features

* initial scaffold — Go HTTP server with `/healthz` and `/readyz` returning 200
* multi-stage Dockerfile (golang:1.25-alpine -> alpine:3.20, non-root)
* release-please + centralized mctl-gitops release-deploy wiring
