# Glovo facade to mctl-api wire protocol (v1alpha1)

Status: CANDIDATE HARNESS INTERFACE. Wire version `glovo-facade-mctl-api/v1alpha1`.

This document records what the Glovo MCP facade (`cmd/glovo-mcp`, image
`ghcr.io/mctlhq/mctl-glovo-mcp`, MCP `serverInfo.name` `mctl-glovo-mcp`) sends
to mctl-api today. It is implemented by the in-repo harness
`internal/glovo/mctlapi/fakeapi` and pinned by
`internal/glovo/mctlapi/wire_test.go` and `testdata/wire.golden.json`. It is
**not** an existing mctl-api API, and the facade is **BLOCKED_FOR_REAL_API**
until it is replaced.

## Ownership

The canonical route, verb, header and schema matrix for all seven tools is
owned by mctl-api#957 (join of #953 connections and #954 provider orders). The
paths below must not be treated as a second contract:

- mctl-api#953 defines `/api/v1/glovo/facade/*` for connections only.
- mctl-api#954 defines `/api/v1/provider-orders/*` for orders and `aar_`.
- Neither defines the aggregate endpoints below. When #957 freezes the matrix,
  `internal/glovo/mctlapi` is the only package that changes (behind the
  `Client` interface), together with this document and the golden fixtures.

Activation requires the same golden fixtures to pass against the real mctl-api
handlers (`TestRealAPI` in `wire_test.go`, enabled by `GLOVO_WIRE_REAL_URL`,
`GLOVO_WIRE_REAL_TOKEN` and `GLOVO_WIRE_REAL_CREDENTIAL`), plus the tenant
negative tests of ADR 0010.

## Identity

The facade does not decide the tenant. It forwards the caller's access token
for re-verification and mctl-api derives the selected team from the verified,
server-owned OAuth grant. The token must carry an explicit, human-selected team
(the `mctl_tenant` claim is only a hint): a token with no explicit selection is
refused, even when only one team qualifies. mctl-api re-checks the grant, the
current membership and the per-(team, principal) pilot allowlist on every call.

## Calls

All paths are under `/api/v1/assistants/glovo/v1alpha1`. No call has a query
string; ids travel in JSON bodies or as one opaque path segment.

| Tool | Call |
| --- | --- |
| (every tool, first) | `POST /resolve` with `{}` |
| `glovo_auth_status` | `GET /connection` |
| `glovo_connect_account` | `POST /connections` with `{"idempotency_key"}` |
| `glovo_get_order_history` | `POST /orders:list` with `{"limit","cursor"}` (read) |
| `glovo_preview_reorder` | `POST /previews` with `{"order_ref"}` (read, no basket write) |
| `glovo_get_basket` | `GET /basket` |
| `glovo_prepare_order` | `POST /orders:prepare` with `{"preview_id","idempotency_key"}` |
| `glovo_order_status` | `GET /orders/{order_id}` |

Response bodies are exactly the tool's output object from
`docs/contracts/glovo-mcp-tools.json`. Error bodies are `{"error":"<code>"}`
with a code from the closed set below.

`POST /resolve` answers `200 {"scope_ref","tenant","expires_at"}` or
`403 {"error":"no_tenant|ambiguous_tenant|scope_unsupported|not_in_pilot|not_authorized|no_install|stale_install"}`.
`scope_ref` is a short-lived (60 s) opaque handle bound to the subject token;
it is sent as `X-Mctl-Scope-Ref` on the following call and re-checked, so it
cannot be reused for another principal.

## Headers

| Header | Value |
| --- | --- |
| `Authorization` | `Bearer` plus the facade workload credential (a mounted file, re-read on change) |
| `X-Mctl-Subject-Token` | the caller's access token, for re-verification |
| `X-Mctl-Selected-Tenant` | the `mctl_tenant` claim or empty; untrusted, diagnostic only |
| `X-Mctl-Scope-Ref` | the handle from `/resolve` (not on `/resolve` itself) |
| `X-Request-Id`, `traceparent` | correlation |

## Refusal codes

`not_authorized`, `no_tenant`, `ambiguous_tenant`, `scope_unsupported`,
`not_in_pilot`, `no_install`, `stale_install`, `no_connection`,
`connection_revoked`, `connection_expired`, `not_found` come from mctl-api. The
facade adds `invalid_arguments`, `rate_limited`, `upstream_unavailable` and
`upstream_invalid`. Foreign and missing ids both answer `not_found`. Any other
upstream code, a non-conforming body or a body over 256 KiB becomes
`upstream_invalid`; upstream text is never returned.

## Limits and retries

Timeout 5 s per call. Reads are retried once with jitter. `connections` and
`orders:prepare` are retried once only on a connection reset (idempotency key).
No other POST is retried.
