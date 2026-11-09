# Glovo MCP facade runbook

`cmd/glovo-mcp` is the OAuth-protected Streamable HTTP MCP resource for the
team-scoped fake Glovo pilot (resource `https://glovo.mctl.ai/mcp`, scopes
`glovo:read` and `glovo:basket:prepare`, tools in
`docs/contracts/glovo-mcp-tools.json`). It is an independent binary and image
(`Dockerfile.glovo-mcp`, `ghcr.io/mctlhq/mctl-glovo-mcp`) and never serves a
`tg.mctl.ai` route. mctl-api stays the only authority for identity, tenant,
connection (`gcn_`), order and `aar_` approval (ADR 0010).

The facade holds no signing or shared secret, no Temporal client, no Glovo
access and no Kubernetes or Vault privileges. Nothing here is deployed,
published or routed: the kill switch defaults to off, no gitops values exist,
and the release job skips publication while they are absent.

## Status: BLOCKED_FOR_REAL_API

The facade is built and tested against the in-repo harness
(`internal/glovo/mctlapi/fakeapi`) over a candidate wire protocol
(`docs/contracts/glovo-facade-mctl-api.md`). That is not evidence it works
against mctl-api. Do not describe it as deployable until the contract join in
mctl-api#957 is merged and the same golden tests pass against the real
handlers, with the public MCP conformance and tenant negative tests.

## Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `GLOVO_MCP_ENABLED` | `false` | kill switch: false answers `/mcp` 503, `/readyz` 503, contacts nothing |
| `GLOVO_MCP_PUBLIC_BASE_URL` | none | for example `https://glovo.mctl.ai` |
| `GLOVO_MCP_RESOURCE` | base URL plus `/mcp` | must equal the contract resource outside dev |
| `GLOVO_MCP_ISSUER` | none | exact `iss` |
| `GLOVO_MCP_JWKS_URL` | none | https; http only with `GLOVO_MCP_DEV=true` on loopback |
| `GLOVO_MCP_AUTHORIZATION_SERVER` | the issuer | advertised in protected-resource metadata |
| `GLOVO_MCP_API_BASE_URL` | none | mctl-api base; https unless dev loopback |
| `GLOVO_MCP_API_CREDENTIAL_FILE` | none | facade workload credential, a mounted file re-read on change |
| `GLOVO_MCP_RATE_PER_MIN`, `GLOVO_MCP_BURST`, `GLOVO_MCP_MAX_INFLIGHT` | 30, 10, 64 | per principal, per principal, global; need operator review before deployment |
| `GLOVO_MCP_METRICS_ALLOW_CIDR` | `127.0.0.1/32` | scrape allow list for `/metrics` |
| `GLOVO_MCP_ADDR` | `:8080` | listen address |

Startup fails when enabled with a missing or malformed value. No variable names
a tenant: the tenant comes from the caller's token and mctl-api only.

## Routes and probes


The ingress **must preserve the original HTTP Host authority** on \`/mcp\`
requests. The facade rejects foreign/malformed Host values with HTTP 403 to
prevent DNS rebinding. For the production resource \`https://glovo.mctl.ai/mcp\`,
both \`Host: glovo.mctl.ai\` and \`Host: glovo.mctl.ai:443\` are accepted;
other ports, unrelated hosts and loopback are refused. Loopback hosts are
allowed only with explicit \`GLOVO_MCP_DEV=true\`, never in production.


`/mcp`, `/.well-known/oauth-protected-resource` (and `/mcp` alias), `/healthz`,
`/readyz`, `/metrics`; everything else is 404. `/healthz` is 200 while the
process runs. `/readyz` is 200 only when enabled, not draining, the JWKS has
been fetched and mctl-api `/healthz` answered within 2 s. On SIGTERM readiness
fails, the listener closes and in-flight requests drain for up to 20 s.

## Run locally against the harness

```
go run -tags glovofake ./cmd/glovo-mcp-fakeapi        # prints a sample token
GLOVO_MCP_ENABLED=true GLOVO_MCP_DEV=true GLOVO_MCP_ADDR=127.0.0.1:8080 \
  GLOVO_MCP_PUBLIC_BASE_URL=http://127.0.0.1:8080 \
  GLOVO_MCP_ISSUER=http://127.0.0.1:9000 \
  GLOVO_MCP_JWKS_URL=http://127.0.0.1:9000/.well-known/jwks.json \
  GLOVO_MCP_API_BASE_URL=http://127.0.0.1:9000 \
  GLOVO_MCP_API_CREDENTIAL_FILE=./cred go run ./cmd/glovo-mcp
```

The credential file holds `fake-workload-credential`. The harness is never part
of the image.

## Kill switch and rollback

Set `GLOVO_MCP_ENABLED=false` (`/mcp` answers 503 and mctl-api is no longer
contacted) or scale the component to zero. The change itself is a plain revert
of the merge commit; `cmd/server` and the tg.mctl.ai image are untouched.

## Activation checklist (all separate gates, none done here)

- G2 and G4: mctl-api M1a/M1b merged, contract join mctl-api#957 merged, golden
  tests green against the real handlers, explicit-team grant verified.
- G5: public MCP conformance and tenant negative tests green.
- G6: gitops values, DNS and TLS for `glovo.mctl.ai` (mctl-gitops#2457) and the
  release guard satisfied. Until `services/labs/glovo-mcp/values.yaml` exists
  on mctl-gitops main, `glovo-mcp-release` publishes nothing.

Not provided by this slice: OTLP trace export (spans use the OpenTelemetry API
and are no-ops until a provider is wired) and any real Glovo provider access.
