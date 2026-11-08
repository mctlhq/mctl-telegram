# ADR 0010: Multi-tenant Glovo account connections

Status: Proposed

Issue: mctlhq/mctl-telegram#1227. The tenancy ADR 0009 is reserved by PR #1187 and is
linked, not duplicated.

## Decision

`GO_FAKE_MULTITENANT`: M1 may be built with a synthetic provider after gates G1 and G2
and its own approval. `BLOCKED_PROVIDER_ACCESS`: no real Glovo account is touched until
G3. Approval of this ADR grants no execution of M1, image publication, GitOps changes,
real-account access, basket writes or pilot activation; each needs its own approval.

## System boundary

Client -> `glovo.mctl.ai/mcp` facade (no secrets, no Temporal) -> mctl-api (sole
Temporal client) -> Temporal control namespace `mctl-assistants` -> Temporal provider
namespace `mctl-assistants-provider-glovo` -> adapter (fake in M1). The two namespaces
are independent; dispatch between them uses a verified Nexus endpoint or a narrowly
authenticated mctl-api bridge, and the provider identity has no authority to signal
control workflows or DevLoop.

## Identity chain

access token -> principal -> tenant membership -> pilot allowlist -> install and
revision -> connection (`gcn_`) -> sealed secret reference. Separate records exist for
principal, membership, install/revision, connection, provider identity and secret. Tenant
is never read from tool arguments or config.

## Connection state machine

`pending_handoff -> pending_provider -> active`; `active -> expired`; failures go to
`failed`; any state to `revoked` (terminal). A reconnect mints a new `gcn_`. The
`glovo_connect_account` tool is a delegated account connection, not OAuth. In M1 it is
fake-only.

## Secrets

Random per-connection DEK wrapped under an independently rotated provider-only KEK. A
key derived from a surviving master key is not crypto-erasure; without destroyed
wrappers and backup-retention evidence, revocation is data deletion only.

## Approval

The provider write is fenced by an `aar_` ActionApprovalRequest and single-use receipt,
bound to tenant, owner, one `we_` execution, connection, install revision, basket
fingerprint, hashed basket intent and target. A `hir_` answer never authorizes a write.

## Authorization checkpoints

1. MCP ingress. 2. Workflow start. 3. Before every provider write. 4. Consent or handoff
token use. 5. Every signal and schedule fire.

## Typed refusal codes

`not_authorized`, `no_tenant`, `ambiguous_tenant`, `scope_unsupported`, `not_in_pilot`,
`no_install`, `stale_install`, `no_connection`, `connection_revoked`,
`connection_expired`, `not_found`.

## Gates

| Gate | Meaning |
| --- | --- |
| G0 | This M0 merged and independently reviewed |
| G1 | Runtime ownership verdict on .github#324 |
| G2 | Separate mctl-api implementation (proposal and merged PR) with tenant and owner separation, order/connection registry, revocation and `aar_` receipt tests; mctl-api#948 and #950 do not count |
| G3 | Legally and technically reviewed real account access, verified mobile basket continuity, no checkout, no hosted `session.json`; accepted #1048 connector threat model |
| G4 | M1 security GO: T1-T16 green and independent review |
| G5 | Temporal client auth (mctl-gitops#2456) and deploy sequencing (#2457); provider identity cannot reach control or DevLoop |
| G6 | Release approval for `glovo.mctl.ai`; related: .github#309 on personal scope |

## Test catalog

- T1 cross-tenant read refused (`not_authorized`, no adapter call)
- T2 cross-tenant ID guessing yields `not_found`
- T3 same-tenant other user refused; distinct connections
- T4 revoke during active workflow; checkpoint 3 refuses
- T5 stale install invalidates consents
- T6 confused deputy: forbidden arguments rejected
- T7 handoff and consent replay, CSRF
- T8 reconnect mints new `gcn_`
- T9 canary leak scan
- T10 egress allowlist
- T11 prompt injection via menu text
- T12 rate limits and circuit breaker
- T13 session expiry
- T14 ambiguous and personal scope
- T15 no regression of `tg.mctl.ai` descriptors
- T16 duplicate actions and idempotency
- T0 `go test ./docs/...` contract test
