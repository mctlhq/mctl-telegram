# Glovo assistant threat model

Scope: the M1 multi-tenant facade, control and provider workers, and the fake provider.
Real-account threats are gated by G3 and need their own review.

## Assets

Connection records and sealed secrets, provider session bytes, order and basket data,
approval receipts, tenant isolation.

## Actors

Authenticated principal, another principal in the same tenant, principal of another
tenant, compromised model or prompt injection, malicious provider content, operator.

## Trust boundaries

Client to facade; facade to mctl-api; mctl-api to Temporal control namespace; control
namespace to provider namespace; provider worker to provider egress.

## Threats

| ID | Threat | Mitigation | Test |
| --- | --- | --- | --- |
| TM1 | Cross-tenant connection use | Scope from token and membership, never from args | T1, T2 |
| TM2 | Same-tenant other user | Owner check at every checkpoint | T3 |
| TM3 | Confused deputy | Facade holds no secrets; worker revalidates; IDs derived server-side | T6 |
| TM4 | Revocation during a workflow | Checkpoint 3 refuses before write | T4 |
| TM5 | Stale install or reinstall revival | Revision bound in consent; new `gcn_` on reconnect | T5, T8 |
| TM6 | Bootstrapping handoff and consent replay | Hashed single-use token with CAS and TTL | T7 |
| TM7 | CSRF on handoff page | Token-bound, SameSite strict, origin check | T7 |
| TM8 | SSRF through provider URLs | Egress allowlist, no URL inputs | T10 |
| TM9 | Remote browser trust | Absent in M1; any use is a G3 decision | T10 |
| TM10 | Session storage and rotation leak | Opaque IDs, redaction, wrapped per-connection DEK | T9 |
| TM11 | Prompt injection via menu text | Bounded sanitised fields; write needs human `aar_` approval | T11 |
| TM12 | Abuse and cost fan-out | Rate limits, breaker, history cap | T12 |
| TM13 | Token and session expiry | `expired` state, no silent refresh outside worker | T13 |
| TM14 | Ambiguous or personal scope fallback | Typed refusals, no default tenant | T14 |
| TM15 | Duplicate or replayed actions | Idempotency keys, `RejectDuplicate` | T16 |
| TM16 | Tool surface drift toward checkout | Closed allowlist and contract test | T0, T15 |
