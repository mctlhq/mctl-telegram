# Glovo connector feasibility (issue #1227, M0)

Labels: `SOURCE` (link and date), `OBSERVED` (seen first-hand), `UNVERIFIED`
(not checked; never to be read as fact).

## 1. Evidence table

| Item | Finding | Label |
| --- | --- | --- |
| Glovo Discover MCP | Search-only; offers no account or basket access. | UNVERIFIED (to be confirmed against the vendor's published description before G3) |
| `denya/glovo-skill` v0.2.1 | MIT, Node 18+, Chrome session bootstrap, local single-user `session.json`; basket read/add/change/remove after approval; no checkout. | SOURCE: the project repository, as cited in issue #1227, 2026-11-08 |
| Official or partner API | No sanctioned consumer API is known. | UNVERIFIED |
| Session lifecycle and refresh | Lifetime and refresh behaviour of the consumer session are unknown. | UNVERIFIED |
| Mobile basket continuity | Whether a basket written through the web session appears in the mobile app is unknown. | UNVERIFIED |
| Montenegro coverage | Unknown. | UNVERIFIED |
| Glovo consumer terms | Whether automated or delegated access is permitted is unknown. | UNVERIFIED |
| MIT license obligations | Copying or deriving code requires preserving the copyright and license notice. | SOURCE: MIT license text, 2026-11-08 |

## 2. Options

| Option | Assessment |
| --- | --- |
| Reference only (read the project, write Go) | Preferred if G3 passes. No Node runtime, no hosted `session.json`. Keep the MIT notice if any code is derived. |
| Subprocess (run the Node project) | Rejected: single-user local session store and Chrome bootstrap cannot be hosted multi-tenant. |
| Reimplementation in Go | Same as the preferred option; behind build tag `glovo_real`, off by default. |

## 3. Verdict

`BLOCKED_PROVIDER_ACCESS` for any real account until G3 (sanctioned partner API,
or a written legal review of the consumer API and terms, plus verified mobile basket
continuity). `GO_FAKE_MULTITENANT` for M1 with a synthetic provider only. No checkout,
order or payment is ever in scope, and no hosted or shared `session.json` is allowed.

## Appendix: follow-up issue drafts (not opened; separate approval required)

1. mctl-api contract (gate G2). Separate implementation proposal and approved, merged PR:
   scope resolve, connections CRUD, order index, pilot allowlist, `aar_` action approval
   and single-use receipt enforcement, tests for tenant and same-tenant owner separation
   and revocation. mctl-api#948 and #950 are contract-only and do not count. Separate
   approval required.
2. mctl-gitops namespace and identity work (gate G5): two Temporal namespaces, verified
   Nexus endpoint or authenticated mctl-api bridge, denial tests for provider to control
   and provider to DevLoop; depends on mctl-gitops#2456 and #2457. Separate approval
   required.
3. Glovo partner or legal outreach (gate G3): request a sanctioned API or a written
   position on delegated consumer access; verify mobile basket continuity. Separate
   approval required.
