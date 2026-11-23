# AgentsPodium (Hermes Agent) compatibility spike: Phase 0 report

Issue: [mctlhq/mctl-telegram#1401](https://github.com/mctlhq/mctl-telegram/issues/1401).
Supersedes the tracking role of
[#1384](https://github.com/mctlhq/mctl-telegram/issues/1384), closed *not
planned* on 2026-11-22 because per-user redirect hosts could not be admitted
as one exact host.

Scope is `GO_RESEARCH`: read-only compatibility and security analysis. This
report changes no allowlist, deploys nothing, creates no pod, signs in to no
external account and touches no real Telegram session.

**Verdict: HOLD.** Gate A is not complete, so Gate B was not started and
Gate C was not tested. Every vendor-reported path in this report is recorded
as a *claim about client identity*, not as evidence of an MCTL sign-in. The
source for all vendor claims is the issue body dated 2026-11-22; no private
mail is reproduced here.

## 1. What this spike could and could not measure

Two kinds of work were in scope and only one of them was possible in this
working environment.

| Kind of check | Possible here | Why |
| --- | --- | --- |
| What MCTL's own OAuth/CIMD code does with a path-scoped vendor host | yes | the code is in this repository; every claim in sections 3 and 4 cites a file and a line |
| Fetching `https://agentspodium.com/...` and inspecting live documents | **no** | this environment has no outbound network access, so no document, certificate chain, redirect set or cache header was retrieved |
| Running a hosted Hermes pod against `https://tg.mctl.ai/mcp` | **no** | needs an admitted host, a vendor-updated test pod and a designated test Telegram account; none exists and none is authorized by this issue |

Everything in section 2 is therefore marked `not measured here`. That is a
statement about this report, not a claim that the vendor's paths are wrong.

## 2. Gate A — vendor domain and metadata verification

| Gate A check | Status | Detail |
| --- | --- | --- |
| Same-operator identity for `agentspodium.com` and RadianceTeam, valid HTTPS, stable production domain | not measured here | no network access; requires an independent client, WHOIS/TLS inspection and operator correlation |
| GET the example CIMD document, save sanitized `client_id`, `redirect_uris`, `token_endpoint_auth_method`, content type, status, chain, redirects, cache | not measured here | the vendor-reported example is `https://agentspodium.com/oauth/mcp/clients/personal-assistant-ae0764/mctl.json`; nothing was fetched, so no field is confirmed |
| `/oauth/mcp/clients/<pod>/<server>.json` binds to callback `/oauth/mcp/cb/<pod>/<server>` | **fails on MCTL's side** | MCTL cannot enforce this binding today — finding **F1**, section 3 |
| Impact of admitting one vendor-owned host under current `OAUTH_ALLOWED_IMPLICIT_HOSTS` and CIMD policy, including negatives | analysed, not applied | section 4; prefix-boundary, traversal, replay and PKCE negatives are covered by existing code, the callback binding is not |
| Independent P1/P2 security review and a narrow candidate GitOps PR | findings in section 3; **no PR proposed** | F1 must be answered before any candidate entry is worth reviewing. Human authorization is required regardless. |

Gate A verdict: **HOLD**. Two checks are unmeasured for want of network
access, and one fails on MCTL's own enforcement.

## 3. Security findings

Line references are to this commit.

### F1 (P1) — a path-scoped CIMD entry binds the document, never the callback

`validateClient` sends a URL `client_id` down the CIMD branch, where the
redirect URI is checked against the fetched document and nothing else:
`internal/oauth/server.go:3788`–`3798`, whose own comment states the redirect
URIs come "from the document on the client's own host, never from a
registration or the implicit-host allowlist".

The document parser accepts any `https` redirect with a host:
`internal/oauth/cimd/cimd.go:736`. Only `jwks_uri` is pinned to the
`client_id` host (`internal/oauth/cimd/cimd.go:698`); `redirect_uris` are
not pinned to the host, let alone to the path prefix that admitted the
document.

Consequence: admitting `agentspodium.com/oauth/mcp/clients/<pod>/` admits
whatever that document says. The document may name a callback under another
pod's `/oauth/mcp/cb/<other-pod>/...` path, or on a third-party host
entirely. `internal/oauth/cimd_client_test.go:156`–`157` pin that a redirect
*absent from* the document is refused; no test pins — and no code
enforces — that a cross-host or cross-pod redirect *present in* the document
is refused.

So the vendor's claimed `clients/<pod>/<server>.json` → `cb/<pod>/<server>`
binding is, from MCTL's position, unverifiable at authorization time. The
whole of its security rests on `agentspodium.com` not letting a pod owner
author or influence that JSON. That is a vendor-side property this spike did
not test and cannot test from here.

Before admission, one of these must hold:

1. the vendor evidences that the CIMD document is server-generated from the
   pod record, that a pod owner cannot set `redirect_uris`, and that a pod
   identifier is never reassigned; or
2. MCTL constrains accepted `redirect_uris` for a path-scoped entry — the
   natural rule being that a document admitted by a path-scoped entry may
   only declare redirects on the same host, and optionally under a
   configured callback prefix. `cimd.Document.AllowEntry`
   (`internal/oauth/cimd/cimd.go:120`–`122`) already carries the admitting
   entry into the server, so the information needed for such a rule is
   present. That is an implementation change, out of scope for
   `GO_RESEARCH`.

### F2 (P2) — the document cache delays vendor-side revocation

A document's lifetime comes from its `Cache-Control`, clamped to
`[30s, 24h]` with a one-hour default: `internal/oauth/cimd/cimd.go:66`–`68`
and `621`–`633`. A pod reassigned to another owner, or a `redirect_uris`
entry the vendor withdraws, therefore keeps working until the cached
document expires — up to 24 hours if the vendor serves a long `max-age`.

Any admission should record the observed `Cache-Control` of the live
document as part of the evidence, which section 2 could not collect. MCTL's
own lever stays removal of the allowlist entry, which also ends that
tenant's refreshes (admission runbook, step 5).

### F3 (P2, largely mitigated) — cross-pod authorization-code forwarding

Existing code already blocks the straightforward forms. PKCE S256 is
mandatory at `/oauth/authorize` (`internal/oauth/server.go:1550`) and S256 is
the only advertised method (`:1499`). An authorization code is bound to both
the `client_id` and the exact `redirect_uri` presented at exchange
(`internal/oauth/server.go:1088`–`1091`, `2560`–`2564`), and a refresh token
is bound to its `client_id` (`:2873`, `:3126`). Each pod has its own CIMD
URL, hence its own `client_id`, so a code issued for pod A cannot be
redeemed as pod B.

The residual exposure is exactly F1: if pod A's document can name a callback
pod A does not control, the code is delivered to the wrong party before any
of these bindings help. Rated P2 only because it is not independently
exploitable.

### F4 (P2) — an admitted client with no profile gets the default scope surface

The admission runbook already states it (step 2): an admitted client without
an `MCP_CLIENT_PROFILES` record gets the default scope surface. A pilot pod
should be bound by `client_id` to a read-only profile — the repository ships
`docs/tool-descriptors.core-readonly.json`, and Town is the precedent for a
restricted binding (`core-reply`) in the compatibility matrix. Admitting a
host without that binding would put the pilot's read-only premise on user
consent alone.

### F5 — negatives that existing code already handles (no action)

Verified by reading the code and its tests, not by a live run:

- **Prefix boundary.** `pod-a/` does not admit `pod-ab/`
  (`internal/oauth/cimd/pathscope_test.go:31`–`33`). The mandatory trailing
  slash on an entry (`internal/oauth/cimd/cimd.go:215`–`217`) is what makes
  the prefix match land on a segment boundary.
- **Path traversal and encoding.** Dot segments and their percent-encoded
  forms are refused when the `client_id` is parsed
  (`internal/oauth/cimd/cimd.go:171`–`176`), and `%2f`, `%5c` and `%25` are
  refused before a path-scoped match
  (`internal/oauth/cimd/cimd.go:384`–`387`).
- **Entry shape.** A path-scoped entry cannot be host-wide, cannot carry a
  port, userinfo, query or fragment, and cannot be combined with a
  `.suffix` entry (`internal/oauth/cimd/cimd.go:190`–`229`). No wildcard
  subdomain entry is proposed anywhere in this report.
- **Replay.** A `private_key_jwt` assertion's `jti` is consumed once, in
  Postgres across replicas (`internal/oauth/cimd_client.go:149`–`181`).
- **Unregistered pod / invalid client_id.** A URL `client_id` outside every
  entry is refused with `ErrNotAllowed` and never falls through to the DCR
  or implicit path (`internal/oauth/cimd/cimd.go:410`–`417`,
  `internal/oauth/cimd_client.go:63`–`81`, and
  `TestCIMD_AuthorizeRefusals`).

## 4. Candidate admission — described, not proposed

Recorded so that a later owner decision starts from an exact shape rather
than a sketch. **Not applied, and not recommended until F1 is answered.**

- `OAUTH_CIMD_ALLOWED_HOSTS` would gain one path-scoped entry of the form
  `agentspodium.com/oauth/mcp/clients/<pod>/`, with the trailing slash. The
  path is compared byte for byte and case-sensitively
  (`internal/oauth/cimd/pathscope_test.go:36`), so the pod identifier must
  be copied exactly from the live document URL.
- It must be paired in the same change with an `MCP_CLIENT_PROFILES`
  `client_id` binding to a read-only profile (F4).
- No `OAUTH_ALLOWED_IMPLICIT_HOSTS` entry is needed or wanted: the CIMD path
  does not consult that list (F1), and a DCR entry for `agentspodium.com`
  would admit the whole host rather than one pod.
- No `.agentspodium.com` suffix entry, under any circumstance.
- Rollback is removal of the entry, which also cuts that tenant's refreshes
  (admission runbook, step 5).

Production refused one Hermes registration on 2026-11-13 with
`redirect_host_not_allowed`; that is the only MCTL-side observation of this
platform to date, and it predates the vendor's reported change.

## 5. Gate B — hosted read-only Hermes matrix

Not started: it is gated on Gate A plus an approved admission, neither of
which exists. The ten checks carried over from #1384 are listed so the
matrix has one place to be filled in.

| # | Check | Status |
| --- | --- | --- |
| 1 | Approved host synced in ArgoCD | not run |
| 2 | CIMD document accepted by `tg.mctl.ai` | not run |
| 3 | Telegram sign-in completes | not run |
| 4 | Exact granted scopes recorded | not run |
| 5 | `tools/list` returns the expected read-only surface | not run |
| 6 | One `list_dialogs` call succeeds | not run |
| 7 | Send is denied while unconsented | not run |
| 8 | Refresh succeeds | not run |
| 9 | Revocation takes effect | not run |
| 10 | User-visible errors are intelligible | not run |

Until row 6 is evidenced, `docs/platforms/compatibility.md` and
`https://tg.mctl.ai/platforms` must keep Hermes Agent at `not tested`. The
vendor's reported end-to-end result with Notion MCP is evidence about the
vendor's client, not about `tg.mctl.ai`.

## 6. Gate C — hosting research

Not tested. No question in Gate C (custom `linux/amd64` or `linux/arm64` Go
binary, persistent `0600` config, backup, restart, outbound websocket to
`wss://tg.mctl.ai/bridge`, operator visibility of secrets, export and exit)
could be answered without the vendor's hosting documentation or a live
account.

One distinction must survive into any later write-up: a Go binary running
inside a third party's infrastructure is **not** the Local Bridge as
`docs/local-bridge.md` defines it. The documented product is a bridge on a
machine the user controls, and even there the relay sees tool arguments and
results in transit. Neither arrangement may be described as end-to-end
encrypted, zero knowledge or fully private from either operator.

## 7. Product and distribution

Baseline: MCTL traffic and conversions attributable to this collaboration
are `UNKNOWN`. No referral link has been issued to MCTL, so loops A, B and C
have no measured events — not zero, unmeasured. The partner terms quoted in
the issue (25% of paid running pod revenue, USDT/USDC or Telegram Stars,
$20 minimum, twelve-month rate protection after a rate change) are recorded
as *the vendor's published terms as of 2026-11-22*, unverified here, and
carry no implication of a payout. Whether a referral for one's own published
agent and a referral to another author's agent can both pay out is
explicitly unresolved and must not be read as 50%.

The product hypothesis remains untested, and the honest form of it is
narrow: AgentsPodium's native Telegram bot-token channel is a conversation
surface, so registering a bot token does not by itself grant an agent access
to the user's existing dialogs and history. That is a statement about the
native channel, not a claim that no other AgentsPodium integration can reach
user-account data. The controlled prompt comparison the issue asks for
(same prompt, bot channel only versus MCTL user-account MCP) has not been
run, so no claim of incremental value is made here.

Phase 2 remains open: `PARTNER_PILOT_GO | REVISE_ONBOARDING |
TECHNICAL_HOLD | DEFER_DISTRIBUTION`. On the evidence in this report the
defensible position is `TECHNICAL_HOLD` until F1 is answered, after which
the distribution question is worth a separate owner decision.

## 8. Outstanding items for the owner

1. Answer F1: a vendor statement on who authors `redirect_uris` and whether
   pod identifiers are reassigned, or an MCTL-side rule binding a
   path-scoped document's redirects to its own host and callback prefix.
2. Fetch and archive the live CIMD document with sanitized headers, chain
   and `Cache-Control` (F2).
3. Decide whether to admit one pod at all. Admission requires explicit owner
   authorization; this issue grants none.
4. If admitted, pair the entry with a read-only `MCP_CLIENT_PROFILES`
   binding in the same change (F4).
5. Only after a Gate B run reaches check 6 may the Hermes Agent row and the
   `/platforms` page move off `not tested`.
