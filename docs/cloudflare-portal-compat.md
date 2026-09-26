# MCP gateway compatibility: protocol and OAuth evidence

This document is the operator half of the Phase A+B compatibility gate for
[mctl-telegram#585](https://github.com/mctlhq/mctl-telegram/issues/585), the execution child of
[.github#44](https://github.com/mctlhq/.github/issues/44) under the enterprise MCP roadmap
[.github#35](https://github.com/mctlhq/.github/issues/35).

It exists because "we are on a recent SDK" is not evidence. Every claim below is either measured by
`cmd/mcpprobe` or marked as not yet measured. A cell nobody has run says `PENDING-OPERATOR`, not `PASS`.

## Running the probe

The probe measures one endpoint, one protocol path, one run. The bearer credential is read from an
environment variable and never from a flag, so it stays out of the shell history and the process table.

```bash
export MCPPROBE_TOKEN='<bearer for the resource>'

# The modern, stateless path.
go run ./cmd/mcpprobe -url https://<host>/mcp -mode modern -source direct-deployed

# The legacy path, for comparison. The version is explicit: nothing is negotiated on your behalf.
go run ./cmd/mcpprobe -url https://<host>/mcp -mode legacy -legacy-version 2025-06-18 -source direct-deployed
```

`-json` emits the same report as JSON for pasting into an issue. `-source` labels the evidence and must
be honest: `in-process-current-main` is what a test binary produces, `direct-deployed` is a run against a
deployed endpoint, and `cloudflare-portal` is a run through a configured gateway. Exit status distinguishes four
outcomes, because "the endpoint is wrong" and "nothing was measured" call for different reactions:

| code | meaning |
|---|---|
| 0 | every mandatory cell ran and passed |
| 1 | a conformance failure was measured, or the endpoint could not be reached |
| 2 | the probe itself was invoked wrongly |
| 3 | the run completed but a mandatory cell never executed, so it proves nothing |

Code 3 is the one to watch against a gateway: an edge that answers a protocol violation with `401` or
`403` leaves every negative unmeasured, and a pipeline reading only "not 1" would call that a pass.

Only one tool is ever invoked, and only when the server's own `tools/list` annotation reports it
read-only. A tool with no annotation is refused: silence is not a promise of safety.

## What has been measured

### `in-process-current-main` — the handler on this branch

Produced by `go test ./internal/mcpprobe/` and reproduced by hand with the CLI.

| path | discover | tools/list | read-only call | session | binding enforced |
|---|---|---|---|---|---|
| modern `2026-07-28` | PASS | PASS | PASS | none minted | PASS, all six negatives |
| legacy `2025-06-18` | n/a | PASS | PASS | minted, required, any well-formed value accepted | n/a |

Three findings worth stating plainly. The first two contradict what was assumed before the probe existed and come from probe runs; the third was verified by a separate experiment rather than by a probe, and is marked as such because this document's whole argument is that a claim must say how it was obtained:

1. **The modern path already works, unchanged.** The server advertises `2026-07-28` and serves
   `server/discover` today. It mints no session identifier on that path, and it enforces the routing
   headers: `initialize` is refused as a removed method, and a missing `Mcp-Protocol-Version` or a
   missing or mismatched `Mcp-Method` or `Mcp-Name` is refused before the request reaches dispatch.
2. **The legacy path requires the session header, but not the issuer.** A request that carries no
   identifier is refused; a request carrying a well-formed identifier the server never issued is served.
   Validation is of shape, not existence. A router in front of this server must forward the header and
   need not pin a request to the process that issued it.
3. **Restricting the advertised protocol versions does not disable the legacy path.** A server built with
   only `2026-07-28` advertised still completed a full legacy session: `initialize` answered 200,
   negotiated `2025-06-18`, minted a session and served `tools/call`. Retiring legacy is therefore a code
   change, not a configuration flag. That work belongs to #568.

### `direct-deployed` — PENDING-OPERATOR

Run the two commands above against the deployed endpoint with a real bearer. Nothing in continuous
integration can produce this row, and an in-process result must never be relabelled as one.

### `cloudflare-portal` — PENDING-OPERATOR

Requires a configured portal. See the next section for the gate that decides whether this row is even
reachable.

## The OAuth gate

This authorization server is a public-client design. It advertises `token_endpoint_auth_methods_supported`
of `["none"]` and proves the client with PKCE S256. There is no client-credential authentication, and
adding one would change the threat model of the authorization server, not just its configuration.

The only sanctioned experiment is therefore: **manual pre-registration, `token_endpoint_auth_method` of
`none`, PKCE S256, per-user authorization enabled.** A gateway that stores an unused credential field to
satisfy its own schema is acceptable — the value is never presented to us and never authenticates
anything. A gateway that genuinely *requires* client-credential authentication is not something to work
around here: record Phase B as **BLOCKED** and open a separate, security-reviewed issue to decide whether
this server should ever support it. Do not reach for a credential-bearing token endpoint auth method as a
fallback.

Client ID Metadata Documents are the direction of travel once both ends support them end to end. Until
then, dynamic client registration is kept as a fallback restricted to the gateway's exact callbacks: see
[Automatic (DCR) mode](#automatic-dcr-mode) below.

### Registering the gateway's callback

Copy the redirect URI from the gateway's own configuration screen. Do not guess it and do not hard-code
it in this repository; it differs between a portal-specific callback and a shared one, and providers
match it exactly.

```bash
OAUTH_PREREGISTERED_CLIENTS='[{"client_id":"<id from the gateway>","client_name":"Enterprise MCP portal","redirect_uris":["<exact callback from the gateway>"]}]'
```

The record is matched byte for byte. A path suffix, an added query, a different port or a fragment are all
rejected, and so is anything but `https` outside a loopback address. Unknown fields are refused at startup
rather than ignored, so a record carrying something this contract does not support fails the boot instead
of silently doing less than the operator intended.

### Automatic (DCR) mode

Pre-registration puts the Cloudflare portal in **manual** mode, which freezes the tool catalogue at the first
login (the portal only re-syncs servers it registered itself) and needs a hand-pasted `client_id`. The
org rule [.github#137](https://github.com/mctlhq/.github/issues/137) therefore runs every upstream that can
do dynamic registration in **automatic** mode, with registration restricted to the portal's own callbacks.
This server does that through `OAUTH_DCR_REDIRECT_URIS`, a comma-separated list of exact redirect URIs:

```bash
OAUTH_DCR_REDIRECT_URIS='<portal servers-callback>,<dashboard oauth-callback for this server id>'
```

The portal's registration carries both its shared servers-callback and the dashboard's per-server admin
callback, which embeds the Cloudflare account id and the portal's id for this server; list both, copied
exactly. The rules:

- A `POST /oauth/register` whose `redirect_uris` are **all** on the list is accepted. The hosts never join
  `OAUTH_ALLOWED_IMPLICIT_HOSTS`, so nothing changes for unregistered `client_id`s, which is the boundary
  #585 set.
- A registration naming a listed URI together with any other URI is refused with `invalid_redirect_uri`.
- A registration naming no listed URI takes the implicit-host path exactly as before. Unset, the variable
  changes nothing at all.
- Matching is byte for byte, and entries are validated at startup like pre-registered redirect URIs.
- The registered client's `client_id` is derived from its redirect set, so the portal re-registering gets
  the same client back and a replayed registration adds no row. Its `client_name` is always the
  server-assigned `Cloudflare MCP portal`; whatever name the registration sends is ignored. It is kept past the 24h registration TTL
  (the portal keeps using it for every user login) and at `/oauth/authorize` each redirect must still be on
  the current list, so deleting an entry revokes it without a database change.
- An authorization request that names no `scope` is granted the principal's full entitlement, which for a
  client-tier user is every scope in `scopes_supported`; one that names scopes gets exactly those. That is
  what the portal needs in automatic mode, where its scope cannot be pinned.

Pre-registration and this list can coexist during a migration: the pre-registered `client_id` keeps working
for a server still in manual mode.

**Do not put the callback in `OAUTH_ALLOWED_IMPLICIT_HOSTS`.** That list governs redirect acceptance for
clients that never registered, and widening it to onboard one gateway would loosen the boundary for every
unregistered client. Exact pre-registration is the narrower tool and the correct one. A pre-registered
record bypasses the host allowlist and nothing else: the shape checks, the exact match and PKCE all still
apply.

## Per-user identity

With per-user authorization enabled, two corporate users must arrive as two distinct principals upstream.
Verify it with two real accounts, not one account twice. If both collapse onto a single subject, the
gateway is authenticating as itself and the deployment is not fit for use, regardless of what the protocol
rows say. A synchronization or administrative credential must never become an end user's credential.

## What this does not tell you

Protocol statelessness is not execution statelessness. This server owns live Telegram sessions and live
Local Bridge connections in process, so a passing modern row is not permission to add replicas. That
question belongs to [mctl-telegram#568](https://github.com/mctlhq/mctl-telegram/issues/568).

Header preservation through a gateway cannot be confirmed from the client side. A 200 response does not
prove the routing headers survived the hop; it only proves the request was answered. Until it can be
observed upstream, that cell stays `PENDING-OPERATOR`.

A note on spelling: the protocol version header is case-insensitive, so `Mcp-Protocol-Version` and
`MCP-Protocol-Version` are the same header to any Go server or HTTP/2 hop. Nothing depends on which form
a client sends.

## Portal tool allowlist — the drift guard

The portal exposes a tool only when its mapping carries an explicit `enabled: true` for it, and hides a tool it has an entry for with `enabled: false`; what it does with a tool it has **no** entry for depends on `default_disabled`, which is why the mapping is kept at `default_disabled: true` plus an explicit entry for every tool. The measured behaviour behind that choice is finding 6 in mctlhq/.github#44.

That configuration is only as good as its coverage, and the upstream tool set changes with releases. `docs/portal-allowlist.json` is the source of truth; `internal/mcp/portal_allowlist_test.go` fails the build when the set of tools this server registers differs from the file in either direction, when a tool is marked enabled without `readOnlyHint: true`, or when an enabled tool carries no `reason`. The hint and the reason answer different questions: `readOnlyHint` says a tool has no side effects, and `get_messages`, `get_unread_messages` and `search_messages` all carry it while returning message bodies. The reason is the privacy decision — what the tool exposes and why that is acceptable on a shared surface — and it is made in the same diff that flips the flag, where a reviewer sees it. Adding a tool therefore forces a decision in the same PR. Publishing the decision is automatic. When a change to `docs/portal-allowlist.json` lands on `main`, `.github/workflows/portal-allowlist-dispatch.yml` sends the file to mctlhq/mctl-gitops. There it is vendored byte-identical and opened as a PR whose `cloudflare-plan` names every tool that flips; the portal changes only when that PR merges and an approved `cloudflare-apply` runs (mctlhq/mctl-gitops#1370). Nothing in this repository talks to Cloudflare any more. The gitops side refuses a file that leaves a synced tool undecided, lets a widening through only once a human edits its `baseline.json` in that PR, and checks nightly that its vendored copy still matches this file. A portal access token carries the tool set as of its issuance; re-issue tokens after the apply.
