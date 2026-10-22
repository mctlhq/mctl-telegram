# A profile-fixed endpoint: `/mcp/core`

Status: Proposed (2026-10-22). Implementation is deferred until Anthropic
replies to the pre-submission email for the Claude Directory listing.
Nothing in this document is built yet; every "today" below describes
`main` at 0.87.3.

## Problem

The restricted profiles of [core-profiles.md](core-profiles.md) are bound
to an OAuth *client*: `MCP_CLIENT_PROFILES` maps an exact `client_id` or
`redirect_uri` to a profile, and the authorization server stamps it into
every token it mints for that client (`prf` claim,
`internal/oauth/server.go` `mintAccessToken` / `profileFor`).

That is the right tool for a client that exists only to be restricted,
such as Town. It is the wrong tool for hosted claude.ai. Every claude.ai
user connects through the same client, so binding that client to
`core-reply` would restrict every claude.ai user of the service, including
the ones who connect the full `/mcp` surface on purpose. The Directory
listing needs a restricted surface; it does not own the claude.ai client.

## Decision (proposed)

Add a second **protected resource**, `https://tg.mctl.ai/mcp/core`, with
its own RFC 9728 metadata. The **resource**, not the client, fixes the
profile: every token for `/mcp/core` carries `prf=core-reply`, whatever
client asked for it. The Directory entry points at `/mcp/core`; a user who
adds `https://tg.mctl.ai/mcp` by hand keeps today's surface.

The endpoint is named after the profile it serves, not after a client, so
it is `/mcp/core` and not `/mcp/claude` (core-profiles.md, Problem: no
per-client endpoints). Any client may use it and gets the same surface.

### What exists today, and what this changes

Grounded in `main` (0.87.3):

| Area | Today | With this design |
|---|---|---|
| Resource indicator | `/oauth/authorize` and `/oauth/token` ignore an RFC 8707 `resource` parameter; nothing in `internal/oauth` reads it. | Both read it, and an unknown value is `invalid_target`. |
| Audience | One deployment-wide `aud`: `OAUTH_JWT_AUDIENCE`, or none (`mintAccessToken`). The verifier checks it only if configured, and requires it only with `OAUTH_JWT_AUDIENCE_REQUIRED=true` (`localjwt.CheckAudience`). | `aud` is the resource URL. `/mcp/core` requires `aud=https://tg.mctl.ai/mcp/core` unconditionally. |
| Profile source | Client binding only (`toolprofile.Bindings.Resolve`), re-resolved at each refresh. | Resource first: `/mcp/core` fixes `core-reply`. `/mcp` keeps the client binding unchanged. |
| Code and refresh family | `authCode` and `db.RefreshToken` carry `client_id`, `redirect_uri`, scope; no resource. | Both carry the resource, and rotation copies it. |
| PRM | `/.well-known/oauth-protected-resource` and `.../oauth-protected-resource/mcp` (`cmd/server/main.go` `protectedResource`). | Adds `.../oauth-protected-resource/mcp/core` with `resource: https://tg.mctl.ai/mcp/core`. |
| Routing | `mux.Mount(cfg.MCPPath, ...)` forwards every sub-path, and mcp-go's `StreamableHTTPServer.ServeHTTP` does not check the path, so **`/mcp/core` today is served as the full `/mcp`**. `ResourceMetadata.wwwAuthenticate` also points every `/mcp/...` path at the `/mcp` metadata. | `/mcp/core` is its own route with its own middleware and challenge. |
| Enforcement | `internal/mcp/profiles.go`: `profileAllows` on `tools/list` and `tools/call` (through `WithToolFilter`), `profileArgGuard` on arguments, `profile_denied` audit. `auth.MCPMiddleware` is the only route that admits a profiled credential. | Reused unchanged on `/mcp/core`; the endpoint adds an audience and profile check in front of it. |

The routing row is a precondition, not only a change: **do not publish
`/mcp/core` anywhere (Directory entry, docs, landing page) before the
implementation ships**, because until then that URL is the full surface.

### Required properties

1. **A request without `resource` never yields a full-surface token usable
   on `/mcp/core`.** An authorization request with no `resource` is bound
   to the default resource, `https://tg.mctl.ai/mcp`, so existing clients
   keep working unchanged. The token it yields carries the `/mcp` audience
   (or the legacy deployment audience), and `/mcp/core` accepts **only**
   tokens whose `aud` is exactly `https://tg.mctl.ai/mcp/core`. A token
   with no `aud`, the legacy `OAUTH_JWT_AUDIENCE`, or several audiences is
   refused there with 401 `invalid_token`, whatever
   `OAUTH_JWT_AUDIENCE_REQUIRED` says. A `resource` that names neither
   resource is `invalid_target` (RFC 8707 §2), never a fallback to the
   default.

2. **The code and the refresh family keep the resource.** `/oauth/authorize`
   stores the resource in the authorization code. The code exchange mints
   for that resource; a `resource` on the token request must equal it
   (absent means "the code's"), otherwise `invalid_target` and no token.
   The family's first row stores it and every rotation copies it, like
   `redirect_uri` in core-profiles step 5. A refresh request may repeat the
   same `resource` or omit it; any other value is `invalid_target`. Refresh
   **never** changes or widens the resource or the profile: a `/mcp/core`
   family always mints `aud=/mcp/core`, `prf=core-reply`, and a change to
   `MCP_CLIENT_PROFILES` cannot move it to another profile or to no
   profile. A family issued before the column exists (NULL) is a `/mcp`
   family; it can never refresh into `/mcp/core`.

   The resource fixes the profile only on `/mcp/core`. On `/mcp` the
   client binding is still re-resolved at every refresh (core-profiles
   decision 1). If a client bound to a *different* profile asks for
   `/mcp/core`, the authorization is refused with `invalid_target` rather
   than picking one of the two silently; see Open questions.

3. **Enforced on every `tools/call`, both ways.** The surface on
   `/mcp/core` is enforced by the server on every `tools/call`, not only
   in `tools/list`: a hidden tool called by name is refused and audited
   `profile_denied`, and the `core-reply` argument rules are checked in
   the handler (`profileArgGuard`). In front of that, the `/mcp/core`
   middleware refuses any token whose `aud` is not the `/mcp/core`
   resource, and any token for that resource whose `prf` is not
   `core-reply` (defence in depth: the mint should make that impossible).
   The `/mcp` middleware refuses a token whose `aud` is the `/mcp/core`
   resource, so a restricted token cannot be replayed against the full
   endpoint, where the profile would still apply but a later change could
   make it not. Both refusals are 401 `invalid_token` with the matching
   `resource_metadata` in the challenge. Every other authenticated route
   already refuses profiled credentials (`auth.Middleware`, 403); a
   `/mcp/core` token is profiled, so it stays refused there.

4. **A change to `core-reply` is a change to the listing.** The Directory
   listing will describe the `core-reply` surface (9 tools, which reads
   are per-chat, that `send_reply` sends only a server-bound draft). Any
   change to the `core-reply` tool set or its argument rules
   (`internal/toolprofile`, `docs/tool-descriptors.core-reply.json`)
   therefore requires a review of the listing claims in the same pull
   request, in addition to the product-update entry the gate already
   demands: [ADR 0007](../adr/0007-tool-surface-as-contract.md) and the
   `product-updates` CI job (`cmd/productupdates`,
   [`docs/product-updates/`](../product-updates/README.md)), which diffs
   the per-profile snapshot (core-profiles rollout step 3). A change that
   the listing no longer describes truthfully is not merged until the
   listing is updated or the change is dropped.

5. **The user and the reviewer see the same surface.** There is no
   reviewer resource, profile or client binding. A Directory reviewer and a
   user connect to the same URL and get the same `tools/list`; the profile
   comes from the resource, never from the account. What may differ is
   the outcome of a call that the send gate decides (the reviewer/demo
   account is preview-only for `send_reply`, core-profiles "As
   implemented"), which is behaviour behind an unchanged surface, not a
   different surface.

6. **Town is not migrated automatically.** Town keeps connecting to `/mcp`
   with its client binding (core-profiles rollout step 4). Moving Town to
   `/mcp/core` is a separate decision with its own change, because it
   changes Town's audience and refresh families and every live Town
   connection would have to authorize again.

### Implementation outline (for when it is unblocked)

- `internal/oauth`: parse and validate `resource` on authorize and token;
  `authCode.Resource`; `mintAccessToken` takes the resource, sets `aud` to
  it and, for `/mcp/core`, `prf=core-reply` without consulting
  `profileFor`.
- `internal/db`: nullable `resource` column on `oauth_refresh_tokens`,
  copied on rotation, NULL meaning the default resource.
- `internal/auth`: a resource-aware MCP middleware: exact `aud` match on
  `/mcp/core`, rejection of the core audience on `/mcp`, `prf` check, and
  `ResourceMetadata.wwwAuthenticate` pointing `/mcp/core` at its own
  metadata.
- `cmd/server`: mount `/mcp/core` explicitly (before `/mcp`, so the
  sub-path no longer falls through) and serve its PRM alias.
- AS metadata keeps one issuer; both resources name it.

## Readiness checks

Each check is proven both ways: it passes on the converged code, and it
fails when the named mutation is applied. A check that cannot be made to
fail does not count.

| Check | Green | Mutation that must turn it red |
|---|---|---|
| `tools/list` on `/mcp/core` returns exactly the 9 `core-reply` tools, equal to `docs/tool-descriptors.core-reply.json`. | 9 names, schemas equal to the snapshot. | Mint `/mcp/core` tokens without `prf` (or let the endpoint serve the unprofiled surface). |
| A hidden tool (e.g. `send_message`, `get_media`) called directly by `tools/call` on `/mcp/core` is refused and audited `profile_denied`; so is a listed tool called outside its rule (`search_messages` without `peer`). | Refusal plus audit row. | Apply the profile only in the `tools/list` filter, not on the call path. |
| A token for another resource is refused: a `/mcp` (or no-`aud`) token on `/mcp/core`, and a `/mcp/core` token on `/mcp`. | 401 `invalid_token` both ways. | Replace the exact `aud` match with today's optional `CheckAudience`. |
| Refresh does not widen: a `/mcp/core` family refreshed with no `resource`, with `resource=/mcp`, and after `MCP_CLIENT_PROFILES` changes, still mints `aud=/mcp/core`, `prf=core-reply`, or is refused. | Same audience and profile, or `invalid_target`. | Drop the stored resource on rotation, or re-resolve the profile from the client binding for a core family. |
| A request with no `resource` gets no full token for `/mcp/core`: the token it yields is refused on `/mcp/core`. | 401 on `/mcp/core`. | Default a missing `resource` to `/mcp/core`, or accept a missing `aud` there. |

## Open questions

- A client bound to `core-readonly` asking for `/mcp/core`: refuse (as
  proposed), or mint the intersection? The `prf` claim names one profile,
  so an intersection would need a named profile of its own.
- Whether `/mcp/core` also gets a `core-readonly` sibling. Not needed for
  the listing; out of scope.
- The Telegram-terms limits in core-profiles.md ("what a profile does not
  solve") apply unchanged: a fixed endpoint narrows the surface, it does
  not obtain consent from the other people in a chat.
