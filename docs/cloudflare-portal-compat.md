# Cloudflare MCP Portal compatibility (issue #585)

This document is the operator runbook for the Cloudflare MCP Portal
compatibility spike (`mctlhq/.github#44`, roadmap `mctlhq/.github#35`). It
covers the current mctl-telegram OAuth contract, how to register a Portal as
a pre-registered exact-redirect client, how to run `cmd/mcpprobe`, and how to
read the resulting three-row evidence matrix.

This spike does **not** change production `/mcp` transport/session
configuration (`#568` owns that decision), does not add confidential-client
OAuth support, and does not change MTProto or Local Bridge ownership,
replica count, or HPA semantics.

Every hostname and callback URI in this document is a **synthetic
placeholder** (`portal.example.test`). Never paste a real Cloudflare
hostname, production credential, token, or callback URI into this file —
paste it only into the operator's own deployment configuration (Vault /
`OAUTH_PREREGISTERED_CLIENTS`), never into a document that lands in this
public git history.

## 1. The current mctl OAuth contract

`GET /.well-known/oauth-authorization-server` on any mctl-telegram
deployment currently advertises:

```json
{
  "token_endpoint_auth_methods_supported": ["none"],
  "code_challenge_methods_supported": ["S256"]
}
```

In plain terms: mctl-telegram is a **public-client, PKCE-S256-only**
authorization server today. There is no `client_secret_basic` /
`client_secret_post` path. This is a load-bearing constraint for the whole
Portal integration, not an implementation detail:

- The preferred Portal path (below) MUST work with
  `token_endpoint_auth_method=none` + PKCE-S256.
- If the Cloudflare MCP Portal (or whichever product Cloudflare ships this
  integration under) requires a confidential-client method instead, this
  spike's Phase B is **BLOCKED** by definition. Do not add
  `client_secret_basic`/`client_secret_post` support to unblock it — that
  changes mctl's authorization-server threat model and requires its own
  security-reviewed issue and design, not an ad hoc opt-in inside this
  spike.

## 2. Registering the Portal as a pre-registered client

The preferred integration path is **exact-redirect pre-registration**, not
RFC 7591 Dynamic Client Registration (DCR) and not the implicit-host
allowlist (`OAUTH_ALLOWED_IMPLICIT_HOSTS`).

### 2.1 Get the real callback URI from Cloudflare

Cloudflare's Portal UI will display the exact callback URI it expects the
upstream authorization server (mctl-telegram) to redirect back to once a
user completes Telegram sign-in. **Copy that URI verbatim** from the
Cloudflare UI. Do not guess it, do not reuse an example from this document,
and do not truncate or normalize it — redirect_uri matching in
`internal/oauth` is byte-for-byte exact (see the DoD in tasks.md task 11:
path, query, and port variants are all rejected).

### 2.2 Set `OAUTH_PREREGISTERED_CLIENTS`

Configure the deployment's `OAUTH_PREREGISTERED_CLIENTS` environment
variable as a JSON array. Each entry needs a `client_id` (anything unique
and non-secret — it is not a credential) and the exact `redirect_uris` list
copied in step 2.1:

```json
[
  {
    "client_id": "cloudflare-mcp-portal",
    "redirect_uris": ["https://portal.example.test/servers-callback"]
  }
]
```

Notes:

- **No secret field.** This is a public client. Do not invent a
  `client_secret` field or store one alongside this configuration — mctl's
  token endpoint does not check one, and pretending otherwise would be
  misleading about what actually protects the flow (PKCE + exact
  redirect_uri, not a shared secret).
- This works with `OAUTH_ALLOW_IMPLICIT_CLIENT=false` (the default). You do
  not need to enable implicit clients to use a pre-registered client.
- This client never needs to call `POST /oauth/register`. Pre-registration
  and DCR are two independent paths into the same `s.clients` registry; the
  Portal only ever needs the pre-registered path.
- Unsetting `OAUTH_PREREGISTERED_CLIENTS` (or removing an entry) is the
  entire rollback: there is no persisted state, no migration, and no other
  client's behavior changes.

### 2.3 Do NOT do this instead

**Do not** add the Portal's callback host to `OAUTH_ALLOWED_IMPLICIT_HOSTS`
(directly, or via a new variable such as `OAUTH_EXTRA_IMPLICIT_HOSTS` — that
variable does not exist and should not be added). The implicit-host
allowlist is a *weaker* boundary than exact pre-registration: it accepts any
redirect_uri whose host matches, not one specific, exact URI. Exact
client registration is the security boundary this spike relies on; broadening
the implicit-host surface for Cloudflare specifically would quietly weaken
it for every other implicit client too.

## 3. `Require user auth=ON` is mandatory

Whatever the Portal product's exact terminology, the setting that forces a
distinct end-user OAuth flow per Portal user (as opposed to a single shared
service-account style connection) **must be enabled**. See section 6: this
spike's whole purpose on the identity side is to prove that two different
corporate users produce two different upstream mctl/Telegram principals, and
that is only possible if the Portal performs the OAuth dance per user rather
than once for the whole Portal deployment.

## 4. Running `cmd/mcpprobe`

`cmd/mcpprobe` is a standalone black-box HTTP client (no `internal/`
application imports beyond `internal/mcpprobe` itself), separate from
`cmd/canary` and the load generator. It never sends `initialize` to
bootstrap a modern request, never sends `Mcp-Session-Id` on a modern
request, and only ever calls one, structurally read-only-annotated tool.

```sh
# Modern (2026-07-28) probe against a direct deployment or preview:
MCPPROBE_BASE_URL=https://<preview-or-tg.mctl.ai> \
MCPPROBE_MODE=modern \
MCPPROBE_EVIDENCE_SOURCE=direct-deployed \
MCPPROBE_BEARER_TOKEN=<read-only bearer token, optional> \
MCPPROBE_LABEL="tg.mctl.ai direct, modern" \
MCPPROBE_BUILD_REF=$(git rev-parse HEAD) \
go run ./cmd/mcpprobe > modern-direct.json

# Legacy initialize/session probe against the same target:
MCPPROBE_BASE_URL=https://<preview-or-tg.mctl.ai> \
MCPPROBE_MODE=legacy \
MCPPROBE_EVIDENCE_SOURCE=direct-deployed \
MCPPROBE_LABEL="tg.mctl.ai direct, legacy" \
go run ./cmd/mcpprobe > legacy-direct.json

# Same two runs again, but through the Portal's public endpoint instead of
# talking to mctl-telegram directly:
MCPPROBE_BASE_URL=https://<the Portal's MCP endpoint> \
MCPPROBE_MODE=modern \
MCPPROBE_EVIDENCE_SOURCE=cloudflare-portal \
MCPPROBE_BEARER_TOKEN=<token minted through the Portal's OAuth flow> \
MCPPROBE_LABEL="cloudflare portal, modern" \
go run ./cmd/mcpprobe > modern-portal.json
```

`MCPPROBE_EVIDENCE_SOURCE=in-process-current-main` is rejected by the
binary on purpose: that row is produced only by `internal/mcpprobe`'s own
Go tests (`go test ./internal/mcpprobe/...`), which run against a real
`httptest.Server` wrapping `internal/mcp.Server.HTTPHandler()`. A live run
of this binary can never honestly claim to be that row (requirements.md
acceptance criterion D: CI evidence must never be mislabeled as live
evidence, and the same rule runs in reverse).

The printed JSON `Report` is redacted by construction: see
`internal/mcpprobe`'s package doc for exactly which fields exist and why no
bearer token, authorization code, tool result body, chat title, peer id,
phone number, or full session id can appear in it.

## 5. The three-row evidence matrix

| Row | Source | Who produces it | Notes |
|---|---|---|---|
| `in-process-current-main` | `go test ./internal/mcpprobe/...` (CI) | CI | What the current checkout's code supports. Never claim this is live evidence for a deployed build. |
| `direct-deployed` | `cmd/mcpprobe` run directly against a preview or `tg.mctl.ai` | Operator | What the actually-deployed build does, bypassing Cloudflare entirely. May be `PENDING-OPERATOR` until run. |
| `cloudflare-portal` | `cmd/mcpprobe` run through the configured Portal | Operator | What survives the enterprise edge. May be `PENDING-OPERATOR` until run. |

Record modern and legacy observations **separately** for every row — never
collapse them into one `session_required` boolean without the protocol-mode
label attached (see `Report.Modern` / `Report.Legacy` in
`internal/mcpprobe/types.go`).

When posting the matrix back to `mctlhq/.github#44`, distinguish CI/
in-process evidence from deployed-direct and Portal evidence explicitly in
the comment text, not just in a table column an unattentive reader could
miss.

## 6. Two-user identity check (Phase F)

With `Require user auth=ON` (section 3), verify with two distinct corporate
Portal accounts that:

1. User A's Portal session resolves, upstream, to Telegram/mctl principal A
   (a distinct `sub` / Telegram user id).
2. User B's Portal session resolves to a **different** upstream principal B.
3. Neither resolves to the Portal's own admin/sync service credential.

The bounded operator procedure:

```sh
# As Portal user A, through the Portal's UI/flow, obtain a bearer token and run:
MCPPROBE_BASE_URL=<portal mcp endpoint> \
MCPPROBE_MODE=modern \
MCPPROBE_EVIDENCE_SOURCE=cloudflare-portal \
MCPPROBE_BEARER_TOKEN=<user A's token> \
MCPPROBE_READ_ONLY_TOOL=get_my_identity \
MCPPROBE_LABEL="portal user A identity check" \
go run ./cmd/mcpprobe > identity-user-a.json

# Repeat as Portal user B with a distinct token:
MCPPROBE_BASE_URL=<portal mcp endpoint> \
MCPPROBE_MODE=modern \
MCPPROBE_EVIDENCE_SOURCE=cloudflare-portal \
MCPPROBE_BEARER_TOKEN=<user B's token> \
MCPPROBE_READ_ONLY_TOOL=get_my_identity \
MCPPROBE_LABEL="portal user B identity check" \
go run ./cmd/mcpprobe > identity-user-b.json
```

`get_my_identity` is read-only-annotated in `internal/mcp`, so the guard in
`internal/mcpprobe` will call it without further configuration. Compare the
two reports' `tool_call` observations are for the same tool but were served
by genuinely different upstream sessions — this package's redacted `Report`
type deliberately does not carry the tool result body needed to compare
identity values directly, so the operator reads the two JSON tool outputs
recorded outside the report (e.g. from `cmd/mcpprobe`'s own request during a
manual `tools/call`, or a one-off script) to confirm the two `sub`/Telegram
ids differ. This report intentionally cannot make that comparison for you —
see section 7 of design.md ("It contains no ... arbitrary tool result
value").

## 7. MTProto / Local Bridge ownership caveat

The MCP protocol becoming stateless (protocol version 2026-07-28) does
**not** mean mctl-telegram's Telegram-execution layer becomes horizontally
safe. The hosted MTProto client pool and Local Bridge daemon connections are
still application-stateful and pinned per account. Do not use this spike's
modern-protocol findings as justification to:

- increase `mctl-telegram` replica count,
- change the MTProto pool's ownership model, or
- change Local Bridge's per-device connection ownership.

Those remain separate decisions outside this spike's scope, and outside
`#568`'s scope too.

## 8. DCR is compatibility-only; CIMD is the target

`POST /oauth/register` (RFC 7591 Dynamic Client Registration) continues to
work for clients that need it (e.g. Claude.ai, ChatGPT), but it is not an
acceptance dependency for this spike and should not become one for
Cloudflare either: the pre-registered exact-redirect path (section 2) is
the preferred integration for the Portal specifically.

CIMD (client ID metadata documents / whatever the MCP-native registration
mechanism lands as) remains the longer-term target registration direction
once it is supported end-to-end by both mctl-telegram and Cloudflare. Until
then, DCR is a compatibility fallback, not a design goal.
