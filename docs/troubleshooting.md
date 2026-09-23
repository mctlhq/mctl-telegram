# Troubleshooting: error families clients actually hit

This page is client-facing: it maps the exact string an MCP tool, the OAuth
endpoints, or the in-browser sign-in wizard hand back to a client or LLM
agent, to what to do next. It is not the alert-driven runbook — for
on-call playbooks tied to Prometheus alert rules, see
[docs/runbook.md](runbook.md).

A 30-day pass over production `audit_logs` (issue
[#669](https://github.com/mctlhq/mctl-telegram/issues/669)) found that almost
every non-`ok` row falls into one of eight families below, and roughly 70% of
them are the first one: an agent passing a bare `channel:<id>` copied from a
message link or forwarded-message header, which carries no access hash.

Each family section below follows the same shape: **Symptom**, **Cause**,
**What the client or agent should do**, **What the operator can do**. Where a
section quotes a string produced by `mtprotoErrCatalog` or
`mtprotoTransientCatalog` in `internal/mcp/errorcatalog.go`, the quote is
preceded by an HTML comment naming the MTProto code (e.g.
`<!-- catalog: PEER_ID_INVALID -->`) — those markers, and the quoted text
after them, are checked verbatim against the source by
`internal/mcp/troubleshooting_doc_test.go` (and the equivalent OAuth-error
quotes by `internal/oauth/troubleshooting_doc_test.go`), so those quoted
strings cannot silently drift from the code. `docs/troubleshooting_test.go`
additionally pins the nine section headings. The 30-day window and the
~70%-share figure above are a point-in-time read of the `audit_logs` pass
from issue #669 — narrative context, not something any test re-derives or
keeps in sync as traffic shifts.

## Table of contents

1. [Peer id errors (`PEER_ID_INVALID` / `CHANNEL_INVALID` / `CHAT_ID_INVALID`)](#1-peer-id-errors)
2. [`get_media` confirmation errors](#2-get_media-confirmation-errors)
3. [Send-code `FLOOD_WAIT` during onboarding](#3-send-code-flood_wait-during-onboarding)
4. [`AUTH_KEY_UNREGISTERED`](#4-auth_key_unregistered)
5. [Exhausted login budget](#5-exhausted-login-budget)
6. [`JWT expired`](#6-jwt-expired)
7. [`invalid_redirect_uri`](#7-invalid_redirect_uri)
8. [`RPC_CALL_FAIL`](#8-rpc_call_fail)
9. [Supported OAuth clients and redirect rules](#9-supported-oauth-clients-and-redirect-rules)

---

## 1. Peer id errors

<a id="1-peer-id-errors"></a>

Covers `PEER_ID_INVALID`, `CHANNEL_INVALID`, and `CHAT_ID_INVALID` — Telegram
rejecting a peer reference because the server-side `InputPeer` it built
carries a zero (or wrong) access hash.

### Symptom

A tool call (`get_messages`, `send_message`, `prepare_get_media`, `pin_message`,
etc.) that takes a `peer` argument fails with one of:

<!-- catalog: PEER_ID_INVALID -->
```
The peer ID is not valid for this account. Use @username, user:<id>, chat:<id>, or channel:<id>. Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.
```

<!-- catalog: CHANNEL_INVALID -->
```
The channel or supergroup reference is not valid for this account. Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.
```

<!-- catalog: CHAT_ID_INVALID -->
```
The chat reference is not valid for this account. Call list_dialogs and pass the id exactly as returned there — a bare numeric id copied from a link or forwarded-message header carries no access hash.
```

### Cause

MTProto peer objects (`InputPeerChannel`, `InputPeerUser`) require an
`access_hash` alongside the numeric id, and Telegram only ever discloses that
hash when it returns the peer as part of a dialog list or another API result
that already includes it. A `channel:<id>` (or `user:<id>`) spec built from a
message link, a forwarded-message header, or a hand-typed numeric id carries
no access hash, so the server can only construct a zero-hash `InputPeer` —
which Telegram rejects with `PEER_ID_INVALID` / `CHANNEL_INVALID` /
`CHAT_ID_INVALID`. This is the single most common non-`ok` row in
`audit_logs` (~70% of all error rows, per issue #669).

### What the client or agent should do

Call `list_dialogs` first and pass the `id` field **exactly as returned
there** — never construct a `channel:<id>`/`user:<id>` spec from a message
link, a forwarded-message header, or any other source. This is the same
wording already used by the hand-written fallbacks in
`internal/telegram/media_download.go` and `internal/telegram/messages.go`
(e.g. `messages.go:587` and `messages.go:616`) when a peer falls out of the
cached dialog list and a direct resolution also fails.

### What the operator can do

There is no server-side remedy — the fix is entirely in what the caller
passes. If a specific integration keeps hitting this, check its logs for
where it derives the peer spec (a chat-forwarding feature or a link parser
are common sources of a bare numeric id).

---

## 2. `get_media` confirmation errors

<a id="2-get_media-confirmation-errors"></a>

### Symptom

`get_media` returns one of four confirmation-related errors instead of the
downloaded file. Quoted verbatim from `internal/mcp/media_tools.go`:

```
confirmation_id not found, expired, or already used
confirmation_id was issued for a different (peer, message_id) — re-run prepare_get_media
confirmation_id belongs to another identity
download already in progress for this confirmation_id — retry shortly
```

### Cause

`get_media` is deliberately a two-step prepare→confirm flow:
`prepare_get_media` issues a `confirmation_id` bound to (peer, message_id,
user), and `get_media` must be called with that same id and the same (peer,
message_id) within `ConfirmationTTL` — **10 minutes** today
(`internal/mcp/confirm.go`). The confirmation store is in-memory, single-shot,
and lost on pod restart by design (see `ConfirmStore` in `confirm.go`), so
each of the four errors corresponds to a specific way the handshake broke:

- **not found, expired, or already used** — the id was never issued, the
  10-minute TTL passed, a pod restarted, or a prior `get_media` call already
  consumed it. These three causes are deliberately collapsed into one message
  so a caller probing the id space cannot distinguish them.
- **issued for a different (peer, message_id)** — the id is real but
  `get_media` was called with a different peer or message_id than the
  matching `prepare_get_media` call used.
- **belongs to another identity** — the id was issued to a different
  authenticated user.
- **download already in progress** — a concurrent `get_media` call is
  already consuming this same id.

### What the client or agent should do

Call `prepare_get_media` immediately before `get_media`, reuse the returned
`confirmation_id` unchanged, pass the identical `peer` and `message_id`, and
do not let more than 10 minutes elapse between the two calls. If you see
"not found, expired, or already used", simply call `prepare_get_media` again
and retry — do not retry `get_media` with the same id, it is gone. If you see
"download already in progress", wait briefly and retry `get_media` with the
same id (a concurrent call may already be running the same download); do not
call `prepare_get_media` again for this same attempt.

### What the operator can do

None of these four are recoverable server-side — each reflects a client
protocol error against the confirm/prepare handshake. Multiple errors of the
"different (peer, message_id)" kind from one integration usually mean it is
caching or reusing a stale `confirmation_id`.

---

## 3. Send-code `FLOOD_WAIT` during onboarding

<a id="3-send-code-flood_wait-during-onboarding"></a>

### Symptom

The in-browser sign-in wizard (phone number step) shows a generic
`Timed out contacting Telegram. Please try again.` message roughly 90 seconds
after submitting the phone number. This text never names Telegram's rate
limit — the wizard's per-step wait gives up before the real reason is known.

### Cause

Telegram's `auth.sendCode` RPC returned a `FLOOD_WAIT_N` error, meaning
Telegram's own anti-abuse gate is throttling SendCode for this phone number
or IP. The HTTP handler for the phone step only waits up to
`enableSendCodeWait` (90 seconds, `internal/oauth/enable_access.go`) before
rendering the generic timeout screen, but the underlying login goroutine
keeps running against a background context bounded by `OAUTH_CODE_TTL`
(default 10 minutes, `internal/config/config.go`). A typical send-code flood
wait is longer than 90 seconds, so by the time the goroutine actually learns
the true `FLOOD_WAIT_N` reason, the HTTP handler has already returned — the
browser never sees the specific wait duration. This is one of the three
families whose real text never reaches a tool response at all: the evidence
only exists server-side.

### What the client or agent should do

Wait several minutes and start the sign-in flow again with the same phone
number. This is Telegram's own rate limit, not a bug in the login flow —
retrying immediately will not help.

### What the operator can do

Grep the service logs for the `"enable: telegram login failed"` slog line
(`internal/oauth/enable_access.go`) and read its `err` field — that is
currently the only place the actual `FLOOD_WAIT_<N>` code and wait duration
are recorded. There is no server-side way to shorten Telegram's own flood
wait.

---

## 4. `AUTH_KEY_UNREGISTERED`

<a id="4-auth_key_unregistered"></a>

### Symptom

Every MCP tool call for the connected account starts failing with:

```
Your Telegram session is no longer valid — it was signed out from another device, or the account is unavailable. Reconnect the connector to sign in again.
```

(This exact text is `sessionErrText(db.ErrSessionRevoked)` in
`internal/mcp/tools.go`, asserted verbatim by
`internal/mcp/troubleshooting_doc_test.go`.)

### Cause

`internal/telegram/clientpool.go` classifies `AUTH_KEY_UNREGISTERED` — along
with `AUTH_KEY_DUPLICATED`, `AUTH_KEY_INVALID`, `SESSION_REVOKED`,
`SESSION_EXPIRED`, `USER_DEACTIVATED`, and `USER_DEACTIVATED_BAN` — as
`db.ErrSessionRevoked`: the stored MTProto session was killed server-side by
Telegram, not merely half-finished. Common triggers: the user signed out of
"mctl-telegram" from Telegram's own **Settings → Devices** list, the account
was deactivated, or the session was superseded.

### What the client or agent should do

**There is no server-side remedy.** The client must reconnect at
[tg.mctl.ai/telegram/connect](https://tg.mctl.ai/telegram/connect) to
establish a fresh session; no tool call can revive a revoked one.

### What the operator can do

Confirm this is a genuine revocation (the account really was signed out or
deactivated on Telegram's side) rather than a transient pool issue by
checking session pool logs/metrics around the same timestamp. There is no way
to un-revoke a session from this codebase — the user must sign in again.

---

## 5. Exhausted login budget

<a id="5-exhausted-login-budget"></a>

### Symptom

Partway through the phone → SMS code → 2FA wizard, a step suddenly renders:

```
This sign-in session has expired. Close this page and reconnect from your MCP client.
```

### Cause

`lookupEnable` (`internal/oauth/enable_access.go`) rejects any `/code` or
`/password` step submitted once the enable-session has existed longer than
`OAUTH_CODE_TTL` (env var, default 10 minutes —
`internal/config/config.go`). This is a whole-flow budget spanning phone,
code, and 2FA password together, distinct from the 90-second
`enableSendCodeWait` per-step wait used by the send-code family above: a user
who pauses too long between steps — or whose SendCode was itself delayed by a
flood wait — can run out of this budget before finishing. Like the send-code
`FLOOD_WAIT` family, the generic expiry text is all the browser ever sees;
the true cause is only visible server-side.

### What the client or agent should do

Restart from `tg.mctl.ai/telegram/connect` and complete phone → SMS code →
2FA promptly, without leaving the tab idle between steps.

### What the operator can do

None — the `OAUTH_CODE_TTL` deadline is deliberate (RFC 6749 §4.1.2
recommends authorization artifacts be short-lived), not a bug. If it proves
too short for a given userbase it can be tuned via the `OAUTH_CODE_TTL`
environment variable. In the logs, look for repeated
`"connect:failed:timeout"` `LogToolCall` entries for the same user with no
matching `"enable: telegram login succeeded"` line.

---

## 6. `JWT expired`

<a id="6-jwt-expired"></a>

### Symptom

An MCP request (or any authenticated HTTP request) returns `401
Unauthorized`.

### Cause

The bearer access token's expiry has passed. `internal/auth/localjwt/issuer.go`
and `internal/auth/sharedhmac/verifier.go` both return the literal error text
`JWT expired` when this happens, and `internal/auth/middleware.go`'s
`classifyAuthError` maps any error containing that substring to the
`jwt_expired` reason label used in `mctl_auth_failures_total`. Access tokens
are intentionally short-lived (`AccessTokenTTL`, default 1 hour) — this is
expected, routine behavior for any client that has been idle.

### What the client or agent should do

Use the refresh token to obtain a new access token via `/oauth/token`
(`grant_type=refresh_token`). If the client has no refresh token (or the
refresh token itself is rejected with `invalid_grant`), re-run the OAuth
authorization-code flow from the start.

### What the operator can do

None needed for an isolated occurrence — this is normal token expiry. A
sustained spike in `jwt_expired`-labeled `mctl_auth_failures_total` usually
means a client is not implementing refresh correctly (it should refresh
before or immediately upon expiry, not require a full re-authorization every
hour); see the `JwtFailures` alert playbook in
[docs/runbook.md](runbook.md#jwtfailures).

---

## 7. `invalid_redirect_uri`

<a id="7-invalid_redirect_uri"></a>

### Symptom

A Dynamic Client Registration request to `POST /oauth/register` with a
`redirect_uri` using a custom app scheme — for example
`cursor://anonymous/callback` — is refused with an OAuth
`error=invalid_redirect_uri` response, HTTP 400. An `/oauth/authorize` call
for an implicit client with the same custom-scheme `redirect_uri` hits the
same underlying check (`validateImplicitRedirectURI`), but
`handleAuthorize` reports every `validateClient` failure as
`error=invalid_client`, HTTP 400 — the `/oauth/authorize` response never
carries `error=invalid_redirect_uri`. For that exact input, the underlying
validation error text is the same on both endpoints:

<!-- source: validateRedirectURIShape (internal/oauth/server.go), asserted by internal/oauth/troubleshooting_doc_test.go -->
```
redirect_uri scheme "cursor" is not allowed (must be https except for http loopback)
```

### Cause

`validateRedirectURIShape` (`internal/oauth/server.go`) requires every
`redirect_uri` to use `https`, with exactly one exception: `http` is allowed
when the host is a loopback address (`localhost`, `127.0.0.1`, or `::1`, per
RFC 8252 §7.3 — see `isLoopbackHost`). Custom URL schemes such as `cursor://`
are rejected outright, with no allowlist mechanism today. This affects any
native/desktop client that expects to register its own custom scheme as a
redirect target.

### What the client or agent should do

Register an `https://` redirect URI, or — if the client is a native/desktop
app that would otherwise use a custom scheme — use a loopback redirect
instead: `http://127.0.0.1:<ephemeral-port>/callback` (or `localhost`/`::1`).
Loopback redirects need no prior allowlisting (see
[section 9](#9-supported-oauth-clients-and-redirect-rules)).

Fixing `invalid_redirect_uri` specifically for `cursor://`-style clients is
tracked separately in issue #668 and is out of scope for this page.

### What the operator can do

None — this is enforced security policy (an open-redirect guard), not a bug.
Do not manually special-case a custom scheme without a security review; see
issue #668 for the tracked follow-up.

---

## 8. `RPC_CALL_FAIL`

<a id="8-rpc_call_fail"></a>

### Symptom

An MCP tool call fails with a message that includes the raw string
`RPC_CALL_FAIL`, for example `get_messages: rpc error code 500:
RPC_CALL_FAIL`. Unlike every family above, the raw MTProto code is visible in
the text the client receives.

### Cause

`RPC_CALL_FAIL` is Telegram's own generic internal-error code (HTTP-style
500) meaning Telegram's infrastructure failed to service that specific RPC —
it is not the caller's fault. `RPC_CALL_FAIL` is not a key in
`mtprotoErrCatalog` or `mtprotoTransientCatalog`
(`internal/mcp/errorcatalog.go`), so `mtprotoErrResult` returns `nil` for it
and the generic `toolErr("%s: %v", tool, err)` fallback renders the raw
`error.Error()` text — which, unlike every catalog entry, does include the
literal MTProto code (`TestMtprotoErrResultCatalog` in
`internal/mcp/errorcatalog_test.go` only asserts catalog entries strip it;
uncataloged codes like this one are exempt by construction).

There is also a related, narrower known gap worth flagging here: the
FLOOD_WAIT handling in `internal/mcp/errorcatalog.go`'s `floodWaitSeconds`
only recognizes the `FLOOD_WAIT_N` / `SLOWMODE_WAIT_N` prefixes, while
`telegram.FloodWaitSeconds` (`internal/telegram/floodwait.go`) also handles
`FLOOD_PREMIUM_WAIT_N`. A premium-account flood wait hitting an MCP tool
therefore falls through past `floodWaitSeconds` to the generic handler
instead of getting the structured `flood_wait` envelope — recorded here as a
known gap tracked under issue #669, not fixed by this page.

### What the client or agent should do

Retry the same call once or twice with a short backoff. This is a transient
failure on Telegram's side, not something the caller did wrong, and does not
warrant changing the peer/arguments before retrying.

### What the operator can do

An isolated `RPC_CALL_FAIL` needs no action. If it recurs across many tools
and users at once, check Telegram's own service status — there is no
server-side mitigation available in this codebase today.

---

## 9. Supported OAuth clients and redirect rules

<a id="9-supported-oauth-clients-and-redirect-rules"></a>

Stated up front so a client developer does not have to discover these rules
by trial and error at `/oauth/register`:

- **Scheme:** `redirect_uri` must be `https://...`, with one exception —
  `http://` is accepted when the host is a loopback address (`localhost`,
  `127.0.0.1`, or `::1`). No other scheme (including custom app schemes like
  `cursor://`) is accepted. See [section 7](#7-invalid_redirect_uri) for the
  exact rejection text.
- **No userinfo:** a `redirect_uri` containing `user@host` userinfo is
  always rejected, regardless of scheme.
- **No backslashes:** a `redirect_uri` containing `\` is rejected before
  parsing, because URL parsers disagree on how to interpret it.
- **Implicit clients** (no prior `/oauth/register` call): the redirect
  host must be on the `AllowedImplicitHosts` allowlist. The built-in default
  is `claude.ai`, `claude.com`, `chatgpt.com`, `localhost`, and `127.0.0.1`;
  deployments override this via the `OAUTH_ALLOWED_IMPLICIT_HOSTS`
  environment variable (comma-separated), which **replaces** the default
  list rather than extending it.
- **Loopback redirects are always accepted** regardless of the implicit-host
  allowlist, so CLI and native clients binding an ephemeral local port need
  no prior registration entry.
- **Dynamic Client Registration** (`POST /oauth/register`, RFC 7591) applies
  the same scheme/host rules as implicit clients to every `redirect_uri` it
  is given, so a registration call cannot smuggle in a redirect target that
  the implicit path would have refused.

For the day-to-day OAuth refresh/re-authorization behavior after a scope
change, see
[docs/runbook.md#oauth-refresh-reauthorization](runbook.md#oauth-refresh-reauthorization).
