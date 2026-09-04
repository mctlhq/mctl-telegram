# Local Bridge (M4) — design and implementation status

## Goal

Give users who do not want to trust a server-side MTProto session an
alternative deployment mode. The Telegram session lives on the user's
machine inside a local daemon; tg.mctl.ai is reduced to a relay that
forwards MCP tool calls down to the daemon and shuttles responses back.

Read the trust-model section below before repeating that goal to a user.
The daemon does hold the only *live* session, but the server does not
forget the hosted one, and the relay still sees every payload it routes.

```
┌──────────────┐                       ┌────────────────┐
│  claude.ai   │── MCP /mcp HTTP ────▶ │ tg.mctl.ai     │
└──────────────┘                       │  (relay only)  │
                                       └───────┬────────┘
                                               │ websocket /bridge
                                               │ short-lived JWT (aud=bridge)
                                               ▼
                                       ┌────────────────┐
                                       │ mctl-telegram- │
                                       │ local (daemon) │ ← MTProto session
                                       └───────┬────────┘  encrypted on local disk
                                               │
                                               ▼
                                       ┌────────────────┐
                                       │  Telegram API  │
                                       └────────────────┘
```

## Status in one line

The server half is production-grade and deployed, and the CLI has caught up
with it: `mctl-telegram-local activate` walks a user from nothing to a
connected, read-only daemon with zero operator MCP tool calls, and
`set_send_consent` lets the owner turn real sending on themselves. What
remains is narrower than it used to be: Windows ACL hardening for on-disk
secrets, and the correctness/cross-repo items below. The legacy
`connect --token` path is intentionally still there, unmodified, for accounts
onboarded before this and for operator-driven recovery -- see "Device-bound
credential lifecycle".

## What is implemented

### Server-side

- **Schema columns**: `telegram_accounts.mode` (`'hosted' | 'local'`,
  default `'hosted'`) and `telegram_accounts.bridge_token_hash`
  (`db.go:308,368`). `mode` is the live switch. `bridge_token_hash` is
  **dead schema**: it is created and migrated (`db.go:116-124`) and never
  read or written by any code path. Either wire it up or drop it; leaving
  it suggests a registration check that does not exist.
- **Audit column**: `audit_logs.call_path TEXT DEFAULT 'hosted'`
  distinguishes relay-forwarded calls (`'local'`) from server-side
  hosted calls (`'hosted'`). Included in the hash-chain canonical input
  after `errMsg`. This column is the only reliable evidence that a
  given call actually travelled through the user's machine.
- **Protocol** (`protocol.go`): the JSON envelope the daemon and the
  relay exchange — `call`, `response`, `error`, `ping`, `pong`. Args and
  Result are `json.RawMessage` so the relay does not need to know each
  tool's schema.
- **Hub** (`hub.go`): in-process router that multiplexes per-user daemon
  connections; `Call` blocks until the daemon answers or the deadline
  elapses; `Register`/`Unregister` maintain the singleton-per-user
  invariant. Backpressure via the `pendingCount` atomic: `Hub.Call`
  returns `ErrDaemonOverloaded` above 100 in-flight calls for one
  daemon, so a slow or stuck daemon cannot grow relay memory without
  bound.
- **Websocket transport** (`server.go`): upgrades HTTP to websocket at
  `GET /bridge`; verifies the bearer JWT (`aud="bridge"` required);
  enforces `mode='local'` on the account (`server.go:65-75`); wires into
  the Hub. Ping/pong liveness: the writer pings every 25 s and the
  reader enforces a 5 s pong deadline on the underlying connection.
- **Bridge token endpoint** (`tokenhandler.go`): `POST /api/bridge/token`
  exchanges an MCP JWT for a short-lived bridge JWT (`aud="bridge"`,
  1 h TTL). The verifier requires a `tg_id` claim and the issuer set
  selected by `selectBridgeIssuer`; see `tokenhandler.go:36-41` for the
  incident where a token minted by a different signer broke `/bridge`
  precisely because it carried no `tg_id`.
- **Dispatch in MCP tools** (`internal/mcp/tools.go`): each tool checks
  `telegram_accounts.mode` and, when `'local'`, calls `Hub.Call` via
  `bridgeCall()` instead of `Pool.Borrow`. `ErrNoDaemonConnected`,
  `ErrCallTimeout` and `ErrDaemonOverloaded` map to readable tool
  errors. `BridgeCallsTotal` is incremented with `{tool, status}`.
- **Audit** (`internal/db/store.go`): `LogToolCall` takes a `callPath`;
  bridge-dispatched calls pass `"local"`, hosted calls pass `""`
  (stored as `'hosted'`).
- **Metrics** (`internal/metrics/metrics.go`): `mctl_bridge_active_daemons`
  gauge (Register/Unregister) and `mctl_bridge_calls_total{tool,status}`.
- **Alert**: `MctlBridgeDaemonsFlapping` fires when the gauge changes
  more than 20 times in 10 minutes — a looping reconnect. Its runbook
  section is `docs/runbook.md#mctlbridgedaemonsflapping`.

### Daemon-side (`cmd/local`, ~1600 lines with tests, plus #484's device-identity/credential additions)

All five subcommands are implemented. This section previously described
them as "scaffolded; implementations are deferred", which was wrong and
was read as a status signal by people scoping the work.

1. **`init`** (`main.go:88`) — prompts for `TG_API_ID` / `TG_API_HASH`
   and a passphrase, derives an AES key (Argon2id) from a generated
   salt, stores a `KeyCheck` verifier and writes `config.json` under the
   config directory with `0600`.
2. **`login --phone`** (`main.go`) — interactive Telegram login writing
   the session to the local encrypted store rather than the server DB.
3. **`activate --telegram-id`** (`activate.go`) — the self-service path
   added by #484: generates an Ed25519 device identity on first run,
   drives the browser-based Telegram sign-in/device-approval flow, and
   bootstraps a device-bound credential via the PoP `/nonce` →
   `/credential` round trip, all before it exits. See "Device-bound
   credential lifecycle" below.
4. **`connect --token`** (`main.go:212-288`) — the legacy, still-supported
   path: exchanges an operator-minted MCP JWT for a bridge token via
   `POST /api/bridge/token` and persists **both** the MCP token and the
   bridge token to `bridge_token.json` (`main.go:270-277`,
   `config.go:143-165`). The earlier claim that the bridge token is held in
   memory and lost on restart is false; the design consequence is the
   opposite one, that two bearer tokens sit in a plaintext JSON file on the
   user's disk.
5. **`daemon`** (`daemon.go`) — connects `wss://tg.mctl.ai/bridge`,
   answers pings, and dispatches call envelopes to the local MTProto
   client. On every connection attempt it picks a refresh mechanism based
   on which credential files are on disk: a device-signed PoP refresh
   (`refreshDeviceCredential`, #484) when `activate` produced a device
   credential, or the original bearer-only re-exchange of the stored MCP
   token (`refreshBridgeToken`) otherwise. It never mixes the two for one
   config directory.

The daemon implements eight tools (`daemon.go:394-630`): `list_dialogs`,
`get_unread_messages`, `get_messages`, `send_message`, `send_media`,
`prepare_get_media`, `get_media`, `pin_message`.

## Remaining gaps

### Blocking a user, in the order a user hits them

1. **No user-facing documentation.** Closed by #444: `docs/local-bridge.md`
   is the guide, and the landing copy links it.
2. **No released binary.** Closed by #448: every release now carries
   builds for `darwin/arm64`, `darwin/amd64`, `linux/amd64`,
   `linux/arm64` and `windows/amd64` plus `SHA256SUMS.txt`. They are
   unsigned, so macOS quarantines a browser download and Windows shows a
   SmartScreen prompt on a double-click; fetching with `curl` and running
   from a terminal avoids both. Signing is a deliberate non-decision, not
   an oversight — see the note in #448.
3. **Windows file protection is unsolved.** The daemon writes its config,
   bridge token and session database `0600` and sets a `0o077` umask, but
   NTFS ignores POSIX modes and inherits an ACL from the parent directory
   instead, so on Windows those files carry whatever the user profile
   grants. `cmd/local/umask_windows.go` is a deliberate no-op for the same
   reason. Closing this means setting an explicit ACL through
   `golang.org/x/sys/windows`, and it has not been done or tested. Until
   then the Windows build is usable but its on-disk secrets — including
   both bearer tokens in `bridge_token.json` — are only as protected as
   the profile directory.
4. **Closed for the self-service path by #484; still open, deliberately, for
   legacy `connect --token`.** `activate` never hands a user a token to
   paste: it mints its own device-bound credential end to end through the
   PoP `/nonce` → `/credential` round trip (see "Device-bound credential
   lifecycle" below), so an account onboarded through `activate` never hits
   this gap at all. It remains open for `connect --token`: an operator still
   has to mint a long-lived credential via `mint_worker_token`/
   `POST /api/mcp/worker-token` and hand it to the user out of band before
   `connect` can do anything. (That endpoint's scopes are no longer
   read-only-only, as this note originally said -- passing
   `purpose="local-bridge"` now grants send/pin too -- but it is still a
   single static bearer credential an operator has to mint and transmit,
   which is exactly what the self-service path was built to avoid.) This
   legacy route is retained on purpose, for pre-#484 accounts and
   operator-driven recovery -- see "Legacy worker-token path" below.
5. **Closed by #484.** Enablement used to be an admin MCP tool call, full
   stop: `set_account_mode` (`internal/mcp/tools.go:1011-1094`) flips an
   existing hosted row, and `provision_local_account`
   (`internal/mcp/tools.go`, added for issue #468) creates a fresh
   local-only row for a Telegram id that has never completed a hosted
   login. Both still exist and are both still admin-gated, but neither is
   on the happy path any more: `mctl-telegram-local activate` now drives a
   user through browser-based Telegram sign-in and device approval and
   provisions the local-only row itself (internally, the same
   `EnsureUserByTelegramID` + `ProvisionLocalAccount` sequence
   `provision_local_account` exposes as a tool -- see
   `internal/oauth/local_bridge_activate.go`), with zero admin MCP tool
   calls involved. `set_account_mode` remains the only route for migrating
   an *existing* hosted account, which `activate` cannot do and does not try
   to.
6. **Five tools are unsupported in local mode** and return an explicit
   error rather than routing to the bridge: `edit_message`,
   `delete_messages`, `forward_messages`, `search_messages`,
   `set_reaction` (`internal/mcp/tools.go:1532,1588,1648,1707,1778`).
   Separately, `fetch_media=true` is refused on `get_unread_messages` and
   `get_messages` (`tools.go:279,496`) with a pointer to
   `prepare_get_media` + `get_media`, which the daemon does implement.
7. **No hosted listener.** The Communication Agent's always-on listener
   needs a server-side Telegram client, which a local-mode account does
   not have.

### Correctness gaps

1. **Fixed (issue #468). Revoking the hosted session and running local
   mode used to be mutually exclusive.** `GetAccountMode` used to return
   `"hosted"` whenever `revoked_at IS NOT NULL`, so revoking a local
   account's session (idle/absolute TTL, explicit disconnect) silently
   reverted it to hosted mode and `/bridge` then refused the daemon.
   `GetAccountMode` (`internal/db/store.go`) no longer filters on
   `revoked_at`: mode is read as a property of the account row, so a
   revoked session no longer changes what mode the row reports.
2. **Fixed (issue #468). The idle sweeper used to silently break local
   accounts.** Bridge calls never touch `last_used_at` — only
   `Pool.Borrow` does (`clientpool.go:167,460`) — so `SweepIdleSessions`
   used to revoke an actively used local account after the idle TTL
   unless its Telegram id was manually added to
   `SESSION_TTL_EXEMPT_TG_IDS`. `SweepIdleSessions` and
   `SweepAbsoluteSessions` (`internal/db/store.go`) now carry an
   `AND mode <> 'local'` predicate, so local-mode rows are excluded from
   both sweeps unconditionally — the exemption list is no longer required
   for Local Bridge accounts (it remains available for its original,
   unrelated use: long-lived hosted operator/service identities).
3. **`bridge_token_hash` is never written**, so nothing ties a
   registered daemon to a specific issued token.
4. **The relay must run at one replica.** The Hub is in-process, so a
   daemon is reachable only from the pod that holds its websocket. The
   deployment is `strategy: Recreate` with no replica override, which
   satisfies this by accident rather than by constraint.

### Cross-repo

- **mctl-portal** (optional): a "Connected daemons" view so a user can
  see when their daemon last reached the relay.

### Rejected — do not implement

An earlier revision listed an `mctl-api` OAuth scope `local-bridge` plus
an `/oauth/local-bridge/authorize` endpoint emitting `aud="bridge"`, and
a matching mctl-web Worker redirect. **This cannot work as written.**
mctl-api has no Telegram identity to put in the required `tg_id` claim,
its tokens carry no `aud` claim at all, and its `scope` is the literal
string `"mctl"` (`mctl-api/internal/auth/oauth_server.go:66,109,361`).
The bridge verifier would reject every such token, and making it accept
them means changing the token format for all mctl clients. The bridge
token is minted by mctl-telegram, which is the only service that knows
the Telegram identity. Removed from #138 for the same reason.

## Device-bound credential lifecycle

This is what `cmd/local activate`/`daemon` and the server's PoP-gated
endpoints (`internal/oauth/local_bridge_credential.go`) do together, and it
is the mechanism the "Closed by #484" notes above point at.

1. **Bootstrap trust boundary.** The device generates its own Ed25519
   keypair locally (`ed25519.GenerateKey`, `cmd/local/config.go`) the first
   time `activate` runs on a machine. Only the public key -- sent once, at
   `POST /api/local-bridge/activate/start` -- and per-request signatures
   (`POST .../nonce` → sign → `POST .../credential` or `.../refresh`) ever
   cross the network. The server records the public key and verifies
   signatures against it; it never receives, stores, or needs the private
   key, and therefore cannot forge a signature on the device's behalf.
2. **First issuance vs. refresh.** `POST .../credential` (first issuance) is
   unconditionally read-only: it mints scopes from the read-only allowlist
   regardless of the account's `send_enabled` value at that moment
   (`local_bridge_credential.go`'s own comment: "ALWAYS read-only at first
   issuance"). `POST .../refresh` -- every later call -- re-derives scopes
   from a live `IsSendEnabled` read every single time, so a `set_send_consent`
   change is reflected on the device's very next refresh with no
   re-activation step.
3. **One-lineage-per-device invariant.** `current_jti`/`credential_issued_at`
   are claimed exactly once, atomically, at first issuance
   (`ClaimDeviceCredentialLineage`) and carried forward unchanged by every
   later refresh -- a refresh never claims a new `jti` of its own. This is
   deliberate: it is what lets a single `RevokeDeviceAndDenylist` call, keyed
   on that one `jti`, invalidate every credential the device has ever held,
   rather than only the one currently in its hands.
4. **Revocation SLA.** For an already-connected daemon, revocation is
   immediate: `revoke_local_bridge_device` calls `Hub.EvictDevice(userID,
   deviceID)` in the same request that records the revocation, force-closing
   the live `/bridge` websocket rather than waiting for it to notice on its
   own. For any future connect or refresh attempt, revocation is immediate
   once `RevokeDeviceAndDenylist`'s transaction commits: the denylist it
   writes to is consulted on every PoP credential verification, so there is
   no independent cache-TTL-style propagation delay to wait out on top of
   the commit itself.

### Legacy worker-token path (compatibility only)

`mint_worker_token` / `POST /api/mcp/worker-token` still mint a single
static bearer worker token (30-day default TTL, 90-day ceiling), and
`connect --token` plus the daemon's unchanged bearer-only bridge-token
re-exchange still consume it exactly as they did before #484. This path is
kept for exactly two reasons: accounts onboarded before this change, and
operator-driven recovery when the browser-driven `activate` flow cannot be
completed for some reason. It is not part of new onboarding -- `activate`
never hands a user a token to paste, by design, and nothing in this proposal
removes or degrades the legacy path's own behavior.

## Trust-model notes (mirrored on /security)

- **Whether the server ever held the session bytes depends on how the
  account became local.** `session_encrypted` is nullable
  (`internal/db/db.go`, made nullable for issue #468). An account
  provisioned directly as local-only -- via a user's own `activate` run
  (the normal path since #484) or via the admin `provision_local_account`
  tool (kept for operator-driven recovery) -- has `session_encrypted = NULL`
  from insert — the server never holds a copy of that session at all. An
  account migrated from an existing hosted
  login via `set_account_mode` keeps the sealed blob stored when it first
  connected; switching to local mode stops the server from *using* that
  session, it does not delete it, and clearing it is explicitly out of
  scope for #468. Revoking a migrated account's hosted session no longer
  reverts it to hosted mode (correctness gap 1 above is fixed) — the
  stored blob simply becomes vestigial. A user who wants a migrated
  account's stored blob rendered useless should terminate that session
  from their own Telegram client (Settings → Devices), which leaves a
  dead auth key in the database.
- **The relay sees MCP payloads.** It has to, in order to route them.
  Message bodies pass through relay memory for the duration of a call.
  This is not end-to-end encryption.
- Genuine end-to-end secrecy from the server would require the MCP
  client to encrypt payloads to the daemon's public key, which needs
  client support that does not exist today.

## Migration story

- New accounts default to `mode='hosted'`; the change is backward
  compatible.
- A brand-new account reaches `mode='local'` by the user's own
  `mctl-telegram-local activate` run -- no operator step -- before the first
  `daemon`. An existing hosted account instead needs an operator to flip it
  with `set_account_mode mode="local"`. Either way, the websocket
  registration ties the daemon to that row, and between the flip (self- or
  operator-driven) and a running daemon the user's connector returns
  "local-bridge daemon not connected" (`internal/mcp/tools.go:111-113`)
  rather than hanging or losing authorization.
- Rollback is the same UPDATE with `mode='hosted'` (via `set_account_mode`;
  there is no self-service equivalent), verified by a subsequent call
  landing with `call_path='hosted'`.
