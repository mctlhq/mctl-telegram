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

The server half is production-grade and deployed. The daemon is written
and tested. What is missing is everything between the two and a user:
there is no released binary, no user-facing documentation, and no way
for a user to turn the mode on without an operator editing the database
by hand.

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

### Daemon-side (`cmd/local`, ~1600 lines with tests)

All four subcommands are implemented. This section previously described
them as "scaffolded; implementations are deferred", which was wrong and
was read as a status signal by people scoping the work.

1. **`init`** (`main.go:88`) — prompts for `TG_API_ID` / `TG_API_HASH`
   and a passphrase, derives an AES key (Argon2id) from a generated
   salt, stores a `KeyCheck` verifier and writes `config.json` under the
   config directory with `0600`.
2. **`login --phone`** (`main.go`) — interactive Telegram login writing
   the session to the local encrypted store rather than the server DB.
3. **`connect --token`** (`main.go:212-288`) — exchanges an MCP JWT for
   a bridge token via `POST /api/bridge/token` and persists **both** the
   MCP token and the bridge token to `bridge_token.json`
   (`main.go:270-277`, `config.go:143-165`). The earlier claim that the
   bridge token is held in memory and lost on restart is false; the
   design consequence is the opposite one, that two bearer tokens sit in
   a plaintext JSON file on the user's disk.
4. **`daemon`** (`daemon.go`) — connects `wss://tg.mctl.ai/bridge`,
   answers pings, dispatches call envelopes to the local MTProto client
   and re-exchanges the stored MCP token for a fresh bridge token before
   expiry.

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
4. **No long-lived MCP token to hand to `connect`.** The daemon
   re-exchanges the stored MCP token indefinitely, but OAuth access
   tokens live one hour (24 h ceiling), so an ordinary OAuth token
   produces a daemon that dies within the hour. The one endpoint that
   mints a long-lived token, `POST /api/mcp/worker-token`, is restricted
   to read-only scopes (`internal/workertoken/tokenhandler.go:50-53`),
   so it cannot carry send. Today the only route is hand-signing an
   HS256 token with `OAUTH_JWT_SIGNING_KEY`.
5. **No self-serve enablement.** Enablement is still an admin MCP tool call,
   not something a user can trigger themselves. Two admin tools now write
   `mode='local'`: `set_account_mode` (`internal/mcp/tools.go:1011-1094`)
   flips an existing hosted row, and `provision_local_account`
   (`internal/mcp/tools.go`, added for issue #468) creates a fresh
   local-only row for a Telegram id that has never completed a hosted
   login, with `session_encrypted` left `NULL`.
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

## Trust-model notes (mirrored on /security)

- **Whether the server ever held the session bytes depends on how the
  account became local.** `session_encrypted` is nullable
  (`internal/db/db.go`, made nullable for issue #468). An account
  provisioned directly as local-only via `provision_local_account` has
  `session_encrypted = NULL` from insert — the server never holds a copy
  of that session at all. An account migrated from an existing hosted
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
- An operator flips a row to `mode='local'` before the first `connect`;
  the websocket registration ties the daemon to that row. Between the
  flip and a running daemon the user's connector returns
  "local-bridge daemon not connected" (`internal/mcp/tools.go:111-113`)
  rather than hanging or losing authorization.
- Rollback is the same UPDATE with `mode='hosted'`, verified by a
  subsequent call landing with `call_path='hosted'`.
