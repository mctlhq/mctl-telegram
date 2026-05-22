# Local Bridge (M4) — design and implementation status

## Goal

Give users who do not want to trust a server-side MTProto session an
alternative deployment mode. The Telegram session lives on the user's
machine inside a local daemon; tg.mctl.ai is reduced to a relay that
forwards MCP tool calls down to the daemon and shuttles responses back.
The server never sees the user's session bytes; the only thing it
persists for a local-mode user is the principal mapping and an audit
trail of which tool was called, when.

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

## What is implemented (as of M4)

### Server-side

- **Schema columns**: `telegram_accounts.mode` (`'hosted' | 'local'`,
  default `'hosted'`) and `telegram_accounts.bridge_token_hash`
  (SHA-256 of the most-recent registered daemon JWT). Idempotent
  migration via `addColumnIfMissing`.
- **Audit column**: `audit_logs.call_path TEXT DEFAULT 'hosted'`
  distinguishes relay-forwarded calls (`'local'`) from server-side
  hosted calls (`'hosted'`). Included in the hash-chain canonical input
  after `errMsg`.
- **Protocol** (`internal/bridge/protocol.go`): the JSON envelope shape
  the daemon and the relay exchange — `call`, `response`, `error`,
  `ping`, `pong`. Args and Result are `json.RawMessage` so the relay
  doesn't need to know each tool's schema.
- **Hub** (`internal/bridge/hub.go`): in-process router that
  multiplexes per-user daemon connections; `Call` blocks until the
  daemon answers or the deadline elapses; `Register`/`Unregister`
  manage the singleton-per-user invariant. Backpressure via
  `pendingCount` atomic: `Hub.Call` returns `ErrDaemonOverloaded` when
  more than 100 calls are in flight for a daemon, preventing runaway
  memory growth under slow or stuck daemons.
- **Websocket transport** (`internal/bridge/server.go`): upgrades HTTP
  to websocket at `GET /bridge`; verifies bearer JWT (must have
  `aud="bridge"`); enforces `mode='local'` on the account; wires into
  the Hub. Ping/pong liveness: writer sends a ping every 25 s, reader
  enforces a 5 s pong deadline by setting a read deadline on the
  underlying connection.
- **Bridge token endpoint** (`internal/bridge/tokenhandler.go`):
  `POST /api/bridge/token` exchanges an MCP JWT for a short-lived
  bridge JWT (`aud="bridge"`, 1 h TTL) that the daemon uses to
  authenticate its websocket connection.
- **Dispatch in MCP tools** (`internal/mcp/tools.go`): every read/write
  tool checks `telegram_accounts.mode`; when `'local'`, calls
  `Hub.Call` via `bridgeCall()` instead of `Pool.Borrow`. Errors
  `ErrNoDaemonConnected`, `ErrCallTimeout`, and `ErrDaemonOverloaded`
  map to clean human-readable tool errors. `BridgeCallsTotal` counter
  is incremented with `{tool, status}` labels after each call.
- **Audit** (`internal/db/store.go`): `LogToolCall` accepts a
  `callPath` parameter; bridge-dispatched calls pass `"local"`,
  hosted calls pass `""` (stored as `'hosted'` in the column).
- **Metrics** (`internal/metrics/metrics.go`):
  - `mctl_bridge_active_daemons` gauge — incremented on Register,
    decremented on Unregister/UnregisterSend.
  - `mctl_bridge_calls_total{tool, status}` counter — incremented by
    `bridgeCall()` in the MCP layer after each hub round-trip.
- **Security page** (`internal/web/security.html`): "Local Bridge mode"
  section describes the data-flow guarantees for `mode='local'` users.
- **CLI** (`cmd/local`): subcommands `init`, `login`, `connect`, `daemon`
  are scaffolded; implementations are deferred — see Daemon-side below.

### Alert rules

- `MctlBridgeDaemonsFlapping` (warning): fires when the
  `mctl_bridge_active_daemons` gauge changes more than 20 times in 10
  minutes — a sign of looping reconnects.

## Remaining gaps

### Server-side

1. **Pong deadline hardening.** The current 5 s read-deadline window is
   set per-ping but only reset on non-ping frames. Under a highly
   loaded daemon that sends only pong frames the deadline logic is
   correct; under a daemon that sends pong AND response frames
   simultaneously the reset is conservative (errs toward keeping the
   connection alive). No known bug, but worth a focused review.
2. **Keychain integration.** The bridge token is currently stored in
   memory by the daemon and lost on restart; a persist-to-OS-keychain
   path is needed for the production daemon workflow.
3. **Distribution / release packaging.** `cmd/local` is not yet built
   into a released binary; release-please does not produce a
   `mctl-telegram-local` artifact. Needs Dockerfile + GoReleaser config.

### Cross-repo

- **mctl-api**: new OAuth scope `local-bridge`; new endpoint
  `/oauth/local-bridge/authorize` that emits a JWT with `aud="bridge"`.
- **mctl-web Worker**: handle `?for=local-bridge` redirect target.
- **mctl-portal** (optional): "Connected daemons" view so a user can
  see when their daemon last contacted the relay.

### Daemon-side (`cmd/local`)

1. **`init`**: prompt for `TG_API_ID` / `TG_API_HASH`, generate a
   passphrase, derive an AES key via Argon2id, store config at
   `~/.config/mctl-telegram-local/config.json` and an empty session
   at `~/.config/mctl-telegram-local/session.bin.enc`.
2. **`login`**: re-use the existing `cmd/login` logic but write to
   the local encrypted file instead of the server DB. Phone, SMS,
   2FA, store session locally.
3. **`connect`**: open the system browser to
   `https://api.mctl.ai/oauth/local-bridge/authorize`, listen on
   `127.0.0.1:<random>` for the redirect, exchange the auth code for
   a short-lived JWT (`aud="bridge"`, 1h), store the refresh token
   in OS keychain.
4. **`daemon`**: long-running process that connects the websocket to
   `wss://tg.mctl.ai/bridge`, sends pings every 25 s, accepts call
   envelopes, dispatches to local MTProto via the existing
   `internal/telegram` helpers, sends responses back. Auto-rotates
   the bridge JWT 5 minutes before expiry.

## Trust-model notes (reflected on /security)

- For `mode='local'` users, the server NEVER sees `session_encrypted`
  (the column is NULL) and the MTProto plaintext only exists on the
  user's local machine.
- The relay still sees the MCP JSON-RPC payloads (it has to route
  them). Messages-as-data flow through the relay's memory for the
  duration of one call.
- For genuine end-to-end secrecy from the server, Claude.ai would
  need to encrypt MCP payloads with the daemon's public key; that
  needs Claude.ai client support which doesn't exist today.

## Migration story

- Default for new accounts is still `mode='hosted'` — backward
  compatible.
- Operators can flip a per-account `mode='local'` row out-of-band
  before the first `connect`; the websocket registration ties the
  daemon to that row.
- An `unconnect` HTTP/MCP endpoint flips a user back to hosted-mode
  (or deletes the row entirely). Symmetric with the existing
  `disconnect_telegram_account` tool.
