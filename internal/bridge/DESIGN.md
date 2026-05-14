# Local Bridge (M4) — design and remaining work

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

## What this PR (scaffolding) ships

- **Schema columns**: `telegram_accounts.mode` (`'hosted' | 'local'`,
  default `'hosted'`) and `telegram_accounts.bridge_token_hash`
  (SHA-256 of the most-recent registered daemon JWT). Idempotent
  migration via `addColumnIfMissing`.
- **Protocol** (`internal/bridge/protocol.go`): the JSON envelope shape
  the daemon and the relay exchange — `call`, `response`, `error`,
  `ping`, `pong`. Args and Result are `json.RawMessage` so the relay
  doesn't need to know each tool's schema.
- **Hub** (`internal/bridge/hub.go`): in-process router that
  multiplexes per-user daemon connections; `Call` blocks until the
  daemon answers or the deadline elapses; `Register`/`Unregister`
  manage the singleton-per-user invariant. Exercised by in-process
  tests; the websocket transport is not yet wired.
- **Binary stub** (`cmd/local`): subcommands `init`, `login`, `connect`,
  `daemon` print a TODO message and exit non-zero. The CLI shape is
  there so the next implementer can fill in commands without
  reorganising.

## What remains for a production-usable Local Bridge

### Server-side (this repo)

1. **Websocket transport**. Pick a library (recommendation: `nhooyr/websocket`
   for stdlib-friendly API, no goroutine leaks on graceful shutdown).
   Adapter at `internal/bridge/server.go`:
   - Upgrade HTTP → websocket at `GET /bridge`.
   - Verify the bearer JWT (must be shared-HMAC with `aud="bridge"`).
   - Look up the user via the existing `auth.Provider`.
   - Call `Hub.Register(userID)` and pump frames in both directions.
   - On disconnect, `Hub.Unregister(userID)`.
2. **Mount** at `cmd/server/main.go` behind the auth middleware (same
   provider as `/mcp`, with `audience="bridge"` enforcement).
3. **Dispatch in MCP tools**. In every read/write tool handler, if the
   user's `telegram_accounts.mode == 'local'`, call `Hub.Call` instead
   of `Pool.Borrow`. Marshal the tool arguments, await the response,
   surface `ErrNoDaemonConnected` as a clean "user is offline" tool
   error.
4. **Audit**. Bridge calls still go through `Store.LogToolCall` so the
   user's audit log and hash chain include them. Add a `via=local`
   marker in the audit row so a user can see whether a call ran
   through their daemon or hosted-mode (probably as a new column or
   suffix in `tool_name`).

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

### Cross-repo

- **mctl-api**: new OAuth scope `local-bridge`; new endpoint
  `/oauth/local-bridge/authorize` that emits a JWT with `aud="bridge"`.
- **mctl-web Worker**: handle `?for=local-bridge` redirect target.
- **mctl-portal** (optional): "Connected daemons" view so a user can
  see when their daemon last contacted the relay.

### Trust-model deltas (must be reflected on /security)

- For `mode='local'` users, the server NEVER sees `session_encrypted`
  (the column is NULL) and the MTProto plaintext only exists on the
  user's local machine.
- The relay still sees the MCP JSON-RPC payloads (it has to route
  them). Messages-as-data flow through the relay's memory for the
  duration of one call.
- For genuine end-to-end secrecy from the server, Claude.ai would
  need to encrypt MCP payloads with the daemon's public key; that
  needs Claude.ai client support which doesn't exist today.

### Migration story

- Default for new accounts is still `mode='hosted'` — backward
  compatible.
- Operators can flip a per-account `mode='local'` row out-of-band
  before the first `connect`; the websocket registration ties the
  daemon to that row.
- An `unconnect` HTTP/MCP endpoint flips a user back to hosted-mode
  (or deletes the row entirely). Symmetric with the existing
  `disconnect_telegram_account` tool.

## Why this isn't done in the M1-M4 6-hour effort window

- Websocket transport + reconnect/backoff/ping handling alone is
  several days of careful work to get right under partial-network
  failures.
- The daemon CLI needs an actually-secure passphrase prompt, KDF, and
  OS-keychain integration on three platforms (macOS/Linux/Windows).
- Cross-repo coordination requires mctl-api PRs that have not been
  drafted yet.
- The plan's own estimate (`plans/humble-seeking-simon.md`) puts M4
  at 4-6 weeks.

What is here is the protocol shape, the hub, the schema columns, and
a stub binary — enough for the next implementer to land the rest in
slices without reorganising the package layout.
