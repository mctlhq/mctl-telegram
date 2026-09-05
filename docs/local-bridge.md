# Local Bridge

Local Bridge is a deployment mode in which your Telegram session lives on a
machine you control instead of on tg.mctl.ai. The server keeps routing MCP
tool calls from your assistant, but instead of opening Telegram itself it
forwards each call over a websocket to a daemon on your machine.

Turning it on is self-service. The zero-admin path is:

1. `init` — Telegram API credentials and a passphrase
2. `login` — ordinary Telegram phone / code / 2FA
3. `activate --server https://tg.mctl.ai` — approve the device in a browser
4. `daemon` — keep it running

Nobody has to flip a database flag, provision an account, or mint you a
token. A brand-new Telegram id is provisioned directly into local mode, so
tg.mctl.ai never holds a session for it.

The first credential is **read-only**. Sending is a separate owner step.
See [Owner controls](/docs/local-bridge/owner).

The only case that still goes through an operator is migrating an
**existing hosted** account into local mode. That is support, not
onboarding. See [Support and recovery](/docs/local-bridge/support).

This overview is enough to decide whether the mode fits. The rest of the
guide is split so you can finish setup without scrolling through operator
procedures.

## When to use it

Use Local Bridge when you want the Telegram session on a machine you
control, and you can keep that machine on. A laptop that sleeps is a poor
host. A small always-on machine is the right one.

The hosted path on the [landing page](/) is the standard ChatGPT / Claude
install. Local Bridge is optional, beta, and costs you a machine that
stays reachable.

## What it changes

- **Telegram traffic originates from your machine.** Once the daemon is
  connected, the MTProto connection to Telegram is made by your daemon
  using the session on your disk. Your assistant still talks to
  tg.mctl.ai, which still authenticates you and writes an audit trail.
- **The relay still sees the payloads.** It has to, in order to route
  them. Tool arguments and results — including message text — pass through
  the relay's memory for the duration of a call. This is not end-to-end
  encryption between your assistant and your daemon.
- **Your connector does not change.** The MCP endpoint is the same. The
  server decides per account whether a call goes to the hosted session
  pool or to your daemon.
- **Starting fresh creates no server-side session.** Running `activate`
  for a brand-new Telegram id never stores `session_encrypted` here. If
  you later migrate an existing hosted account, that sealed copy stays in
  the database until you terminate it from Telegram yourself. Migration
  is an operator step; see [Support and recovery](/docs/local-bridge/support).

## Limitations today

These are current, not permanent. Plan around them.

- Five tools return an explicit error: `edit_message`, `delete_messages`,
  `forward_messages`, `search_messages`, `set_reaction`. The daemon
  implements `list_dialogs`, `get_unread_messages`, `get_messages`,
  `send_message`, `send_media`, `prepare_get_media`, `get_media`, and
  `pin_message`.
- `fetch_media=true` is refused on `get_messages` and
  `get_unread_messages`. Use `prepare_get_media` then `get_media`.
- No always-on Communication Agent listener. That path needs a
  server-side Telegram client.
- One account per machine (`init` overwrites the previous setup). One
  daemon per account (a second daemon starts a reconnect loop).
- Moving an existing hosted account into local mode, or back to hosted,
  is still an operator action (`set_account_mode`).

Until the daemon is running, tool calls return
`local-bridge daemon not connected`. That error is explicit and
recoverable — it clears as soon as the daemon connects.

Start at [Quick start](/docs/local-bridge/quickstart). Support, recovery,
and `connect --token` are labelled as such and are not part of this path.
