# Local Bridge owner controls

These are things you do yourself after
[Quick start](/docs/local-bridge/quickstart). None of them need an
operator.

## Turn sending on

`activate` gets you a **read-only** daemon. That is deliberate: the first
credential a device is issued carries only read scopes, regardless of
any `send_enabled` value on the account. Activation and consent-to-send
are two different decisions.

To let the daemon send or pin, grant consent on your own account:

- Call the `set_send_consent` MCP tool with `enabled: true`. It is gated
  on the `account:manage` scope, always acts on your own account, and
  has no `telegram_id` argument. Confirm the gate with
  `get_my_send_status` — it reports the same verdict `send_message`
  uses.
- If you authenticated through the hosted Telegram connect wizard
  (local-jwt / connect cookie), you can also enable **Send messages**
  on that session's manage page (`/telegram/connect/manage`). That
  route is only mounted in local-jwt mode; shared-hmac deploys do
  not serve it.

`set_account_send` is the admin recovery tool. It is not how you turn
sending on for yourself.

**What actually gates a real send**, in the order that matters:

- **Turning consent off** protects you on the very next send. The server
  reads `send_enabled` live on every call. If you revoke consent
  mid-conversation, the next `send_message` comes back a dry-run whether
  or not the daemon has refreshed. Consent does not evict the websocket;
  device revocation (below) does that.
- **Turning consent on** takes effect once the credential your MCP
  client presents carries `telegram:messages:send`. That scope is
  derived from the live `send_enabled` flag every time a device
  credential is issued or refreshed. If you have just granted consent
  and want to send immediately, refresh the credential your client
  authenticates with. The daemon cannot hurry this: a refused send is
  decided on the server and never reaches the daemon.
- **On tg.mctl.ai**, `ALLOW_SEND=false` still returns a dry-run
  *before* the daemon is contacted. Real delivery also needs the
  `telegram:messages:send` scope and the per-peer rate limit.

If a send comes back as a dry-run after you granted consent, check the
`dry_reason` and `hint`. A typical reason is
`per-account send_enabled=false` — enable sending with `set_send_consent`,
then refresh the client credential. `get_my_send_status` reports the
same gate `send_message` uses.

## Revoke a device

`revoke_local_bridge_device` is the kill switch for one of *your*
devices. It is gated on `account:manage`, same as `set_send_consent`.

It revokes the device row, denylists its entire credential lineage
(`current_jti`, carried forward unchanged from first issuance), and
evicts any live `/bridge` websocket that device holds.

Use this — not `set_send_consent` — when a device's key material or
credential might be compromised. Revoking send consent stops that device
from sending, but it stays connected and able to read. Revoking the
device disconnects it and locks it out.

Pass the `device_id` that `activate` printed. A device id belonging to
someone else is refused without revealing whether it exists. Safe to
call again on an already-revoked device: it repairs a partial
revocation.

## Confirm the call path

`get_my_audit_log` and `GET /api/account/audit` return a `call_path`
field per entry: `"local"` when the call was routed to your daemon,
absent when it was served by the hosted session pool. That is the
authoritative record.

```
23:45:41  list_dialogs  status=ok     call_path=(absent — hosted)
23:48:29  list_dialogs  status=error  call_path=local
23:50:00  list_dialogs  status=ok     call_path=local
```

The error in the middle is the expected one: the account was already in
local mode while the daemon was not yet running.

## Next

- [How it works](/docs/local-bridge/how-it-works) — why the first token is read-only
- [Support and recovery](/docs/local-bridge/support) — migration, rollback, emergencies
- [Overview](/docs/local-bridge)
