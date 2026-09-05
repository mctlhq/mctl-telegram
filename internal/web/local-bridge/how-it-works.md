# How Local Bridge works

Short version of activation, proof of possession, and the read-only first
token. Setup steps live in [Quick start](/docs/local-bridge/quickstart).
Owner actions live in [Owner controls](/docs/local-bridge/owner).

## Activation

`mctl-telegram-local activate` talks to:

- `POST /api/local-bridge/activate/start` — unauthenticated; the CLI
  sends your Telegram id, a device registration key, a label, and an
  Ed25519 public key.
- A browser page at `/local-bridge/activate` — you type the short code,
  sign in with Telegram, and approve.
- `POST /api/local-bridge/activate/poll` — the CLI waits until you
  approve or deny.

Nothing is written to the server database until you approve. A brand-new
Telegram id is created as `mode=local` with `session_encrypted = NULL`
and `send_enabled = false`.

## Proof of possession

After approval the CLI does not paste a token. It:

1. `POST /api/local-bridge/devices/{device_id}/nonce`
2. Signs `device_id + "." + nonce` with the local Ed25519 private key
3. `POST /api/local-bridge/devices/{device_id}/credential` with the
   nonce and signature

The private key never leaves `device_key.json`. The server verifies a
signature; it cannot forge one. Every later `daemon` connection repeats
the same shape against `/refresh` instead of `/credential`.

A device-signed credential lasts hours, not months. There is no bearer
secret sitting in a file that you have to rotate by hand — that is the
legacy worker-token path, documented under
[Legacy connect](/docs/local-bridge/legacy).

## Read-only first token

The first credential a newly registered device receives is read-only,
regardless of the account's `send_enabled` value. Getting send
capability is always the separate `set_send_consent` (or manage-page)
step. A refresh after you grant consent is what adds
`telegram:messages:send` and `telegram:messages:pin`.

This is why a just-activated daemon can list dialogs immediately and
cannot send until you say so.

## Device binding and revocation

`device_key.json` holds the private key, the public key, and — once
issued — the device credential, in one record. Everything the daemon
writes is owner-only (`0600`), including the session database and its
SQLite sidecar files.

`revoke_local_bridge_device` denylists the `jti` claimed at first
issuance. Every later refresh carries that same `jti` forward, so
denylisting it kills every credential the device has ever held. If the
device is already connected, the same call evicts its live `/bridge`
websocket.

## What the server keeps

Depends on how the account became local:

- **Onboarded through `activate`:** no stored session here, ever.
- **Migrated from hosted via `set_account_mode`:** the sealed session
  from the original hosted login stays in the database. The server stops
  using it. To make that copy useless, terminate the session from your
  own Telegram client (Settings → Devices). Migration is an operator
  step; see [Support and recovery](/docs/local-bridge/support).

Local accounts are excluded from the idle and absolute session sweepers,
so nothing silently reverts to hosted after 30 days.

## What the relay sees

Tool arguments and results pass through the relay in memory for the
duration of a call. Audit rows stay metadata-only and record
`call_path=local` when the daemon served the call. This is not
end-to-end encryption.

## Next

- [Owner controls](/docs/local-bridge/owner)
- [Support and recovery](/docs/local-bridge/support)
- [Legacy connect](/docs/local-bridge/legacy)
- [Overview](/docs/local-bridge)
