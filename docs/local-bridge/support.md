# Local Bridge support and recovery

Everything on this page is for migrating an account that predates
`activate`, recovering from something going wrong, or an emergency. None
of it is part of onboarding a new account.

The normal path is [Quick start](/docs/local-bridge/quickstart).

## Operator: migrate a hosted account

`activate` provisions a *brand-new* local account. It does not flip an
account that already has a hosted session.

An operator runs `set_account_mode` with `mode="local"` for you. The
sealed session from the original hosted login stays in the database
(switching stops the server from using it; it does not erase it). You
then run `activate` — or reuse an already-registered device — as normal.

Reverting to hosted is the same tool with `mode="hosted"`. Calls resume
through the server's own session, provided you did not terminate that
session from Telegram. Stop the daemon once the switch is done.

There is currently no self-service way to flip a local-only account back
to hosted. For an account onboarded through `activate`, stopping the
daemon is all you can do yourself; ask an operator if the account row
itself must revert.

## Operator: `provision_local_account`

The admin tool `activate`'s server-side flow uses internally to create a
fresh local-only row. It still exists as a standalone admin-only MCP
tool for rare recovery (scripting a batch migration, or an `activate`
run that cannot complete). Running `activate` never requires anyone to
call it separately.

## Troubleshooting

**`local-bridge daemon not connected`** — the account is in local mode
but no daemon is attached. Check the service is running and look at its
log.

**The daemon exits immediately at startup** — read the error. Common
causes: the passphrase is wrong (or the file has a stray newline in an
older build); a device credential's signing key is unusable, in which
case the error names `activate` as the fix (re-run it, do not edit the
device file by hand); or, on the legacy path, the MCP token has expired
and needs a fresh `connect`. See [Legacy connect](/docs/local-bridge/legacy).

**Reconnect loop** — usually an expired legacy MCP token, sometimes a
second daemon running elsewhere. Check for the second daemon first.

**The daemon starts by hand but not under launchd** — the passphrase is
being prompted for. Confirm `MCTL_LOCAL_PASSPHRASE_FILE` is set in the
service definition and points at a readable file.

**Windows: `init` cannot read the passphrase** — run it in PowerShell
rather than Git Bash.

**No server configured** — `daemon` has no `--server` flag. Run
`activate --server https://tg.mctl.ai` once (or `connect --server`
on the legacy path).

**First send after granting consent is still a dry-run** — the
credential your MCP client presents has not picked up the send scope
yet. Refresh that credential. Confirm `set_send_consent` reports
`send_enabled: true`. See [Owner controls](/docs/local-bridge/owner).

**Between finishing `activate` and starting the daemon, tools fail.**
The mode switch lands as part of `activate`. In the gap your assistant
gets `local-bridge daemon not connected`, not a hang. Plan the switch
for a moment when you are ready to run `daemon`.

## Emergency

- **Compromised device:** `revoke_local_bridge_device` with that
  `device_id`. This evicts the live connection and denylists the
  credential lineage. `set_send_consent enabled=false` only stops
  sending.
- **Compromised passphrase / disk:** stop the daemon, revoke the
  device, terminate the Telegram session from Settings → Devices, and
  start again from `init` / `login` / `activate` on a clean config
  directory.
- **Need the account back on the hosted pool:** operator
  `set_account_mode mode="hosted"`, then stop the daemon.

## Next

- [Legacy connect](/docs/local-bridge/legacy) — `connect --token`
- [Quick start](/docs/local-bridge/quickstart) — the path that avoids this page
- [Overview](/docs/local-bridge)
