# Local Bridge

Local Bridge is a deployment mode in which your Telegram session lives on a
machine you control instead of on tg.mctl.ai. The server keeps routing MCP tool
calls from your assistant, but instead of opening Telegram itself it forwards
each call over a websocket to a daemon running on your machine, and that daemon
talks to Telegram.

Turning it on is self-service: run `mctl-telegram-local activate` and you end
up with a connected, read-only daemon with no operator involved. Nobody has to
flip a database flag, provision an account for you, or mint you a token first.
The only case that still goes through an operator is migrating an **existing
hosted** account into local mode — see "Operator: support and recovery only"
below.

This document describes what the mode actually does today, including the parts
that are unfinished, so you can decide whether it fits your workflow before you
set it up.

## What it changes, and what it does not

**Telegram traffic originates from your machine.** Once the daemon is
connected, the MTProto connection to Telegram is made by your daemon using the
session stored on your disk. Your assistant still talks to tg.mctl.ai, which
still authenticates you and still writes an audit trail.

**The relay still sees the payloads.** It has to, in order to route them. Tool
arguments and results — including message text — pass through the relay's memory
for the duration of a call. This is not end-to-end encryption between your
assistant and your daemon, and no amount of local-mode configuration makes it
one.

**Your existing server-side session is not deleted (if you had one).**
Running `activate` for a brand-new Telegram id never creates a server-side
session in the first place — see below. But if you migrate an existing hosted
account into local mode instead, switching stops the server from using its
stored copy; it does not erase it, and it cannot be revoked without leaving
local mode (a revoked account reverts to hosted, and the bridge then refuses
your daemon). If you want the stored copy to be worthless, terminate that
session from your own Telegram client — Settings → Devices → find the session
→ terminate. The bytes remain in the database but hold a dead authorization
key. Do this **after** your local login works, not before.

**Your connector does not change.** The MCP endpoint is the same; the server
decides per account whether a call goes to the hosted session pool or to your
daemon. You do not need to remove and re-add the connector.

## Before you start

**You do not need a hosted login first.** Running `activate` for a brand-new
Telegram id provisions the account directly into local mode, so tg.mctl.ai
never holds a session for it. If you already have a hosted account and want to
move it instead, that works too, but it is the one step in this whole flow
that still needs an operator (`set_account_mode`) — starting fresh with
`activate` is the option that leaves nothing behind here and needs nobody's
help.

**You need a machine that stays on.** The daemon must be reachable for a tool
call to succeed; when it is not, calls fail with a clear error rather than
falling back to the server. A laptop that sleeps is a poor host. A small
always-on machine is the right one.

**You need your own Telegram API credentials.** Register an application at
<https://my.telegram.org/apps> and use the `api_id` and `api_hash` it shows.
Telegram issues one application per account and offers no way to delete it, so
if you have registered one before, that page shows the existing credentials
rather than a form. The credentials identify the *application*, not the account
— one pair can authorize any Telegram account, which is how any third-party
client works.

## Install

Download the build for your platform from the
[releases page](https://github.com/mctlhq/mctl-telegram/releases) and check it
against `SHA256SUMS.txt`:

```sh
VERSION=$(curl -fsSL https://api.github.com/repos/mctlhq/mctl-telegram/releases/latest \
  | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p')
BASE=https://github.com/mctlhq/mctl-telegram/releases/download/$VERSION
mkdir -p ~/mctl-local/logs && cd ~/mctl-local &&
curl -fsSLO "$BASE/mctl-telegram-local-$VERSION-darwin-arm64" &&
curl -fsSLO "$BASE/SHA256SUMS.txt" &&
shasum -a 256 -c SHA256SUMS.txt --ignore-missing &&
chmod +x mctl-telegram-local-$VERSION-darwin-arm64 &&
mv mctl-telegram-local-$VERSION-darwin-arm64 mctl-telegram-local
```

The `&&` matter. `shasum -c` exits non-zero on a mismatch but prints its
complaint and moves on if the commands are merely listed one after another, so
an unchained sequence installs a corrupted or tampered binary and tells you
only in a line you have already scrolled past.

`VERSION` is read from the releases API rather than written out, so this block
does not rot. A version pinned in prose is wrong from the next release onward,
and the reader has no way to tell whether the number is deliberate or stale.

`~/mctl-local` is where this guide keeps the binary, the passphrase file and
the daemon's log; `~/.config/mctl-telegram-local` is where the daemon itself
keeps its config, device identity and session, and it creates that one for
you.

Builds are published for `darwin/arm64`, `darwin/amd64`, `linux/amd64`,
`linux/arm64` and `windows/amd64`. Check which one you need before downloading —
an Intel Mac needs `darwin-amd64` and will not run the `arm64` build.

**The binaries are not signed.** Downloading with `curl` avoids the problem
entirely: macOS attaches its quarantine attribute only to files a browser
saved, so a `curl`-fetched binary runs without ceremony. If you did download
through a browser, clear it with
`xattr -d com.apple.quarantine mctl-telegram-local`. On Windows, running the
`.exe` from a terminal does not trigger the SmartScreen prompt that
double-clicking it would.

Building from source works too and produces a binary with no quarantine
attribute at all:

```sh
git clone https://github.com/mctlhq/mctl-telegram && cd mctl-telegram
go build -o mctl-telegram-local ./cmd/local
```

## Client / owner actions

Five commands get you from nothing to a connected, sending-capable daemon,
and every one of them is something you run yourself. Everything lives under
`~/.config/mctl-telegram-local/`.

### 1. `init`

```sh
./mctl-telegram-local init
```

Asks for your `TG_API_ID`, your `TG_API_HASH`, and a passphrase. The passphrase
encrypts the local session database via Argon2id.

**There is no recovery.** If you lose the passphrase, the stored session is
unreadable and you start again from `login`. Generate a strong one and store it
in a password manager, and — if you plan to run the daemon unattended, which you
should — also write it to a file:

```sh
mkdir -p ~/mctl-local &&
(umask 077 && LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40 > ~/mctl-local/passphrase)
```

Write it without a trailing newline, or rely on the daemon trimming one.

The `umask 077` is not decoration. A plain redirection creates the file under
your usual umask — world-readable on most systems — and a `chmod` on the next
line closes that only after the passphrase is already on disk in the clear. The
subshell means it is never created readable.

`init` does not ask for the server address. `activate` and `daemon` default to
whatever `server` is already in `config.json`, and `--server` overrides it —
see step 3.

### 2. `login`

```sh
./mctl-telegram-local login --phone +1234567890
```

An ordinary Telegram login: it asks for the passphrase from step 1, then for the
code Telegram sends, then for your cloud password if you have two-factor
enabled. The code arrives inside Telegram when the account is signed in
somewhere else, and by SMS when it is not.

This creates a **second** session on your account, alongside any hosted one.
Both are live until you terminate one.

### 3. `activate`

```sh
./mctl-telegram-local activate --telegram-id <your numeric Telegram id>
```

`--server <url>` overrides the server address from `config.json` (needed the
first time, since `init` never asks for one), and `--label <name>` sets the
device's human-readable label (defaults to your machine's hostname).

This is the step that used to end with "an operator still needs to issue this
device a token." It no longer does. `activate`:

1. Generates an Ed25519 keypair the first time it runs on this machine and
   keeps it in `device_key.json`, `0600`, alongside the rest of your device's
   identity. The private half never leaves your disk; every later step signs
   with it locally and sends only the signature.
2. Prints a verification URL and a short code. Open the URL, type the code,
   sign in with Telegram, and approve the device from the consent screen it
   shows you. Nothing is written to the database until you approve.
3. Once you approve, immediately and automatically bootstraps a device
   credential — no separate step, no token to copy from anywhere: it asks the
   server for a one-time nonce, signs it with the private key from step 1, and
   exchanges the signature for a worker credential, which it saves alongside
   the device identity.

The command's last line tells you to run `daemon` next, because at that point
you can. A brand-new Telegram id never touches a hosted session: it is
provisioned directly into local mode, so `session_encrypted` for that account
is `NULL` from the very first row.

**Re-running `activate` is safe.** It reuses the same keypair and device id it
generated the first time, and if the credential step already succeeded it
reports the device as already activated and exits 0 rather than re-minting.
If a previous run was interrupted between registering the device and saving
its credential, re-running repairs that instead of leaving you stuck — you
never need to delete the config directory and start over.

### 4. `daemon`

```sh
./mctl-telegram-local daemon
```

Connects to `wss://tg.mctl.ai/bridge` and serves calls. If `activate` produced
a device credential, `daemon` refreshes it itself on every connection attempt
— proving possession of the private key each time, not presenting a bearer
token that can go stale unattended — so there is nothing here to renew by
hand. (If instead you set this machine up through the legacy `connect --token`
path, see "Operator: support and recovery only" below; that path keeps working
exactly as before.)

Until the daemon is running, your assistant's calls return
`local-bridge daemon not connected`. That error is explicit and recoverable —
it clears as soon as the daemon connects — never a hang and never a loss of
authorization.

### 5. `set_send_consent` — turning sending on

`activate` gets you a **read-only** daemon. That is deliberate and unconditional:
the very first credential your device is issued carries only read scopes,
regardless of any `send_enabled` value on the account, because activation and
consent-to-send are two different decisions and this mode never conflates
them. To let the daemon actually send or pin messages, call the
`set_send_consent` MCP tool yourself, with `enabled: true`. It is gated on the
`account:manage` scope, not on an admin scope, and it always acts on your own
account — there is no `telegram_id` argument for it to get wrong, and nobody
else can flip it for you.

**What actually gates a real send**, in the order that matters, because
getting this backwards in either direction is worse than saying nothing:

- **Turning consent off** protects you on the very next send, with no
  daemon action needed. `evaluateSendGate` reads `send_enabled` live from
  your account row on every call — it is the authoritative check, and it is
  already true before this proposal touched anything. If you revoke consent
  mid-conversation, the very next `send_message` your daemon attempts comes
  back a dry-run, whether or not the daemon's own credential has refreshed and
  whether or not it is still connected. Nothing here evicts the daemon's
  websocket connection on a consent change — that would overstate what
  consent does and understate what device revocation (below) is for.
- **Turning consent on** is the direction that needs the daemon's own
  credential to catch up before a send can actually go through, because the
  scope baked into that credential is the coarse gate the server checks before
  it even gets to the live `send_enabled` read. Waiting for the daemon's
  normal, hours-scale scheduled refresh would mean granting consent and then
  waiting hours for your first real message to leave — so the daemon does not
  wait: when a send comes back as a dry-run draft, it opportunistically
  refreshes its own device credential out of band, at most once every 30
  seconds (`outOfBandRefreshCooldown` in `cmd/local/daemon.go`), and retries
  the same send as real **only if** the refreshed credential's scopes
  actually gained `telegram:messages:send`. If consent is still off, the
  refresh comes back exactly as read-only as before, the daemon reports the
  same dry-run it would have anyway, and it will not refresh again for
  another 30 seconds no matter how many sends you retry in the meantime — a
  refusal can trigger at most one refresh, never a loop.

  **This out-of-band refresh is a documented assumption, not a guarantee.**
  It works because in the zero-admin flow this guide describes, the same
  worker credential the daemon refreshes doubles as the credential your MCP
  client itself authenticates with — mirroring how the legacy
  `bridge_token.json`'s `mcp_token` field serves both purposes today. If your
  MCP client is instead authenticating with some other credential entirely,
  refreshing the daemon's own copy has no effect on that other credential's
  scope, and your send stays a dry run until whatever issued *that* credential
  refreshes it. If your first send after granting consent does not go
  through immediately, wait a moment and try again — most of the time the
  next daemon-initiated refresh (the ordinary hours-scale one, not the
  opportunistic one) closes the gap.

Three things that are **no longer** operator steps, in case you read an older
description of this mode:

- **No hosted login first.** A local account can be created directly by
  `activate`, so the server never holds a session for it.
- **No TTL exemption.** Local accounts are excluded from the idle and absolute
  session sweepers in the query itself, so nothing has to be added to an
  exemption list and no account silently reverts to hosted after 30 days.
- **No operator-minted credential, and no operator flip to turn sending on.**
  `activate` mints its own device credential end to end, and `set_send_consent`
  lets you turn real sending on yourself. For an account onboarded through
  `activate`, nobody but you ever has to touch `mint_worker_token` or the old
  admin-only `set_account_send`.

## Operator: support and recovery only

Everything below this line is for migrating an account that predates this
guide, or for recovering from something going wrong. None of it is part of
onboarding a new account through `activate`.

**`connect --token`** — the pre-#484 way to get a daemon running, kept
working unmodified as a compatibility and recovery path:

```sh
./mctl-telegram-local connect --token "$(cat mcp-token.txt)" --server https://tg.mctl.ai
```

Exchanges a long-lived MCP token for a short-lived bridge token and saves
both to `bridge_token.json`. `--server` is required the first time, for the
same reason it is under `activate`. An operator mints the token with the
`mint_worker_token` MCP tool (or the equivalent `POST /api/mcp/worker-token`)
using `telegram_id` and `purpose="local-bridge"` — this grants the
`telegram:messages:send`/`telegram:messages:pin` scopes in addition to the
read-only ones, all in one static, long-lived credential rather than a
refreshing device-bound one. The daemon repeatedly exchanges this same
worker token for a fresh short-lived bridge token via
`POST /api/bridge/token`, but the worker token's own expiry never moves —
once it lapses (up to 90 days after minting), the fix is an operator
re-minting a fresh one and you re-running `connect` with it, not anything
the daemon can do by itself. `daemon` picks this bearer path automatically
whenever there is no device credential on disk —
you do not choose between the two paths yourself, the presence or absence of
`activate`'s device files decides it.

`--token` is currently the only way to pass the token, so it appears in the
process argument list and is readable by other local accounts through `ps`
for as long as the command runs — a second or two. On a single-user machine
that is a small window; on a shared one, run `connect` when nobody else is
logged in. A `--token-file` option that avoids the argument list entirely is
tracked in #454.

**`set_account_mode`** — migrates an **existing hosted** account into local
mode. This is the one case `activate` genuinely cannot do by itself: it only
knows how to provision a brand-new local-only account, never how to flip an
account that already has a hosted session. An operator runs
`set_account_mode` with `mode="local"` for you; the sealed session stored
from your original hosted login stays in the database (see "What it changes,
and what it does not" above), and you then run `activate` — or reuse an
already-registered device — as normal.

**`provision_local_account`** — the admin tool `activate`'s server-side flow
now uses internally to create a fresh local-only row. It still exists as a
standalone admin-only MCP tool for the rare recovery case where an operator
needs to create that row directly (for example, scripting a batch migration,
or recovering an account whose `activate` run cannot complete for some
reason) — it is not part of the self-service path, and running `activate`
never requires anyone to call it separately.

**`revoke_local_bridge_device`** — the kill switch for a specific device,
callable by the account owner (not admin-gated) with the same
`account:manage` scope as `set_send_consent`. It revokes the device row,
denylists its entire credential lineage (`current_jti`, which every refresh
carries forward unchanged from first issuance — see "Security notes" below)
so no future `/refresh` or reconnect for that device succeeds, and then
actively evicts any live `/bridge` websocket connection the device currently
holds. Use this — not `set_send_consent` — when a device's key material or
credential might be compromised: revoking send consent stops that device
from sending, but it stays connected and able to read; revoking the device
disconnects and locks it out entirely.

## Running it unattended

Run the daemon under a service manager, not in a terminal. It takes its
passphrase from the environment when one is supplied:

| Variable | Meaning |
|---|---|
| `MCTL_LOCAL_PASSPHRASE_FILE` | Path to a file holding the passphrase. Takes precedence. |
| `MCTL_LOCAL_PASSPHRASE` | The passphrase itself. |

**Use the file, not the value.** A launchd plist lives in
`~/Library/LaunchAgents` and is world-readable; a systemd unit's `Environment=`
lines are visible through `systemctl show`. A passphrase written into the
service definition is therefore readable by every account on the machine, while
a path to a `0600` file is not.

**The macOS keychain is not an option.** The login keychain is locked outside a
GUI session, so `security find-generic-password` fails for a service started at
boot exactly as it fails over SSH. This looks like the obvious place to put the
secret and does not work.

### launchd (macOS)

`~/Library/LaunchAgents/ai.mctl.telegram-local.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>ai.mctl.telegram-local</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/you/mctl-local/mctl-telegram-local</string>
    <string>daemon</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>MCTL_LOCAL_PASSPHRASE_FILE</key>
    <string>/Users/you/mctl-local/passphrase</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>30</integer>
  <key>StandardOutPath</key><string>/Users/you/mctl-local/logs/daemon.log</string>
  <key>StandardErrorPath</key><string>/Users/you/mctl-local/logs/daemon.log</string>
</dict>
</plist>
```

```sh
mkdir -p ~/mctl-local/logs
launchctl load -w ~/Library/LaunchAgents/ai.mctl.telegram-local.plist
launchctl list | grep ai.mctl.telegram-local
```

The log directory must exist before loading: launchd does not create the
parent of `StandardOutPath`, and a job whose output cannot be opened fails to
start with a bare exit code rather than a message explaining it.

A **LaunchAgent runs inside your login session**, so after a reboot it starts
only once someone logs in. On a headless machine that means enabling automatic
login — which in turn requires FileVault to be off, so the disk is unencrypted
and anyone with physical access can read the passphrase file as the
auto-logged-in user. That may be an acceptable trade for a machine in your
office; it is a trade, not a detail. The alternative is a LaunchDaemon in
`/Library/LaunchDaemons`, which starts at boot without a session but runs as
root and needs absolute paths for everything.

Test the restart path before trusting it:

```sh
launchctl kickstart -k gui/$(id -u)/ai.mctl.telegram-local
tail -f ~/mctl-local/logs/daemon.log
```

### systemd (Linux)

This is a **user** unit — put it in `~/.config/systemd/user/mctl-telegram-local.service`,
not in `/etc/systemd/system/`. A system unit runs as root by default, which
would give the daemon, and anything that can read its unit file, more privilege
over your Telegram session than it needs. `WantedBy=default.target` below is
the user-unit target, and would be wrong for a system unit.

```ini
[Unit]
Description=mctl-telegram Local Bridge daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%h/mctl-local/mctl-telegram-local daemon
Environment=MCTL_LOCAL_PASSPHRASE_FILE=%h/mctl-local/passphrase
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now mctl-telegram-local
loginctl enable-linger "$USER"   # start at boot, without waiting for a login
journalctl --user -u mctl-telegram-local -f
```

`enable-linger` is the part people miss: without it a user unit stops when
your last session ends and does not come back until you log in again.

## Limitations

These are current, not permanent, but plan around them today.

**Five tools do not work in local mode** and return an explicit error rather
than failing strangely: `edit_message`, `delete_messages`, `forward_messages`,
`search_messages`, `set_reaction`. The daemon implements `list_dialogs`,
`get_unread_messages`, `get_messages`, `send_message`, `send_media`,
`prepare_get_media`, `get_media` and `pin_message`.

**`fetch_media=true` is refused** on `get_messages` and `get_unread_messages`.
Use `prepare_get_media` followed by `get_media` for each item instead.

**No always-on listener.** The Communication Agent's hosted listener needs a
server-side Telegram client, which a local-mode account does not have.

**One account per machine.** The config path is fixed, and running `init` again
overwrites the previous setup. Two accounts need two machines or two user
accounts.

**One daemon per account.** A second daemon displaces the first, which
reconnects and displaces the second; the result is a reconnect loop that trips
an alert on our side. If you move the daemon to another machine, stop the old
one.

**Migrating an existing hosted account, and reverting one back to hosted, are
still operator actions.** `activate` provisions a *brand-new* local account by
itself; it does not — and cannot — flip an account that already has a hosted
session. Moving an existing account into local mode, or moving a local account
back to hosted, both go through an operator (`set_account_mode`), covered in
"Operator: support and recovery only" above.

**Between finishing `activate` (or an operator's `set_account_mode` migration)
and starting the daemon, your tools will fail.** The relay refuses a daemon
whose account is not already in local mode, so the mode switch has to land
first — which it does automatically as part of `activate`, or as soon as the
operator's `set_account_mode` call returns for a migration. In the gap your
assistant gets a clear `local-bridge daemon not connected` error rather than a
hang, and the error clears as soon as the daemon connects. Plan the switch for
a moment when you are ready to run `daemon`, not hours before.

## Security notes

Everything the daemon writes is owner-only (`0600`), including the device
identity file, the session database and its SQLite sidecar files, and (for
the legacy path) `bridge_token.json`. A few things are worth knowing in
detail:

**Device binding.** `activate` generates an Ed25519 keypair on your machine
and never lets the private half leave it. Only the public key (sent once, at
registration) and per-request signatures ever cross the network — the server
verifies a signature but never possesses anything that could let it forge
one. `device_key.json` holds the private key, the public key, and — once
issued — your device's credential, all in one record so a reader never sees a
credential naming a device whose key is not in the same file.

**Read-only by default, always.** The first credential a newly registered
device receives is read-only regardless of your account's `send_enabled`
value — this has been true server-side since #483 and `activate` does not
change it. Getting send capability is always the separate, explicit
`set_send_consent` step described above.

**Hours-scale TTL with automatic refresh.** A device-signed credential is
issued for hours, not months, and both `activate`'s bootstrap and every
`daemon` connection attempt refresh it via signed proof of possession — there
is no bearer secret sitting in a file that has to be manually rotated before
it expires, the way the legacy worker token does.

**Revocation.** `revoke_local_bridge_device` denylists the device's entire
credential lineage in one call: the `jti` claimed at first issuance is
carried forward unchanged by every later refresh, precisely so that
denylisting it kills every credential the device has ever held, not just its
current one. A denylisted device is refused on its very next `/refresh` or
reconnect attempt. If the device is already connected, revocation does not
wait for that — the same call actively evicts its live `/bridge` websocket
(`Hub.EvictDevice`), so a compromised, already-connected daemon is
disconnected immediately, not merely locked out of renewing.

**The legacy manually-minted worker-token path is compatibility only.** It
remains fully supported — `connect --token`, `mint_worker_token`/
`POST /api/mcp/worker-token`, and the daemon's bearer-only self-renewal all
keep working exactly as before — but it is not how new onboarding happens.
It exists for accounts set up before this guide's `activate` flow, and for
operator-driven recovery. A worker token minted this way is long-lived (up to
90 days) and announces nothing as it approaches expiry: the first symptom is
the daemon reconnecting in a loop. An operator revokes it by `jti` — the
identifier recorded when the token was minted — or, if that was not written
down, by Telegram id, which kills every token issued for the account up to
that moment and drops a connected daemon along with it.

**What the server keeps depends on how the account became local.** An
account onboarded through `activate` has no stored session here, ever. An
account migrated from a hosted login via `set_account_mode` keeps the sealed
session from when it first connected: the server stops using it, but it is
still in the database. Revoking that hosted session does not disable local
mode or disconnect your daemon. To make the stored copy useless, end that
session from your own Telegram client (Settings → Devices); the stored bytes
then hold a dead authorization key.

You can confirm which route a call actually took. `get_my_audit_log` and
`GET /api/account/audit` return a `call_path` field per entry: `"local"` when
the call was routed to your daemon, absent when it was served by the hosted
session pool. That is the authoritative record — the server writes it — and it
is worth checking once after the switch:

```
23:45:41  list_dialogs  status=ok     call_path=(absent — hosted)
23:48:29  list_dialogs  status=error  call_path=local
23:50:00  list_dialogs  status=ok     call_path=local
```

The error in the middle is the expected one: the account was already in local
mode while the daemon was not yet running. Your daemon's own log shows the
matching `dispatch` line for each successful call.

## Troubleshooting

**`local-bridge daemon not connected`** — the account is in local mode but no
daemon is attached. Check the service is running and look at its log.

**The daemon exits immediately at startup** — read the error. Common causes:
the passphrase is wrong (or the file has a stray newline in an older build);
a device credential's signing key material is unusable, in which case the
error names `activate` as the fix, and you should re-run it rather than edit
the device file by hand; or, on the legacy path, the MCP token has expired,
which needs a fresh `connect`.

**Reconnect loop** — usually an expired legacy MCP token (if you are on that
path), sometimes a second daemon running elsewhere. Both look identical from
the server; check for the second daemon first, because it is the one you can
rule out immediately.

**The daemon starts by hand but not under launchd** — the passphrase is being
prompted for. Confirm `MCTL_LOCAL_PASSPHRASE_FILE` is set in the service
definition and points at a readable file.

**Windows: `init` cannot read the passphrase** — run it in PowerShell rather
than Git Bash; the no-echo prompt does not work under mintty.

**My first send after granting consent didn't go through** — check the
`dry_run` field of the response. If it is still a dry-run, the daemon's
opportunistic out-of-band refresh (see `set_send_consent` above) may be
cooling down from a previous attempt; wait a few seconds and retry. If it
still doesn't clear, confirm `set_send_consent` actually reports
`send_enabled: true` for your account.

## Rolling back

For an account onboarded through `activate`: stop the daemon. There is
currently no self-service way to flip the account back to hosted mode; ask an
operator to run `set_account_mode mode="hosted"` if you need the account
itself to revert, not just the daemon to stop.

For an account migrated from hosted mode: ask the operator to move it back to
hosted mode with `set_account_mode`. Calls resume through the server's own
session, provided you did not terminate it from your Telegram client — if you
did, you will need to reconnect the account normally. Stop the daemon once the
switch is done.
