# Local Bridge

Local Bridge is a deployment mode in which your Telegram session lives on a
machine you control instead of on tg.mctl.ai. The server keeps routing MCP tool
calls from your assistant, but instead of opening Telegram itself it forwards
each call over a websocket to a daemon running on your machine, and that daemon
talks to Telegram.

The mode is in beta and is enabled per account by an operator. This document
describes what it actually does today, including the parts that are unfinished,
so you can decide whether it fits your workflow before you set it up.

![Маршрут вызова: локальный путь через демон и hosted-ветка через серверный пул](img/local-bridge.svg)

The diagram is generated from `img/local-bridge.architecture.json` with
[Archify](https://github.com/tt-a1i/archify) — edit the JSON and re-render
rather than editing the SVG, otherwise the two drift apart:

```sh
node ~/.agents/skills/archify/bin/archify.mjs deliver architecture \
  docs/img/local-bridge.architecture.json /tmp/local-bridge.html --quality showcase
```

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

**Your existing server-side session is not deleted.** Switching to local mode
stops the server from using its stored copy; it does not erase it, and it
cannot be revoked without leaving local mode (a revoked account reverts to
hosted, and the bridge then refuses your daemon). If you want the stored copy to
be worthless, terminate that session from your own Telegram client — Settings →
Devices → find the session → terminate. The bytes remain in the database but
hold a dead authorization key. Do this **after** your local login works, not
before.

**Your connector does not change.** The MCP endpoint is the same; the server
decides per account whether a call goes to the hosted session pool or to your
daemon. You do not need to remove and re-add the connector.

## Before you start

**You need an account that is already connected to tg.mctl.ai.** Local mode is
a migration, not a way to sign up without the server. The database row the
operator flips is created by an ordinary hosted login, so if the account has
never connected, there is nothing to flip. Connect it normally first.

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
keeps its config and session, and it creates that one for you.

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

## Set up

Four commands, in order. Everything lives under
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

`init` does not ask for the server address. That matters in step 3.

### 2. `login`

```sh
./mctl-telegram-local login --phone +1234567890
```

An ordinary Telegram login: it asks for the passphrase from step 1, then for the
code Telegram sends, then for your cloud password if you have two-factor
enabled. The code arrives inside Telegram when the account is signed in
somewhere else, and by SMS when it is not.

This creates a **second** session on your account, alongside the server's. Both
are live until you terminate one.

### 3. `connect`

```sh
./mctl-telegram-local connect --token "$(cat mcp-token.txt)" --server https://tg.mctl.ai
```

Exchanges a long-lived MCP token for a short-lived bridge token and saves both.

**`--server` is required the first time.** `init` never asks for it, so the
config starts with an empty server URL, and omitting the flag produces a request
to a URL with no host.

The MCP token is issued to you by an operator. An ordinary OAuth access token
from your connector will not do: those live one hour, and the daemon needs a
credential it can keep re-exchanging. Ask for one when your account is enabled
for local mode.

**One caveat about that command.** `--token` is currently the only way to pass
the token, so it appears in the process argument list and is readable by other
local accounts through `ps` for as long as the command runs — a second or two.
On a single-user machine that is a small window; on a shared one, run `connect`
when nobody else is logged in. Delete `mcp-token.txt` once `connect` has
succeeded: the daemon stores its own copy in
`~/.config/mctl-telegram-local/bridge_token.json`, and the file you pasted from
is not read again. A `--token-file` option that avoids the argument list
entirely is tracked in #454.

### 4. `daemon`

```sh
./mctl-telegram-local daemon
```

Connects to `wss://tg.mctl.ai/bridge` and serves calls. Until an operator has
flipped your account to local mode, the bridge refuses the connection; until the
daemon is running, your assistant's calls return
`local-bridge daemon not connected`. Neither state loses your authorization or
hangs — the errors are explicit and recoverable.

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

**Enabling and disabling the mode is an operator action.** Nothing in the
service writes the mode column, so there is no self-serve switch yet.

## Security notes

Everything the daemon writes is owner-only (`0600`), including the session
database and its SQLite sidecar files. Two things are worth knowing about the
contents:

- `config.json` holds your `api_hash` in plaintext.
- `bridge_token.json` holds both your MCP token and the current bridge token in
  plaintext. Anyone who can read it can act as your account until those expire.

The MCP token is long-lived — months, typically. Nothing warns you as it
approaches expiry: the first symptom is the daemon reconnecting in a loop. Note
the expiry date somewhere you will see it.

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

**The daemon exits immediately at startup** — read the error. Two are common:
the passphrase is wrong (or the file has a stray newline in an older build), and
the MCP token has expired, which no longer resolves itself and needs a fresh
`connect`.

**Reconnect loop** — usually an expired MCP token, sometimes a second daemon
running elsewhere. Both look identical from the server; check for the second
daemon first, because it is the one you can rule out immediately.

**The daemon starts by hand but not under launchd** — the passphrase is being
prompted for. Confirm `MCTL_LOCAL_PASSPHRASE_FILE` is set in the service
definition and points at a readable file.

**Windows: `init` cannot read the passphrase** — run it in PowerShell rather
than Git Bash; the no-echo prompt does not work under mintty.

## Rolling back

Ask the operator to move the account back to hosted mode. Calls resume through
the server's own session, provided you did not terminate it from your Telegram
client — if you did, you will need to reconnect the account normally. Stop the
daemon once the switch is done.
