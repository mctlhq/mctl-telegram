# Local Bridge quick start

This is the zero-admin path. Four commands get you a connected, read-only
daemon. Nobody else has to do anything.

Sending is a later, explicit owner step — see
[Owner controls](/docs/local-bridge/owner). Operator procedures
(migration, rollback, `connect --token`) are not on this page.

## Before you start

**You do not need a hosted login first.** `activate` for a brand-new
Telegram id provisions the account directly into local mode.

**You need a machine that stays on.** When the daemon is not reachable,
calls fail with `local-bridge daemon not connected` rather than falling
back to the server.

**You need your own Telegram API credentials.** Register an application
at <https://my.telegram.org/apps> and use the `api_id` and `api_hash` it
shows. Telegram issues one application per account and offers no way to
delete it, so if you have registered one before, that page shows the
existing credentials. The credentials identify the *application*, not
the account — one pair can authorize any Telegram account.

## Install

Download the build for your platform from the
[releases page](https://github.com/mctlhq/mctl-telegram/releases) and
check it against `SHA256SUMS.txt`:

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
complaint and moves on if the commands are merely listed one after
another.

`VERSION` is read from the releases API rather than written out, so this
block does not rot.

`~/mctl-local` is where this guide keeps the binary, the passphrase file
and the daemon's log. `~/.config/mctl-telegram-local` is where the
daemon itself keeps its config, device identity and session; it creates
that directory for you.

Builds are published for `darwin/arm64`, `darwin/amd64`, `linux/amd64`,
`linux/arm64` and `windows/amd64`. An Intel Mac needs `darwin-amd64`.

**The binaries are not signed.** Downloading with `curl` avoids macOS
quarantine (attached only to files a browser saved). If you did download
through a browser, clear it with
`xattr -d com.apple.quarantine mctl-telegram-local`. On Windows, run the
`.exe` from a terminal rather than double-clicking it.

Building from source works too:

```sh
git clone https://github.com/mctlhq/mctl-telegram && cd mctl-telegram
go build -o mctl-telegram-local ./cmd/local
```

`mctl-telegram-local init --help` and `daemon --help` print usage.
`init --help` and `daemon --help` do not start those commands.

## 1. `init`

```sh
./mctl-telegram-local init
```

Asks for your `TG_API_ID`, your `TG_API_HASH`, and a passphrase. The
passphrase encrypts the local session database via Argon2id.

**There is no recovery.** If you lose the passphrase, the stored session
is unreadable and you start again from `login`. Generate a strong one
and store it in a password manager, and — if you plan to run the daemon
unattended, which you should — also write it to a file:

```sh
mkdir -p ~/mctl-local &&
(umask 077 && LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 40 > ~/mctl-local/passphrase)
```

Write it without a trailing newline, or rely on the daemon trimming one.
The `umask 077` is not decoration: a plain redirection can create the
file world-readable under your usual umask.

`init` does not ask for the server address. `activate --server` sets it
and persists it for `daemon`.

## 2. `login`

```sh
./mctl-telegram-local login --phone +1234567890
```

An ordinary Telegram login: passphrase, then the code Telegram sends,
then your cloud password if you have two-factor enabled. The code
arrives inside Telegram when the account is signed in somewhere else,
and by SMS when it is not.

A successful login writes your numeric Telegram id to `config.json`.
`activate` reads that id, so you do not have to type `--telegram-id`
unless you want to override it.

This creates a **second** session on your account, alongside any hosted
one. Both are live until you terminate one.

On Windows, run `init` and `login` in PowerShell rather than Git Bash;
the no-echo prompt does not work under mintty.

## 3. `activate`

```sh
./mctl-telegram-local activate --server https://tg.mctl.ai
```

`--server` is required the first time (`init` never asks for one) and is
saved to `config.json` for `daemon`. `--telegram-id <n>` overrides the
id persisted by `login`. `--label <name>` sets the device's
human-readable label (defaults to the machine hostname).

`activate`:

1. Generates an Ed25519 keypair the first time it runs on this machine
   and keeps it in `device_key.json`, `0600`. The private half never
   leaves your disk.
2. Prints a verification URL and a short code. Open the URL, type the
   code, sign in with Telegram, and approve the device. Nothing is
   written to the server database until you approve.
3. After you approve, bootstraps a device credential automatically: it
   asks the server for a one-time nonce, signs it, and exchanges the
   signature for a worker credential. There is no token to copy.

The command's last line tells you to run `daemon` next. A brand-new
Telegram id never touches a hosted session: `session_encrypted` for that
account is `NULL` from the first row.

**Re-running `activate` is safe.** It reuses the same keypair and device
id. If the credential step already succeeded it reports the device as
already activated and exits 0. If a previous run was interrupted, re-run
it rather than deleting the config directory.

## 4. `daemon`

```sh
./mctl-telegram-local daemon
```

Connects to `wss://tg.mctl.ai/bridge` and serves calls. If `activate`
produced a device credential, `daemon` refreshes it on every connection
attempt by proving possession of the private key — nothing here to renew
by hand.

`daemon` has no `--server` flag. It reads the URL `activate` (or
`connect`) persisted. If config has no server, it exits naming
`activate --server`.

Until the daemon is running, your assistant's calls return
`local-bridge daemon not connected`.

You now have a **read-only** daemon. To send or pin, continue at
[Owner controls](/docs/local-bridge/owner). To keep the process alive
across reboot, use the service unit below.

## Running it unattended

Run the daemon under a service manager, not in a terminal. It takes its
passphrase from the environment when one is supplied:

| Variable | Meaning |
|---|---|
| `MCTL_LOCAL_PASSPHRASE_FILE` | Path to a file holding the passphrase. Takes precedence. |
| `MCTL_LOCAL_PASSPHRASE` | The passphrase itself. |

**Use the file, not the value.** A launchd plist in
`~/Library/LaunchAgents` is world-readable; a systemd unit's
`Environment=` lines are visible through `systemctl show`.

The macOS login keychain is locked outside a GUI session, so
`security find-generic-password` fails for a service started at boot.

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
parent of `StandardOutPath`.

A LaunchAgent runs inside your login session, so after a reboot it
starts only once someone logs in. On a headless machine that means
automatic login (and usually FileVault off). The alternative is a
LaunchDaemon in `/Library/LaunchDaemons`, which starts at boot but runs
as root.

```sh
launchctl kickstart -k gui/$(id -u)/ai.mctl.telegram-local
tail -f ~/mctl-local/logs/daemon.log
```

### systemd (Linux)

This is a **user** unit —
`~/.config/systemd/user/mctl-telegram-local.service`, not
`/etc/systemd/system/`.

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

Without `enable-linger` a user unit stops when your last session ends.

## Next

- [Owner controls](/docs/local-bridge/owner) — turn sending on; revoke a device
- [How it works](/docs/local-bridge/how-it-works) — activation, PoP, first token
- [Support and recovery](/docs/local-bridge/support) — not part of this path
