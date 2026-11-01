# Runbook: live Telegram login proof

Tracks mctl-telegram#1057. This is the low-frequency proof that the real
`telegram.LoginQR` and `telegram.Login` code signs in against Telegram itself.
Fakes (`internal/telegram/login_test.go`, `loginqr_test.go`) cover the logic, the
synthetic probes (#959) and the connect funnel (#960) cover reachability and real
users; this covers the product code against the live service. Test datacenters
are not used: they no longer complete `signIn` (#854).

## Dedicated account only

Use only the dedicated login-proof service account. Never a personal, operator
or canary account. The `TG_LIVE_SESSION` account belongs to the production
canary and the message-tool round trip; it must not be reused here.

The proof is never scheduled. The `live-telegram-login` workflow has
`workflow_dispatch` as its only trigger and `release-please.yml` does not
dispatch it; `cmd/login-proof/workflow_test.go` enforces both.

## When it is required

Run it once before release for a PR that materially changes phone login, SRP or
2FA handling, session persistence, QR login, or login error classification. It
is not needed for unrelated changes.

## One-time setup

1. Create a Telegram account for the proof and note its numeric id. Give it a
   2FA password if you want the SRP path covered.
2. Seed its anchor session with `cmd/ci-anchor` into a state directory outside
   the repository, using a separate directory from the canary's:

   ```
   TG_LIVE_API_ID=... TG_LIVE_API_HASH=... go run ./cmd/ci-anchor send -state DIR -phone +...
   TG_LIVE_API_ID=... TG_LIVE_API_HASH=... go run ./cmd/ci-anchor confirm -state DIR -code ...
   ```

   `DIR/session.json` is the value of `TG_PROOF_ANCHOR_SESSION`.
3. Create the GitHub environment `live-telegram-login`, restricted to `main`,
   with the secrets `TG_PROOF_API_ID`, `TG_PROOF_API_HASH`,
   `TG_PROOF_ANCHOR_SESSION`, `TG_PROOF_EXPECT_TG_ID` and, if the account has
   2FA, `TG_PROOF_PASSWORD`.

## QR proof (CI)

Dispatch the `live-telegram-login` workflow on `main`. The anchor session accepts
the exported login token, so no human is needed. It passes only when the session
was stored, one `list_dialogs` call (limit 1) succeeded through the MCP server,
and the new authorization was logged out. Do not dispatch it while a phone proof
is running: both use the same account.

## Phone proof (attended)

On an operator machine with a terminal. Credentials are environment variables,
never flags:

```
export TG_PROOF_API_ID=... TG_PROOF_API_HASH=... TG_PROOF_EXPECT_TG_ID=... TG_PROOF_PHONE=+...
export COMMIT=$(git rev-parse HEAD)
go run ./cmd/login-proof phone                         # sign in, MCP call, logout
go run ./cmd/login-proof phone -expect wrong-password  # must fail with bad_password
go run ./cmd/login-proof phone -expect expired-code    # must fail with code_expired
```

The login code is typed at a hidden prompt, and so is the 2FA password unless
`TG_PROOF_PASSWORD` is set. The command refuses to run without a terminal.
Nothing is written to disk. For `expired-code`, wait past the code lifetime
before typing it, or type a code from an earlier send. Telegram may answer
`PHONE_CODE_INVALID` instead; the run then reports `code_invalid`, which is not a
pass, and the fake test remains the authority for that case.

## Evidence

Each run prints exactly one line and exits 0 only on `outcome=pass`:

```
login-proof mode=qr outcome=pass reached=cleanup commit=<sha> at=<utc>
```

It holds no phone number, Telegram id, username, name, session, code, password or
token. Paste that line (result, commit SHA, timestamp) into #1057 or the PR.
Outcomes other than `pass`: `fail`, `bad_password`, `code_expired`,
`code_invalid`, `flood_wait`, `auth_restart`, `identity_mismatch`, `refused`,
`cleanup_failed`, `timeout`, `unknown`. Report them as they are; none is a pass.

## cleanup_failed

The proof could not end the authorization it created. In Telegram, open Settings,
Devices, on the proof account (from the anchor or another session) and terminate
the "MCTL Assistant" device. Then re-run.

## Anchor session lost

If the anchor session is terminated, the proof fails closed (`refused` or
`unknown`). Re-seed it with `cmd/ci-anchor` and update the secret.
