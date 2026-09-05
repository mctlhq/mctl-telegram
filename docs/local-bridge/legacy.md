# Local Bridge legacy connect

`connect --token` is the pre-`activate` way to get a daemon running. It
is kept as a compatibility and recovery path. New onboarding uses
[Quick start](/docs/local-bridge/quickstart).

## `connect --token`

```sh
./mctl-telegram-local connect --token-file mcp-token.txt --server https://tg.mctl.ai
```

Exchanges a long-lived MCP token for a short-lived bridge token and
saves both to `bridge_token.json`. `--server` is required the first
time, for the same reason it is under `activate`.

An operator mints the token with the `mint_worker_token` MCP tool (or
`POST /api/mcp/worker-token`) using `telegram_id` and
`purpose="local-bridge"`. That grants
`telegram:messages:send` / `telegram:messages:pin` in addition to the
read-only scopes, in one static, long-lived credential rather than a
refreshing device-bound one.

The daemon repeatedly exchanges this same worker token for a fresh
short-lived bridge token via `POST /api/bridge/token`, but the worker
token's own expiry never moves. Once it lapses (up to 90 days after
minting), the fix is an operator re-minting a fresh one and you
re-running `connect` — not anything the daemon can do by itself.

`daemon` picks this bearer path automatically when there is no device
credential on disk. You do not choose between the two paths; the
presence or absence of `activate`'s device files decides it.

`--token "$(cat mcp-token.txt)"` puts the token in the process argument
list, readable by other local accounts through `ps` or
`/proc/<pid>/cmdline`. On a shared machine prefer `--token-file`:

```sh
./mctl-telegram-local connect --token-file mcp-token.txt --server https://tg.mctl.ai
```

```sh
op read op://vault/mcp-token/credential | ./mctl-telegram-local connect --token-file - --server https://tg.mctl.ai
```

`--token-file -` (or `--token -`) reads stdin. `--token` and
`--token-file` are mutually exclusive.

## Why this path still exists

It remains fully supported for accounts set up before `activate`, and
for operator-driven recovery. A worker token minted this way is
long-lived and announces nothing as it approaches expiry: the first
symptom is the daemon reconnecting in a loop.

An operator revokes it by `jti` — the identifier recorded when the
token was minted — or, if that was not written down, by Telegram id,
which kills every token issued for the account up to that moment and
drops a connected daemon along with it.

Prefer `activate` for any new machine. It never hands you a token to
paste.

## Next

- [Quick start](/docs/local-bridge/quickstart)
- [Support and recovery](/docs/local-bridge/support)
- [Overview](/docs/local-bridge)
