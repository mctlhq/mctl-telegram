# 0006. Local Bridge: the session stays on the user's machine

Status: Accepted (beta)

## Context

The hosted mode asks users to trust the operator with their Telegram
session ([0001](0001-per-user-session-keys.md)). Some users, and most
companies evaluating the service for their staff, will not. They still want
the same MCP endpoint, so that their AI client's configuration does not
change.

## Decision

- A daemon, `mctl-telegram-local` (`cmd/local`), runs on the user's machine
  and holds the MTProto session there, encrypted with a key derived from a
  local passphrase (Argon2id).
- The daemon connects out to the server over a websocket (`GET /bridge`)
  with a short-lived token for that audience. The server becomes a relay: an
  MCP call for a Local Bridge account is forwarded down the socket and the
  answer comes back the same way (`internal/bridge`, `DESIGN.md`).
- A new account can activate the mode itself (`mctl-telegram-local
  activate`, #484). That path registers an Ed25519 device key and renews
  the bridge credential with proof of possession of it, so a copied token
  alone does not let another machine take the device's place. Moving an
  existing hosted account, in either direction, is still an operator action
  (`set_account_mode`).
- The mode first shipped in 0.27.0 (issue-94) and is marked beta since
  0.30.0 (#151).

## Consequences

- The session never reaches the server, so a server compromise does not
  expose the account's Telegram key.
- It is not end-to-end encryption. The relay sees the MCP payloads it
  forwards, including message text, in memory. `DESIGN.md` states this,
  and so must any description aimed at platforms.
- After a migration from hosted mode, the old hosted blob stays on the
  server until it is deleted.
- The daemon must be running for calls to work, and a few tools are not
  yet supported in local mode. The older `connect --token` path, still
  supported, keeps two bearer tokens in a plaintext file on the user's
  disk. `DESIGN.md` keeps the list of gaps.
- The relay currently depends on running as one replica; scaling it out
  needs the same routing work as the hosted mode
  ([0005](0005-session-pool-and-sticky-routing.md)).

## Alternatives

- **A fully local MCP server with no relay.** Works for desktop clients but
  not for hosted ones such as ChatGPT or Claude on the web, which need a
  public HTTPS endpoint.
- **Authorizing the bridge through mctl-api's OAuth** (a dedicated scope
  and endpoint there). Rejected and recorded in `DESIGN.md` so it is not
  revived: mctl-api has no Telegram user id and no audience to bind the
  token to.
