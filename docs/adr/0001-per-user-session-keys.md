# 0001. Per-user session keys, and an honest "not zero-knowledge"

Status: Accepted

## Context

To call Telegram on a user's behalf, the hosted service needs that user's
MTProto session: an authorization key that is, in effect, a logged-in
Telegram client. Whoever holds it can read and send everything the user
can. The service has to persist it, because asking the user to sign in to
Telegram again after every restart is not a product.

Two things had to be settled: how the session is protected at rest, and
what the service claims about it.

## Decision

- A session is stored only as a sealed blob in
  `telegram_accounts.session_encrypted` (`internal/db/store.go`, `SaveSession`).
- Each blob is sealed with AES-256-GCM under a key derived per user:
  HKDF-SHA256 over the master `ENCRYPTION_KEY`, with the user id as salt and
  the info string `mctl-telegram-session-v2` (`internal/crypto/aesgcm.go`,
  `deriveKey`, `SealForUser`).
- Every blob starts with a version byte (`0x00` plaintext, `0x01` legacy
  master key, `0x02` per-user). Reads accept the legacy form so that stored
  blobs can be re-sealed lazily, without a migration window.
- The server refuses to start without `ENCRYPTION_KEY` unless it is bound to
  loopback in a local environment (`cmd/server/bootguard.go`,
  `checkBootGuard`). Plaintext blobs exist only for local development.
- The public pages say plainly that the hosted mode is **not
  zero-knowledge**: the server decrypts the session to use it, and the
  operator holds the master key (`SECURITY.md`, `/security`, `/privacy`).

## Consequences

- A leaked database alone does not expose sessions, and a key recovered for
  one user does not open another user's blob.
- It is not protection against a compromised server. One master key, one
  database and one process mean a compromise of the running service
  exposes every hosted account. The documentation says so, rather than
  letting "encrypted at rest" imply more than it does.
- The users who cannot accept that trade-off have a different mode, Local
  Bridge ([0006](0006-local-bridge-relay.md)), where the session never
  reaches the server.

## Alternatives

- **One master key for every blob** (the `0x01` format). Simpler, but a key
  compromise is total and per-user revocation is impossible. Kept only as a
  readable legacy format.
- **Client-held keys in the hosted mode.** The server must call Telegram
  while the user is away (unread digests, background agent work), so it
  needs the session in the clear at call time. A client-held key would only
  move the trust, not remove it, and would break those flows. That
  requirement is what Local Bridge exists for instead.
