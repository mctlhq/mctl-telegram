# 0005. A per-pod MTProto session pool, one replica, sticky routing ready

Status: Accepted

## Context

An MTProto session is a long-lived, stateful connection. Opening it costs
round trips to Telegram, and opening the same authorization key from two
places at once is unsafe. When a second server instance opens a new
session for a user, Telegram shows that user a "New login" notification,
which looks exactly like an account takeover (`docs/hpa.md`).

## Decision

- Each process keeps a pool of live clients, one per user, with an idle
  timeout and a cap on open sessions (`internal/telegram/clientpool.go`,
  `ClientPool`).
- Production runs one replica with the `Recreate` strategy, so two pods
  never hold the same authorization key at once.
- Sticky routing for more replicas is built and tested but not needed yet.
  The ingress copies the token's subject into `X-Mctl-Route-Key` and hashes
  on it (`deploy/ingress/sticky-nginx.yaml`, `sticky-envoy.yaml`; 0.28.0,
  0.29.0). The `sticky-ingress-acceptance` workflow proves it on kind,
  against ingress-nginx and Istio.
- Rate limiters, confirmation ids and pending OAuth flows are in memory.

## Consequences

- One user's calls reuse a warm connection, and users never see spurious
  "New login" notices.
- There is no horizontal scaling and no redundancy. A deploy or a crash is
  a short outage, measured against the published SLOs (`docs/slo.md`).
- In-memory state is lost on restart: pending confirmations and sign-ins
  have to be repeated, and rate-limit budgets reset.
- Going to two replicas needs more than the sticky ingress: the in-memory
  state has to move to a shared store, and the limiter has to fail closed
  when that store is unavailable. That work is deliberately deferred until
  load or an availability commitment calls for it.

## Alternatives

- **Open a session per request.** Slow, and every request would risk a
  "New login" notice.
- **Several replicas with a shared session store.** The MTProto client
  itself lives in process memory; sharing the stored key does not share the
  connection, and two pods using one key at once is the failure this
  decision avoids.
