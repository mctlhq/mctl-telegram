# mctl-api work-context contract, as mctl-telegram consumes it

**Pinned copy, not the source of truth.** This file summarises the mctl-api contracts the Telegram work-item adapter (#443) must build against. The authoritative text lives in mctl-api at revision `5ee21e9` (main, 2026-09-23, after mctl-api#370):

- `docs/work-context-contract.md`: § Identity and authorization, § REST surface, § Implementation status → Surface relay and → Execution requests;
- `internal/api/router.go` (`surfacePrincipalGate`);
- `internal/openapi/openapi.yaml`.

mctl-docs `docs/human-input/surface-identity.md` covers the user-facing link flow. If mctl-api changes, update this file in the same change that relies on the new behaviour.

It is kept in this repository because the agents that investigate and implement mctl-telegram issues clone only this repository.

## Rules that are not negotiable

1. **The bot never supplies an actor.** mctl-api derives the acting principal from authentication only. Any body field that names an actor (`created_by`, `actor`, `principal`, `on_behalf_of`, …) is refused with `400 actor_not_accepted`. There is no `tg:<id>` subject and no `ActorSubject` field in any request.
2. **The bot authenticates as its own surface principal.** That principal is `surface:telegram`, with bearer `MCTL_SURFACE_TELEGRAM_TOKEN`. It is non-admin, has no tenant, and is distinct from `mctl-agent`. The bot never uses `MCTL_API_TOKEN` or the `mctl-agent` principal to act for a user.
3. **It acts for a user only by relay.** On a relay route, the bot names the Telegram user in the header `X-MCTL-Surface-Actor: <telegram user id, digits>`. mctl-api resolves the verified `SurfaceIdentityLink` for (`telegram`, that id) and runs the request as the linked human (`github:<login>`), with that human's tenants and never as admin. Work-item events and audit rows carry the human as actor and `acting_principal: surface:telegram`.
4. **Execution attachment is platform-owned.** The bot never starts, attaches or correlates an execution, and never seals or reads a context snapshot. Those routes are service-principal only (the engine side: mctl-agents / Temporal). The bot records user intent and **requests** execution (`POST .../execution-requests`). The platform dispatcher (mctl-agents#461) claims the request, starts the run and attaches the canonical execution identity. **A surface requests execution; a surface does not declare execution identity:** the bot never sends `engine`, `engine_ref` or `execution_id`.
5. **Telegram reachability is not authorization.** A deployment allowlist such as `telegram_owner_ids` is not proof of identity for work-item attribution.

## Linking a Telegram user (one time)

1. The human calls `POST /api/v1/surface-identities/challenges` `{"surface":"telegram"}` with their own GitHub credential. They get a one-time code, valid for 10 minutes and stored hashed.
2. The human sends the code to the bot.
3. The bot calls `POST /api/v1/surface-identities/redeem` `{"code"}` with `X-MCTL-Surface-Actor: <their telegram id>`. The results are:
   - `201`: link created;
   - `403 challenge_invalid`;
   - `409 link_conflict`.

The human can list and revoke links with `GET /api/v1/surface-identities` and `POST /api/v1/surface-identities/{id}/revoke`. The bot does not call these.

Relay refusals, which the bot must handle by offering the link flow or explaining the problem:
- `403 link_not_found`, `link_revoked` or `link_expired`;
- `403 relay_required` (header missing);
- `400` when the header is sent on a route that is not a relay route.

## The only routes `surface:telegram` may call

| Route | Body | Notes |
|---|---|---|
| `POST /api/v1/work-items` | `{tenant, title, visibility?: tenant\|private, origin_surface?, external_key?, idempotency_key?}` | `origin_surface` is forced to `telegram`; claiming another is 400. `external_key` dedupes open work. |
| `GET /api/v1/work-items/{id}` | – | Item, latest execution, pending approval and latest snapshot pointers, `state_version`. |
| `POST /api/v1/work-items/{id}/intents` | `{text, params?, surface?, idempotency_key?}` | Appends a user intent. |
| `POST /api/v1/work-items/{id}/execution-requests` | `{kind: start\|resume, expected_state_version, resumed_from_execution_id?, intent_id?, surface?, idempotency_key?}` | Asks the platform to run or continue the item. `engine`, `engine_ref` or `execution_id` in the body → `400 execution_identity_not_accepted`. |
| `GET /api/v1/work-items/{id}/execution-requests[/{request_id}]` | – | Request state: `pending` → `claimed` → `fulfilled` (with `execution_id`) or `rejected` (with a typed `reason`). |
| `POST /api/v1/work-items/{id}/surface-refs` | `{external_id, actor_external_id?}` | `surface` defaults to telegram. `actor_external_id` is correlation-only, never identity. |
| `GET /api/v1/human-input`, `GET /api/v1/human-input/{request_id}`, `POST /api/v1/human-input/{request_id}/response` | – | Human-input relay. Owned by #571, not by #443. |

**Not available to the bot:**
- `GET /work-items` (list);
- `PATCH /work-items/{id}`;
- `POST /work-items/{id}/resume`: it names the engine run, so it is not a relay route. Use an execution request.
- `POST /execution-requests/claim`, `/{request_id}/fulfil`, `/{request_id}/reject`: the platform dispatcher only;
- `GET|POST /work-items/{id}/executions`;
- `GET|POST /work-items/{id}/executions/{execution_id}/snapshot`;
- `GET /work-items/{id}/snapshots[/{snapshot_id}]`;
- `GET /work-items/{id}/events`;
- anything under `/approvals`.

A design that needs any of these from the bot is wrong for this contract.

## `workitem/v1` envelope and semantics

- Responses carry `"schema_version": "workitem/v1"`. The item view is `{schema_version, work_item, state_version, latest_execution, …}`.
- States: `active`, `waiting`, `completed`, `superseded`, `archived`.
- `state_version` is optimistic concurrency: send `expected_state_version`, and a mismatch is 409.
- Idempotency comes from the `Idempotency-Key` header or `idempotency_key`, bound to the acting (relayed) human.
- Mutating routes spend the linked human's write budget (20/min). The surface as a whole has an aggregate ceiling.

## Execution request semantics

Create refuses:
- a stale `expected_state_version` (`409 state_version_conflict`);
- a terminal item (`409 invalid_transition`);
- a kind the item cannot take (`start` needs an active item that never ran; `resume` needs a waiting item or one that ran);
- a Pending/Running execution (`409 execution_active`);
- a `resumed_from_execution_id` or `intent_id` of another item (`404`);
- a second open request for the item (`409 execution_request_open`, with the open request's id in `details`).

Requests have no TTL and cannot be cancelled by the requester yet (mctl-api#371). An open request waits for the dispatcher, so the bot should show "requested" rather than "running" until the request is fulfilled.

## Rollout gate

Code may target this contract now. End-to-end use needs an mctl-api release and deployment with the surface principal token configured. Until then every call answers as the running mctl-api version does, so the adapter must stay behind a flag that is off by default, with no behaviour change when it is off.
