# Glovo checkout-handoff contract (spike, not implemented)

Status: draft from spike #1184. Provider-neutral: Claude and ChatGPT surfaces reuse it
as MCP tools later. See [ADR 0009](../adr/0009-assistant-temporal-tenancy.md) and the
[report](../reports/glovo-assistant-spike.md). MCTL never pays, stores card data, or
reports an order as paid.

## Provider adapter (owner: mctl-assistants provider worker, candidate repo mctl-api or a new worker repo)

```
SearchStores(ctx, conn, query) / GetMenu(ctx, conn, store)         // read, idempotent
GetPastOrders(ctx, conn, since)                                    // read
QuoteBasket(ctx, conn, BasketDraft) -> Quote{fingerprint, totals}  // read
MutateBasket(ctx, conn, BasketDraft, idemKey) -> BasketRef         // write, authorized only
ReadBasket(ctx, conn, BasketRef) -> Quote                          // verify read-back
HandoffTarget(ctx, conn, BasketRef) -> {kind: app_open|web_url|unverified, ...}
```

There is no `PlaceOrder` and no `Pay`. `conn` is the opaque `glovo_connection_id`,
dereferenced only by the provider worker from encrypted, tenant-owned state
(AES-GCM, as `internal/crypto`). Egress uses `internal/netsafe`.

## OrderSnapshot (owner: mctl-api)

```
{ order_id, tenant_id, owner_principal_id, install_id, install_revision,
  policy_digest, connection_ref, request_ref,
  trigger: {kind: owner|schedule, schedule_id?, occurrence?} }
```

Immutable. Workflow inputs carry opaque references only: no tokens, cookies,
addresses, cart contents, raw menu text or payment details in history, search
attributes, logs or LLM tool results.

## States

```
prepared -> quoted -> awaiting_consent(fingerprint, expires_at)
  -> basket_mutated -> verified -> handoff_issued(token_hash, ttl)
  -> handoff_opened -> OUTCOME_UNKNOWN
```

Side terminals: `stale_install`, `consent_expired`, `basket_changed` (re-asks the
owner), `provider_unavailable`, `cancelled`. No step is skipped.

## Fingerprint and consent

Fingerprint = SHA-256 over canonical encoding of: store, item IDs, quantities,
modifiers, unit and total prices, fees, currency, delivery-address reference.
Consent goes through the existing human-input relay
(`docs/contracts/mctl-api-human-input.md`) bound to
`(order_id, fingerprint, install_revision)`; any other value is rejected. If verify
read-back differs from the consented fingerprint, consent is invalidated and the
owner is asked again; the changed basket is never handed off. An existing provider
cart is shown as a diff and never silently overwritten.

## Revalidation and retries

`RevalidateScope` (install active, revision equal, tenant membership, connection
live) runs before every provider write, every signal handler and every schedule fire.
Failure stops the order as `stale_install` with no provider write. Only idempotent
reads are retried (with backoff). A write that times out is followed by a read-back
verify, never a blind re-mutation. Revoking an install or deleting a connection
deletes the encrypted order state and session reference.

## Handoff token

256-bit random, only its hash stored, single-use (compare-and-set), TTL 15 minutes in
the PoC, bound to order, owner and fingerprint. Reuse, expiry or another principal is
refused and leaves the order unchanged. When continuity is `unverified` the UI says
"Open Glovo and review the basket" and claims no deep link.

## Outcome

After the owner opens the handoff the status is `handoff_opened`, then
`OUTCOME_UNKNOWN` indefinitely unless verifiable external evidence exists. A later
phase may match past orders read-only to reach `observed_placed`, which is still not
"paid by MCTL".

## Schedules (owner: Automation Control Plane, mctlhq/.github#318)

Each occurrence starts the order workflow with ID
`glovo-order/<tenant>/<install>/<schedule_id>/<occurrence_utc>` and
`WorkflowIDReusePolicy=RejectDuplicate`: one run per occurrence, crash dedupe, no
overlapping fires. A scheduled order only prepares and asks; it never mutates a
basket without consent for that occurrence (unless install policy pre-authorizes the
mutation, never payment). The assistant has no scheduler of its own.

## Owner channel and Telegram UI (owner: mctl-telegram)

Only owner commands (Saved Messages `/mctl`, an authenticated MCTL surface) and
server-fired schedules start orders; third-party DMs never do. Notifications go to
the owner channel. Message: basket preview (store, items, modifiers, totals,
address label only) with buttons `Confirm basket`, `Change`, `Cancel`, and after
verify `Open Glovo`. Callbacks carry only `order_id` and a nonce; a second press is
an acknowledged no-op.

## MCP tool shapes (portable)

`glovo_prepare_order`, `glovo_order_status`, `glovo_confirm_basket`. They take and
return opaque `order_id` handles. No namespace, workflow ID, run ID or task queue is
ever a parameter or a result.

## Refusals

Missing, revoked, expired or ambiguous identity links return typed reasons
(`no_tenant`, `ambiguous_tenant`, `no_connection`, ...). A mismatched or unknown
`tenant_id`, `owner_principal_id` or `order_id` returns the same not-found error
whether or not the target exists.
