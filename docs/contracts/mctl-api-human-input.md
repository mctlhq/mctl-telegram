# mctl-api human-input contract, as mctl-telegram consumes it

**Pinned copy, not the source of truth, and NOT YET VERIFIED against a deployed mctl-api.** This file records the human-input (agent clarification) relay contract the Telegram adapter (#571) is built against. The authoritative text is mctl-api#261. At the time this adapter was written the final DTO was not available in this repository, so every field and error code below is the adapter's **assumption**, taken from the #571 proposal. The mctl-api revision that confirms it is: `UNPINNED` — fill it in, and correct any field or code that differs, in the same change that enables `HUMAN_INPUT_ENABLED` anywhere. Until then the adapter ships disabled.

The identity and authorization rules are exactly those of [mctl-api-work-context.md](mctl-api-work-context.md): authenticate as `surface:telegram` (`MCTL_SURFACE_TELEGRAM_TOKEN`), name the human only through `X-MCTL-Surface-Actor: <telegram user id>`, and never decide authorization locally. A clarification answer is never an approval and never touches `/approvals`.

## Routes (relay routes, owned by #571)

| Route | Request | Response |
|---|---|---|
| `GET /api/v1/human-input` | – | `{schema_version, requests: [RequestView]}`: requests pending for the acting human. |
| `GET /api/v1/human-input/{request_id}` | – | `RequestView` (canonical state, any state). |
| `POST /api/v1/human-input/{request_id}/response` | `{request_hash, kind, value}`, header `Idempotency-Key` | `{schema_version, request_id, state}`; `state` is `answered` on success. |

`schema_version` is expected to be `workitem/v1`, like the work-context envelope; any other value is rejected (`ErrIncompatibleSchema`).

`RequestView` fields the adapter reads (all others are ignored by construction; there is no field for `prompt`, `reasoning` or `logs`):

| Field | Meaning |
|---|---|
| `request_id`, `request_hash` | Identity of the request and of its current version. An answer names both. |
| `version` | Monotonic version number, shown as `v<N>`. |
| `kind` | `single_choice` or `free_text`. Other kinds are not delivered. |
| `state` | `pending`, `answered`, `rejected`, `expired`, `cancelled`, `superseded`. |
| `question`, `why` | Text shown to the human (sanitized and capped by the adapter). |
| `options[{id,label}]` | `single_choice` only. The human answers by number; the adapter submits the option `id`. |
| `deadline` | RFC 3339; omitted when none. |
| `work_item_id`, `work_ref` | Correlation with the work item; `work_ref` is a display string. |
| `links[]` | Safe https links. |
| `max_length` | Free-text cap in characters; the adapter defaults to 2000. |

The request body carries `request_hash`, `kind` and `value` only. No actor field and no approval field exists in any human-input request type.

## Error mapping

| Status / `error` code | Adapter sentinel | Rendered to the human |
|---|---|---|
| `409`/`410` `request_hash_mismatch`, `request_superseded` | `ErrRequestSuperseded` | `This question is no longer active.` (row `superseded`) |
| `409`/`410` `request_expired`, `request_cancelled`, `request_not_active` | `ErrRequestNotActive` | `This question is no longer active.` (row `inactive`) |
| `409` `already_answered` | `ErrAlreadyAnswered` | `Already answered.` |
| `403` `not_eligible` | `ErrNotEligible` | neutral wording, no policy detail, no retry |
| `403` `link_not_found`, `link_revoked`, `link_expired` | `ErrLinkNotFound`, ... | neutral wording; the poller backs the actor off |
| `400`/`422` `answer_invalid` | `ErrAnswerInvalid` | `That answer was not accepted...` |
| transport error, timeout, `5xx` | none | re-read `GET .../{request_id}` and render that state; never report success |

The mctl-api `X-Request-ID` response header is kept as a correlation id in logs.

## Idempotency

`Idempotency-Key` is `sha256(request_id|request_hash|command message id)` in hex, so a redelivered Saved Messages command reuses the key and mctl-api dedupes the write.
