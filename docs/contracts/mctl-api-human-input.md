# mctl-api human-input contract, as mctl-telegram consumes it

**Pinned copy, not the source of truth.** This file records the human-input (agent clarification) relay contract the Telegram adapter (#571) is built against. The source of truth is mctl-api (mctl-api#261). Every field, status and code below was read from mctl-api `main` at revision **`7656351875a78989f65719908065e1206485ff57`**:

- `internal/api/handlers_human_input.go` (list and get, the `humanInputView` read model, states);
- `internal/api/handlers_human_input_response.go` (the response route, its body, results and rejections);
- `internal/humaninput/contract.go` (`ValidateValue`), `internal/humaninput/ledger.go` (delivery ledger and dedupe);
- `internal/api/router.go` (route groups), `internal/api/handlers_surface_identity.go` (relay allowlist and refusals);
- `docs/work-context-contract.md`, section "Surface identity and relay".

Re-pin (and re-read these files) whenever mctl-api changes any of them.

The identity and authorization rules are those of [mctl-api-work-context.md](mctl-api-work-context.md): authenticate as `surface:telegram` (`MCTL_SURFACE_TELEGRAM_TOKEN`), name the human only through `X-MCTL-Surface-Actor: <telegram user id>`, and never decide authorization locally. On a relay route mctl-api resolves the verified link and runs the handler **as the linked human**, never as admin and never as the service principal. A clarification answer is never an approval: the response route never signals approve, and nothing it records is read by the approval path.

## Routes

All three are on the surface-relay allowlist. The two reads sit outside mctl-api's write rate-limit group; the response shares the 20/min write budget.

| Route | Request | 2xx response |
|---|---|---|
| `GET /api/v1/human-input` | query `state=pending` (default) or `all`, optional `work_item_id`. The adapter sends neither. | `200 {"items": [RequestView], "count": N}`. **No `schema_version`.** `invalid_documents` is added only for admins and the service principal, never for a relayed human. |
| `GET /api/v1/human-input/{request_id}` | `request_id` must match `^hir-[0-9a-f]{16}$` (else 400) | `200 RequestView`, in any state. |
| `POST /api/v1/human-input/{request_id}/response` | body `{"request_hash", "value", "surface"}` | `200` status `accepted`, or `202` status `pending_delivery` (see below). |

Listing and reading only show requests the caller may see. For a relayed human that is exactly the requests whose `actor_refs` contain their verified `github:<login>`; anything else is not listed, and a GET answers `404`, not `403`.

`GET /api/v1/human-input` with `state=pending` answers **`503`, never a short or empty list**, when the Temporal client is missing or the state of any candidate request could not be determined. The adapter treats any failed list as "nothing observed": it never infers that a request went away from it.

## RequestView

`humanInputView` fields, and what the adapter does with each:

| Field | Type | Adapter |
|---|---|---|
| `request_id` | string `hir-<16 hex>` | Identity; validated, used in the URL path. |
| `request_hash` | string | Identity of the sealed version; the answer must name it. |
| `request_version`, `round` | int | Shown as `v<request_version>`. |
| `work_item_id`, `service`, `proposal` | string | Correlation; `work_item_id` is matched against `work_item_bindings` for the `Work:` ref. |
| `workflow_id`, `agent`, `audience` | string | **Not decoded.** |
| `question`, `reason` | string | Rendered (sanitized, capped, continuation lines indented). |
| `response_type` | `free_text`, `single_choice`, `multi_choice`, `structured` | Only `single_choice` and `free_text` are delivered. The others are logged once and counted as `delivery_attempt{outcome="undeliverable"}`. |
| `options` | `[]string`, `single_choice`/`multi_choice` only | Numbered `1.`..`N.` in order. The answer value is the **exact option string**. |
| `context_refs` | `[]string` | Only `https://` entries are shown, as `Link:` lines. |
| `eligible_actors` | `[]string` | Only for admins and the service principal; never sent to a relayed human. **Not decoded.** |
| `can_respond` | bool | A request with `can_respond: false` is not delivered. |
| `created_at`, `expires_at` | string (RFC 3339, or naive = UTC) | `expires_at` is shown as `Expires:`. |
| `state` | see below | Required. |
| `state_detail` | string | Decoded, never rendered or logged. |

There is no `schema_version`, `kind`, `why`, `deadline`, `version`, `links`, `work_ref` or `max_length` field. Option ids do not exist: options are plain strings.

### States

`state` is one of:

| State | Meaning | Adapter |
|---|---|---|
| `pending` | The owning workflow waits on this request and it has not expired. The only state that takes an answer. | Deliver; keep the row open. |
| `expired` | `expires_at` has passed. | Terminal (`inactive`). |
| `timed_out` | The workflow timed out waiting. | Terminal (`inactive`). |
| `resolved` | The workflow resumed after this request: it was answered (by someone). | Terminal: `answered` if this human's own answer was recorded (`submitted`) or just submitted, otherwise `inactive`. |
| `not_pending` | The workflow is not waiting on this request (moved on, or no longer exists). | Terminal (`inactive`). |
| `unknown` | mctl-api could not determine the state (the workflow did not answer). | **Never terminal**; nothing changes. |

## Response

Body, decoded by mctl-api with `DisallowUnknownFields` (any other key is a 400; a key naming an actor, such as `actor`, `user`, `subject` or `acting_principal`, is a 400 `actor_not_accepted` even before that):

```json
{"request_hash": "<hash of the version shown>", "value": "<answer>", "surface": "telegram"}
```

- `value` is any JSON value; for `free_text` a non-empty string, for `single_choice` one of `options` exactly (case-sensitive). The adapter always sends a string.
- `surface` is caller-declared provenance. For a relayed call mctl-api **forces** it to the relaying surface (`telegram`), and a different claim is a 400. The adapter sends `telegram`.
- The respondent is taken from authentication (`github:<login>` of the linked human). There is no respondent field. The service principal itself can never answer (403).

Results are `{"request_id", "status", "state", "detail", "respondent", "received_at"}`:

| HTTP | `status` | `state` | Meaning | Adapter |
|---|---|---|---|---|
| `200` | `accepted` | `resolved` | The workflow confirmed this answer. | `Answered by you: <value>. Agent will resume.`; row `answered`. |
| `200` | `accepted` | (`detail: "already accepted"`) | Replay of the same human's identical, already accepted answer. | `Already answered.`; row `answered`. |
| `202` | `pending_delivery` | `pending` | Recorded and signalled, **not yet confirmed** by the workflow. | **Not success.** `Submitted: <value>. The platform has not confirmed it yet; check with /mctl input status <code>`; row `submitted` (still open). `/mctl input status` and the poller settle it from the canonical state. |
| `409` | `rejected` | `superseded` | `request_hash` is not the current one. | `This question is no longer active.`; row `superseded`. |
| `422` | `rejected` | `invalid_value` | Not a valid value for the response type. | `That answer was not accepted...`; row stays open. |
| `409` | `rejected` | `pending` | The workflow refused this payload but still waits. | Same as `invalid_value`. |
| `409` | `rejected` | `expired`, `timed_out`, `not_pending`, `resolved` | The request no longer takes an answer. | `This question is no longer active.`; row `inactive`. |
| `409` | `rejected` | `answered` | Another response holds the request (another eligible human, or a different value). | `This question is no longer active.` (the other actor is not named); row `inactive`. |
| `403` | `rejected` | `not_eligible` | The linked human is not an eligible respondent. | Neutral wording, no policy detail, no retry; row unchanged. |
| `404` | – | – | Not found, or not visible to this human. | `This question is no longer active.` |
| `503` | `pending_delivery` / – | `unknown` / – | Workflow or ledger unavailable; an answer may be recorded. | Re-read `GET .../{request_id}` and render that; never success. |

`detail` can list the question's options and `respondent` is the human's GitHub login: the adapter never logs or renders either, and a rejection's `APIError.Message` is left empty for that reason.

Relay refusals use mctl-api's `writeErrorCode` shape `{"error": "<message>", "code": "<code>"}`: `403` `link_not_found`, `link_revoked`, `link_expired`, `relay_required`, `surface_route_not_allowed`, `principal_disabled`, `identity_refused`; `400` `actor_not_accepted`; `503` `surface_identity_unavailable`. On the poll, a `link_*` code makes the actor dormant with backoff.

## Idempotency and dedupe

mctl-api does **not** read `Idempotency-Key` on this route (nothing in `handlers_human_input_response.go` or the router consults it); an unknown header is simply ignored. Deduplication is mctl-api's delivery ledger (`internal/humaninput/ledger.go`), one row per request: a submission is "the same" when respondent, `request_hash` and the hash of the canonical value all match (`Delivery.SameSubmission`). The same human resubmitting the same answer gets the recorded result back (and a `pending_delivery` row is pushed through again); a different answer while one is pending or accepted is refused with `409 answered`. The first claim per request wins, matching the workflow's first-valid-response rule, and two identical racing submissions may both signal, which the workflow tolerates.

The adapter still sends `Idempotency-Key: sha256(request_id|request_hash|command message id)` (hex). It is harmless, keeps the value stable across a redelivered Saved Messages command, and would take effect if mctl-api ever reads it; correctness does not depend on it.

## Correlation

mctl-api's chi `RequestID` middleware adopts an incoming `X-Request-Id`, but at this revision mctl-api neither echoes a request id in a response header nor logs it. The adapter therefore generates one per relay call (`tg-<16 hex>`), sends it as `X-Request-Id`, and logs it as `correlation_id`. If a future mctl-api response carries `X-Request-ID`, that value is used instead. To join with mctl-api's own logs, use `request_id`: every `human_input.*` log and audit line there carries it.
