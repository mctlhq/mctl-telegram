# Forks and private definitions (P4 decision record)

Status: **Accepted (owner, 2026-10-31)**. Option B; the owner's answers are
under [Decisions](#decisions). Spike: #1042; implemented by P4.2 (#1043).

A fork is an account-private assistant that a user derives from a catalog
assistant: their own instructions, fewer tools, stricter intents, lower
limits. This record decides where fork definitions live, and fixes the fork
model that P4.2 implements whichever storage wins. It assumes
[spec.md](spec.md), in particular [Registry form](spec.md#registry-form),
[Install revisions](spec.md#install-revisions),
[Tool names](spec.md#tool-names), [Audience](spec.md#audience) and
[MCP tools](spec.md#mcp-tools).

## Context

After P3 the chain for a catalog assistant is: author → version →
canonical materialized JSON → digest → mctl-api registry
(`agent_definition_versions`, kind `TelegramAssistant`) → mctl-telegram
durable snapshot (`assistant_definitions`, keyed by digest) → install (the
profile pins the digest and moves `install_revision`) → claim (renders from
the snapshot, never calls the registry).

Facts the decision rests on:

- **Publishing to the registry is human-admin only.**
  `PublishDefinitionVersion` is behind `requireAgentRegistryHumanAdmin`
  (mctl-api `internal/api/handlers_agent_platform.go`). The one non-human
  publisher, `service:mctl-agents-registry-publisher`, is confined to three
  v1 routes, and the agent service principal was deliberately refused
  publish rights (mctlhq/mctl-agents#470) so that nothing publishes on its
  own authority.
- **Registry rows are immutable and are never deleted.** Only `lifecycle`
  moves (`published → deprecated | disabled`, `deprecated → disabled`);
  `spec_json` is stored as plain JSONB and readable by admins through the
  registry read routes and `GET .../definition`.
- **mctl-api knows nothing about mctl-telegram accounts.** An install
  belongs to a mctl-telegram `users.id` (the `agent_profiles` row); the
  registry has no subject it could check ownership against.
- **mctl-telegram already stores user-written prompt text.** `ownerNotes`
  (up to 2000 characters) live in the install, encrypted with the per-user
  key (`agent_profiles.install_encrypted`, `internal/crypto` HKDF subkey),
  and `HardDeleteAccount` → `purgeAgentData` deletes them with the profile.
- **The snapshot is shared.** `assistant_definitions` rows are keyed by
  digest only, carry no owner, store the document in plaintext, are not
  purged with an account, and every pinned row is re-read from the registry
  every 5 minutes (`assistantregistry.Refresher`); a `404` is recorded as
  `disabled`.

## Options

**A. mctl-api stays the single authority.** The registry gains
`metadata.visibility: private` with an owner subject. mctl-telegram
publishes each fork version to mctl-api on the user's behalf, with a new
narrow right: the `surface:telegram` principal may publish only `private`
`TelegramAssistant` versions, for the owner it says it acts for.
`GET .../definition` returns a private version only to that surface acting
for that owner; the public catalog never lists it. mctl-telegram snapshots
the fork like any other definition.

**B. Private definitions live in mctl-telegram.** A fork version is stored in
mctl-telegram's database with an owner, encrypted with the owner's key.
`assistantinstall` and the claim resolve from three sources: registry
snapshot, embedded bridge, and the owner's private forks.

## Comparison

| | A: registry holds forks | B: mctl-telegram holds forks |
|---|---|---|
| **One lifecycle and digest chain** | One store for every version; the fork digest goes through `contentHash` like a catalog version. | Same document form, canonicalization and digest function (`assistant.ParseMaterialized`); the fork records its base's digest, and the base still comes through the registry. Storage is split: the fork row is in mctl-telegram. |
| **Who can publish; new authority** | New write right in mctl-api for a surface token. The registry must trust mctl-telegram's claim of who the owner is, since it cannot verify a Telegram account. A leaked surface token can publish private versions for any owner subject. This reverses the direction #470 took. | No new right in mctl-api. In mctl-telegram the new right is self-only `account:manage` writes of fork versions, which validation confines to narrowing a registry base. |
| **Revocation** | An admin can disable one private version, or the base. | An admin disables the base in the registry; every fork of that base stops within one refresh, because a fork's lifecycle is its base's (see [Lifecycle](#status-and-lifecycle)). There is no per-fork admin switch in the registry; a global `ASSISTANT_FORKS_ENABLED` switch stops all forks. |
| **Deletion and account purge** | The registry has no delete: it needs a hard-delete path for private rows, which breaks its immutability invariant, plus a purge-by-owner call from `HardDeleteAccount`. That call crosses services, so the purge transaction needs an outbox with retries. mctl-telegram still holds a copy in its snapshot, which also has to be encrypted and purged. | One `DELETE` in `purgeAgentData`, in the same transaction as the profile. No cross-service step. |
| **Availability** | Claims are unaffected (they read the snapshot). Creating and editing a fork, and installing one, need mctl-api. | Claims are unaffected. Creating and editing a fork needs only the base, which comes from the snapshot when it is already installed or from the registry otherwise. Installing a fork needs the base's lifecycle, read the same way as for a catalog install. |
| **Privacy** | The instructions are plaintext JSONB in mctl-api, readable by every registry admin and by the read routes, and they are stored twice (registry and snapshot). Encrypting them before publish makes them opaque to mctl-api, so the registry can no longer validate what it is said to be the authority for. | Encrypted with the owner's per-user key, like `ownerNotes`. The server process decrypts to render a claim; a database dump or a DB admin sees ciphertext; mctl-api admins see nothing. The worker receives the rendered prompt per job, as it already does for `ownerNotes`. |
| **Cross-surface reuse** | Natural: another surface could read the fork once it has an owner model. | Telegram-only. Because the document is the same canonical materialized form, moving forks to the registry later is a copy with unchanged digests (see [Later move to A](#later-move-to-a)). |
| **Work in mctl-api** | Visibility `private` + owner subject; a publish route and guard for the surface; owner-scoped `/definition` read; filters on admin listings and MCP tools; hard delete and purge-by-owner; encryption at rest for private rows; docs. | None for P4. |
| **Work in mctl-telegram** | Fork validation, MCP tools, a publish client, an outbox for purge, plus an owner-aware, encrypted, purgeable snapshot for private rows (that is, B's storage work as well). | Fork validation, MCP tools, the `assistant_forks` store, a third resolution source, refresh of base lifecycles. |

## Decision: B, as a constrained overlay

Keep forks in mctl-telegram, but not as a second registry: a fork is a
private, owner-scoped derivative of exactly one registry base, which stays
the authority.

1. **A does not give one authority for forks.** The registry cannot verify
   ownership; it would record whatever mctl-telegram asserts. The authority
   over "may this user run this text on this account" is mctl-telegram's
   either way. A adds a surface write right to a registry that has been
   narrowed on purpose (#470), and keeps nothing in exchange.
2. **A fork's instructions are user data, and mctl-telegram already handles
   that class.** `ownerNotes` set the precedent: user-written prompt text,
   per-user encryption, purged with the account. A would put the same class
   of data, in plaintext, into an immutable store with no delete path.
3. **MCTL stays the authority through the base.** A fork can only narrow a
   registry base. It pins the base's digest, it takes its lifecycle from the
   base, and the same parser and digest function validate both. An admin who
   disables a base stops every fork of it within one refresh.
4. **A strictly contains B's work in mctl-telegram.** Under A the snapshot
   still holds the fork, so it still needs an owner column, encryption and
   purge, and A adds the mctl-api changes and a cross-service purge on top.
5. **A stays open.** The document format is the same, so if forks ever need
   to run on another surface, they move to the registry when it has a real
   owner model, with their digests unchanged.

The cost of B is honest: `assistantinstall` and the claim gain a third
source. It is contained by keeping forks in their own table and code path
(below), never in `assistant_definitions`.

### Storage under B

- New table `assistant_forks`: `user_id`, `name` (the full fork name),
  `version`, `digest`, `base_name`, `base_version`, `base_digest`,
  `document_encrypted` (canonical materialized JSON, per-user key),
  `promotion` (P4.3; `observe` until promoted), `created_at`.
  Unique on `(user_id, name, version)` and on `(user_id, digest)`.
- Not in `assistant_definitions`: that table is shared by digest, plaintext,
  not purged per account, and the refresher would read every pinned row
  from the registry and record a fork's `404` as `disabled`.
- The profile keeps pinning `assistant_name`, `assistant_version` and
  `assistant_definition_digest`. A name containing `~` (see
  [Naming](#naming)) is a fork; resolution then reads `assistant_forks`
  by `(user_id, digest)` only, never another account's rows, and never by
  name alone.
- The base's snapshot is stored in `assistant_definitions` as for any
  install, in the same transaction as the fork install, so a claim can
  check the base lifecycle without the registry.
- `purgeAgentData` deletes `assistant_forks` rows for the user.

## Fork model

This part holds under either option.

### Copy-on-write

`fork_assistant` takes a base `name@version`, resolves it exactly as an
install would (registry fetch, digest check, lifecycle `published`; a
`deprecated` base only for the name@version the account already runs), and
copies its materialized document. The fork document is a complete
`TelegramAssistant`: the base with the fork's changes applied and
`metadata.fork` added:

```yaml
metadata:
  name: hr-recruiter~k7f3q2mxa4~careful
  version: 0.1.0
  owner: acct:k7f3q2mxa4
  visibility: private
  status: active
  fork:
    base: {name: hr-recruiter, version: 0.1.0, digest: "sha256:875d7b32..."}
```

The digest is computed over this whole document with the same function as
for catalog definitions, so the base reference is part of what is pinned.
Later edits of the base never reach the fork; moving to a new base version
is an explicit `rebase` that creates a new fork version.

### Naming

`<base>~<owner-scope>~<slug>`:

- `<base>`: the base's catalog name.
- `<owner-scope>`: 10 characters of lowercase base32 from
  `HMAC-SHA256(server key, "assistant-fork-owner:" || users.id)`. It
  identifies the owning account without revealing a Telegram id or the
  internal row id, and is the value of `metadata.owner` as `acct:<scope>`.
- `<slug>`: the user's name for the fork, `^[a-z0-9][a-z0-9_-]{0,31}$`.

No collision with a catalog name is possible: a catalog name must match the
slug pattern `^[a-z0-9][a-z0-9_-]{0,62}$`, which has no `~`. The parser
accepts a `~` name only together with `metadata.fork` and
`visibility: private`, and refuses `metadata.fork` on a `~`-less name, so
neither form can be passed off as the other. Uniqueness between accounts
does not rest on the hash: lookups are always by `(user_id, digest)`, and
the database's unique keys include `user_id`. The scope keeps names
globally unique as well, which a later move to the registry needs.

### Versions

Fork versions are immutable and assigned by the server; the user never
chooses one. The first version is `0.1.0`. Each edit creates the next one:

- **patch** when only `instructions` change;
- **minor** when anything that is part of the authority diff changes:
  tools, intents or their tiers, limits, ceilings, disclosure policy, or
  the base (a rebase).

So a minor bump tells the owner, and P4.3's promotion screen, that the
fork's permissions moved and not only its wording. Either bump resets the
version to `observe` (P4.3). Major is not used in P4.

### What a fork may change in P4

Validated by one function, `assistant.ValidateFork(base, fork)`, in addition
to the full `ParseDefinition` / `ParseMaterialized` checks every definition
passes:

- **Instructions** replace the base's. Capped at 16 KiB of UTF-8 (the
  hr-recruiter prompt is about 8 KiB). They may not contain the
  `ownerNotes` block delimiters. `ownerNotes` from the install are still
  appended below them, as for a catalog assistant.
- **Intents** must be **equal or stricter** than the base's: a tier may only
  move `auto → approve → never`; an intent may be removed (a reply labelled
  with it is then unknown, and unknown intents never auto-send); a new
  intent may be added only at `approve` or `never`; `userOverride` may only
  narrow (`any → tighten → none`). Reasons: an `auto` tier is safe only
  because the base author defined what the intent covers and the C1 eval
  measured it; the model's single intent label is still trusted (mixed
  intents are an open acceptance scenario), so a user-defined `auto` intent
  would be a loosening that nothing has measured. P4.3's eval measures the
  fork's behaviour, not the meaning of new labels, so promotion does not
  lift this rule either.
- **Tools**: a subset of the base's, by canonical name or alias, including
  `get_event` and `complete_agent_job` (as for any definition) and enforced
  by the P4.0 tool gate. Until #1043 moves `get_lead` to a lead-only route, a
  fork that keeps `get_lead` and drops `get_conversation_context` is
  refused: the gate maps `GET /conversations/{id}/context` to both tools, so
  that subset would claim a restriction the server does not enforce.
- **Limits**: defaults and ceilings each at most the base's ceilings, and a
  default at most the fork's own ceiling.
- **Variables**: inherited unchanged, except that a variable's default
  disclosure may be made stricter. No new variables in P4.

### What a fork inherits unchanged

- `records` (custom schemas are P4.4, #1045).
- `escalation`, `examples` and the remaining descriptive parts. `title` and
  `description` may be edited, since they describe the fork to its owner.
- `defaults.disclosure`: `policy` may go `optional → required`, never back;
  the default text is inherited.
- `execution` stays reserved and rejected, as for any definition.
- `metadata.status` is `active` (a fork version is immutable from birth);
  `visibility` is `private`.

### Status and lifecycle

- A fork version has two states of its own: `observe` (the start, and after
  every new version) and `promoted` (P4.3, #1044). It cannot be installed or
  updated into `guarded` until promoted.
- Its **registry lifecycle is its base's**. The refresher reads the base's
  name@version for every pinned fork, exactly as for a pinned catalog
  version, and the claim's lifecycle gate applies the base's value:
  `disabled`, or unknown for 24 hours, stops new jobs; `deprecated` keeps a
  pinned fork running but refuses new forks of that base and rebases onto it.
- Installing a fork is self-only: the install service refuses a fork whose
  owner is not the calling account, whatever route it comes through
  (MCP, web or the admin route).
- **Quotas**: at most 10 forks per account and 50 versions per fork. A
  write past either limit is refused (`fork_limit`) and changes nothing;
  the owner frees room by deleting a fork or unpinned versions.
- **Deletion**: `delete_fork` removes versions the current install does not
  pin and refuses the pinned one (`fork_in_use`), so a pin never points at a
  missing document. Account purge removes all of them with the profile.

### Prompt-injection posture

The platform floor does not change: every reply is checked on the server
(policy, URL and credential deny, audience, schedule, tool gate), whatever
the prompt says, so fork instructions cannot relax it. Fork instructions run
with the account owner's authority on the owner's own account; they are not
a channel for a third party, and `ownerNotes` stay bounded and delimited as
today.

Two things are new:

1. **Authoring may be driven by a model.** `fork_assistant` and
   `update_fork` are MCP tools, and the MCP client calling them may also
   have read untrusted Telegram messages. A prompt injection there could
   create or edit a fork. Containment: a new version always starts in
   `observe`, so it can only draft; the P4.3 promotion is a human step on
   tg.mctl.ai or in `/mctl`, never an MCP tool; and every fork write is
   audited with the version and digest (never the text) and notifies the
   owner in the bot chat.
2. **Instructions replace rather than append.** The base author's
   workflow text is gone in a fork, so behaviour inside the allowed intents
   can change completely with permissions unchanged. That is what P4.3's
   eval gate is for; P4.2 adds only the size cap, the delimiter check and
   the strictness rules above.

## Work slices

### B (accepted), all in mctl-telegram

| Slice | Files |
|---|---|
| Fork document and rules | `assistants/schemas/assistant.schema.json` (`visibility: private`, `metadata.fork`, fork name pattern), `internal/assistant` (`ValidateFork`, name parsing, owner scope), tests |
| Storage and purge | `internal/db/agent_schema.go` (`assistant_forks`), `internal/db/assistant_forks.go`, `purgeAgentData` in `internal/db/agent_domain.go`, `agent_purge_test.go` |
| Install path | `internal/assistantinstall/service.go` (fork source in `Prepare`, owner check, observe-only mode until promoted, base snapshot in the same transaction) |
| Claim and refresh | `internal/agentapi/events.go` (`resolveAssistant`: fork source by `(user_id, digest)`, base lifecycle gate), `internal/assistantregistry/refresh.go` (read base refs of pinned forks) |
| MCP tools | `fork_assistant`, `update_fork`, `list_my_forks`, `delete_fork` (#1043), self-only, `account:manage`, audited |
| Docs | `spec.md` (forks in Registry form, MCP tools, Customization tiers) |

mctl-api: nothing in P4.

### A (for comparison)

mctl-api: `internal/agentregistry/assistant_catalog.go` (`private`
visibility, owner subject), `v1alpha2_store.go` (owner column, encrypted
spec for private rows, hard delete and purge-by-owner),
`internal/api/handlers_assistant_catalog.go` (surface publish route and
guard, owner-scoped `/definition`), admin listings and MCP tools filtered,
`docs/agent-platform-registry.md`. mctl-telegram: everything in B except the
storage slice, which becomes an owner-aware encrypted snapshot, plus
`internal/assistantregistry/client.go` (publish), and a purge outbox.

## Later move to A

If forks need another surface, the registry first needs an owner model it
can verify, private-row encryption and deletion. A fork version then moves
as a copy of its canonical document: same bytes, same digest, so existing
pins keep matching. Nothing in this record has to be undone.

## Decisions

The owner answered the spike's questions on 2026-10-31 (#1053):

1. **Storage**: Option B, a constrained overlay in mctl-telegram:
   `assistant_forks`, encrypted with the per-user key.
2. **Intents**: equal to the base's or stricter. A new intent only at
   `approve` or `never`, never `auto`, and promotion does not change that.
3. **Instruction cap**: 16 KiB of UTF-8.
4. **Versions**: patch when only the instructions change, minor when
   anything in the authority diff changes.
5. **Kill switch**: disabling the base plus the global
   `ASSISTANT_FORKS_ENABLED` switch. No per-fork admin switch for now.
6. **Quotas**: 10 forks per account, 50 versions per fork.
