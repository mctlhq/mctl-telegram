# Assistant definitions (assistants.mctl.ai/v1alpha1)

Status: draft (P2 done, pending release). The server compiles the catalog in, an
account's install is applied through `PUT /api/admin/agent/install`, and
every claimed job carries its assistant's instructions. Of the P2 policy
settings, policy enforces the `never` tier, `outside_hours` schedules and
the audience scope so far; see [What the runtime enforces](#what-the-runtime-enforces) and
[Phases](#phases).

The communication agent that answers recruiters is the first of a family of
assistants a person can install into their own Telegram account. Today its
definition is spread across a global prompt (`AGENT_SYSTEM_PROMPT`), the
`agent_profiles` row, the encrypted owner profile, a fixed tool set in
`internal/agentworker/mcpserver.go` and floors in `internal/agent/policy`.
This document gives it one declarative shape, so that:

- a catalog can list assistants a user picks from;
- installing one is a document of values and overrides, validated before it
  is applied;
- the split between what the author decides, what the user may change and
  what the platform never lets either relax is written down, not implied.

## Two documents

Following ADR 007's definition / execution-profile split (mctl-agents), an
assistant is two documents:

| Document | Kind | Who writes it | Lifecycle |
|---|---|---|---|
| Definition | `TelegramAssistant` | assistant author | versioned (semver); a `draft` may still change under its version, an `active` one may not |
| Install | `AssistantInstall` | the account owner | one per account, pins an exact definition version |

Schemas: [`assistants/schemas/assistant.schema.json`](../../assistants/schemas/assistant.schema.json)
and [`assistants/schemas/assistant-install.schema.json`](../../assistants/schemas/assistant-install.schema.json)
(JSON Schema 2020-12). `internal/assistant` validates both, checks the install
against its definition and maps it onto today's profile.

Worked example: [`assistants/hr-recruiter/assistant.yaml`](../../assistants/hr-recruiter/assistant.yaml)
and [`install.example.yaml`](../../assistants/hr-recruiter/install.example.yaml).

## Definition

```yaml
apiVersion: assistants.mctl.ai/v1alpha1
kind: TelegramAssistant
metadata:      # catalog listing: name, title, description, version, owner,
               # visibility (public|tenant|admin), status (draft|active|deprecated),
               # tags, examples
spec:
  instructions: {path: ...}  # persona and workflow (markdown or text)
  variables: [...]           # what the install fills in
  intents: [...]             # reply intents, each with a tier
  tools: [...]               # subset of the platform tool registry
  records: {kind: job_lead}  # what the assistant saves
  escalation: [...]          # when the owner is pulled in
  defaults: {mode, limits, ceilings, disclosure}
  execution: {model, budgetUsd, timeoutSeconds}  # reserved, see below
```

**instructions.path** is relative to the definition's directory and may not
leave the repository. The recruiter agent's points at
`deploy/agent-worker/system-prompt.txt`, the file the Mac mini worker's
self-update also installs, so there is one copy of that prompt. Because a
`draft` definition's instructions can change under the same version, the
catalog computes a digest of the definition file and its instructions; the
claim response reports it next to `name@version`, so a job's behaviour is
traceable to exact content, not only to a version.

**execution** is reserved: the worker's model, budget and timeout still come
from its own environment. A definition that sets any of them cannot be
installed (`ErrUnsupported`), so nothing looks enforced that is not.

**variables** generalise the owner profile. Each has a `type` (string,
number, boolean, string_list), `required`, optional `choices`, and a
`profilePath` into the profile document (`identity.*`, `public_profile.*`,
`preferences.*`, `skills`, `restricted.*`). Ordinary fields carry a
`disclosure` level (public, after_owner_engaged, never) — the same levels
`internal/agent/profile` enforces. Restricted fields carry `send` instead
(`approval` or `never`): the value is never sent automatically and is used to
block a reply that would reveal it.

A variable without a `disclosure` gets the runtime's default level
(public for `identity.name`, `identity.role` and `skills`,
after_owner_engaged otherwise), and an install may only make it stricter.

**intents** are the controlled vocabulary of reply intents. `tier` says
what happens to a reply with that intent:

| Tier | Meaning | Today |
|---|---|---|
| `auto` | sent without the owner (guarded mode) | `intent_allowlist` |
| `approve` | waits for the owner's approval | every intent not in the allowlist |
| `never` | the assistant may not send it at all, not even with the owner's approval | `intent_denylist` |

`userOverride` limits what the install may change: `none`, `tighten`
(default: only towards approve/never) or `any`. The install changes settings
inside the envelope the author set and the platform enforces; it is not
always a tightening. `any` lets it loosen a tier, and a limit can rise from
its default up to the ceiling.

**defaults.ceilings** cap what an install may set; an install cannot raise a
limit above them. **defaults.disclosure.policy** is `required` (the user
cannot turn the "sent by an AI assistant" line off) or `optional`.

## Install

```yaml
apiVersion: assistants.mctl.ai/v1alpha1
kind: AssistantInstall
spec:
  assistant: {name: hr-recruiter, version: 0.1.0}
  mode: guarded            # observe | guarded | off; default: the definition's
  paused: false            # default: true
  listening: true          # default: false
  values: {...}            # variable values
  disclosureLevels: {...}  # per variable, stricter only
  intentTiers: {...}       # per intent, within userOverride
  limits: {...}            # at most the ceilings
  audience:                # Telegram chat-automation recipients model
    scope: {contacts, nonContacts, newChats, existingChats}
    onlySenders: [...]
    blockedSenders: [...]
  disclosure: {enabled, text}
  schedule: {mode: always | outside_hours, timezone, hours}
  ownerNotes: "..."        # the user's own instructions, max 2000 chars
```

`ownerNotes` are appended after the definition's instructions in a delimited
block, introduced as lower priority than everything before them; the notes
cannot close that block early. Variable values are never rendered into the
prompt: the model sees the owner's details only through
`get_recruiter_profile`, which returns what the current conversation may be
told. The owner's notes are the owner's own words and are rendered as
written, so they should not hold anything the owner would not want the model
to read.

An install that leaves out `mode`, `paused` or `listening` starts the way a
new account does today: in the definition's default mode, paused, and not
listening. Going live is an explicit change, never a side effect of a
minimal install.

## Who controls what

| Setting | Author (definition) | User (install) | Platform (never relaxable) |
|---|---|---|---|
| Persona and workflow | `instructions` | `ownerNotes`, appended below them | policy checks every proposed reply on the server, whatever the prompt says |
| Owner facts | which variables, default disclosure | values; disclosure only stricter | the model only sees fields the conversation may be told; a reply quoting a protected value verbatim is blocked |
| Reply intents | intents, default tiers, `userOverride` | tiers within `userOverride` | URL, credential, phone and code deny; injection handling |
| Tools | subset of the registry | — | tool registry, server-side validation |
| Limits | defaults and ceilings | any value up to the ceilings | 60 s rate window, fallbacks |
| Disclosure line | `required` or `optional`, default text | text and off switch, only if optional | — |
| Who it answers | — | audience scope, only/blocked senders | private chats only; groups and channels never |
| When it answers | — | schedule | takeover when the owner replies |
| Model and budget | `execution` (reserved) | — | the worker's per-job budget cap |

## What the runtime enforces

`PUT /api/admin/agent/install` (admin scope) takes
`{"telegram_id": ..., "install": {...}}`, validates the install against its
catalog definition, and writes in one UPDATE every profile setting it
resolves to, the owner profile, the assistant reference and the install
itself (tenant-key encrypted, like the owner profile). It replaces all of
them; `PUT /api/admin/agent/profile` remains for single-field changes.

Accounts that existed before the catalog are migrated by the column defaults:
`assistant_name` = `hr-recruiter`, `assistant_version` = `0.1.0`, no stored
install. Their jobs run exactly the prompt the worker used to read from
`AGENT_SYSTEM_PROMPT`.

`POST /jobs/claim` returns, per job, `instructions` (the rendered prompt),
`assistant` (`name@version`) and `assistant_digest`. They are resolved
before anything is claimed: if the account's assistant is missing from the
catalog or its stored install no longer parses, the claim fails and the jobs
stay queued, rather than running with another assistant's prompt. The worker
uses the server's instructions and falls back to its own
`AGENT_SYSTEM_PROMPT` only when a server without a catalog sends none. The
prompt reaches `claude` through `--system-prompt-file` (a 0600 temp file),
not argv, since it can carry the owner's notes.

### Install revisions

Every install, whether it reconfigures, re-versions or switches the
assistant, moves `agent_profiles.install_revision` in the same UPDATE as the
settings and records the definition's digest. A job takes the revision
current when it is claimed (the claim envelope carries it as
`install_revision`), and an action copies its job's revision, or the
profile's when it has no job. Work behind the current revision is refused:

- at propose (`propose_reply`, `request_owner_approval`,
  `send_owner_summary`), as the policy denial `install_changed`;
- at `/mctl approve`, which denies the draft and tells the owner the
  assistant or its settings changed since it was written;
- at send and at crash recovery, as the same policy denial.

The revision check is the source of truth. After an install the server
also denies proposed and approved actions from earlier revisions, but that
is cleanup: a race with it cannot let stale work act. Drafts awaiting the
owner's approval are left for `/mctl approve` to refuse, so the owner is
told the assistant changed rather than that the code was not found;
approval expiry clears the ones never approved. A job that is claimed
again after the change takes the new revision and runs with the new
assistant.

Switching to another assistant is therefore allowed. Its install time is
reset to the switch, so its new chats start then; a reinstall of the same
assistant keeps the first install time. Conversation transcripts stay as
account history: the new assistant can read earlier messages through
`get_conversation_context`, and nothing claims otherwise. Saved records
stay as they are; only `job_lead` exists today.

### Mapping

`assistant.Resolve` turns an install into profile settings, and
`assistant.ProfileRequest` into the body of `PUT /api/admin/agent/profile`.
A test applies the HR example through the real handler and checks the stored
profile equals the configuration the agent runs with today.

| Today | New field |
|---|---|
| `AGENT_SYSTEM_PROMPT` (global env) | definition `instructions` + install `ownerNotes`, per account, via the claim |
| `mode` | install `mode` |
| `autopilot_paused` | install `paused` |
| `listener_enabled` | install `listening` |
| `disclosure_text`, `disclosure_disabled` | install `disclosure` within definition `defaults.disclosure` |
| `max_autonomous_turns`, `max_msgs_per_minute`, `max_reply_chars` | install `limits` within definition `ceilings` |
| `intent_allowlist` (CSV) | intents whose resolved tier is `auto` |
| `intent_denylist` (CSV) | intents whose resolved tier is `never` |
| `working_hours` | install `schedule` with mode `outside_hours` |
| `sender_allowlist`, `blocked_senders` | install `audience.onlySenders`, `audience.blockedSenders` |
| `audience_excludes` (CSV) | install `audience.scope` classes set to `false` |
| owner profile document | install `values` placed by each variable's `profilePath` |
| owner profile `disclosure` map | variable `disclosure`, install `disclosureLevels` |
| fixed MCP tool set | definition `tools`, by canonical name or alias |
| `job_leads` table | definition `records.kind` |
| worker model and budget env | definition `execution` (reserved, rejected if set) |

Settings the runtime cannot enforce yet fail with `ErrUnsupported` instead of
being dropped: a tool subset, record kinds other than `job_lead`, and any
`execution` setting. An install is applied entirely or not at all.

The guarantee is about this mapping: every setting either reaches the
profile or the install fails. It does not extend to the definition's
descriptive parts (`escalation`, `examples`), which document behaviour the
instructions produce and are not enforced on their own.

## Schedules

`schedule.mode: outside_hours` names the owner's working hours, when the
owner answers messages personally:

```yaml
schedule:
  mode: outside_hours
  timezone: Europe/Zurich          # IANA zone, required
  hours: [mon-fri 09:00-18:00, sat 22:00-02:00]
```

Inside those hours every reply the assistant proposes waits for the owner's
approval, whatever its intent tier; outside them the usual rules apply.
Policy checks this when a reply is proposed and again at send time, so a
reply allowed at 17:55 and still queued at 18:05 is not sent on its own:
the executor refuses an automatically allowed reply that now needs
approval. Messages that arrive inside working hours are therefore never
held and replayed in a burst when the hours end; each becomes a draft for
the owner.

- The windows follow the zone's wall clock, so they move with DST.
- A window whose end is not after its start runs past midnight and belongs
  to the day it starts on: `sat 22:00-02:00` covers Saturday night and the
  first two hours of Sunday. Day ranges may wrap (`fri-mon`); `24:00` is
  allowed as an end.
- Changing the zone or the hours is a reinstall; the next evaluation uses
  the new value.
- `always`, or no schedule, means no working hours. A `timezone` or `hours`
  given with `always` is rejected rather than ignored.
- A stored value that fails to parse holds every reply for approval
  instead of letting the assistant act at any time; the admin endpoints
  refuse to store one.

## Audience

`audience.scope` turns classes of chats off; every class is on by default:

```yaml
audience:
  scope: {contacts: true, nonContacts: true, newChats: false, existingChats: true}
```

- **Contacts** are judged by the contact flag Telegram sends with each
  inbound message and stored on the conversation. Removing someone from
  contacts takes effect with their next message, not instantly.
- **Existing chats** are conversations the agent first saw before the
  assistant was installed, plus any chat with a contact. **New chats** are
  everything else. The install moment is stamped on the first install and
  kept on reinstalls of the same assistant, so it does not move.
- Limitation: a chat that began before the install but that the agent never
  saw (the listener was off) has no conversation row from before the
  install and therefore counts as new.
- A chat outside the scope never becomes a job: the listener keeps its
  conversation row and contact flag, so the class stays decidable, but
  stores no message body and spends no model run. Policy checks the scope
  again before every proposal and send (`audience_excluded`), so a peer who
  drops out mid-conversation gets no further replies.
- What the decision needs but cannot see excludes rather than admits: an
  unknown contact status when contacts matter, a missing install time, or a
  class the runtime does not know. Turning off both halves of a pair
  (`contacts` and `nonContacts`, or `newChats` and `existingChats`) answers
  nobody and is rejected.
- `blockedSenders` always wins; an empty `onlySenders` means everyone.

## Tool names

The worker implements eleven tools. Three carry recruiter-specific names,
and a definition may call them by a generic alias instead:

| Canonical | Alias |
|---|---|
| `get_recruiter_profile` | `get_owner_profile` |
| `get_lead` | `get_record` |
| `save_job_lead` | `save_record` |

Each claimed job carries the definition's tool names (`tools` in the
envelope). The worker allows exactly those names on the `claude` command
line and registers each tool under its name in the job's MCP server; the
implementation behind an alias is the same tool. A job from a server
without a catalog carries no names and gets the canonical ones.

A definition must still name every tool, each once: naming both a tool and
its alias is an error, and a subset is `ErrUnsupported`. The agent API does
not check which tools a job may call, so a subset would look enforced while
it is not; tool restriction needs that server-side check first.

## Customization tiers

| Tier | The user | Gate |
|---|---|---|
| T0 Install | picks a catalog assistant, fills the required values | schema validation |
| T1 Tune | mode, tiers (tighten), limits, audience, schedule, disclosure, `ownerNotes` | schema and definition checks |
| T2 Fork | own instructions, intents and records on a catalog base; tools from the registry | private visibility; observe mode first |
| T3 Connectors | adds MCP servers (calendar, CRM), each tool with a tier, approve by default | admin review |
| T4 Own runtime | runs their own worker against the agent job API (claim, propose, complete) | account-scoped token; policy enforced server-side |

## Phases

- **P0 (done, #1003):** format, schemas, HR example, validation and mapping
  tests, this document.
- **P1 (done, #1005, 0.112.0):** the profile row gets `assistant_name`,
  `assistant_version` and an encrypted install; `PUT /api/admin/agent/install`;
  the claim response carries the rendered instructions (definition +
  `ownerNotes`, never variable values) and a content digest; existing
  profiles default to `hr-recruiter@0.1.0`.
- **P2:** tiers including `never` (done: a reply whose intent is on the
  profile's `intent_denylist` is denied when proposed and again at send
  time, and no approval releases it), the audience scope and schedules in
  `policy.go` (both done: see [Schedules](#schedules) and
  [Audience](#audience)); `/mctl` gets unpause and shows the install (done:
  `/mctl unpause`, `/mctl assistant`); recruiter-specific
  tool names get generic aliases (done: see [Tool names](#tool-names)).
- **P3:** definitions published to the mctl-api agent registry, a
  per-account install binding, MCP tools `list_assistants`,
  `install_assistant`, `update_install`, and a page on tg.mctl.ai.
- **P4:** forks, user connectors with review, own-runtime documentation.

## How this compares

The product is not "AI that answers Telegram messages"; Telegram itself now
offers that. It is a governed delegation runtime: the author defines an
envelope, the owner configures inside it and may only tighten, the runtime
enforces rules neither can relax, and every action is checked against the
current install revision before it is sent. The comparison is split by what
each product is to that thesis. Facts were checked against public,
preferably first-party documentation on 2026-10-31; a cell reads "not
verified" when documentation does not settle it, never "no".

### Telegram Chat Automation (official)

Since 2026-05-07 every Telegram user can connect a bot to their profile to
answer messages on their behalf (Settings > Chat Automation; Telegram blog
"AI bot revolution"), and since Bot API 10.0 (2026-05-08) a business bot does
not need Telegram Premium. It is a real personal-account delegation
primitive, with a narrower envelope than this runtime's MTProto path:

| Dimension | Chat Automation | Source |
|---|---|---|
| Acts in the owner's personal account with third parties | yes: private chats, `can_reply` covers chats "that had incoming messages in the last 24 hours" | Bot API `BusinessBotRights` |
| Audience | yes: the owner picks the chats at connection time, e.g. excluding contacts or only new chats | Telegram blog, 2026-05-07 |
| Tell the bot's own sends apart | yes: `Message.sender_business_bot` on outgoing messages sent by the bot | Bot API `Message` |
| Owner takeover | not verified: documentation does not say whether the owner's own manual messages reach the bot as `business_message` | spike in #1026 |
| History, groups, channels, global search | no: managed private chats only | Bot API, Bot Features |
| Bot-to-bot | yes, opt-in; Telegram requires loop safeguards (dedup, rate limits, maximum depth or timeouts) | Bot Features, "Bot-to-Bot Communication" |
| Versioned definitions, tighten-only installs, per-intent tiers, revision fence | no: the platform provides the connection; any policy is the bot's own | |

Its risk profile differs from MTProto: an official API with no user session
held by the operator, so materially lower platform and account risk, while a
bot remains subject to Telegram's platform rules and Bot Developer Terms
(section 5.4 for business bots). Whether it can serve as a transport for
these assistants without weakening the guarantees above is the subject of
the spike tracked in #1026, outside P3.

### Direct alternatives: delegating a Telegram identity

All three are self-hosted, MIT-licensed open-source projects. SmarTel
(github.com/AliZakaee/SmarTel; its README also names ITheEqualizer/SmarTel)
and tg-secretary (github.com/sepehr071/tg-secretary) connect as business
bots; Iva (github.com/smixs/iva-agent) runs an MTProto userbot. Sources are
each project's README and docs as of 2026-10-31.

| Dimension | MCTL | Chat Automation | SmarTel | tg-secretary | Iva |
|---|---|---|---|---|---|
| Transport | MTProto, server-held session | business bot | business bot | business bot | MTProto userbot, self-hosted |
| Replies to third parties autonomously | yes | yes (the bot's logic) | yes, opt-in | yes | not verified (sends found only in owner-started or scheduled turns) |
| History, groups, channels, search | yes | no | no | no | yes |
| Versioned assistant definition with digest | yes | no | not verified | not verified | not verified |
| Author envelope, installer may only tighten | yes | no | not verified | not verified | not verified |
| Approval before send | per intent: `auto` / `approve` / `never` | no | global mode; sensitive topics forced to approval | global mode; close-contact gate | global read-only switch |
| Owner takeover | yes | not verified (see above) | yes, 30 min pause | yes, cooldown and re-check before send | not verified |
| Approval bound to the install revision | yes (#1023, not yet released) | no | not verified | not verified | not verified |
| Per-field disclosure of owner details | yes | no | not verified | not verified | not verified |
| AI disclosure line to the counterparty | yes, required or optional per assistant | no | not verified | no, by design | not verified |
| Audience scope | yes | yes | partial (Telegram chat selection) | partial (chat selection, relationship tags) | not verified |
| Working hours | yes | no | not verified | yes | not verified |
| Conversation limits | turns and rate per conversation | no | 20 messages per customer per hour | delays and a spend cap | anti-flood pacing only |

In the Chat Automation column, "no" means the platform does not provide it;
a connected bot may implement it itself, as the next two projects do.

The two business-bot projects implement a takeover pause, which suggests the
owner's activity is observable through the business connection; the spike
in #1026 confirms that against Telegram itself before the official column
changes.

### Benchmarks for packaging and isolation

OpenClaw with its ClawHub registry (docs.openclaw.ai) and NanoClaw
(github.com/nanocoai/nanoclaw) are not substitutes for delegating a
Telegram identity; both connect to Telegram as an ordinary bot. They set the
bar for distributing and running agent packages:

| Dimension | ClawHub / OpenClaw | NanoClaw |
|---|---|---|
| Versioned, immutable releases | yes (semver, changelogs, compatibility metadata) | partial (templates, no registry) |
| Integrity digest | partial (plugins) | not verified |
| Security scan, moderation | yes (scan state shown before install) | not verified |
| Publisher provenance | partial (GitHub account-age gate) | not verified |
| Update that respects local changes | yes (lockfile, pins, refuses over modified files) | yes (dry-run plan flags customized files) |
| Permission or authority diff on update | not verified | partial (per-surface plan, not framed as authority) |
| Runtime isolation | partial (sandbox off by default) | yes (container per agent) |
| Credentials kept out of the agent | partial | yes (injected by a gateway at request time) |

What this runtime takes from them for P3 and later: immutable versions with
a digest (done in P3.2), scan and provenance before third-party publishers,
and an update that shows how authority changes rather than a text diff.

### Design precedents

Formats and products that informed this one; they are not competitors for
delegating a person's own account:

| Product | What we took | What it lacks for this use |
|---|---|---|
| Microsoft 365 declarative agents | instructions + capabilities + disclaimer; user overrides that can only remove | runs in the user's own chat, not on their behalf with third parties |
| Claude subagents, Agent Skills | markdown instructions with frontmatter, tool lists | no owner, counterparty or disclosure model |
| OpenAI GPT Actions, Lindy, Relevance, n8n | per-tool approval: auto, approve, never | approval is per tool, not per reply intent |
| Voiceflow, Respond.io, Wati | exit conditions, handoff with a summary | business inboxes, not a person's account |
| MCP `server.json`, Oracle Agent Spec, Letta `.af` | typed variables, secrets kept out of the definition | no catalog-to-account install step |
| A2A agent card | public listing: name, version, examples | describes an agent to other agents, not to an owner |

### What the combination is

Among the products reviewed here, we did not find another documented system
combining all of: delegation through a personal account; an author-defined
authority envelope; owner-side tightening only; platform rules neither can
override; per-intent `auto` / `approve` / `never`; per-field disclosure of the
owner's details; owner takeover; refusal of work from an older install
revision (#1023, merged, not yet released); and a policy re-check at send
time. This compares documented features of the products named here, not the
whole market. Known limits stay as stated above: protected values are
guarded by context filtering and an exact-value match, which does not catch
paraphrase or translation, and a reply mixing intents is judged by the
model's single label (#602).

## Acceptance scenarios for later phases

These cases come from review of the format and must have tests before the
features they touch go live. None is a known defect today.

1. The owner replies while a reply is being prepared or sent: takeover is
   checked again at send time, and pending drafts and approvals for that
   chat are invalidated. A message Telegram has already accepted cannot be
   recalled.
2. A stale approval: an approval binds to account, peer, payload, install
   revision and an expiry; policy is evaluated again at send time.
3. `after_owner_engaged` after a takeover and resume: the scope and lifetime
   of engagement are defined, per conversation and per assistant.
4. Switching assistants: an atomic revision change, cancellation of
   incompatible jobs, and rules for carrying history over. (Covered since
   P3.1, see [Install revisions](#install-revisions): stale work is fenced
   by revision, open actions are denied as cleanup, history stays.)
5. A reply that mixes intents ("thanks, Tuesday works, €X is fine"): the
   strictest applicable tier wins; a model-chosen intent is not evidence of
   safe content; an unknown intent is never sent automatically.
6. A retried job after an ambiguous send result: a stable action id and an
   "outcome unknown" state, never a second message.
7. Audience changes mid-flight (blocked, removed contact, outside hours):
   eligibility is checked at send time; blocked wins; empty `onlySenders`
   means everyone; "new chat" is defined against a fixed moment. (Covered
   since P2, see [Audience](#audience).)
8. Schedules across midnight and DST, and a change of timezone; messages
   that arrive outside the window are skipped, queued or escalated by an
   explicit rule, never replayed in a burst. (Covered since P2: the rule is
   escalate, see [Schedules](#schedules).)
9. Account-level limits: a spend budget, concurrency, owner-notification
   rate and a circuit breaker for bot-to-bot loops, beyond per-conversation
   limits.
10. Protected facts already present in history, records or summaries: the
    verbatim matcher does not catch paraphrase or translation, so promises
    about disclosure are scoped to what the matcher and context filtering
    actually cover.
