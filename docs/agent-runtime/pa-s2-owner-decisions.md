# Personal Assistant S2: owner decisions

Decisions of the owner of 2026-11-27 on the limits the Phase 2 code has. Every recommended option was accepted. "You" in an entry is the principal who talks to the assistant.
A gap of [pa-s2-manifest.yaml](pa-s2-manifest.yaml) that names one of these in `accepted` is a limit the owner accepted: it stays listed and no longer blocks the S2 gate.

### D1 Queued requests after /disconnect

- Behaviour: A request already queued is not cancelled by /disconnect. Its next call to the disconnected service is refused.
- Cost: The run ends with a refusal message instead of a clean "cancelled".
- Decision: Keep as is.

### D2 A failed re-check spends the approval

- Behaviour: After you tap Approve the device and the tool list are read again. If that read fails, even for a network blip, the approval is used up and you ask again.
- Cost: One extra request from you after a transient failure. Nothing is sent without a fresh tap.
- Decision: Keep as is.

### D3 Card answer after /forget or consent withdrawal

- Behaviour: The approval rows are deleted, so a tap on an old card answers "unknown button", not "cancelled".
- Cost: Wording only. Nothing runs.
- Decision: Keep as is.

### D4 "Timeout" in an error means outcome unknown

- Behaviour: Any upstream error mentioning a timeout is reported as "I do not know whether it ran", even when the call was in fact rejected.
- Cost: A less exact message in a rare case. The safe direction.
- Decision: Keep as is.

### D5 Model asks again after an abandoned card

- Behaviour: If you ignore a card and the model asks for the tool again, you get a second card; when the run times out you get the run-failed notice.
- Cost: Possibly two cards for one request.
- Decision: Keep as is.

### D6 Revoked permissions do not come back

- Behaviour: Withdrawing consent, /forget and an admin disable revoke your standing permissions for good. A new consent does not restore them.
- Cost: You grant them again by hand.
- Decision: Keep as is.

### D7 An action under a standing permission does not mark the run

- Behaviour: The result of such an action is not shown to the model (it gets fixed server text), so a second covered action in the same run also runs without a card. Only reading external content turns cards back on.
- Cost: Several covered actions in a row without a card, all inside limits you set.
- Decision: Keep as is.

### D8 An action without a card uses the run's only card

- Behaviour: A run may show one card. An action carried out under a standing permission counts as that one.
- Cost: "Set volume to 3 and play jazz" does the volume and refuses the music; you ask for the music separately.
- Decision: Keep as is.

### D9 A revoke that lands mid-flight

- Behaviour: A revoke that commits after the server has already admitted an action does not stop that one action.
- Cost: A window of milliseconds; the next action is stopped.
- Decision: Keep as is.

### D10 Device changed since the card: refuse, not re-card

- Behaviour: If the device was renamed, moved or removed between the check and the call, the action is refused and you are told. No new card is made automatically.
- Cost: You repeat the request.
- Decision: Keep as is.

### D11 Light has no ceiling

- Behaviour: A standing permission for a light covers every brightness, colour temperature and scene, except siren and alarm, which always need a card. Volume does have a ceiling.
- Cost: A prompt injection could flash a lamp you allowed, within normal scenes.
- Decision: Keep as is.

### D12 TVs and set-top boxes in the speaker rule

- Behaviour: Speaker tools accept smart speakers and also "media_device", the type Yandex gives a TV or set-top box (only if the listing also flags it as a speaker).
- Cost: Wider than needed. Dropping it means a TV with built-in Alice cannot be controlled.
- Decision: Drop media_device: smart speakers only.
- Done: the speaker tools take smart speakers only.

### D13 One approved call may reach the speaker twice

- Behaviour: The Alice service first sends a voice command and, if that fails, falls back to the device API. Read in its source, not yet observed.
- Cost: "Volume 6" twice is harmless; "next track" twice skips two. It is to be watched in the preview evals.
- Decision: Keep as is.

### D14 Speaker that cannot play music still gets a card

- Behaviour: The listing does not say whether a speaker can take the music command, so you may approve a card and then get a refusal from the service.
- Cost: A wasted tap on unusual hardware.
- Decision: Keep as is.

### D15 Gap between the re-check and the call

- Behaviour: The device is read and then called in two requests; a change in between is not seen, and the service may answer the read from its own cache.
- Cost: A window of under a second on your own home.
- Decision: Keep as is.

### D16 Links on a card are shown defanged

- Behaviour: A link-like value is shown as a[.]b on the card while the call sends it as is. Values that already contain such a mark are refused.
- Cost: The card is not byte-for-byte the call for such values. Mostly relevant to music queries.
- Decision: Keep as is.

### D17 "Say a phrase" and "send a command" are not offered

- Behaviour: Both need a broader Yandex permission (quasar) that the owner decided on 2026-11-21 not to request. Any call is refused.
- Cost: The assistant cannot make Alice speak. Eval A3 is reworded to "the tool is not offered and a call is refused".
- Decision: Keep as is.
- Done: acceptance eval A3 is reworded in the threat model.

### D18 Generic device and room control are refused

- Behaviour: "Control any device" and "control a room" have no card built, so they are always refused. Volume, playback, light and music work.
- Cost: No thermostat, socket or whole-room commands in the pilot.
- Decision: Keep as is.

### D19 Scenarios are refused

- Behaviour: The Alice service cannot list a scenario's steps, so a card could not show what would run. Every call is refused.
- Cost: No "run my evening scenario" in the pilot.
- Decision: Keep as is.

### D20 Token answer without a scope fails the connection

- Behaviour: If the Alice sign-in answers without saying which permissions were granted, the connection fails instead of being kept as read-only.
- Cost: You connect again. Nothing is assumed.
- Decision: Keep as is.

### D21 "Consent needed" notices come once per connection

- Behaviour: The hints "accept the consent to actions" and "reconnect with control permission" are sent once for the life of a connection, not on every request.
- Cost: If you miss it, later requests just say the action is not available.
- Decision: Keep as is.

### D22 Two internal checks say the same thing

- Behaviour: Two independent tables decide which tools can run without a card; they agree, so removing one alone changes nothing. A test pins that they agree.
- Cost: None: this is deliberate double protection that a single-fault test cannot show.
- Decision: Keep as is.

### D23 A2 says "volume 55"; the tool takes 1 to 10

- Behaviour: The Alice volume tool takes a level from 1 to 10. Today 55 is refused and a level is shown and sent as is.
- Cost: A2 is reworded: "set volume to 6" shows 6 of 10 and sends 6; "55" is refused with no card.
- Decision: Reword A2 to the 1 to 10 scale.
- Done: acceptance eval A2 is reworded in the threat model.

### D24 Preview-only checks move to the acceptance evals

- Behaviour: About 15 items can be proven only on preview with actions on (real Alice, real speaker, process kill, two replicas). The owner chose to move them out of the S2 gate into the acceptance evals.
- Cost: Actions go on for the owner's account on preview once the gate closes on code and on this page; the pilot still waits for A1 to A7 on preview.
- Decision: Confirmed.
- Done: such a gap names its acceptance evals in `eval`; A8 to A12 were added for what A1 to A7 do not cover.
