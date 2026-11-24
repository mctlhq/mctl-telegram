// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package connector

// disclosure.go is what a disclosure must pass before it gets a card
// (#1322 slice P2-S6, threat model T6; S2-D2, S2-D3, S2-D4). A disclosure
// sends text out of MCTL to a speaker: alice_say_phrase says it aloud in a
// room, alice_send_command hands it to the assistant behind the speaker.
// Neither can be undone.
//
// Every check here refuses. Nothing is rewritten, cut, split or defaulted:
// the call the principal approves is the call the worker made, or there is
// no card.
//
//   - The target must be a device id that a read of the connection's
//     speakers, made for this card, lists. A name, a room and an omitted
//     device are refused: the server would resolve a name by substring and
//     an omitted device to a default speaker, so the card could not say
//     where the text goes.
//   - The text is capped by the pin, in characters (runes). Longer text is
//     refused and the principal is told it can be sent in parts.
//   - Text holding a link is refused (Phase 2 default).
//
// Like the rest of the card path, none of this runs in a deployed service:
// nothing constructs Cards outside tests.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// Reasons a disclosure gets no card.
const (
	// ReasonDeviceNotListed: the call names no device, or names one by
	// anything other than the id of a speaker the fresh read lists.
	ReasonDeviceNotListed = "device_not_listed"
	// ReasonDevicesUnreadable: the speakers could not be read, or the read
	// was empty or malformed. That is not "no such device".
	ReasonDevicesUnreadable = "devices_unreadable"
	// ReasonDeviceChanged: at dispatch the device is listed under another
	// name, room, home, type or kind than the card was made from
	// (device_recheck.go).
	ReasonDeviceChanged = "device_changed"
	// ReasonTextTooLong: the text is over the pin's cap (S2-D3).
	ReasonTextTooLong = "text_too_long"
	// ReasonTextHasLink: the text holds a URL or another link token.
	ReasonTextHasLink = "text_has_link"
)

// Speaker is one speaker as the server lists it. Everything in it is the
// server's text: it is shown to the principal on a card and never to the
// model.
type Speaker struct {
	// ID is the device id, the only form of a target a card accepts.
	ID string
	// Name is required. Room and Home are "" when the server does not
	// report one; the card then says so.
	Name, Room, Home string
	// Type is the device type the server reports, "" when it reports
	// none. It is not shown; it is sealed with the card and compared at
	// dispatch.
	Type string
}

// SpeakerRequest names the connection whose speakers are read.
type SpeakerRequest struct {
	Principal         int64
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Token             connection.Secret
	// ApprovalID is the approval a read at dispatch is made for, for the
	// audit entry of the read; "" for a read made for a card or a grant.
	ApprovalID string
}

// ErrSpeakersUnreadable is any device read that did not yield a complete,
// well-formed list.
var ErrSpeakersUnreadable = errors.New("pa connector: speakers unreadable")

// SpeakerReader reads the speakers of one connection from its server, now.
// It never answers from a cache, and it returns an error for anything but a
// complete list it could parse: a failed call, a tool error, a result it
// does not recognise. "Could not read" is never an empty list. A list that
// was read in full and holds no speaker is ErrNoSuchDevices, which is not
// "unreadable"; an empty list with no error is treated as unreadable.
type SpeakerReader interface {
	Speakers(ctx context.Context, req SpeakerRequest) ([]Speaker, error)
}

// disclosureTool says how a disclosure tool's arguments are read. The
// table is code, not pin data: a disclosure tool that is not in it gets no
// card at all.
type disclosureTool struct {
	// textArg is the argument that holds the text; deviceArg the target.
	textArg, deviceArg string
	// spoken: the text is said aloud in the room.
	spoken bool
}

var disclosureTools = map[string]disclosureTool{
	"alice_say_phrase":   {textArg: "phrase", deviceArg: "device", spoken: true},
	"alice_send_command": {textArg: "command", deviceArg: "device"},
}

// cardDetail is what a card shows that the arguments do not hold. It is
// sealed into the approval next to the arguments (approval.SealWithDetail)
// and read back when the card is sent.
type cardDetail struct {
	// Speaker is the target of a disclosure, as read for the card.
	Speaker *detailSpeaker `json:"speaker,omitempty"`
	// Scenario is the scenario of a scenario call, with its steps
	// (scenario.go).
	Scenario *detailScenario `json:"scenario,omitempty"`
}

type detailSpeaker struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Room string `json:"room"`
	Home string `json:"home"`
	// Type is the device type the read reported, "" for none. Kind is
	// detailKindSpeaker or detailKindLight: what the read said the device
	// is. Both are compared with a read made at dispatch.
	Type string `json:"type"`
	Kind string `json:"kind"`
}

const (
	detailKindSpeaker = "speaker"
	detailKindLight   = "light"
)

// stringArg returns the string value of args[name]. ok is false when the
// member is missing or is not a JSON string.
func stringArg(args map[string]json.RawMessage, name string) (string, bool) {
	raw, present := args[name]
	if !present || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// disclosureText returns the text of a disclosure call from its canonical
// arguments. They are decoded to be read only: what is sealed and sent is
// the canonical bytes.
func disclosureText(spec disclosureTool, canonical []byte) (text, device string, hasDevice bool, err error) {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil || args == nil {
		return "", "", false, errors.New("arguments are not an object")
	}
	text, ok := stringArg(args, spec.textArg)
	if !ok || text == "" {
		return "", "", false, fmt.Errorf("%s is not a non-empty string", spec.textArg)
	}
	if _, present := args[spec.deviceArg]; !present {
		return text, "", false, nil
	}
	device, ok = stringArg(args, spec.deviceArg)
	if !ok {
		return "", "", false, fmt.Errorf("%s is not a string", spec.deviceArg)
	}
	return text, device, true, nil
}

// disclosureCall is a disclosure call that passed the checks that need no
// server.
type disclosureCall struct {
	spec         disclosureTool
	text, device string
}

// precheckDisclosure runs the checks of a disclosure that read nothing but
// the call: the tool is one this file can read, its text is within the
// pin's cap and holds no link, and it names a device.
func precheckDisclosure(tool string, pinned catalog.PinnedTool, canonical []byte) (disclosureCall, *refusal) {
	spec, ok := disclosureTools[tool]
	if !ok {
		// A disclosure nobody taught this file to read gets no card.
		return disclosureCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	limit := 0
	if pinned.Constraints != nil {
		limit = pinned.Constraints.TextCap[spec.textArg]
	}
	// One cap for every disclosure: it is the number the refusal's notice
	// (safetext.TextDisclosureTooLong) tells the principal. A pin with
	// another cap, or none, has no card path.
	if limit != catalog.MaxDisclosureText {
		return disclosureCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	text, device, hasDevice, err := disclosureText(spec, canonical)
	if err != nil {
		return disclosureCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	// Characters, not bytes: 1000 Cyrillic letters are 2000 bytes.
	if utf8.RuneCountInString(text) > limit {
		return disclosureCall{}, &refusal{ReasonTextTooLong, http.StatusRequestEntityTooLarge}
	}
	if safetext.ContainsLink(text) {
		return disclosureCall{}, &refusal{ReasonTextHasLink, http.StatusUnprocessableEntity}
	}
	if !hasDevice || device == "" {
		return disclosureCall{}, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	return disclosureCall{spec: spec, text: text, device: device}, nil
}

// disclosureTarget reads the connection's speakers and returns what the
// card of call shows and the detail to seal with its arguments. The device
// must be the id of a listed speaker; a read that failed is a refusal of
// its own, never "not listed".
func (c *Cards) disclosureTarget(ctx context.Context, req CardRequest, call disclosureCall) (d safetext.Disclosure, detail []byte, ref *refusal) {
	reader := c.cfg.Speakers[req.Server]
	if reader == nil {
		return d, nil, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	target, ref := listedSpeaker(ctx, reader, req, call.device)
	if ref != nil {
		return d, nil, ref
	}
	detail, err := json.Marshal(cardDetail{Speaker: target})
	if err != nil {
		return d, nil, &refusal{ReasonInternal, http.StatusInternalServerError}
	}
	return safetext.Disclosure{
		Home: target.Home, Room: target.Room, Name: target.Name, ID: target.ID,
		Phrase: call.text, Spoken: call.spec.spoken,
	}, detail, nil
}

// listedSpeaker reads the connection's speakers and returns the one whose
// id is device, byte for byte, as the detail a card seals. A read that
// failed, came back empty without saying so, or holds a speaker without an
// id or a name or one id twice is unreadable; a list read in full that
// does not hold the id is "not listed".
func listedSpeaker(ctx context.Context, reader SpeakerReader, req CardRequest, device string) (*detailSpeaker, *refusal) {
	speakers, err := reader.Speakers(ctx, SpeakerRequest{
		Principal: req.Policy.Principal().TelegramID(), ConnectionID: req.ConnectionID,
		AuthorityRevision: req.AuthorityRevision, Server: req.Server, Token: req.Token,
	})
	if errors.Is(err, ErrNoSuchDevices) {
		return nil, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	if err != nil || len(speakers) == 0 {
		return nil, &refusal{ReasonDevicesUnreadable, http.StatusServiceUnavailable}
	}
	var target *Speaker
	seen := make(map[string]bool, len(speakers))
	for i := range speakers {
		s := &speakers[i]
		// A list with a speaker it cannot name, or one id twice, is not a
		// list this card can be built from.
		if s.ID == "" || s.Name == "" || seen[s.ID] {
			return nil, &refusal{ReasonDevicesUnreadable, http.StatusServiceUnavailable}
		}
		seen[s.ID] = true
		// The id, byte for byte. A name or a room never matches here.
		if s.ID == device {
			target = s
		}
	}
	if target == nil {
		return nil, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	return &detailSpeaker{
		ID: target.ID, Name: target.Name, Room: target.Room, Home: target.Home, Type: target.Type, Kind: detailKindSpeaker,
	}, nil
}

// disclosureOf rebuilds what a disclosure card shows from the approval's
// sealed arguments and detail. The text and the device id come from the
// arguments, the bytes the executor sends; the detail must name the same
// device.
func disclosureOf(tool string, args, detail []byte) (safetext.Disclosure, error) {
	spec, ok := disclosureTools[tool]
	if !ok {
		return safetext.Disclosure{}, errors.New("pa card: not a known disclosure tool")
	}
	text, device, hasDevice, err := disclosureText(spec, args)
	if err != nil || !hasDevice {
		return safetext.Disclosure{}, errors.New("pa card: disclosure arguments unreadable")
	}
	var cd cardDetail
	dec := json.NewDecoder(strings.NewReader(string(detail)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cd); err != nil || cd.Speaker == nil {
		return safetext.Disclosure{}, errors.New("pa card: disclosure detail unreadable")
	}
	if cd.Speaker.ID != device || cd.Speaker.Name == "" || cd.Speaker.Kind != detailKindSpeaker {
		return safetext.Disclosure{}, errors.New("pa card: disclosure detail does not match the arguments")
	}
	return safetext.Disclosure{
		Home: cd.Speaker.Home, Room: cd.Speaker.Room, Name: cd.Speaker.Name, ID: device,
		Phrase: text, Spoken: spec.spoken,
	}, nil
}
