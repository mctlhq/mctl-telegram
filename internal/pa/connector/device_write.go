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

// device_write.go is what a write to one device must pass before it gets a
// card (#1322 slice P2-S8, threat model T6): alice_media_control,
// alice_set_volume and alice_set_light.
//
// The server behind these tools rounds a number, clamps it into a range
// and resolves a device from a name, a room or a default. Each of those
// would make the call that runs differ from the call on the card, so every
// check here refuses and nothing is rounded, clamped, defaulted or
// rewritten:
//
//   - A number is an integer in its plain spelling (5; never 5.0, 5e0 or
//     "5") inside the pin's integer_bounds for its argument.
//   - A choice is one of the strings the pinned input schema lists.
//   - The target is a device id that a read of the connection's speakers
//     or lights, made for this card, lists. A name, a room and an omitted
//     device are refused.
//   - An argument this file cannot show on the card is refused.
//
// A Phase 2 write tool that is not in deviceWriteTools has no card path
// here (alice_control_device, alice_control_room).
//
// These checks run on the card path only. All three tools can be lowered
// by a standing permission, and nothing acts on a lowered outcome yet: the
// code that will must run precheckDeviceWrite and deviceWriteTarget before
// it sends a call without a card, or the server's rounding, clamping and
// name matching come back.
//
// Like the rest of the card path, none of this runs in a deployed service:
// nothing constructs Cards outside tests.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// ReasonValueNotAllowed: a value of a device write is not one the pin
// allows: a number that is not a plain integer or is outside its bounds, a
// choice the schema does not list, or a value of another type.
const ReasonValueNotAllowed = "value_not_allowed"

// Light is one light as the server lists it, under the rules of Speaker.
type Light struct {
	ID               string
	Name, Room, Home string
}

// LightReader reads the lights of one connection from its server, now,
// under the rules of SpeakerReader: never from a cache, and an error for
// anything but a complete, non-empty list it could parse.
//
// No reader of the alice server exists: its alice_list_devices prints an
// id for speakers only, so a light's id cannot be read and
// alice_set_light gets no card there.
type LightReader interface {
	Lights(ctx context.Context, req SpeakerRequest) ([]Light, error)
}

// writeValue is one argument of a device write that sets something.
type writeValue struct {
	arg string
	// kind picks the label the card writes before the value.
	kind safetext.ValueKind
	// bound is the inclusive range of an integer argument. It is the range
	// the kind's label names, and the pin's integer_bounds must be the same: a
	// pin with other bounds, or none, has no card path. Nil: the argument
	// is one of the strings the pinned input schema lists.
	bound *catalog.IntBound
}

// deviceWriteTool says how a device write's arguments are read. The table
// is code, not pin data: a tool that is not in it gets no card from here.
type deviceWriteTool struct {
	// light: the target is a light; otherwise it is a speaker.
	light bool
	// deviceArg holds the target. roomArg, when the schema has one, is
	// refused whenever it is present: the server would use it to pick the
	// device.
	deviceArg, roomArg string
	// values are the arguments the call may set, in the order the card
	// shows them. all: each of them is required; otherwise at least one.
	values []writeValue
	all    bool
}

var deviceWriteTools = map[string]deviceWriteTool{
	"alice_media_control": {deviceArg: "device", all: true, values: []writeValue{
		{arg: "action", kind: safetext.ValuePlayback},
	}},
	"alice_set_volume": {deviceArg: "device", all: true, values: []writeValue{
		{arg: "level", kind: safetext.ValueVolume, bound: &catalog.IntBound{Min: 1, Max: 10}},
	}},
	"alice_set_light": {light: true, deviceArg: "device", roomArg: "room", values: []writeValue{
		{arg: "state", kind: safetext.ValuePower},
		{arg: "brightness", kind: safetext.ValueBrightness, bound: &catalog.IntBound{Min: 1, Max: 100}},
		{arg: "color_temp_k", kind: safetext.ValueColorTemp, bound: &catalog.IntBound{Min: 1500, Max: 6500}},
		{arg: "scene", kind: safetext.ValueScene},
	}},
}

// deviceWriteCall is a device write that passed the checks that need no
// server.
type deviceWriteCall struct {
	spec   deviceWriteTool
	device string
	// values are what the card shows, each the text of the argument as it
	// is sent.
	values []safetext.CardValue
}

// writeDetail is what the card of a device write shows that the arguments
// do not hold. It is sealed into the approval next to the arguments and
// read back when the card is sent.
type writeDetail struct {
	Device *detailSpeaker `json:"device"`
}

// precheckDeviceWrite runs the checks of a device write that read nothing
// but the call and the pin.
func precheckDeviceWrite(tool string, pinned catalog.PinnedTool, canonical []byte) (deviceWriteCall, *refusal) {
	spec, ok := deviceWriteTools[tool]
	if !ok {
		return deviceWriteCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil || args == nil {
		return deviceWriteCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	call := deviceWriteCall{spec: spec}
	known := map[string]bool{spec.deviceArg: true}
	for _, v := range spec.values {
		known[v.arg] = true
		// The pin first, whatever the call holds: a pin this table does
		// not agree with has no card path at all.
		var choices []string
		if v.bound != nil {
			if pinned.Constraints == nil || pinned.Constraints.IntegerBounds[v.arg] != *v.bound {
				return deviceWriteCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
			}
		} else if choices, ok = pinned.EnumValues(v.arg); !ok {
			return deviceWriteCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
		}
		raw, present := args[v.arg]
		if !present {
			if spec.all {
				return deviceWriteCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
			}
			continue
		}
		text := string(raw)
		if v.bound != nil {
			// An integer in its one plain spelling: CanonicalArgs keeps
			// a number's literal text, so 5.0, 5e0 and -0 arrive as
			// written and are not it. Refused, never rounded or clamped:
			// the server would do both, and the card would then show a
			// value that is not set.
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != text || n < v.bound.Min || n > v.bound.Max {
				return deviceWriteCall{}, &refusal{ReasonValueNotAllowed, http.StatusUnprocessableEntity}
			}
		} else if text, ok = stringArg(args, v.arg); !ok || !slices.Contains(choices, text) {
			return deviceWriteCall{}, &refusal{ReasonValueNotAllowed, http.StatusUnprocessableEntity}
		}
		call.values = append(call.values, safetext.CardValue{Kind: v.kind, Value: text})
	}
	if len(call.values) == 0 {
		// A call that sets nothing is not an action to approve.
		return deviceWriteCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	if spec.roomArg != "" {
		known[spec.roomArg] = true
		if _, present := args[spec.roomArg]; present {
			// A room is not a device id, and the card's room is the one
			// the read gives.
			return deviceWriteCall{}, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
		}
	}
	for name := range args {
		if !known[name] {
			// The pinned schema declares an argument this file cannot
			// show on a card.
			return deviceWriteCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
		}
	}
	raw, present := args[spec.deviceArg]
	if !present {
		return deviceWriteCall{}, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	if len(raw) == 0 || raw[0] != '"' {
		return deviceWriteCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	if call.device, ok = stringArg(args, spec.deviceArg); !ok || call.device == "" {
		return deviceWriteCall{}, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	return call, nil
}

// readDevices reads the connection's speakers, or its lights, for a card.
// A reader that is missing is "no card path"; a read that failed or came
// back empty is unreadable, never an empty list to look a device up in.
func (c *Cards) readDevices(ctx context.Context, req CardRequest, light bool) ([]detailSpeaker, *refusal) {
	sreq := SpeakerRequest{
		Principal: req.Policy.Principal().TelegramID(), ConnectionID: req.ConnectionID,
		AuthorityRevision: req.AuthorityRevision, Server: req.Server, Token: req.Token,
	}
	unreadable := &refusal{ReasonDevicesUnreadable, http.StatusServiceUnavailable}
	var out []detailSpeaker
	if light {
		reader := c.cfg.Lights[req.Server]
		if reader == nil {
			return nil, &refusal{ReasonNoWritePath, http.StatusForbidden}
		}
		lights, err := reader.Lights(ctx, sreq)
		if err != nil {
			return nil, unreadable
		}
		for _, l := range lights {
			out = append(out, detailSpeaker{ID: l.ID, Name: l.Name, Room: l.Room, Home: l.Home})
		}
	} else {
		reader := c.cfg.Speakers[req.Server]
		if reader == nil {
			return nil, &refusal{ReasonNoWritePath, http.StatusForbidden}
		}
		speakers, err := reader.Speakers(ctx, sreq)
		if err != nil {
			return nil, unreadable
		}
		for _, s := range speakers {
			out = append(out, detailSpeaker{ID: s.ID, Name: s.Name, Room: s.Room, Home: s.Home})
		}
	}
	if len(out) == 0 {
		return nil, unreadable
	}
	return out, nil
}

// deviceWriteTarget reads the connection's devices of the tool's kind and
// returns what the card of call shows and the detail to seal with its
// arguments. The device must be the id of a listed device of that kind: a
// speaker's id is no target for a light's tool.
func (c *Cards) deviceWriteTarget(ctx context.Context, req CardRequest, call deviceWriteCall) (w safetext.DeviceWrite, detail []byte, ref *refusal) {
	devices, ref := c.readDevices(ctx, req, call.spec.light)
	if ref != nil {
		return w, nil, ref
	}
	var target *detailSpeaker
	seen := make(map[string]bool, len(devices))
	for i := range devices {
		d := &devices[i]
		// A list with a device it cannot name, or one id twice, is not a
		// list this card can be built from.
		if d.ID == "" || d.Name == "" || d.Room == "" || seen[d.ID] {
			return w, nil, &refusal{ReasonDevicesUnreadable, http.StatusServiceUnavailable}
		}
		seen[d.ID] = true
		// The id, byte for byte. A name or a room never matches here.
		if d.ID == call.device {
			target = d
		}
	}
	if target == nil {
		return w, nil, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	detail, err := json.Marshal(writeDetail{Device: target})
	if err != nil {
		return w, nil, &refusal{ReasonInternal, http.StatusInternalServerError}
	}
	return safetext.DeviceWrite{
		Light: call.spec.light, Home: target.Home, Room: target.Room, Name: target.Name, ID: target.ID,
		Values: call.values,
	}, detail, nil
}

// deviceWriteOf rebuilds what a device write card shows from the
// approval's sealed arguments and detail. The values and the device id
// come from the arguments, the bytes the executor sends, through the
// checks the card was made under; the detail must name the same device.
func deviceWriteOf(tool string, pinned catalog.PinnedTool, args, detail []byte) (safetext.DeviceWrite, error) {
	call, ref := precheckDeviceWrite(tool, pinned, args)
	if ref != nil {
		return safetext.DeviceWrite{}, errors.New("pa card: device write arguments unreadable")
	}
	var wd writeDetail
	dec := json.NewDecoder(strings.NewReader(string(detail)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wd); err != nil || wd.Device == nil {
		return safetext.DeviceWrite{}, errors.New("pa card: device write detail unreadable")
	}
	if wd.Device.ID != call.device || wd.Device.Name == "" || wd.Device.Room == "" {
		return safetext.DeviceWrite{}, errors.New("pa card: device write detail does not match the arguments")
	}
	return safetext.DeviceWrite{
		Light: call.spec.light, Home: wd.Device.Home, Room: wd.Device.Room, Name: wd.Device.Name, ID: call.device,
		Values: call.values,
	}, nil
}
