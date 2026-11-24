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

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

func phase2Tool(t *testing.T, name string) catalog.PinnedTool {
	t.Helper()
	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := pin.Servers["alice"].Tools[name]
	if !ok {
		t.Fatalf("the Phase 2 pin has no %s", name)
	}
	return pt
}

// TestLowerable_OnlyDeviceWritesWithARule: of the Phase 2 pin's tools, a
// standing permission is looked up for alice_set_volume,
// alice_media_control and alice_set_light and for nothing else.
func TestLowerable_OnlyDeviceWritesWithARule(t *testing.T) {
	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"alice_set_volume": true, "alice_media_control": true, "alice_set_light": true}
	for name, pt := range pin.Servers["alice"].Tools {
		if got := lowerable(name, pt); got != want[name] {
			t.Errorf("lowerable(%s) = %v", name, got)
		}
		if _, isWrite := deviceWriteTools[name]; isWrite != want[name] {
			t.Errorf("%s: device write table %v, lowerable %v", name, isWrite, want[name])
		}
	}
	// A pin that says otherwise does not make a tool lowerable.
	vol := phase2Tool(t, "alice_set_volume")
	for name, mutate := range map[string]func(pt *catalog.PinnedTool){
		"a disclosure":    func(pt *catalog.PinnedTool) { pt.Class = catalog.ClassDisclosure },
		"a read":          func(pt *catalog.PinnedTool) { pt.Class = catalog.ClassRead },
		"never lowerable": func(pt *catalog.PinnedTool) { pt.Lowerable = catalog.LowerableNever },
		"unmarked":        func(pt *catalog.PinnedTool) { pt.Lowerable = "" },
	} {
		pt := vol
		mutate(&pt)
		if lowerable("alice_set_volume", pt) {
			t.Errorf("%s: lowerable", name)
		}
	}
	say := phase2Tool(t, "alice_say_phrase")
	say.Class, say.Lowerable = catalog.ClassWrite, catalog.LowerableYes
	if lowerable("alice_say_phrase", say) {
		t.Error("alice_say_phrase is lowerable under a pin that calls it a lowerable write")
	}
	room := phase2Tool(t, "alice_control_room")
	room.Lowerable = catalog.LowerableYes
	if lowerable("alice_control_room", room) {
		t.Error("alice_control_room is lowerable under a pin that says yes")
	}
}

// TestLoweringCondition: alice_media_control is conditional on its action
// being one the pin lets a permission cover; a condition this file cannot
// check is an error, which the gate decides as unmet.
func TestLoweringCondition(t *testing.T) {
	media := phase2Tool(t, "alice_media_control")
	if media.Lowerable != catalog.LowerableConditional || media.Constraints == nil || media.Constraints.PlaybackActions == nil {
		t.Fatalf("the pin's alice_media_control: %+v", media)
	}
	for _, action := range media.Constraints.PlaybackActions.Values {
		raw, _ := json.Marshal(map[string]string{"action": action, "device": "spk-kitchen-0001"})
		if met, err := loweringCondition(media, raw); !met || err != nil {
			t.Errorf("action %q: %v, %v", action, met, err)
		}
	}
	for name, args := range map[string]string{
		"an action outside the list": `{"action":"shuffle","device":"spk-kitchen-0001"}`,
		"no action":                  `{"device":"spk-kitchen-0001"}`,
		"an action that is a number": `{"action":1,"device":"spk-kitchen-0001"}`,
	} {
		if met, _ := loweringCondition(media, []byte(args)); met {
			t.Errorf("%s: condition met", name)
		}
	}
	if met, err := loweringCondition(media, []byte(`[`)); met || err == nil {
		t.Errorf("unreadable arguments: %v, %v", met, err)
	}
	// alice_control_device is conditional on a device type nothing here
	// can read.
	device := phase2Tool(t, "alice_control_device")
	if met, err := loweringCondition(device, []byte(`{"device":"lamp-desk-0003","state":"on"}`)); met || err == nil {
		t.Errorf("a device-type condition: %v, %v", met, err)
	}
	noConstraints := media
	noConstraints.Constraints = nil
	if met, err := loweringCondition(noConstraints, []byte(`{"action":"pause"}`)); met || err == nil {
		t.Errorf("a conditional tool without constraints: %v, %v", met, err)
	}
	// A tool that is not conditional has no condition to fail.
	if met, err := loweringCondition(phase2Tool(t, "alice_set_volume"), []byte(`{}`)); !met || err != nil {
		t.Errorf("an unconditional tool: %v, %v", met, err)
	}
}

// TestLoweredTarget: the executor's own reading of a lowered call's bytes.
func TestLoweredTarget(t *testing.T) {
	device, ints, ok := loweredTarget("alice_set_volume", []byte(`{"device":"spk-kitchen-0001","level":5}`))
	if !ok || device != "spk-kitchen-0001" || len(ints) != 1 || ints["level"] != 5 {
		t.Fatalf("volume: %q %v %v", device, ints, ok)
	}
	device, ints, ok = loweredTarget("alice_set_light", []byte(`{"brightness":40,"color_temp_k":2700,"device":"lamp-desk-0003","state":"on"}`))
	if !ok || device != "lamp-desk-0003" || len(ints) != 2 || ints["brightness"] != 40 || ints["color_temp_k"] != 2700 {
		t.Fatalf("light: %q %v %v", device, ints, ok)
	}
	if device, ints, ok = loweredTarget("alice_media_control", []byte(`{"action":"pause","device":"spk-kitchen-0001"}`)); !ok || device != "spk-kitchen-0001" || len(ints) != 0 {
		t.Fatalf("playback: %q %v %v", device, ints, ok)
	}
	for name, c := range map[string][2]string{
		"a tool that is not a device write": {"alice_say_phrase", `{"device":"spk-kitchen-0001","phrase":"hi"}`},
		"control room":                      {"alice_control_room", `{"room":"Kitchen","state":"off"}`},
		"no device":                         {"alice_set_volume", `{"level":5}`},
		"an empty device":                   {"alice_set_volume", `{"device":"","level":5}`},
		"a device that is a number":         {"alice_set_volume", `{"device":7,"level":5}`},
		"a level 5.0":                       {"alice_set_volume", `{"device":"spk-kitchen-0001","level":5.0}`},
		"a level in quotes":                 {"alice_set_volume", `{"device":"spk-kitchen-0001","level":"5"}`},
		"not an object":                     {"alice_set_volume", `[5]`},
		"null":                              {"alice_set_volume", `null`},
	} {
		if device, ints, ok := loweredTarget(c[0], []byte(c[1])); ok {
			t.Errorf("%s: read %q %v", name, device, ints)
		}
	}
}

// TestUnlowered: only a refusal that sent and wrote nothing, for a reason
// that means "the permission or the clean run is gone", turns into a card.
func TestUnlowered(t *testing.T) {
	for _, reason := range []string{ReasonPermissionGone, ReasonPermissionUnreadable, ReasonRunTainted} {
		if !unlowered(WriteOutcome{Status: StatusRefused, Reason: reason}) {
			t.Errorf("%s is not unlowered", reason)
		}
		if unlowered(WriteOutcome{Status: StatusRefused, Reason: reason, DispatchID: "d"}) {
			t.Errorf("%s with a dispatch record is unlowered", reason)
		}
	}
	for _, out := range []WriteOutcome{
		{Status: StatusOK}, {Status: StatusToolError}, {Status: StatusOutcomeUnknown, Reason: ReasonOutcomeUnknown},
		{Status: StatusFenced, Reason: ReasonFenced}, {Status: StatusRefused, Reason: ReasonNotLowerable},
		{Status: StatusRefused, Reason: ReasonWritesOff}, {Status: StatusRefused, Reason: ReasonRevisionMismatch},
		{Status: StatusRefused, Reason: ReasonAuditUnavailable}, {Status: StatusRefused},
		{Status: StatusOK, Reason: ReasonPermissionGone},
	} {
		if unlowered(out) {
			t.Errorf("%+v is unlowered", out)
		}
	}
}

// TestAnswerLowered: the worker is told what became of a lowered call in
// server text, never in the tool's own words, and an outcome that is not
// known is never answered as done.
func TestAnswerLowered(t *testing.T) {
	d := &Dispatcher{}
	const external = "EXTERNAL tool text"
	for name, c := range map[string]struct {
		out    WriteOutcome
		code   int
		status string
		stop   string
	}{
		"ok":              {WriteOutcome{Status: StatusOK, Output: []byte(external)}, http.StatusOK, string(StatusOK), ""},
		"tool error":      {WriteOutcome{Status: StatusToolError, Output: []byte(external)}, http.StatusOK, string(StatusToolError), ""},
		"unknown":         {WriteOutcome{Status: StatusOutcomeUnknown, Reason: ReasonOutcomeUnknown}, http.StatusBadGateway, "", ReasonOutcomeUnknown},
		"fenced":          {WriteOutcome{Status: StatusFenced, Reason: ReasonFenced}, http.StatusConflict, "", ReasonFenced},
		"refused":         {WriteOutcome{Status: StatusRefused, Reason: ReasonWritesOff}, http.StatusForbidden, "", ReasonWritesOff},
		"server refused":  {WriteOutcome{Status: StatusRefused, Reason: ReasonServerRefused}, http.StatusBadGateway, "", ReasonServerRefused},
		"audit down":      {WriteOutcome{Status: StatusRefused, Reason: ReasonAuditUnavailable}, http.StatusServiceUnavailable, "", ReasonAuditUnavailable},
		"an empty status": {WriteOutcome{}, http.StatusBadGateway, "", ReasonOutcomeUnknown},
		"no reason":       {WriteOutcome{Status: StatusRefused}, http.StatusForbidden, "", ReasonInternal},
	} {
		w := httptest.NewRecorder()
		d.answerLowered(w, "alice", c.out)
		var body struct {
			Stop, Status, Output string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if w.Code != c.code || body.Status != c.status || body.Stop != c.stop {
			t.Errorf("%s: %d %+v", name, w.Code, body)
		}
		if got := w.Body.String(); got == "" || json.Valid([]byte(got)) && (body.Output == external || (c.status == "" && body.Output != "")) {
			t.Errorf("%s: answered %s", name, got)
		}
	}
}
