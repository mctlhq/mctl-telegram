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

package pa_test

// Device write cards (#1322 slice P2-S8): alice_media_control,
// alice_set_volume and alice_set_light through the real tool route, card
// emitter, outbox, webhook and write executor. The tools are the Phase 2
// pin's own entries, placed under the harness's one linked server ("tg");
// the speakers and the lights come from fake readers.
//
// Threat model: T6 ("the executor never transforms arguments"), the value
// half of S2-D2, eval A2.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const (
	mediaTool   = "alice_media_control"
	volumeTool  = "alice_set_volume"
	lightTool   = "alice_set_light"
	deviceTool  = "alice_control_device"
	roomTool    = "alice_control_room"
	scenarioRun = "alice_trigger_scenario"

	// Synthetic light ids.
	deskLampID = "lamp-desk-0003"
	hallLampID = "lamp-hall-0004"
)

func testLights() []connector.Light {
	return []connector.Light{
		{ID: deskLampID, Name: "Desk lamp", Room: "Study", Home: "Alice home", Type: lightType},
		{ID: hallLampID, Name: "Hall light", Room: "Hall", Type: lightType + ".ceiling"},
	}
}

// fakeLights is a LightReader with a fixed answer.
type fakeLights struct {
	mu    sync.Mutex
	list  []connector.Light
	err   error
	calls int
}

func (f *fakeLights) Lights(_ context.Context, req connector.SpeakerRequest) ([]connector.Light, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if req.Token.Reveal() == "" || req.Server != "tg" || req.ConnectionID == "" || req.Principal != alice {
		return nil, errors.New("fake: unexpected light request")
	}
	return slices.Clone(f.list), f.err
}

func (f *fakeLights) set(list []connector.Light, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list, f.err = list, err
}

func (f *fakeLights) asked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// writeFresh lists every tool as an approve-tier write.
type writeFresh struct{}

func (writeFresh) FreshTool(_ context.Context, req connector.FreshRequest) (connector.FreshTool, error) {
	if req.Token.Reveal() == "" || req.Server != "tg" {
		return connector.FreshTool{}, errors.New("fake: unexpected fresh request")
	}
	return connector.FreshTool{
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), Tier: catalog.TierApprove, Class: catalog.ClassWrite,
	}, nil
}

// deviceWritePin holds the Phase 2 pin's entries of every write tool,
// unchanged, under "tg".
func deviceWritePin(t *testing.T) *catalog.Pin {
	t.Helper()
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]catalog.PinnedTool{"get_messages": {Tier: catalog.TierAuto, Class: catalog.ClassRead}}
	for _, name := range []string{mediaTool, volumeTool, lightTool, deviceTool, roomTool, scenarioRun, musicTool} {
		pt, ok := p2.Servers["alice"].Tools[name]
		if !ok || pt.Class != catalog.ClassWrite || pt.Tier != catalog.TierApprove {
			t.Fatalf("the Phase 2 pin does not hold %s as an approve-tier write: %+v", name, pt)
		}
		tools[name] = pt
	}
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"tg": {Tools: tools}}}
}

type deviceWriteEnv struct {
	*disclosureEnv
	lights *fakeLights
}

func newDeviceWriteEnvOn(t *testing.T, s *db.Store, pin *catalog.Pin) *deviceWriteEnv {
	t.Helper()
	sp, li := &fakeSpeakers{list: testSpeakers()}, &fakeLights{list: testLights()}
	return &deviceWriteEnv{
		disclosureEnv: &disclosureEnv{
			cardEnv: newCardEnvOn(t, s, pin, writeFresh{}, func(c *connector.CardConfig) {
				c.Speakers = map[string]connector.SpeakerReader{"tg": sp}
				c.Lights = map[string]connector.LightReader{"tg": li}
			}),
			speakers: sp,
		},
		lights: li,
	}
}

func newDeviceWriteEnv(t *testing.T, s *db.Store) *deviceWriteEnv {
	t.Helper()
	return newDeviceWriteEnvOn(t, s, deviceWritePin(t))
}

// shownDevice is the device block and the values of a device write card.
type shownDevice struct {
	light                bool
	home, room, name, id string
	// values are the lines under the values head: a label and the value.
	values [][2]string
}

func line(tp safetext.Template, l safetext.Lang, value string) [2]string {
	return [2]string{tp.In(l), value}
}

// deviceWriteCardText is the card of a device write, as
// safetext.DeviceWriteCard lays it out.
func deviceWriteCardText(l safetext.Lang, tool, args string, d shownDevice) string {
	head, home := safetext.TextCardSpeaker, d.home
	if d.light {
		head = safetext.TextCardLight
	}
	if home == "" {
		home = safetext.TextCardHomeUnknown.In(l)
	}
	s := safetext.TextCardHead.In(l) + "\n\n" + safetext.TextCardAction.In(l) + "\n" + tool + " (tg)\n\n" +
		head.In(l) + "\n" +
		safetext.TextCardHome.In(l) + " " + home + "\n" +
		safetext.TextCardRoom.In(l) + " " + d.room + "\n" +
		safetext.TextCardDeviceName.In(l) + " " + d.name + "\n" +
		safetext.TextCardDeviceID.In(l) + " " + d.id + "\n\n" +
		safetext.TextCardValues.In(l)
	for _, v := range d.values {
		s += "\n" + v[0] + " " + v[1]
	}
	return s + "\n\n" + safetext.TextCardArgs.In(l) + "\n" + args + "\n\n" + safetext.TextCardFoot.In(l)
}

// TestDeviceWrite_CardShowsTheValuesThatAreSent: a value inside its range
// gets a card that shows the device as the fresh read gave it and exactly
// that value, in the device's units; after Approve the call carries the
// approved bytes, unchanged. The volume case is eval A2: the level on the
// card is the level that is sent.
func TestDeviceWrite_CardShowsTheValuesThatAreSent(t *testing.T) {
	kitchen := shownDevice{home: "Alice home", room: "Kitchen", name: "Kitchen speaker", id: kitchenID}
	desk := shownDevice{light: true, home: "Alice home", room: "Study", name: "Desk lamp", id: deskLampID}
	hall := shownDevice{light: true, room: "Hall", name: "Hall light", id: hallLampID}
	cases := []struct {
		name, tool, args string
		device           shownDevice
		values           func(l safetext.Lang) [][2]string
	}{
		{"volume", volumeTool, `{"device":"` + kitchenID + `","level":5}`, kitchen, func(l safetext.Lang) [][2]string {
			return [][2]string{line(safetext.TextCardVolume, l, "5")}
		}},
		{"volume at the bottom", volumeTool, `{"device":"` + kitchenID + `","level":1}`, kitchen, func(l safetext.Lang) [][2]string {
			return [][2]string{line(safetext.TextCardVolume, l, "1")}
		}},
		{"volume at the top", volumeTool, `{"device":"` + kitchenID + `","level":10}`, kitchen, func(l safetext.Lang) [][2]string {
			return [][2]string{line(safetext.TextCardVolume, l, "10")}
		}},
		{"playback", mediaTool, `{"action":"pause","device":"` + kitchenID + `"}`, kitchen, func(l safetext.Lang) [][2]string {
			return [][2]string{line(safetext.TextCardPlayback, l, "pause")}
		}},
		{"every value of a light", lightTool,
			`{"brightness":40,"color_temp_k":2700,"device":"` + deskLampID + `","scene":"reading","state":"on"}`, desk,
			func(l safetext.Lang) [][2]string {
				return [][2]string{
					line(safetext.TextCardPower, l, "on"), line(safetext.TextCardBrightness, l, "40"),
					line(safetext.TextCardColorTemp, l, "2700"), line(safetext.TextCardScene, l, "reading"),
				}
			}},
		{"the bounds of a light", lightTool, `{"brightness":1,"color_temp_k":6500,"device":"` + hallLampID + `"}`, hall,
			func(l safetext.Lang) [][2]string {
				return [][2]string{line(safetext.TextCardBrightness, l, "1"), line(safetext.TextCardColorTemp, l, "6500")}
			}},
		{"the other bounds of a light", lightTool, `{"brightness":100,"color_temp_k":1500,"device":"` + hallLampID + `"}`, hall,
			func(l safetext.Lang) [][2]string {
				return [][2]string{line(safetext.TextCardBrightness, l, "100"), line(safetext.TextCardColorTemp, l, "1500")}
			}},
		{"a light switched off", lightTool, `{"device":"` + hallLampID + `","state":"off"}`, hall, func(l safetext.Lang) [][2]string {
			return [][2]string{line(safetext.TextCardPower, l, "off")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDeviceWriteEnv(t, s)
				row := e.emitTool(tc.tool, tc.args)
				e.noCalls()
				if n := e.speakers.asked() + e.lights.asked(); n != 1 {
					t.Fatalf("%d device reads for one card", n)
				}
				cards := e.sentCards(alice)
				if len(cards) != 1 {
					t.Fatalf("%d cards: %+v", len(cards), e.h.MessagesTo(alice))
				}
				d := tc.device
				d.values = tc.values(safetext.LangEN)
				if want := deviceWriteCardText(safetext.LangEN, tc.tool, tc.args, d); cards[0].Text != want {
					t.Fatalf("card:\n got %q\nwant %q", cards[0].Text, want)
				}
				card, err := e.cards.RenderApprovalCard(context.Background(), alice, row.approve)
				if err != nil {
					t.Fatal(err)
				}
				d.values = tc.values(safetext.LangRU)
				if got, want := card.Text.In(safetext.LangRU).String(), deviceWriteCardText(safetext.LangRU, tc.tool, tc.args, d); got != want {
					t.Fatalf("Russian card:\n got %q\nwant %q", got, want)
				}
				// Every value on the card is a member of the arguments, as
				// it is written there.
				var args map[string]json.RawMessage
				if err := json.Unmarshal([]byte(tc.args), &args); err != nil {
					t.Fatal(err)
				}
				for _, v := range d.values {
					found := false
					for _, raw := range args {
						if strings.Trim(string(raw), `"`) == v[1] {
							found = true
						}
					}
					if !found {
						t.Errorf("the card shows %q, which is not a value of %s", v[1], tc.args)
					}
				}
				if len(d.values) != len(args)-1 {
					t.Errorf("the card shows %d values of %s", len(d.values), tc.args)
				}
				// The device's names are sealed with the arguments.
				var sealed []byte
				if err := s.DB.QueryRow(`SELECT sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&sealed); err != nil {
					t.Fatal(err)
				}
				if len(sealed) == 0 || strings.Contains(string(sealed), tc.device.name) || strings.Contains(string(sealed), tc.device.id) {
					t.Fatal("the device is readable in sealed_args")
				}
				// Approve: exactly the approved bytes are sent, once.
				if got := e.press(alice, row.approve); got != "" {
					t.Fatalf("approve queued the reply %q", got)
				}
				if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != tc.args {
					t.Fatalf("sent %q, want %q", sent, tc.args)
				}
			})
		})
	}
}

// TestDeviceWrite_ValuesAreRefusedNeverClamped: a value outside its range,
// a number that is not a plain integer, a value of another type and a
// choice the schema does not list are refused before anything is read or
// written. The server would round and clamp them; here "volume 55" (eval
// A2) is no card at all, not a card for 10.
func TestDeviceWrite_ValuesAreRefusedNeverClamped(t *testing.T) {
	volume := func(level string) string { return `{"device":"` + kitchenID + `","level":` + level + `}` }
	light := func(member string) string { return `{` + member + `,"device":"` + deskLampID + `"}` }
	media := func(action string) string { return `{"action":` + action + `,"device":"` + kitchenID + `"}` }
	type bad struct{ name, tool, args string }
	var cases []bad
	for name, level := range map[string]string{
		"volume 55": "55", "volume 0": "0", "volume 11": "11", "volume -1": "-1", "volume -5": "-5",
		"volume 5.0": "5.0", "volume 5.5": "5.5", "volume 5e0": "5e0", "volume -0": "-0", "volume 5.00": "5.00", "volume 1e1": "1e1", "volume 0.5e1": "0.5e1",
		"volume as a string": `"5"`, "volume null": "null", "volume true": "true", "volume in a list": "[5]",
		"volume in an object": `{"value":5}`, "a huge volume": "9000000000000000", "volume 100": "100",
	} {
		cases = append(cases, bad{name, volumeTool, volume(level)})
	}
	for name, member := range map[string]string{
		"brightness 0": `"brightness":0`, "brightness 101": `"brightness":101`, "brightness 50.0": `"brightness":50.0`,
		"brightness 50.5": `"brightness":50.5`, "brightness as a string": `"brightness":"50"`, "brightness -10": `"brightness":-10`,
		"color 1499": `"color_temp_k":1499`, "color 6501": `"color_temp_k":6501`, "color 2700.0": `"color_temp_k":2700.0`,
		"color 2.7e3": `"color_temp_k":2.7e3`, "color as a word": `"color_temp_k":"warm"`, "color 0": `"color_temp_k":0`,
		"an unknown state": `"state":"toggle"`, "a state in capitals": `"state":"ON"`, "a state that is a bool": `"state":true`,
		"an unknown scene": `"scene":"disco"`, "a scene that is a number": `"scene":3`, "an empty scene": `"scene":""`,
		"one bad value next to a good one": `"brightness":40,"color_temp_k":9000`,
	} {
		cases = append(cases, bad{name, lightTool, light(member)})
	}
	for name, action := range map[string]string{
		"an unknown action": `"resume"`, "an action in capitals": `"PAUSE"`, "an action with a space": `"pause "`,
		"an action that is a number": "1", "an empty action": `""`, "a free-text action": `"play jazz"`, "action null": "null",
	} {
		cases = append(cases, bad{name, mediaTool, media(action)})
	}
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		for _, tc := range cases {
			e.refused(tc.name, tc.tool, tc.args, http.StatusUnprocessableEntity, connector.ReasonValueNotAllowed)
		}
		// A missing value, and a call that sets nothing.
		e.refused("no level", volumeTool, `{"device":"`+kitchenID+`"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("no action", mediaTool, `{"device":"`+kitchenID+`"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("a light with no value", lightTool, `{"device":"`+deskLampID+`"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		// An argument the pinned schema does not declare.
		e.refused("an undeclared argument", volumeTool, `{"device":"`+kitchenID+`","level":5,"query":"jazz"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.nothingWritten()
		if n := e.speakers.asked() + e.lights.asked(); n != 0 {
			t.Fatalf("%d device reads for refused values", n)
		}
		if msgs := e.sentCards(alice); len(msgs) != 0 {
			t.Fatalf("cards for refused values: %+v", msgs)
		}
	})
}

// TestS2D2_DeviceWriteTargetMustBeAListedDeviceID is the card half of
// S2-D2 for device writes: the target is the id of a device of the tool's
// kind that the fresh read lists. A name, a room, an unlisted id, an
// omitted device and a device of the other kind are refused, so the
// server's name matching and default speaker are never reached.
func TestS2D2_DeviceWriteTargetMustBeAListedDeviceID(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		notListed := func(name, tool, args string) {
			t.Helper()
			e.refused(name, tool, args, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		}
		for name, device := range map[string]string{
			"a speaker's name":      `"device":"Kitchen speaker",`,
			"a room":                `"device":"Kitchen",`,
			"a name in lower case":  `"device":"kitchen speaker",`,
			"an unlisted id":        `"device":"spk-garage-0009",`,
			"the id in other case":  `"device":"SPK-KITCHEN-0001",`,
			"the id with a space":   `"device":"` + kitchenID + ` ",`,
			"a light's id":          `"device":"` + deskLampID + `",`,
			"an empty device":       `"device":"",`,
			"no device (a default)": ``,
		} {
			notListed(name, volumeTool, `{`+device+`"level":5}`)
			notListed(name, mediaTool, `{`+device+`"action":"pause"}`)
		}
		for name, device := range map[string]string{
			"a light's name":       `"device":"Desk lamp"`,
			"a room":               `"device":"Study"`,
			"an unlisted id":       `"device":"lamp-attic-0009"`,
			"a speaker's id":       `"device":"` + kitchenID + `"`,
			"an empty device":      `"device":""`,
			"the id and its room":  `"device":"` + deskLampID + `","room":"Study"`,
			"the id, another room": `"device":"` + deskLampID + `","room":"Hall"`,
			"a room and no device": `"room":"Study"`,
		} {
			notListed(name, lightTool, `{"brightness":40,`+device+`}`)
		}
		notListed("no device", lightTool, `{"brightness":40}`)
		e.refused("a device that is not a string", volumeTool, `{"device":7,"level":5}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("a device that is a list", lightTool, `{"brightness":40,"device":["`+deskLampID+`"]}`, http.StatusBadRequest, connector.ReasonBadRequest)
		// A device named like another device's id does not make the name a
		// target.
		e.speakers.set([]connector.Speaker{{ID: kitchenID, Name: bedroomID, Room: "Kitchen"}}, nil)
		notListed("an id that is only a name", volumeTool, `{"device":"`+bedroomID+`","level":5}`)
		e.lights.set([]connector.Light{{ID: deskLampID, Name: hallLampID, Room: "Study"}}, nil)
		notListed("a light id that is only a name", lightTool, `{"brightness":40,"device":"`+hallLampID+`"}`)
		e.nothingWritten()
	})
}

// TestS2D2_DeviceWriteApprovalBindsDeviceAndValue is the dispatch half of
// S2-D2 for device writes: the approval's hash covers the device id and
// the value, in the spelling the card showed, so arguments changed after
// the card are refused and nothing is called.
func TestS2D2_DeviceWriteApprovalBindsDeviceAndValue(t *testing.T) {
	approved := `{"device":"` + kitchenID + `","level":5}`
	changed := map[string]string{
		"another value":    `{"device":"` + kitchenID + `","level":10}`,
		"another device":   `{"device":"` + bedroomID + `","level":5}`,
		"no device":        `{"level":5}`,
		"another spelling": `{"device":"` + kitchenID + `","level":5.0}`,
	}
	for name, other := range changed {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDeviceWriteEnv(t, s)
				e.manyCardsPerRun()
				row := e.emitTool(volumeTool, approved)
				bound := e.strings(`SELECT args_sha FROM pa_approvals WHERE id = $1`, row.id)
				if len(bound) != 1 || bound[0] != sha(approved) {
					t.Fatalf("the approval binds %v, want the hash of all of the arguments %s", bound, sha(approved))
				}
				e.setSealed(row.id, forgeSeal(t, alice, row.id, bound[0], []byte(other)))
				if got := e.press(alice, row.approve); got != "" {
					t.Fatalf("approve queued the reply %q", got)
				}
				if sent := e.ep.sent(); len(sent) != 0 {
					t.Fatalf("changed arguments were sent: %q", sent)
				}
				e.mu.Lock()
				outcomes := slices.Clone(e.outcomes)
				e.mu.Unlock()
				if len(outcomes) != 1 || outcomes[0].Reason != connector.ReasonArgsChanged {
					t.Fatalf("outcomes %+v, want one refusal %s", outcomes, connector.ReasonArgsChanged)
				}
			})
		})
	}
	// Two calls that differ only in the value are two different approvals.
	e := newDeviceWriteEnv(t, sqliteStore(t))
	e.manyCardsPerRun()
	a := e.emitTool(volumeTool, approved)
	b := e.emitTool(volumeTool, `{"device":"`+kitchenID+`","level":6}`)
	hashes := e.strings(`SELECT args_sha FROM pa_approvals WHERE id IN ($1, $2)`, a.id, b.id)
	if len(hashes) != 2 || hashes[0] == hashes[1] {
		t.Fatalf("args_sha of two values: %v", hashes)
	}
}

// TestDeviceWrite_UnreadableDevicesRefuse: a device read that failed, came
// back empty or cannot be trusted is a refusal of its own, never "no such
// device" and never a card; without a reader there is no card at all.
func TestDeviceWrite_UnreadableDevicesRefuse(t *testing.T) {
	volume := `{"device":"` + kitchenID + `","level":5}`
	bright := `{"brightness":40,"device":"` + deskLampID + `"}`
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		unreadable := func(name, tool, args string) {
			t.Helper()
			e.refused(name, tool, args, http.StatusServiceUnavailable, connector.ReasonDevicesUnreadable)
		}
		for name, tc := range map[string]struct {
			list []connector.Speaker
			err  error
		}{
			"the read failed":  {nil, errors.New("injected read failure")},
			"failed with data": {testSpeakers(), connector.ErrSpeakersUnreadable},
			"an empty list":    {nil, nil},
			"a nameless one":   {[]connector.Speaker{{ID: kitchenID, Room: "Kitchen"}}, nil},
			"one without an id": {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"},
				{Name: "Bedroom speaker", Room: "Bedroom"}}, nil},
			"one id twice": {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"},
				{ID: kitchenID, Name: "Bedroom speaker", Room: "Bedroom"}}, nil},
		} {
			e.speakers.set(tc.list, tc.err)
			unreadable(name, volumeTool, volume)
			unreadable(name, mediaTool, `{"action":"stop","device":"`+kitchenID+`"}`)
		}
		for name, tc := range map[string]struct {
			list []connector.Light
			err  error
		}{
			"the light read failed": {nil, errors.New("injected read failure")},
			"failed with lights":    {testLights(), connector.ErrSpeakersUnreadable},
			"no light":              {nil, nil},
			"a nameless light":      {[]connector.Light{{ID: deskLampID, Room: "Study"}}, nil},
			"one light id twice": {[]connector.Light{{ID: deskLampID, Name: "Desk lamp", Room: "Study"},
				{ID: deskLampID, Name: "Hall light", Room: "Hall"}}, nil},
		} {
			e.lights.set(tc.list, tc.err)
			unreadable(name, lightTool, bright)
		}
		// A device name the card cannot show exactly refuses the card too.
		e.speakers.set([]connector.Speaker{{ID: kitchenID, Name: "Kitchen\nVolume: 1", Room: "Kitchen"}}, nil)
		e.refused("a two-line speaker name", volumeTool, volume, http.StatusUnprocessableEntity, connector.ReasonCardUnshowable)
		e.nothingWritten()
	})
	// No reader of the kind: the speakers' reader does not serve a light,
	// nor the lights' reader a speaker.
	for name, tc := range map[string]struct {
		opt        func(*connector.CardConfig)
		tool, args string
	}{
		"no reader at all": {func(*connector.CardConfig) {}, volumeTool, volume},
		"only a speaker reader": {func(c *connector.CardConfig) {
			c.Speakers = map[string]connector.SpeakerReader{"tg": &fakeSpeakers{list: testSpeakers()}}
		}, lightTool, bright},
		"only a light reader": {func(c *connector.CardConfig) {
			c.Lights = map[string]connector.LightReader{"tg": &fakeLights{list: testLights()}}
		}, volumeTool, volume},
	} {
		e := &disclosureEnv{cardEnv: newCardEnvOn(t, sqliteStore(t), deviceWritePin(t), writeFresh{}, tc.opt)}
		e.refused(name, tc.tool, tc.args, http.StatusForbidden, connector.ReasonNoWritePath)
		e.nothingWritten()
	}
}

// TestDeviceWrite_OtherPhase2WritesHaveNoCard: a Phase 2 write without a
// card of its own is refused, never shown as a plain card of raw
// arguments: alice_control_device, alice_control_room and
// alice_trigger_scenario have no card here.
func TestDeviceWrite_OtherPhase2WritesHaveNoCard(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		for tool, args := range map[string]string{
			deviceTool:  `{"device":"` + deskLampID + `","state":"on"}`,
			roomTool:    `{"action":"turn_off","room":"Kitchen"}`,
			scenarioRun: `{"scenario":"scn-evening-0001"}`,
		} {
			e.refused(tool, tool, args, http.StatusForbidden, connector.ReasonNoWritePath)
		}
		e.nothingWritten()
		if n := e.speakers.asked() + e.lights.asked(); n != 0 {
			t.Fatalf("%d device reads for tools without a card", n)
		}
	})
	// Every write of the Phase 2 pin is one of the two kinds.
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	withCard := []string{mediaTool, volumeTool, lightTool, musicTool}
	without := []string{deviceTool, roomTool, scenarioRun}
	for name, pt := range p2.Servers["alice"].Tools {
		if pt.Class == catalog.ClassWrite && !slices.Contains(withCard, name) && !slices.Contains(without, name) {
			t.Errorf("%s is a Phase 2 write this test does not place", name)
		}
		if pt.Class == catalog.ClassWrite && !catalog.Phase2Tool(name) {
			t.Errorf("%s is a pinned write that catalog.Phase2Tool does not name", name)
		}
	}
}

// TestDeviceWrite_PinAndCardAgree: the labels of a card name the range of
// each number, so the range is the pin's: the Phase 2 pin holds exactly
// the bounds the labels say, a pin with other bounds, or none, gets no
// card, and so does a pin whose schema gained an argument or lost a list
// of choices.
func TestDeviceWrite_PinAndCardAgree(t *testing.T) {
	pin := deviceWritePin(t)
	for _, tc := range []struct {
		tool, arg string
		label     safetext.Template
	}{
		{volumeTool, "level", safetext.TextCardVolume},
		{lightTool, "brightness", safetext.TextCardBrightness},
		{lightTool, "color_temp_k", safetext.TextCardColorTemp},
	} {
		c := pin.Servers["tg"].Tools[tc.tool].Constraints
		if c == nil {
			t.Fatalf("%s has no constraints in the Phase 2 pin", tc.tool)
		}
		b, ok := c.IntegerBounds[tc.arg]
		if !ok {
			t.Fatalf("the Phase 2 pin does not bound %s.%s", tc.tool, tc.arg)
		}
		lo, hi := strconv.FormatInt(b.Min, 10), strconv.FormatInt(b.Max, 10)
		if en := tc.label.In(safetext.LangEN); !strings.Contains(en, "from "+lo+" to "+hi) {
			t.Errorf("the label %q does not name the pin's %s..%s", en, lo, hi)
		}
		if ru := tc.label.In(safetext.LangRU); !strings.Contains(ru, "от "+lo+" до "+hi) {
			t.Errorf("the label %q does not name the pin's %s..%s", ru, lo, hi)
		}
	}
	// The choices are the pinned schema's, all of them.
	for _, action := range []string{"play", "pause", "stop", "next", "prev"} {
		e := newDeviceWriteEnv(t, sqliteStore(t))
		e.emitTool(mediaTool, `{"action":"`+action+`","device":"`+kitchenID+`"}`)
	}

	volume := `{"device":"` + kitchenID + `","level":5}`
	edit := func(tool string, f func(*catalog.PinnedTool)) *catalog.Pin {
		p := deviceWritePin(t)
		pt := p.Servers["tg"].Tools[tool]
		if pt.Constraints != nil {
			c := *pt.Constraints
			pt.Constraints = &c
		}
		f(&pt)
		p.Servers["tg"].Tools[tool] = pt
		return p
	}
	// schema edits the properties of a pinned input schema.
	schema := func(pt *catalog.PinnedTool, f func(props map[string]map[string]any)) {
		var sc struct {
			Type       string                    `json:"type"`
			Properties map[string]map[string]any `json:"properties"`
			Required   []string                  `json:"required"`
		}
		if err := json.Unmarshal(pt.InputSchema, &sc); err != nil || len(sc.Properties) == 0 {
			t.Fatalf("pinned schema: %v", err)
		}
		f(sc.Properties)
		raw, err := json.Marshal(sc)
		if err != nil {
			t.Fatal(err)
		}
		pt.InputSchema = raw
	}
	for name, tc := range map[string]struct {
		pin        *catalog.Pin
		tool, args string
	}{
		"wider bounds": {edit(volumeTool, func(pt *catalog.PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]catalog.IntBound{"level": {Min: 1, Max: 100}}
		}), volumeTool, volume},
		"narrower bounds": {edit(volumeTool, func(pt *catalog.PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]catalog.IntBound{"level": {Min: 1, Max: 8}}
		}), volumeTool, volume},
		"no bounds": {edit(volumeTool, func(pt *catalog.PinnedTool) { pt.Constraints = nil }), volumeTool, volume},
		"one bound of a light missing": {edit(lightTool, func(pt *catalog.PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]catalog.IntBound{"brightness": {Min: 1, Max: 100}}
		}), lightTool, `{"brightness":40,"device":"` + deskLampID + `"}`},
		"an argument the card cannot show": {edit(volumeTool, func(pt *catalog.PinnedTool) {
			schema(pt, func(props map[string]map[string]any) { props["fade_seconds"] = map[string]any{"type": "number"} })
		}), volumeTool, `{"device":"` + kitchenID + `","fade_seconds":3,"level":5}`},
		"an action without choices": {edit(mediaTool, func(pt *catalog.PinnedTool) {
			schema(pt, func(props map[string]map[string]any) { delete(props["action"], "enum") })
		}), mediaTool, `{"action":"pause","device":"` + kitchenID + `"}`},
	} {
		e := newDeviceWriteEnvOn(t, sqliteStore(t), tc.pin)
		e.refused(name, tc.tool, tc.args, http.StatusForbidden, connector.ReasonNoWritePath)
		e.nothingWritten()
	}
}
