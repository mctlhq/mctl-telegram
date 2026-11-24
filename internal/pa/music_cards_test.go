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

// Acceptance tests of #1322 slice P2-S14b: the card path of
// alice_play_music and the device read the write executor makes right
// before it sends (connector/alice_music.go, connector/device_recheck.go).
//
// Threat model: T6 (S2-D2, S2-D4, S2-D5), T7 (S2-D1).

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

const (
	musicTool = "alice_play_music"
	// musicPrefix is the fixed start of the command mctl-alice sends for a
	// music request. It is data: the words the speaker is handed.
	musicPrefix = "включи музыку "
)

func musicArgs(device, query string) string {
	return `{"device":"` + device + `","query":"` + query + `"}`
}

// musicCardText is the card of an alice_play_music call, as
// safetext.MusicCard lays it out.
func musicCardText(l safetext.Lang, args string, sp connector.Speaker, query string) string {
	home, room := sp.Home, sp.Room
	if home == "" {
		home = safetext.TextCardHomeUnknown.In(l)
	}
	if room == "" {
		room = safetext.TextCardHomeUnknown.In(l)
	}
	return safetext.TextCardHead.In(l) + "\n\n" + safetext.TextCardAction.In(l) + "\n" + musicTool + " (tg)\n\n" +
		safetext.TextCardSpeaker.In(l) + "\n" +
		safetext.TextCardHome.In(l) + " " + home + "\n" +
		safetext.TextCardRoom.In(l) + " " + room + "\n" +
		safetext.TextCardDeviceName.In(l) + " " + sp.Name + "\n" +
		safetext.TextCardDeviceID.In(l) + " " + sp.ID + "\n\n" +
		safetext.TextCardMusicQuery.In(l) + "\n" + query + "\n\n" +
		safetext.TextCardMusicCommand.In(l) + "\n" + musicPrefix + query + "\n\n" +
		safetext.TextCardArgs.In(l) + "\n" + args + "\n\n" + safetext.TextCardFoot.In(l)
}

// outcomesOf returns what the write executor answered the approvals
// pressed so far.
func (e *cardEnv) outcomesOf() []connector.WriteOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.outcomes)
}

// TestS2D4_MusicCardShowsTheQueryTheCommandAndTheSpeaker: the card of a
// music request holds the query exactly, on a line of its own, the whole
// command the speaker receives on another, and the speaker's home, room,
// name and id as the fresh read gave them, in both languages. Approve
// sends exactly the approved bytes, once, after one more device read.
func TestS2D4_MusicCardShowsTheQueryTheCommandAndTheSpeaker(t *testing.T) {
	kitchen := testSpeakers()[0]
	for _, query := range []string{"Кино Группа крови", "AC-DC & Guns N' Roses live 1991", "jazz"} {
		t.Run(query, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDeviceWriteEnv(t, s)
				args := musicArgs(kitchenID, query)
				row := e.emitTool(musicTool, args)
				e.noCalls()
				if n := e.speakers.asked(); n != 1 || e.lights.asked() != 0 || e.devices.asked() != 0 {
					t.Fatalf("%d speaker reads, %d light reads, %d executor reads for one card", n, e.lights.asked(), e.devices.asked())
				}
				cards := e.sentCards(alice)
				if len(cards) != 1 {
					t.Fatalf("%d cards: %+v", len(cards), e.h.MessagesTo(alice))
				}
				if want := musicCardText(safetext.LangEN, args, kitchen, query); cards[0].Text != want {
					t.Fatalf("card:\n got %q\nwant %q", cards[0].Text, want)
				}
				lines := strings.Split(cards[0].Text, "\n")
				for _, want := range []string{query, musicPrefix + query, "Home: Alice home", "Room: Kitchen",
					"Name: Kitchen speaker", "Device id: " + kitchenID, args} {
					if !slices.Contains(lines, want) {
						t.Errorf("no line of the card is %q", want)
					}
				}
				card, err := e.cards.RenderApprovalCard(context.Background(), alice, row.approve)
				if err != nil {
					t.Fatal(err)
				}
				if got, want := card.Text.In(safetext.LangRU).String(), musicCardText(safetext.LangRU, args, kitchen, query); got != want {
					t.Fatalf("Russian card:\n got %q\nwant %q", got, want)
				}
				if got := card.Text.In(safetext.LangEN).String(); got != cards[0].Text {
					t.Fatalf("the card rebuilt from the sealed call differs:\n got %q\nwant %q", got, cards[0].Text)
				}
				// The query and the speaker are sealed, not stored in the clear.
				var sealed []byte
				if err := s.DB.QueryRow(`SELECT sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&sealed); err != nil {
					t.Fatal(err)
				}
				if len(sealed) == 0 || strings.Contains(string(sealed), query) || strings.Contains(string(sealed), kitchenID) {
					t.Fatal("the call is readable in sealed_args")
				}
				// The approval binds the canonical arguments.
				var argsSHA string
				if err := s.DB.QueryRow(`SELECT args_sha FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&argsSHA); err != nil {
					t.Fatal(err)
				}
				if argsSHA != shaHex([]byte(args)) {
					t.Fatalf("args_sha %s is not the digest of the canonical arguments", argsSHA)
				}

				if got := e.press(alice, row.approve); got != "" {
					t.Fatalf("approve queued the reply %q", got)
				}
				if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != args {
					t.Fatalf("sent %q, want %q once", sent, args)
				}
				if n := e.devices.asked(); n != 1 {
					t.Fatalf("%d device reads at dispatch, want one", n)
				}
				// The harness's endpoint answers only its own write tool, so
				// the outcome of a call that was sent is "unknown" here.
				if out := e.outcomesOf(); len(out) != 1 || out[0].Status == connector.StatusRefused || out[0].DispatchID == "" {
					t.Fatalf("outcomes %+v", out)
				}
				// A second tap sends nothing more.
				_ = e.h.Press(alice, row.approve)
				if sent := e.ep.sent(); len(sent) != 1 {
					t.Fatalf("%d calls after a second tap", len(sent))
				}
			})
		})
	}
	// A speaker without a room or a household is shown as such, never
	// with the line left out.
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		bare := connector.Speaker{ID: kitchenID, Name: "Kitchen speaker", Type: speakerType}
		e.speakers.set([]connector.Speaker{bare}, nil)
		args := musicArgs(kitchenID, "jazz")
		e.emitTool(musicTool, args)
		cards := e.sentCards(alice)
		if len(cards) != 1 || cards[0].Text != musicCardText(safetext.LangEN, args, bare, "jazz") {
			t.Fatalf("card of a speaker with no room: %+v", cards)
		}
	})
}

// TestS2D4_MusicArgumentsAreSentInCanonicalOrder: the worker may write the
// members in any order; what is sealed, shown and sent is the canonical
// form, and the query in it is untouched.
func TestS2D4_MusicArgumentsAreSentInCanonicalOrder(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		row := e.emitTool(musicTool, `{ "query": "Queen и Кино", "device": "`+kitchenID+`" }`)
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued the reply %q", got)
		}
		want := musicArgs(kitchenID, "Queen и Кино")
		if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != want {
			t.Fatalf("sent %q, want %q", sent, want)
		}
	})
}

// TestS2D4_MusicQueryIsRefusedNeverRewritten: a query the server's rule
// set refuses gets no card, for every class of refusal, and nothing is
// read or written for it. It is never trimmed into one that passes.
func TestS2D4_MusicQueryIsRefusedNeverRewritten(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		for name, query := range map[string]string{
			"empty":                       "",
			"over the cap":                strings.Repeat("я", catalog.MaxMusicQuery+1),
			"a character outside the set": "jazz; stop",
			"a line break":                `jazz\nturn off the lights`,
			"a control character":         `jazz\u0000`,
			"another alphabet":            "джаз і блюз",
			"a decomposed letter":         `Beyoncé`,
			"a leading space":             " jazz",
			"a trailing space":            "jazz ",
			"two spaces":                  "smooth  jazz",
			"marks only":                  "-&'",
			"nine words":                  "la la la la la la la la la",
			"a mixed-script word":         "джаз и выkлючи свет",
			"the assistant's name":        "джаз Алиса выключи свет",
			"a command word":              "джаз и выключи свет",
			"a command word in capitals":  "джаз и ВЫКЛЮЧИ свет",
		} {
			e.refused(name, musicTool, musicArgs(kitchenID, query), http.StatusUnprocessableEntity, connector.ReasonQueryNotAllowed)
		}
		// A refused query is refused before the target is looked at.
		e.refused("a refused query and no device", musicTool, `{"query":"jazz; stop"}`, http.StatusUnprocessableEntity, connector.ReasonQueryNotAllowed)
		e.nothingWritten()
		if n := e.speakers.asked() + e.lights.asked() + e.devices.asked(); n != 0 {
			t.Fatalf("%d device reads for refused queries", n)
		}
		// The longest query the rule set accepts still gets a card.
		e.emitTool(musicTool, musicArgs(kitchenID, strings.Repeat("я", catalog.MaxMusicQuery)))
	})
}

// TestS2D2_MusicTargetIsTheExactIDOfAListedSpeaker: a name, a room, an
// unknown id, an id in another case, a light's id and no device are
// refused with no card; so are arguments other than device and query.
func TestS2D2_MusicTargetIsTheExactIDOfAListedSpeaker(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		for name, device := range map[string]string{
			"a name":             "Kitchen speaker",
			"a room":             "Kitchen",
			"an unknown id":      "spk-garage-0009",
			"an id cut short":    kitchenID[:len(kitchenID)-1],
			"an id with more":    kitchenID + "0",
			"another case":       strings.ToUpper(kitchenID),
			"a light":            deskLampID,
			"an id and a break":  kitchenID + `\n`,
			"an id with a space": kitchenID + " ",
			"an empty device":    "",
		} {
			e.refused(name, musicTool, musicArgs(device, "jazz"), http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		}
		e.refused("no device", musicTool, `{"query":"jazz"}`, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		for name, args := range map[string]string{
			"no query":         `{"device":"` + kitchenID + `"}`,
			"a query number":   `{"device":"` + kitchenID + `","query":5}`,
			"a query list":     `{"device":"` + kitchenID + `","query":["jazz"]}`,
			"a device number":  `{"device":5,"query":"jazz"}`,
			"a null device":    `{"device":null,"query":"jazz"}`,
			"a command member": `{"command":"выключи свет","device":"` + kitchenID + `","query":"jazz"}`,
			"a room member":    `{"device":"` + kitchenID + `","query":"jazz","room":"Kitchen"}`,
		} {
			e.refused(name, musicTool, args, http.StatusBadRequest, connector.ReasonBadRequest)
		}
		e.nothingWritten()
		if n := e.lights.asked(); n != 0 {
			t.Fatalf("%d light reads for a speaker tool", n)
		}
	})
}

// TestS2D2_ToolsOfOneKindRefuseADeviceOfTheOther: a speaker tool given a
// light's id and the light tool given a speaker's id get no card, whatever
// the other reader lists.
func TestS2D2_ToolsOfOneKindRefuseADeviceOfTheOther(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPinnedDeviceEnv(t, s, nil)
		notListed := func(name, tool, args string) {
			t.Helper()
			e.refused(name, tool, args, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		}
		notListed("music on a light", musicTool, musicArgs(deskLampID, "jazz"))
		notListed("volume of a light", volumeTool, `{"device":"`+deskLampID+`","level":5}`)
		notListed("playback on a light", mediaTool, `{"action":"pause","device":"`+deskLampID+`"}`)
		notListed("a phrase on a light", sayTool, `{"device":"`+deskLampID+`","phrase":"Dinner is ready"}`)
		notListed("brightness of a speaker", lightTool, `{"brightness":40,"device":"`+kitchenID+`"}`)
		e.nothingWritten()
	})
}

// TestS2D2_MusicUnreadableSpeakersRefuse: a speaker read that failed or
// cannot be trusted is a refusal of its own, never "no such device" and
// never a card; without a reader there is no card path.
func TestS2D2_MusicUnreadableSpeakersRefuse(t *testing.T) {
	args := musicArgs(kitchenID, "jazz")
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDeviceWriteEnv(t, s)
		for name, tc := range map[string]struct {
			list []connector.Speaker
			err  error
		}{
			"the read failed":  {nil, errors.New("injected read failure")},
			"failed with data": {testSpeakers(), connector.ErrSpeakersUnreadable},
			"an empty list":    {nil, nil},
			"a nameless one":   {[]connector.Speaker{{ID: kitchenID, Room: "Kitchen"}}, nil},
			"one id twice": {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"},
				{ID: kitchenID, Name: "Bedroom speaker", Room: "Bedroom"}}, nil},
		} {
			e.speakers.set(tc.list, tc.err)
			e.refused(name, musicTool, args, http.StatusServiceUnavailable, connector.ReasonDevicesUnreadable)
		}
		// A listing read in full that holds no speaker: the target is
		// known to be absent.
		e.speakers.set(nil, connector.ErrNoSuchDevices)
		e.refused("no speaker is listed", musicTool, args, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		e.speakers.set([]connector.Speaker{{ID: kitchenID, Name: "Kitchen\nQuery: other", Room: "Kitchen"}}, nil)
		e.refused("a two-line speaker name", musicTool, args, http.StatusUnprocessableEntity, connector.ReasonCardUnshowable)
		e.nothingWritten()
	})
	e := &disclosureEnv{cardEnv: newCardEnvOn(t, sqliteStore(t), deviceWritePin(t), writeFresh{}, func(c *connector.CardConfig) {
		c.Lights = map[string]connector.LightReader{"tg": &fakeLights{list: testLights()}}
	})}
	e.refused("no speaker reader", musicTool, args, http.StatusForbidden, connector.ReasonNoWritePath)
	e.nothingWritten()
}

// TestS2D4_MusicPinAndCardAgree: the card path of a music request stands
// on the pin's entry: the Phase 2 pin holds the tool as an approve-tier
// write that is never lowered, with the server's cap on the query, and a
// pin that says anything else has no card path.
func TestS2D4_MusicPinAndCardAgree(t *testing.T) {
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := p2.Servers["alice"].Tools[musicTool]
	if !ok || pt.Tier != catalog.TierApprove || pt.Class != catalog.ClassWrite || pt.Lowerable != catalog.LowerableNever ||
		pt.Constraints == nil || pt.Constraints.TextCap["query"] != catalog.MaxMusicQuery || pt.Constraints.TextCap["device"] != 128 {
		t.Fatalf("the Phase 2 pin holds alice_play_music as %+v", pt)
	}
	if !catalog.Phase2Tool(musicTool) || !catalog.IsNeverLowerable(musicTool) || permissions.HasRule(musicTool) {
		t.Fatal("alice_play_music must be a Phase 2 tool that is never lowered and has no grant rule")
	}
	if p1, err := catalog.LoadPin(); err != nil {
		t.Fatal(err)
	} else if _, ok := p1.Servers["alice"].Tools[musicTool]; ok {
		t.Fatal("the Phase 1 pin holds alice_play_music")
	}
	args := musicArgs(kitchenID, "jazz")
	for name, mutate := range map[string]func(*catalog.PinnedTool){
		"lowerable": func(p *catalog.PinnedTool) { p.Lowerable = catalog.LowerableYes },
		"conditional": func(p *catalog.PinnedTool) {
			p.Lowerable = catalog.LowerableConditional
		},
		"a cap of 200": func(p *catalog.PinnedTool) {
			c := *p.Constraints
			c.TextCap = map[string]int{"device": 128, "query": 200}
			p.Constraints = &c
		},
		"no cap": func(p *catalog.PinnedTool) { p.Constraints = nil },
	} {
		pin := deviceWritePin(t)
		entry := pin.Servers["tg"].Tools[musicTool]
		mutate(&entry)
		pin.Servers["tg"].Tools[musicTool] = entry
		e := newDeviceWriteEnvOn(t, sqliteStore(t), pin)
		e.refused(name, musicTool, args, http.StatusForbidden, connector.ReasonNoWritePath)
		e.nothingWritten()
	}
}

// TestS2D1_MusicIsNeverLowered: a standing permission row forced into the
// store for alice_play_music lowers nothing. The call gets its card, no
// permission is looked up for it, and the executor, handed the call
// directly with that row, sends nothing.
func TestS2D1_MusicIsNeverLowered(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newLowerEnv(t, s)
		e.grant("prm_music", musicTool, permissions.NoCeiling, kitchenID, bedroomID)
		e.grant("prm_music5", musicTool, 5, kitchenID)
		if e.tainted() {
			t.Fatal("the run is not clean")
		}
		args := musicArgs(kitchenID, "jazz")
		row := e.carded("play music", musicTool, args)
		e.noPermissionInAudit("play music")
		if n := e.look.calls.Load(); n != 0 {
			t.Fatalf("%d permission lookups for a tool that is never lowered", n)
		}
		for _, id := range []string{"prm_music", "prm_music5"} {
			call := e.loweredCall(id, musicTool, args, catalog.ClassWrite)
			call.Target = sealedDevice(kitchenID, "Kitchen speaker", "Kitchen", "Alice home", speakerType, "speaker", "speaker")
			out := e.dispatchLowered(call)
			if out.Status != connector.StatusRefused || out.Reason != connector.ReasonNotLowerable || out.DispatchID != "" {
				t.Fatalf("%s handed to the executor: %+v", id, out)
			}
		}
		e.nothingSent("play music with a forced permission")
		if n := e.fresh.asked(); n != 1 {
			t.Fatalf("%d fresh listings, want the card's one", n)
		}
		// The same run does lower a write it has a permission for, so the
		// card above is the tool's rule and not a tainted run.
		e.grant("prm_vol", volumeTool, 5, kitchenID)
		e.lowered("a write in the same run", "prm_vol", volumeTool, volume5)
		// The card still works: approve sends the approved bytes.
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued the reply %q", got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != args {
			t.Fatalf("sent %q, want %q", sent, args)
		}
	})
}

// newPinnedDeviceEnv is a device write env over every Phase 2 write and
// disclosure tool, each listed with the class the pin gives it. write, if
// not nil, changes the write executor's configuration last.
func newPinnedDeviceEnv(t *testing.T, s *db.Store, write func(*connector.WriteConfig)) *deviceWriteEnv {
	t.Helper()
	pin := lowerPin(t)
	sp, li := &fakeSpeakers{list: testSpeakers()}, &fakeLights{list: testLights()}
	ce := newCardEnvWith(t, s, pin, &pinFresh{pin: pin}, write, func(c *connector.CardConfig) {
		c.Speakers = map[string]connector.SpeakerReader{"tg": sp}
		c.Lights = map[string]connector.LightReader{"tg": li}
	})
	return &deviceWriteEnv{disclosureEnv: &disclosureEnv{cardEnv: ce, speakers: sp}, lights: li}
}

// changedDevice is one way a device differs at dispatch from the device
// the card was made from, and the refusal it must end in.
type changedDevice struct {
	name   string
	change func(e *deviceWriteEnv)
	reason string
}

func changedDevices() []changedDevice {
	speakers := func(mutate func(*connector.Speaker)) func(e *deviceWriteEnv) {
		return func(e *deviceWriteEnv) {
			list := testSpeakers()
			mutate(&list[0])
			e.speakers.set(list, nil)
		}
	}
	lights := func(mutate func(*connector.Light)) func(e *deviceWriteEnv) {
		return func(e *deviceWriteEnv) {
			list := testLights()
			mutate(&list[0])
			e.lights.set(list, nil)
		}
	}
	both := func(sp func(*connector.Speaker), li func(*connector.Light)) func(e *deviceWriteEnv) {
		return func(e *deviceWriteEnv) {
			speakers(sp)(e)
			lights(li)(e)
		}
	}
	return []changedDevice{
		{"removed", func(e *deviceWriteEnv) {
			e.speakers.set(testSpeakers()[1:], nil)
			e.lights.set(testLights()[1:], nil)
		}, connector.ReasonDeviceNotListed},
		{"renamed", both(func(s *connector.Speaker) { s.Name = "Bedroom speaker" }, func(l *connector.Light) { l.Name = "Hall light" }),
			connector.ReasonDeviceChanged},
		{"moved to another room", both(func(s *connector.Speaker) { s.Room = "Bedroom" }, func(l *connector.Light) { l.Room = "Hall" }),
			connector.ReasonDeviceChanged},
		{"left without a room", both(func(s *connector.Speaker) { s.Room = "" }, func(l *connector.Light) { l.Room = "" }),
			connector.ReasonDeviceChanged},
		{"moved to another home", both(func(s *connector.Speaker) { s.Home = "Bob home" }, func(l *connector.Light) { l.Home = "Bob home" }),
			connector.ReasonDeviceChanged},
		{"retyped", both(func(s *connector.Speaker) { s.Type = "devices.types.media_device.tv" },
			func(l *connector.Light) { l.Type = "devices.types.light.strip" }), connector.ReasonDeviceChanged},
		{"left without a type", both(func(s *connector.Speaker) { s.Type = "" }, func(l *connector.Light) { l.Type = "" }),
			connector.ReasonDeviceChanged},
		{"the list is unreadable", func(e *deviceWriteEnv) {
			e.speakers.set(nil, connector.ErrSpeakersUnreadable)
			e.lights.set(nil, connector.ErrSpeakersUnreadable)
		}, connector.ReasonDevicesUnreadable},
		{"the read failed", func(e *deviceWriteEnv) {
			e.speakers.set(testSpeakers(), errors.New("injected read failure"))
			e.lights.set(testLights(), errors.New("injected read failure"))
		}, connector.ReasonDevicesUnreadable},
		{"listed twice", func(e *deviceWriteEnv) {
			e.speakers.set(append(testSpeakers(), testSpeakers()[0]), nil)
			e.lights.set(append(testLights(), testLights()[0]), nil)
		}, connector.ReasonDevicesUnreadable},
	}
}

// someChangedDevices is the short list a tool gets when another tool of
// the same kind already ran every change: the device gone, renamed and
// retyped. It keeps the Postgres run of these tests in minutes.
func someChangedDevices() []changedDevice {
	var out []changedDevice
	for _, tc := range changedDevices() {
		switch tc.name {
		case "removed", "renamed", "retyped":
			out = append(out, tc)
		}
	}
	return out
}

// deviceCalls is one call of every tool whose card names a device.
func deviceCalls() map[string][2]string {
	return map[string][2]string{
		"music":    {musicTool, musicArgs(kitchenID, "jazz")},
		"volume":   {volumeTool, `{"device":"` + kitchenID + `","level":5}`},
		"playback": {mediaTool, `{"action":"pause","device":"` + kitchenID + `"}`},
		"a phrase": {sayTool, kitchenSay},
		"command":  {commandTool, `{"command":"play jazz","device":"` + kitchenID + `"}`},
		"light":    {lightTool, `{"brightness":40,"device":"` + deskLampID + `"}`},
	}
}

// TestS2D2_DispatchReadsTheDeviceAgain is S2-D2 and S2-D5 at dispatch: the
// executor reads the device list once more right before it sends an
// approved device write, disclosure or music request, and a device that
// was removed, renamed, moved or retyped since the card, or a list it
// cannot read, means nothing is sent. The approval is spent and the
// principal is told. An unchanged device costs exactly one read.
func TestS2D2_DispatchReadsTheDeviceAgain(t *testing.T) {
	for callName, call := range deviceCalls() {
		t.Run(callName, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newPinnedDeviceEnv(t, s, nil)
				notices := func() int {
					e.h.Loop().WaitDeliveries()
					return len(e.strings(`SELECT kind FROM pa_outbox WHERE kind = 'write_not_sent'`))
				}
				// Every change for one speaker tool and for the light; the
				// other speaker tools share the code path and get the short
				// list.
				changes := someChangedDevices()
				if callName == "music" || callName == "light" {
					changes = changedDevices()
				}
				for i, tc := range changes {
					e.speakers.set(testSpeakers(), nil)
					e.lights.set(testLights(), nil)
					row := e.emitTool(call[0], call[1])
					reads, told, answered := e.devices.asked(), notices(), len(e.outcomesOf())
					tc.change(e)
					if code := e.h.Press(alice, row.approve); code != http.StatusOK {
						t.Fatalf("%s: approve: %d", tc.name, code)
					}
					if sent := e.ep.sent(); len(sent) != 0 {
						t.Fatalf("%s: sent %q to a device that is not the one on the card", tc.name, sent)
					}
					out := e.outcomesOf()
					if len(out) != answered+1 || out[answered].Status != connector.StatusRefused || out[answered].Reason != tc.reason {
						t.Fatalf("%s: outcomes %+v, want one more refusal %s", tc.name, out[answered:], tc.reason)
					}
					if n := e.devices.asked() - reads; n != 1 {
						t.Fatalf("%s: %d device reads at dispatch, want one", tc.name, n)
					}
					// The approval is spent, and the principal is told once.
					// (One second tap per run: every tap counts against the
					// principal's rate window.)
					if i == 0 {
						_ = e.h.Press(alice, row.approve)
						if sent := e.ep.sent(); len(sent) != 0 || e.devices.asked()-reads != 1 {
							t.Fatalf("%s: a second tap: sent %q, %d reads", tc.name, sent, e.devices.asked()-reads)
						}
					}
					if n := notices() - told; n != 1 {
						t.Fatalf("%s: %d \"not carried out\" notices", tc.name, n)
					}
				}
				// An unchanged device is sent, after exactly one read.
				// Another device changing is not this one changing.
				e.speakers.set(testSpeakers(), nil)
				e.lights.set(testLights(), nil)
				row := e.emitTool(call[0], call[1])
				sp, li := testSpeakers(), testLights()
				sp[1].Name, li[1].Room = "Guest speaker", "Porch"
				e.speakers.set(sp, nil)
				e.lights.set(li, nil)
				reads := e.devices.asked()
				canonical, err := catalog.CanonicalArgs([]byte(call[1]))
				if err != nil {
					t.Fatal(err)
				}
				if got := e.press(alice, row.approve); got != "" {
					t.Fatalf("approve queued the reply %q", got)
				}
				if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != string(canonical) {
					t.Fatalf("sent %q, want %q once", sent, canonical)
				}
				if n := e.devices.asked() - reads; n != 1 {
					t.Fatalf("%d device reads for one dispatch", n)
				}
			})
		})
	}
}

// TestS2D2_DispatchNeedsADeviceReader: an executor with no device reader
// for the server sends no call that names a device, and still sends one
// that names none.
func TestS2D2_DispatchNeedsADeviceReader(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newPinnedDeviceEnv(t, s, func(c *connector.WriteConfig) { c.Devices = nil })
		for name, call := range deviceCalls() {
			row := e.emitTool(call[0], call[1])
			if code := e.h.Press(alice, row.approve); code != http.StatusOK {
				t.Fatalf("%s: approve: %d", name, code)
			}
			e.h.Loop().WaitDeliveries()
		}
		if sent := e.ep.sent(); len(sent) != 0 {
			t.Fatalf("sent %q with no device reader", sent)
		}
		out := e.outcomesOf()
		if len(out) != len(deviceCalls()) {
			t.Fatalf("outcomes %+v", out)
		}
		for _, o := range out {
			if o.Status != connector.StatusRefused || o.Reason != connector.ReasonNoWritePath {
				t.Fatalf("outcome %+v", o)
			}
		}
	})
}

// TestS2D5_LoweredDispatchReadsTheDeviceAgain: a write a standing
// permission covers has no card, and the executor still reads the device
// list itself right before it sends. A device that changed between the
// emitter's read and that one, or a list that cannot be read, means
// nothing is sent; so does a target the caller did not hand over or one
// that is not the device the bytes name.
func TestS2D5_LoweredDispatchReadsTheDeviceAgain(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newLowerEnv(t, s)
		e.grant("prm_vol", volumeTool, 5, kitchenID)
		e.grant("prm_light", lightTool, permissions.NoCeiling, deskLampID)
		short := map[string]bool{}
		for _, tc := range someChangedDevices() {
			short[tc.name] = true
		}
		for _, tc := range changedDevices() {
			for _, call := range [][2]string{
				{volumeTool, volume5},
				{lightTool, `{"brightness":40,"device":"` + deskLampID + `"}`},
			} {
				// Every change for the volume, the short list for the light.
				if call[0] == lightTool && !short[tc.name] {
					continue
				}
				name := call[0] + " " + tc.name
				e.speakers.set(testSpeakers(), nil)
				e.lights.set(testLights(), nil)
				// The device changes after the emitter read it and before
				// the executor does.
				e.devices.between(func() { tc.change(e.deviceWriteEnv) })
				before, handed := e.devices.asked(), len(e.hook.outcomes())
				e.freshCalls()
				a := e.call(e.token, toolCall(call[0], call[1]))
				e.h.Loop().WaitDeliveries()
				e.devices.between(nil)
				if a.code == http.StatusOK && a.Status == "ok" {
					t.Fatalf("%s: answered %+v", name, a)
				}
				e.nothingSent(name)
				outs := e.hook.outcomes()
				if len(outs) != handed+1 || outs[handed].Status != connector.StatusRefused || outs[handed].Reason != tc.reason {
					t.Fatalf("%s: outcomes %+v, want one refusal %s", name, outs[handed:], tc.reason)
				}
				if n := e.devices.asked() - before; n != 1 {
					t.Fatalf("%s: %d device reads at dispatch", name, n)
				}
				if n := len(e.sentCards(alice)); n != 0 {
					t.Fatalf("%s: %d cards", name, n)
				}
			}
		}
		// With the devices as they were, both calls are sent.
		e.speakers.set(testSpeakers(), nil)
		e.lights.set(testLights(), nil)
		e.lowered("the volume, unchanged", "prm_vol", volumeTool, volume5)
		e.lowered("the light, unchanged", "prm_light", lightTool, `{"brightness":40,"device":"`+deskLampID+`"}`)
	})
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newLowerEnv(t, s)
		e.grant("prm_vol", volumeTool, 5, kitchenID)
		good := e.loweredCall("prm_vol", volumeTool, volume5, catalog.ClassWrite)
		for name, target := range map[string][]byte{
			"no target":            nil,
			"an unreadable target": []byte(`{"device":`),
			"another device":       sealedDevice(bedroomID, "Bedroom speaker", "Bedroom", "Alice home", speakerType, "speaker", "device"),
			"a target of no kind":  sealedDevice(kitchenID, "Kitchen speaker", "Kitchen", "Alice home", speakerType, "", "device"),
			"a type the rule does not allow": sealedDevice(kitchenID, "Kitchen speaker", "Kitchen", "Alice home",
				"devices.types.thermostat", "speaker", "device"),
			"a type that only starts like a speaker's": sealedDevice(kitchenID, "Kitchen speaker", "Kitchen", "Alice home",
				"devices.types.smart_speakerphone", "speaker", "device"),
		} {
			call := good
			call.Target = target
			out := e.dispatchLowered(call)
			if out.Status != connector.StatusRefused || out.Reason != connector.ReasonNotLowerable || out.DispatchID != "" {
				t.Errorf("%s: %+v", name, out)
			}
		}
		e.nothingSent("lowered calls with a bad target")
		if n := e.devices.asked(); n != 0 {
			t.Fatalf("%d device reads for calls refused before anything is read", n)
		}
		// What the caller says it read is checked against the executor's
		// own read: a name the listing does not hold is a changed device.
		lied := good
		lied.Target = sealedDevice(kitchenID, "Another name", "Kitchen", "Alice home", speakerType, "speaker", "device")
		if out := e.dispatchLowered(lied); out.Status != connector.StatusRefused || out.Reason != connector.ReasonDeviceChanged {
			t.Fatalf("a target the listing does not hold: %+v", out)
		}
		e.nothingSent("a target the listing does not hold")
		if out := e.dispatchLowered(good); out.Status != connector.StatusOK {
			t.Fatalf("the granted call: %+v", out)
		}
		if n := e.devices.asked(); n != 2 {
			t.Fatalf("%d device reads for two dispatches", n)
		}
	})
}
