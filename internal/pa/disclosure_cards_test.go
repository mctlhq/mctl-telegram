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

// Disclosure cards (#1322 slice P2-S6): alice_say_phrase and
// alice_send_command through the real tool route, card emitter, outbox,
// webhook and write executor. The two tools are the Phase 2 pin's own
// entries, placed under the harness's one linked server ("tg"); the
// speakers come from a fake SpeakerReader.
//
// Threat model rows: S2-D2, S2-D3, S2-D4 (T6).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	sayTool     = "alice_say_phrase"
	commandTool = "alice_send_command"

	// Synthetic device ids and names.
	kitchenID  = "spk-kitchen-0001"
	bedroomID  = "spk-bedroom-0002"
	kitchenSay = `{"device":"` + kitchenID + `","phrase":"Dinner is ready"}`
)

func testSpeakers() []connector.Speaker {
	return []connector.Speaker{
		{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen", Home: "Alice home"},
		{ID: bedroomID, Name: "Bedroom speaker", Room: "Bedroom", Home: "Alice home"},
	}
}

// fakeSpeakers is a SpeakerReader with a fixed answer.
type fakeSpeakers struct {
	mu    sync.Mutex
	list  []connector.Speaker
	err   error
	calls int
}

func (f *fakeSpeakers) Speakers(_ context.Context, req connector.SpeakerRequest) ([]connector.Speaker, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if req.Token.Reveal() == "" || req.Server != "tg" || req.ConnectionID == "" || req.Principal != alice {
		return nil, errors.New("fake: unexpected speaker request")
	}
	return slices.Clone(f.list), f.err
}

func (f *fakeSpeakers) set(list []connector.Speaker, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.list, f.err = list, err
}

func (f *fakeSpeakers) asked() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// disclosureFresh lists the two disclosure tools as the pin has them.
type disclosureFresh struct{}

func (disclosureFresh) FreshTool(_ context.Context, req connector.FreshRequest) (connector.FreshTool, error) {
	if req.Token.Reveal() == "" || req.Server != "tg" || (req.Tool != sayTool && req.Tool != commandTool) {
		return connector.FreshTool{}, errors.New("fake: unexpected fresh request")
	}
	return connector.FreshTool{
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), Tier: catalog.TierApprove, Class: catalog.ClassDisclosure,
	}, nil
}

// disclosurePin holds the Phase 2 pin's entries of the two disclosure
// tools, unchanged, under "tg".
func disclosurePin(t *testing.T) *catalog.Pin {
	t.Helper()
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	tools := map[string]catalog.PinnedTool{"get_messages": {Tier: catalog.TierAuto, Class: catalog.ClassRead}}
	for _, name := range []string{sayTool, commandTool} {
		pt, ok := p2.Servers["alice"].Tools[name]
		if !ok || pt.Class != catalog.ClassDisclosure || pt.Tier != catalog.TierApprove || pt.Lowerable != catalog.LowerableNever {
			t.Fatalf("the Phase 2 pin does not hold %s as an approve-tier disclosure that is never lowerable: %+v", name, pt)
		}
		tools[name] = pt
	}
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"tg": {Tools: tools}}}
}

type disclosureEnv struct {
	*cardEnv
	speakers *fakeSpeakers
}

func newDisclosureEnv(t *testing.T, s *db.Store) *disclosureEnv {
	t.Helper()
	sp := &fakeSpeakers{list: testSpeakers()}
	return &disclosureEnv{
		cardEnv: newCardEnvOn(t, s, disclosurePin(t), disclosureFresh{}, func(c *connector.CardConfig) {
			c.Speakers = map[string]connector.SpeakerReader{"tg": sp}
		}),
		speakers: sp,
	}
}

func toolCall(tool, args string) string {
	return `{"server":"tg","tool":"` + tool + `","arguments":` + args + `}`
}

// freshCalls gives the run its whole call budget back: these tests make
// more calls than one run may, and the cap is not what they are about.
func (e *disclosureEnv) freshCalls() {
	e.t.Helper()
	if _, err := e.store.DB.Exec(`UPDATE pa_jobs SET tool_calls = 0 WHERE id = $1`, e.job); err != nil {
		e.t.Fatal(err)
	}
}

// emitTool calls tool and returns the one pending approval it made.
func (e *disclosureEnv) emitTool(tool, args string) cardRow {
	e.t.Helper()
	e.freshCalls()
	had := map[string]bool{}
	for _, r := range e.approvals(alice) {
		had[r.id] = true
	}
	a := e.call(e.token, toolCall(tool, args))
	e.h.Loop().WaitDeliveries()
	if a.code != http.StatusOK || a.Status != connector.StatusApprovalPending {
		e.t.Fatalf("answer %+v", a)
	}
	var made []cardRow
	for _, r := range e.approvals(alice) {
		if !had[r.id] {
			made = append(made, r)
		}
	}
	if len(made) != 1 || made[0].status != "pending" {
		e.t.Fatalf("approvals made by the call: %+v", made)
	}
	return made[0]
}

// refused asserts the call is refused with code and reason.
func (e *disclosureEnv) refused(name, tool, args string, code int, reason string) {
	e.t.Helper()
	e.freshCalls()
	if a := e.call(e.token, toolCall(tool, args)); a.code != code || a.Stop != reason {
		e.t.Fatalf("%s: answer %+v, want %d %s", name, a, code, reason)
	}
}

func (e *disclosureEnv) splitOffers() []string {
	e.h.Loop().WaitDeliveries()
	return e.strings(`SELECT status FROM pa_outbox WHERE kind = 'disclosure_too_long' ORDER BY id`)
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// disclosureCardText is the card of a say_phrase or send_command call, as
// safetext.DisclosureCard lays it out.
func disclosureCardText(l safetext.Lang, tool, args string, sp connector.Speaker, text string) string {
	home := sp.Home
	if home == "" {
		home = safetext.TextCardHomeUnknown.In(l)
	}
	s := safetext.TextCardHead.In(l) + "\n\n" + safetext.TextCardAction.In(l) + "\n" + tool + " (tg)\n\n" +
		safetext.TextCardSpeaker.In(l) + "\n" +
		safetext.TextCardHome.In(l) + " " + home + "\n" +
		safetext.TextCardRoom.In(l) + " " + sp.Room + "\n" +
		safetext.TextCardDeviceName.In(l) + " " + sp.Name + "\n" +
		safetext.TextCardDeviceID.In(l) + " " + sp.ID + "\n\n"
	if tool == sayTool {
		s += safetext.TextCardPhrase.In(l) + "\n" + text + "\n\n" + safetext.TextCardRoomWarning.In(l) + "\n\n"
	} else {
		s += safetext.TextCardCommand.In(l) + "\n" + text + "\n\n"
	}
	return s + safetext.TextCardArgs.In(l) + "\n" + args + "\n\n" + safetext.TextCardFoot.In(l)
}

// TestS2D4_CardShowsTheWholeTextAndTheSpeaker is S2-D4: the card of a
// disclosure holds the whole text, verbatim, on a line of its own, and
// the speaker's home, room, name and device id as the fresh read gave
// them; a phrase that is said aloud carries the room warning.
func TestS2D4_CardShowsTheWholeTextAndTheSpeaker(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDisclosureEnv(t, s)
		e.manyCardsPerRun()
		kitchen := testSpeakers()[0]
		// A long text with punctuation, quotes and Cyrillic: nothing of
		// it may be cut, escaped or rewritten on its own line.
		text := strings.Repeat("Ужин готов, все к столу! ", 30) + `He said "now" & left <5 min ago`
		args := `{"device":"` + kitchenID + `","phrase":"` + strings.ReplaceAll(text, `"`, `\"`) + `"}`
		row := e.emitTool(sayTool, args)
		e.noCalls()
		if n := e.speakers.asked(); n != 1 {
			t.Fatalf("%d speaker reads for one card", n)
		}
		cards := e.sentCards(alice)
		if len(cards) != 1 {
			t.Fatalf("%d cards: %+v", len(cards), e.h.MessagesTo(alice))
		}
		if want := disclosureCardText(safetext.LangEN, sayTool, args, kitchen, text); cards[0].Text != want {
			t.Fatalf("card:\n got %q\nwant %q", cards[0].Text, want)
		}
		lines := strings.Split(cards[0].Text, "\n")
		for _, want := range []string{text, "Home: Alice home", "Room: Kitchen", "Name: Kitchen speaker", "Device id: " + kitchenID,
			safetext.TextCardRoomWarning.String()} {
			if !slices.Contains(lines, want) {
				t.Errorf("no line of the card is %q", want)
			}
		}
		card, err := e.cards.RenderApprovalCard(context.Background(), alice, row.approve)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := card.Text.In(safetext.LangRU).String(), disclosureCardText(safetext.LangRU, sayTool, args, kitchen, text); got != want {
			t.Fatalf("Russian card:\n got %q\nwant %q", got, want)
		}
		// The speaker's names are sealed with the arguments, not stored
		// in the clear.
		var sealed []byte
		if err := s.DB.QueryRow(`SELECT sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if len(sealed) == 0 || strings.Contains(string(sealed), "Kitchen") || strings.Contains(string(sealed), kitchenID) {
			t.Fatal("the speaker is readable in sealed_args")
		}

		// Approve: the call that is made carries the approved bytes.
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued the reply %q", got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != args {
			t.Fatalf("sent %q, want %q", sent, args)
		}

		// A command is not said aloud: the same card without the warning.
		cmd := `{"command":"включи джаз","device":"` + bedroomID + `"}`
		e.emitTool(commandTool, cmd)
		cards = e.sentCards(alice)
		if want := disclosureCardText(safetext.LangEN, commandTool, cmd, testSpeakers()[1], "включи джаз"); cards[len(cards)-1].Text != want {
			t.Fatalf("command card:\n got %q\nwant %q", cards[len(cards)-1].Text, want)
		}
		if strings.Contains(cards[len(cards)-1].Text, safetext.TextCardRoomWarning.String()) {
			t.Fatal("a command card warns about the room")
		}

		// A home the service does not report is shown as not reported.
		e.speakers.set([]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"}}, nil)
		e.emitTool(sayTool, kitchenSay)
		cards = e.sentCards(alice)
		if !slices.Contains(strings.Split(cards[len(cards)-1].Text, "\n"), "Home: "+safetext.TextCardHomeUnknown.String()) {
			t.Fatalf("card without a home:\n%s", cards[len(cards)-1].Text)
		}
	})
}

// TestS2D3_TextCapIsCountedInCharacters is S2-D3: a text of exactly 1000
// characters gets a card that shows all of it; one character more is
// refused before anything is read or written, and the principal is offered
// to send it in parts. The server never cuts or splits the text.
func TestS2D3_TextCapIsCountedInCharacters(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDisclosureEnv(t, s)
		say := func(text string) string { return `{"device":"` + kitchenID + `","phrase":"` + text + `"}` }
		// Cyrillic: 1000 characters are 2000 bytes.
		at := strings.Repeat("ж", catalog.MaxDisclosureText)
		over := at + "ж"

		e.refused("1001 characters", sayTool, say(over), http.StatusRequestEntityTooLarge, connector.ReasonTextTooLong)
		e.refused("1001 characters of a command", commandTool, `{"command":"`+over+`","device":"`+kitchenID+`"}`,
			http.StatusRequestEntityTooLarge, connector.ReasonTextTooLong)
		// Far over the cap is the same refusal, not "card too large".
		e.refused("5000 characters", sayTool, say(strings.Repeat("ж", 5000)), http.StatusRequestEntityTooLarge, connector.ReasonTextTooLong)
		e.nothingWritten()
		if n := e.speakers.asked(); n != 0 {
			t.Fatalf("%d speaker reads for refused calls", n)
		}
		// One offer for the run, however often it was refused.
		if got := e.splitOffers(); !slices.Equal(got, []string{"sent"}) {
			t.Fatalf("split offers %v, want one sent", got)
		}
		msgs := e.h.MessagesTo(alice)
		offers := 0
		for _, m := range msgs {
			if m.Text == safetext.TextDisclosureTooLong.String() {
				offers++
			}
			if strings.Contains(m.Text, "жжж") {
				t.Fatalf("a part of the refused text was sent: %q", m.Text)
			}
		}
		if offers != 1 {
			t.Fatalf("%d split offers among %+v", offers, msgs)
		}

		// Exactly at the cap: a card with every character.
		e.emitTool(sayTool, say(at))
		cards := e.sentCards(alice)
		if len(cards) != 1 || !slices.Contains(strings.Split(cards[0].Text, "\n"), at) {
			t.Fatalf("the 1000 character card: %d cards", len(cards))
		}
		if got := e.splitOffers(); len(got) != 1 {
			t.Fatalf("split offers after a card: %v", got)
		}
	})
}

// TestS2D2_TargetMustBeAListedDeviceID is the card half of S2-D2: a
// disclosure gets a card only for the id of a speaker the fresh read
// lists. A name, a room, an unlisted id and an omitted device are refused,
// so the server's name matching and default speaker are never reached.
func TestS2D2_TargetMustBeAListedDeviceID(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDisclosureEnv(t, s)
		for name, device := range map[string]string{
			"a speaker's name":      `"device":"Kitchen speaker",`,
			"a room":                `"device":"Kitchen",`,
			"a name in lower case":  `"device":"kitchen speaker",`,
			"an unlisted id":        `"device":"spk-garage-0009",`,
			"the id in other case":  `"device":"SPK-KITCHEN-0001",`,
			"the id with a space":   `"device":"` + kitchenID + ` ",`,
			"an empty device":       `"device":"",`,
			"no device (a default)": ``,
		} {
			e.refused(name, sayTool, `{`+device+`"phrase":"Dinner is ready"}`, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
			e.refused(name, commandTool, `{`+device+`"command":"play jazz"}`, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		}
		e.refused("a device that is not a string", sayTool, `{"device":7,"phrase":"x"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("a text that is not a string", sayTool, `{"device":"`+kitchenID+`","phrase":["x"]}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("no text", sayTool, `{"device":"`+kitchenID+`"}`, http.StatusBadRequest, connector.ReasonBadRequest)
		// A speaker named like another speaker's id does not make the name
		// a target.
		e.speakers.set([]connector.Speaker{
			{ID: kitchenID, Name: bedroomID, Room: "Kitchen"},
		}, nil)
		e.refused("an id that is only a name", sayTool, `{"device":"`+bedroomID+`","phrase":"x"}`, http.StatusUnprocessableEntity, connector.ReasonDeviceNotListed)
		e.nothingWritten()
	})
}

// TestS2D2_ApprovalBindsTextAndDevice is the dispatch half of S2-D2: the
// approval's hash covers the text and the device id, so arguments changed
// after the card (another text, another device, or no device, which the
// server would send to its default speaker) are refused and nothing is
// called.
func TestS2D2_ApprovalBindsTextAndDevice(t *testing.T) {
	changed := map[string]string{
		"another text":   `{"device":"` + kitchenID + `","phrase":"Dinner is cancelled"}`,
		"another device": `{"device":"` + bedroomID + `","phrase":"Dinner is ready"}`,
		"no device":      `{"phrase":"Dinner is ready"}`,
	}
	for name, other := range changed {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newDisclosureEnv(t, s)
				e.manyCardsPerRun()
				row := e.emitTool(sayTool, kitchenSay)
				bound := e.strings(`SELECT args_sha FROM pa_approvals WHERE id = $1`, row.id)
				if len(bound) != 1 || bound[0] != sha(kitchenSay) {
					t.Fatalf("the approval binds %v, want the hash of all of the arguments %s", bound, sha(kitchenSay))
				}
				// The stored arguments are replaced by a writer of the row
				// who holds the service key.
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
	// Two calls that differ only in the device are two different
	// approvals.
	e := newDisclosureEnv(t, sqliteStore(t))
	e.manyCardsPerRun()
	a := e.emitTool(sayTool, kitchenSay)
	b := e.emitTool(sayTool, `{"device":"`+bedroomID+`","phrase":"Dinner is ready"}`)
	hashes := e.strings(`SELECT args_sha FROM pa_approvals WHERE id IN ($1, $2)`, a.id, b.id)
	if len(hashes) != 2 || hashes[0] == hashes[1] {
		t.Fatalf("args_sha of two devices: %v", hashes)
	}
}

// TestDisclosure_OneCapForEveryTool: the notice of a refused text names
// the cap as a number, so the cap is that number for every disclosure
// tool: the Phase 2 pin holds it, and a pin with another cap gets no card.
func TestDisclosure_OneCapForEveryTool(t *testing.T) {
	limit := strconv.Itoa(catalog.MaxDisclosureText)
	for _, l := range []safetext.Lang{safetext.LangEN, safetext.LangRU} {
		if !strings.Contains(safetext.TextDisclosureTooLong.In(l), limit+" ") {
			t.Errorf("the notice does not name the cap of %s: %q", limit, safetext.TextDisclosureTooLong.In(l))
		}
	}
	pin := disclosurePin(t)
	for tool, arg := range map[string]string{sayTool: "phrase", commandTool: "command"} {
		if got := pin.Servers["tg"].Tools[tool].Constraints.TextCap[arg]; got != catalog.MaxDisclosureText {
			t.Errorf("the Phase 2 pin caps %s.%s at %d, the notice says %s", tool, arg, got, limit)
		}
	}
	// A lower cap in the pin: the notice would name the wrong number.
	low := pin.Servers["tg"].Tools[sayTool]
	c := *low.Constraints
	c.TextCap = map[string]int{"phrase": 500, "device": 200}
	low.Constraints = &c
	pin.Servers["tg"].Tools[sayTool] = low
	sp := &fakeSpeakers{list: testSpeakers()}
	e := &disclosureEnv{cardEnv: newCardEnvOn(t, sqliteStore(t), pin, disclosureFresh{}, func(c *connector.CardConfig) {
		c.Speakers = map[string]connector.SpeakerReader{"tg": sp}
	}), speakers: sp}
	e.refused("a cap of 500", sayTool, kitchenSay, http.StatusForbidden, connector.ReasonNoWritePath)
	e.refused("a cap of 500, long text", sayTool, `{"device":"`+kitchenID+`","phrase":"`+strings.Repeat("a", 700)+`"}`, http.StatusForbidden, connector.ReasonNoWritePath)
	e.nothingWritten()
	if got := e.splitOffers(); len(got) != 0 {
		t.Fatalf("split offers %v", got)
	}
}

// TestDisclosure_UnreadableSpeakersRefuse: a speaker read that failed, came
// back empty or cannot be trusted is a refusal of its own, never "no such
// device" and never a card; without a reader there is no card at all.
func TestDisclosure_UnreadableSpeakersRefuse(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDisclosureEnv(t, s)
		for name, tc := range map[string]struct {
			list []connector.Speaker
			err  error
		}{
			"the read failed":  {nil, errors.New("injected read failure")},
			"failed with data": {testSpeakers(), connector.ErrSpeakersUnreadable},
			"an empty list":    {nil, nil},
			"a nameless one":   {[]connector.Speaker{{ID: kitchenID, Room: "Kitchen"}}, nil},
			"a roomless one":   {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker"}}, nil},
			"one without an id": {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"},
				{Name: "Bedroom speaker", Room: "Bedroom"}}, nil},
			"one id twice": {[]connector.Speaker{{ID: kitchenID, Name: "Kitchen speaker", Room: "Kitchen"},
				{ID: kitchenID, Name: "Bedroom speaker", Room: "Bedroom"}}, nil},
		} {
			e.speakers.set(tc.list, tc.err)
			e.refused(name, sayTool, kitchenSay, http.StatusServiceUnavailable, connector.ReasonDevicesUnreadable)
		}
		e.nothingWritten()
	})
	e := &disclosureEnv{cardEnv: newCardEnvOn(t, sqliteStore(t), disclosurePin(t), disclosureFresh{})}
	e.refused("no speaker reader", sayTool, kitchenSay, http.StatusForbidden, connector.ReasonNoWritePath)
	e.nothingWritten()
}

// TestDisclosure_TextRefusals: text holding a link is refused (the Phase 2
// default), and so is text the card could not show exactly as it is sent.
func TestDisclosure_TextRefusals(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newDisclosureEnv(t, s)
		say := func(text string) string { return `{"device":"` + kitchenID + `","phrase":"` + text + `"}` }
		for name, text := range map[string]string{
			"a URL":              "open https://example.com/a?b=c now",
			"a bare domain":      "go to example.com",
			"a t.me link":        "see t.me/example_bot?start=x",
			"an e-mail address":  "write to carol@example.com",
			"a mention":          "ask @example_bot",
			"a tg scheme":        "tg://resolve?domain=example",
			"a punycode domain":  "visit xn--e1afmkfd.xn--p1ai",
			"a Cyrillic domain":  "зайди на пример.рф",
			"a URL in a command": "https://example.com",
		} {
			e.refused(name, sayTool, say(text), http.StatusUnprocessableEntity, connector.ReasonTextHasLink)
			e.refused(name, commandTool, `{"command":"`+text+`","device":"`+kitchenID+`"}`, http.StatusUnprocessableEntity, connector.ReasonTextHasLink)
		}
		if n := e.speakers.asked(); n != 0 {
			t.Fatalf("%d speaker reads for refused text", n)
		}
		for name, text := range map[string]string{
			"two lines":        `first\nsecond`,
			"a leading space":  ` Dinner is ready`,
			"a trailing space": `Dinner is ready `,
			"a zero width":     "Din​ner",
			"a defang mark":    "example[.]com",
		} {
			e.refused(name, sayTool, say(text), http.StatusUnprocessableEntity, connector.ReasonCardUnshowable)
		}
		// A speaker name the card cannot show exactly refuses the card too.
		e.speakers.set([]connector.Speaker{{ID: kitchenID, Name: "Kitchen\nHome: Bob home", Room: "Kitchen"}}, nil)
		e.refused("a two-line speaker name", sayTool, kitchenSay, http.StatusUnprocessableEntity, connector.ReasonCardUnshowable)
		e.nothingWritten()
		if got := e.splitOffers(); len(got) != 0 {
			t.Fatalf("split offers for other refusals: %v", got)
		}
		// Plain text with dots, colons and numbers is not a link.
		e.speakers.set(testSpeakers(), nil)
		e.emitTool(sayTool, say("Dinner at 19:30. Table for 2, version 2.0!"))
	})
}
