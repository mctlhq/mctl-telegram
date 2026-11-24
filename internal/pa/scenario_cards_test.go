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

// Scenario cards (#1322 slice P2-S9): alice_trigger_scenario through the
// real tool route, card emitter, outbox, webhook and write executor. The
// tool is the Phase 2 pin's own entry, placed under the harness's one
// linked server ("tg"); the steps come from a fake ScenarioSteps reader,
// the only kind there is.
//
// Threat model row: S2-D6 (T6).

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const (
	scenarioTool = "alice_trigger_scenario"
	// A synthetic scenario id.
	nightID   = "scn-night-0000001"
	nightCall = `{"scenario":"` + nightID + `"}`
)

func nightScenario() connector.Scenario {
	return connector.Scenario{ID: nightID, Name: "Good night",
		Steps: []string{"Turn off Kitchen lamp", "Set Bedroom speaker volume to 2", "Lock the front door"}}
}

// fakeScenarios is a ScenarioSteps reader with a fixed answer.
type fakeScenarios struct {
	mu    sync.Mutex
	sc    connector.Scenario
	err   error
	asked []string
}

func (f *fakeScenarios) ScenarioSteps(_ context.Context, req connector.ScenarioRequest) (connector.Scenario, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, req.Scenario)
	if req.Token.Reveal() == "" || req.Server != "tg" || req.ConnectionID == "" || req.Principal != alice {
		return connector.Scenario{}, errors.New("fake: unexpected scenario request")
	}
	sc := f.sc
	sc.Steps = slices.Clone(sc.Steps)
	return sc, f.err
}

func (f *fakeScenarios) set(sc connector.Scenario, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sc, f.err = sc, err
}

func (f *fakeScenarios) reads() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.asked)
}

// scenarioFresh lists the scenario tool as the pin has it and counts the
// listings read.
type scenarioFresh struct {
	mu    sync.Mutex
	calls int
}

func (f *scenarioFresh) FreshTool(_ context.Context, req connector.FreshRequest) (connector.FreshTool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if req.Token.Reveal() == "" || req.Server != "tg" || req.Tool != scenarioTool {
		return connector.FreshTool{}, errors.New("fake: unexpected fresh request")
	}
	return connector.FreshTool{
		SchemaSHA: shaHex([]byte("schema")), DescriptionSHA: shaHex([]byte("description")),
		AnnotationSHA: shaHex([]byte("annotations")), Tier: catalog.TierApprove, Class: catalog.ClassWrite,
	}, nil
}

func (f *scenarioFresh) listed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// scenarioPin holds the Phase 2 pin's entry of the scenario tool,
// unchanged, under "tg".
func scenarioPin(t *testing.T) *catalog.Pin {
	t.Helper()
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := p2.Servers["alice"].Tools[scenarioTool]
	if !ok || pt.Class != catalog.ClassWrite || pt.Tier != catalog.TierApprove || pt.Lowerable != catalog.LowerableNever {
		t.Fatalf("the Phase 2 pin does not hold %s as an approve-tier write that is never lowerable: %+v", scenarioTool, pt)
	}
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"tg": {Tools: map[string]catalog.PinnedTool{
		"get_messages": {Tier: catalog.TierAuto, Class: catalog.ClassRead}, scenarioTool: pt,
	}}}}
}

type scenarioEnv struct {
	*disclosureEnv
	scenarios *fakeScenarios
	fresh     *scenarioFresh
}

// newScenarioEnv builds the card path with reader as the server's
// ScenarioSteps; a nil reader is the deployed shape: none.
func newScenarioEnv(t *testing.T, s *db.Store, reader *fakeScenarios) *scenarioEnv {
	t.Helper()
	fresh := &scenarioFresh{}
	return &scenarioEnv{
		disclosureEnv: &disclosureEnv{cardEnv: newCardEnvOn(t, s, scenarioPin(t), fresh, func(c *connector.CardConfig) {
			if reader != nil {
				c.Scenarios = map[string]connector.ScenarioSteps{"tg": reader}
			}
		})},
		scenarios: reader, fresh: fresh,
	}
}

func scenarioCardText(l safetext.Lang, args string, sc connector.Scenario) string {
	s := safetext.TextCardHead.In(l) + "\n\n" + safetext.TextCardAction.In(l) + "\n" + scenarioTool + " (tg)\n\n" +
		safetext.TextCardScenario.In(l) + "\n" +
		safetext.TextCardDeviceName.In(l) + " " + sc.Name + "\n" +
		safetext.TextCardScenarioID.In(l) + " " + sc.ID + "\n\n" +
		safetext.TextCardScenarioSteps.In(l)
	for i, step := range sc.Steps {
		s += "\n" + string(rune('1'+i)) + ". " + step
	}
	return s + "\n\n" + safetext.TextCardArgs.In(l) + "\n" + args + "\n\n" + safetext.TextCardFoot.In(l)
}

// TestS2D6_ScenarioCardShowsEveryStep is the first half of S2-D6: with a
// reader, the card lists the scenario and every step the read returned,
// and Approve runs exactly the approved call.
func TestS2D6_ScenarioCardShowsEveryStep(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		reader := &fakeScenarios{sc: nightScenario()}
		e := newScenarioEnv(t, s, reader)
		row := e.emitTool(scenarioTool, nightCall)
		e.noCalls()
		if !slices.Equal(reader.asked, []string{nightID}) {
			t.Fatalf("scenario reads %v", reader.asked)
		}
		cards := e.sentCards(alice)
		if len(cards) != 1 {
			t.Fatalf("%d cards: %+v", len(cards), e.h.MessagesTo(alice))
		}
		if want := scenarioCardText(safetext.LangEN, nightCall, nightScenario()); cards[0].Text != want {
			t.Fatalf("card:\n got %q\nwant %q", cards[0].Text, want)
		}
		lines := strings.Split(cards[0].Text, "\n")
		for _, want := range []string{"Name: Good night", "Scenario id: " + nightID,
			"1. Turn off Kitchen lamp", "2. Set Bedroom speaker volume to 2", "3. Lock the front door"} {
			if !slices.Contains(lines, want) {
				t.Errorf("no line of the card is %q", want)
			}
		}
		card, err := e.cards.RenderApprovalCard(context.Background(), alice, row.approve)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := card.Text.In(safetext.LangRU).String(), scenarioCardText(safetext.LangRU, nightCall, nightScenario()); got != want {
			t.Fatalf("Russian card:\n got %q\nwant %q", got, want)
		}
		// The steps are sealed with the arguments, not stored in the clear.
		var sealed []byte
		if err := s.DB.QueryRow(`SELECT sealed_args FROM pa_approvals WHERE principal = $1 AND id = $2`, alice, row.id).Scan(&sealed); err != nil {
			t.Fatal(err)
		}
		if len(sealed) == 0 || strings.Contains(string(sealed), "Kitchen") || strings.Contains(string(sealed), nightID) {
			t.Fatal("the scenario is readable in sealed_args")
		}
		if got := e.press(alice, row.approve); got != "" {
			t.Fatalf("approve queued the reply %q", got)
		}
		if sent := e.ep.sent(); len(sent) != 1 || string(sent[0]) != nightCall {
			t.Fatalf("sent %q, want %q", sent, nightCall)
		}
		// The most steps a card lists; one more is refused, not shortened.
		many := nightScenario()
		many.Steps = nil
		for range connector.MaxScenarioSteps {
			many.Steps = append(many.Steps, "Turn off Kitchen lamp")
		}
		reader.set(many, nil)
		e.emitTool(scenarioTool, nightCall)
		cards = e.sentCards(alice)
		if n := strings.Count(cards[len(cards)-1].Text, ". Turn off Kitchen lamp\n"); n != connector.MaxScenarioSteps {
			t.Fatalf("%d of %d steps on the card", n, connector.MaxScenarioSteps)
		}
	})
}

// TestS2D6_UnreadableScenarioIsRefused is the second half of S2-D6: a
// steps read that failed, or came back without steps or malformed, gives
// no card, no approval and no call. It is never a card without steps.
func TestS2D6_UnreadableScenarioIsRefused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		reader := &fakeScenarios{sc: nightScenario()}
		e := newScenarioEnv(t, s, reader)
		set := func(f func(*connector.Scenario)) connector.Scenario {
			sc := nightScenario()
			f(&sc)
			return sc
		}
		tooMany := set(func(sc *connector.Scenario) {
			for len(sc.Steps) <= connector.MaxScenarioSteps {
				sc.Steps = append(sc.Steps, "Turn off Kitchen lamp")
			}
		})
		unreadable := map[string]struct {
			sc  connector.Scenario
			err error
		}{
			"the read failed":              {connector.Scenario{}, errors.New("injected read failure")},
			"failed with a result":         {nightScenario(), connector.ErrScenarioUnreadable},
			"nothing returned":             {connector.Scenario{}, nil},
			"no steps":                     {set(func(sc *connector.Scenario) { sc.Steps = nil }), nil},
			"an empty step":                {set(func(sc *connector.Scenario) { sc.Steps[1] = "" }), nil},
			"a blank step":                 {set(func(sc *connector.Scenario) { sc.Steps[2] = "  " }), nil},
			"no name":                      {set(func(sc *connector.Scenario) { sc.Name = "" }), nil},
			"no id":                        {set(func(sc *connector.Scenario) { sc.ID = "" }), nil},
			"more steps than a card lists": {tooMany, nil},
		}
		for name, tc := range unreadable {
			reader.set(tc.sc, tc.err)
			e.refused(name, scenarioTool, nightCall, http.StatusServiceUnavailable, connector.ReasonScenarioUnreadable)
		}
		// Steps the card could not show as they are: no card either.
		reader.set(set(func(sc *connector.Scenario) { sc.Steps[0] = "Turn off Kitchen lamp\n2. Nothing else" }), nil)
		e.refused("a two-line step", scenarioTool, nightCall, http.StatusUnprocessableEntity, connector.ReasonCardUnshowable)
		// The scenario is named by its id only: the server matches a name
		// by substring, so the name could run another scenario later.
		reader.set(nightScenario(), nil)
		for name, arg := range map[string]string{"its name": "Good night", "a part of its name": "night", "the id in other case": strings.ToUpper(nightID)} {
			e.refused(name, scenarioTool, `{"scenario":"`+arg+`"}`, http.StatusUnprocessableEntity, connector.ReasonScenarioNotListed)
		}
		e.refused("no scenario", scenarioTool, `{}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("an empty scenario", scenarioTool, `{"scenario":""}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.refused("a scenario that is not a string", scenarioTool, `{"scenario":7}`, http.StatusBadRequest, connector.ReasonBadRequest)
		e.nothingWritten()
		e.noCalls()
		if cards := e.sentCards(alice); len(cards) != 0 {
			t.Fatalf("%d cards for refused scenarios", len(cards))
		}
	})
}

// TestS2D6_NoReaderRefusesBeforeAnythingIsRead: without a ScenarioSteps
// reader, which is every deployed configuration, the call is refused
// before the tool listing or anything else is read from the server.
func TestS2D6_NoReaderRefusesBeforeAnythingIsRead(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		e := newScenarioEnv(t, s, nil)
		for name, args := range map[string]string{"an id": nightCall, "a name": `{"scenario":"Good night"}`} {
			e.refused(name, scenarioTool, args, http.StatusForbidden, connector.ReasonNoWritePath)
		}
		e.nothingWritten()
		e.noCalls()
		if n := e.fresh.listed(); n != 0 {
			t.Fatalf("tools/list read %d times for a call that can get no card", n)
		}
		if cards := e.sentCards(alice); len(cards) != 0 {
			t.Fatalf("%d cards without a reader", len(cards))
		}
	})
}

// TestS2D6_ServiceScenariosAreNeverRun: a scenario whose name or id starts
// with "mctl-" is the service's own. It is refused with a reader and
// without one, by the name the call gives and by what the read returns.
func TestS2D6_ServiceScenariosAreNeverRun(t *testing.T) {
	forEachDialect(t, func(t *testing.T, s *db.Store) {
		reader := &fakeScenarios{sc: nightScenario()}
		for name, e := range map[string]*scenarioEnv{"with a reader": newScenarioEnv(t, s, reader), "without a reader": newScenarioEnv(t, sqliteStore(t), nil)} {
			for _, arg := range []string{"mctl-tts", "MCTL-Speech", " mctl-x", "mctl-"} {
				e.refused(name+": "+arg, scenarioTool, `{"scenario":"`+arg+`"}`, http.StatusForbidden, connector.ReasonScenarioReserved)
			}
			e.nothingWritten()
			if n := e.fresh.listed(); n != 0 {
				t.Fatalf("%s: tools/list read %d times", name, n)
			}
		}
		if n := reader.reads(); n != 0 {
			t.Fatalf("%d scenario reads for reserved names", n)
		}
		// An id that turns out to be one of the service's own scenarios.
		e := newScenarioEnv(t, sqliteStore(t), reader)
		for name, sc := range map[string]connector.Scenario{
			"a reserved name behind the id": {ID: nightID, Name: "mctl-tts", Steps: []string{"Say a phrase"}},
			"a reserved name in other case": {ID: nightID, Name: "Mctl-TTS", Steps: []string{"Say a phrase"}},
			"a reserved id behind a name":   {ID: "mctl-0001", Name: "Good night", Steps: []string{"Say a phrase"}},
		} {
			reader.set(sc, nil)
			e.refused(name, scenarioTool, nightCall, http.StatusForbidden, connector.ReasonScenarioReserved)
		}
		e.nothingWritten()
		e.noCalls()
	})
}
