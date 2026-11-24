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
	"os"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// musicCases is testdata/alice_music_queries.json: the query cases of the
// server's own tests of alice_play_music, with the numbers and the fixed
// words those tests ran under.
type musicCases struct {
	Source        string `json:"source"`
	MaxLength     int    `json:"max_query_length"`
	MaxWords      int    `json:"max_query_words"`
	CommandPrefix string `json:"command_prefix"`
	Refused       []struct {
		Label, Query string
	} `json:"refused"`
	Accepted []struct {
		Label, Query string
	} `json:"accepted"`
}

func loadMusicCases(t *testing.T) musicCases {
	t.Helper()
	raw, err := os.ReadFile("testdata/alice_music_queries.json")
	if err != nil {
		t.Fatal(err)
	}
	var c musicCases
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		t.Fatal(err)
	}
	// A file that lost its cases would pass every loop below.
	if len(c.Refused) < 80 || len(c.Accepted) < 15 || c.Source == "" {
		t.Fatalf("%d refused and %d accepted cases from %q", len(c.Refused), len(c.Accepted), c.Source)
	}
	return c
}

func musicPinned(t *testing.T) catalog.PinnedTool {
	t.Helper()
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	pt, ok := p2.Servers[aliceServer].Tools[musicTool]
	if !ok {
		t.Fatal("the Phase 2 pin does not hold alice_play_music")
	}
	return pt
}

func musicJSON(t *testing.T, device, query string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"device": device, "query": query})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := catalog.CanonicalArgs(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

// TestMusicQuery_AgreesWithUpstreamCases: the rule set a query must pass
// here is the server's. Every query the server's tests refuse is refused
// here, before a card, and every query they accept is accepted, so a rule
// that changes on one side fails a case. The numbers and the fixed words
// are the server's too.
func TestMusicQuery_AgreesWithUpstreamCases(t *testing.T) {
	c := loadMusicCases(t)
	if c.MaxLength != catalog.MaxMusicQuery || c.MaxWords != maxMusicQueryWords || c.CommandPrefix != musicCommandPrefix {
		t.Fatalf("the server's numbers are %d characters, %d words and the prefix %q", c.MaxLength, c.MaxWords, c.CommandPrefix)
	}
	pinned := musicPinned(t)
	for _, tc := range c.Refused {
		if musicQueryProblem(tc.Query) == "" {
			t.Errorf("%s: %q is accepted; the server refuses it", tc.Label, tc.Query)
		}
		if _, ref := precheckMusic(musicTool, pinned, musicJSON(t, "spk-kitchen-0001", tc.Query)); ref == nil ||
			ref.reason != ReasonQueryNotAllowed || ref.code != http.StatusUnprocessableEntity {
			t.Errorf("%s: %q: precheck %+v, want query_not_allowed", tc.Label, tc.Query, ref)
		}
	}
	for _, tc := range c.Accepted {
		if p := musicQueryProblem(tc.Query); p != "" {
			t.Errorf("%s: %q is refused (%s); the server accepts it", tc.Label, tc.Query, p)
		}
		call, ref := precheckMusic(musicTool, pinned, musicJSON(t, "spk-kitchen-0001", tc.Query))
		if ref != nil {
			t.Errorf("%s: %q: precheck %+v", tc.Label, tc.Query, ref)
			continue
		}
		// Never trimmed or rewritten: the query read back is the query.
		if call.query != tc.Query || call.command() != c.CommandPrefix+tc.Query || call.device != "spk-kitchen-0001" {
			t.Errorf("%s: read back %+v", tc.Label, call)
		}
	}
}

// TestMusicQuery_RefusedClasses names one query of every class of refusal,
// so a class whose check is removed fails here by name.
func TestMusicQuery_RefusedClasses(t *testing.T) {
	for query, want := range map[string]string{
		"":                               "empty",
		"jazz\xff":                       "not valid text",
		strings.Repeat("a", 101):         "too long",
		strings.Repeat("\U0001d49c", 51): "a character that is not allowed",
		"jazz; stop":                     "a character that is not allowed",
		"джаз і блюз":                    "a character that is not allowed",
		"Beyoncé":                       "a character that is not allowed",
		" jazz":                          "spaces",
		"jazz ":                          "spaces",
		"smooth  jazz":                   "spaces",
		"-&'":                            "no letter or digit",
		"la la la la la la la la la":     "too many words",
		"la-la-la-la-la-la-la-la-la":     "too many words",
		"джаз и выkлючи свет":            "a word mixes Latin and Cyrillic letters",
		"джаз Алиса":                     "the assistant's name",
		"jazz YANDEX":                    "the assistant's name",
		"джаз и ВЫКЛЮЧИ свет":            "a command word",
		"джаз набёри маму":               "a command word",
	} {
		if got := musicQueryProblem(query); got != want {
			t.Errorf("%q: %q, want %q", query, got, want)
		}
	}
	// 100 astral letters are 200 UTF-16 units: refused for the letters,
	// and 101 of them for the length before the letters are looked at.
	if got := musicQueryProblem(strings.Repeat("\U0001d49c", 101)); got != "too long" {
		t.Errorf("101 astral letters: %q", got)
	}
	// A precomposed letter is in composed form and passes; a letter of
	// the Latin script that only has a compatibility form does not.
	if got := musicQueryProblem("Beyoncé"); got != "" {
		t.Errorf("a precomposed letter: %q", got)
	}
	if got := musicQueryProblem("ſong"); got != "not in composed form" {
		t.Errorf("a long s: %q", got)
	}
}

// TestMusicPrecheck_ArgumentsAndPin: only device and query, both strings;
// a missing or empty device is "not listed"; the pin must hold the tool as
// a write that is never lowered with the server's cap.
func TestMusicPrecheck_ArgumentsAndPin(t *testing.T) {
	pinned := musicPinned(t)
	if pinned.Tier != catalog.TierApprove || pinned.Class != catalog.ClassWrite || pinned.Lowerable != catalog.LowerableNever {
		t.Fatalf("pinned %+v", pinned)
	}
	for name, tc := range map[string]struct {
		args   string
		reason string
	}{
		"not an object":      {`[]`, ReasonBadRequest},
		"null":               {`null`, ReasonBadRequest},
		"no query":           {`{"device":"spk-kitchen-0001"}`, ReasonBadRequest},
		"a query number":     {`{"device":"spk-kitchen-0001","query":5}`, ReasonBadRequest},
		"a query list":       {`{"device":"spk-kitchen-0001","query":["jazz"]}`, ReasonBadRequest},
		"a device number":    {`{"device":5,"query":"jazz"}`, ReasonBadRequest},
		"a null device":      {`{"device":null,"query":"jazz"}`, ReasonBadRequest},
		"a command member":   {`{"command":"выключи свет","device":"spk-kitchen-0001","query":"jazz"}`, ReasonBadRequest},
		"a room member":      {`{"device":"spk-kitchen-0001","query":"jazz","room":"Kitchen"}`, ReasonBadRequest},
		"no device":          {`{"query":"jazz"}`, ReasonDeviceNotListed},
		"an empty device":    {`{"device":"","query":"jazz"}`, ReasonDeviceNotListed},
		"a refused query":    {`{"device":"spk-kitchen-0001","query":"jazz; stop"}`, ReasonQueryNotAllowed},
		"refused, no device": {`{"query":"jazz; stop"}`, ReasonQueryNotAllowed},
	} {
		if _, ref := precheckMusic(musicTool, pinned, []byte(tc.args)); ref == nil || ref.reason != tc.reason {
			t.Errorf("%s: %+v, want %s", name, ref, tc.reason)
		}
	}
	good := []byte(`{"device":"spk-kitchen-0001","query":"jazz"}`)
	if _, ref := precheckMusic(musicTool, pinned, good); ref != nil {
		t.Fatalf("the plain call: %+v", ref)
	}
	other := func(mutate func(*catalog.PinnedTool)) catalog.PinnedTool {
		pt := pinned
		c := *pinned.Constraints
		c.TextCap = map[string]int{}
		for k, v := range pinned.Constraints.TextCap {
			c.TextCap[k] = v
		}
		pt.Constraints = &c
		mutate(&pt)
		return pt
	}
	for name, pt := range map[string]catalog.PinnedTool{
		"a disclosure":      other(func(p *catalog.PinnedTool) { p.Class = catalog.ClassDisclosure }),
		"lowerable":         other(func(p *catalog.PinnedTool) { p.Lowerable = catalog.LowerableYes }),
		"unmarked":          other(func(p *catalog.PinnedTool) { p.Lowerable = "" }),
		"a cap of 200":      other(func(p *catalog.PinnedTool) { p.Constraints.TextCap[musicQueryArg] = 200 }),
		"no cap on a query": other(func(p *catalog.PinnedTool) { delete(p.Constraints.TextCap, musicQueryArg) }),
		"no constraints":    other(func(p *catalog.PinnedTool) { p.Constraints = nil }),
	} {
		if _, ref := precheckMusic(musicTool, pt, good); ref == nil || ref.reason != ReasonNoWritePath {
			t.Errorf("%s: %+v, want no_write_path", name, ref)
		}
	}
	if _, ref := precheckMusic("alice_send_command", pinned, good); ref == nil || ref.reason != ReasonNoWritePath {
		t.Errorf("another tool: %+v", ref)
	}
}
