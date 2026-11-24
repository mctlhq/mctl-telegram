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
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
)

// Synthetic speakers, in the text form alice_list_devices answers with.
const (
	spkKitchen = "- **Kitchen speaker** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)"
	spkBedroom = "- **Bedroom speaker** (Комната: Bedroom, ID: `spk-bedroom-0002`, Статус: offline)"
)

func aliceText(lines ...string) string {
	return "### Умный дом Яндекса\n\n" + strings.Join(lines, "\n") + "\n"
}

func aliceResult(t *testing.T, text string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type aliceEP struct {
	server string
	out    []byte
	err    error
	calls  []string
}

func (e *aliceEP) Server() string { return e.server }
func (e *aliceEP) ListTools(context.Context, connection.Secret) ([][]byte, error) {
	return nil, errors.New("not used")
}
func (e *aliceEP) CallTool(_ context.Context, _ connection.Secret, tool string, args json.RawMessage) ([]byte, error) {
	e.calls = append(e.calls, tool+" "+string(args))
	return e.out, e.err
}

func alicePin() *catalog.Pin {
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"alice": {Tools: map[string]catalog.PinnedTool{
		"alice_list_devices": {Tier: catalog.TierAuto, Class: catalog.ClassRead},
	}}}}
}

func TestAliceSpeakers_ReadsTheList(t *testing.T) {
	ep := &aliceEP{server: "alice", out: aliceResult(t, aliceText("**Колонки с Алисой (2):**", spkKitchen, spkBedroom, "", "**Комнаты:** Kitchen, Bedroom", "",
		"**Сценарии (1):**", "- Good night (ID: `scn-night-0000001`, активен)", "", "**Другие устройства (1):**", "- Lamp (Kitchen, тип: `devices.types.light`)"))}
	r, err := NewAliceSpeakers(alicePin(), ep)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Speakers(context.Background(), SpeakerRequest{Server: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	want := []Speaker{
		{ID: "spk-kitchen-0001", Name: "Kitchen speaker", Room: "Kitchen"},
		{ID: "spk-bedroom-0002", Name: "Bedroom speaker", Room: "Bedroom"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("speakers %+v, want %+v", got, want)
	}
	if !slices.Equal(ep.calls, []string{`alice_list_devices {"only_speakers":true}`}) {
		t.Fatalf("calls %v", ep.calls)
	}
	// The Phase 2 pin lists the tool the reader calls as an auto read.
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAliceSpeakers(p2, ep); err != nil {
		t.Fatalf("over the Phase 2 pin: %v", err)
	}
}

// TestAliceSpeakers_UnreadableIsAnError: a failed call and every result
// that is not exactly the known shape is ErrSpeakersUnreadable, never a
// shorter or an empty list.
func TestAliceSpeakers_UnreadableIsAnError(t *testing.T) {
	head := "**Колонки с Алисой (1):**"
	results := map[string][]byte{
		"empty":                []byte(``),
		"not an object":        []byte(`[]`),
		"null":                 []byte(`null`),
		"a tool error":         []byte(`{"isError":true,"content":[{"type":"text","text":"` + head + `\n` + spkKitchen + `"}]}`),
		"no content":           []byte(`{"content":[]}`),
		"two texts":            []byte(`{"content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]}`),
		"not a text":           []byte(`{"content":[{"type":"image","text":"a"}]}`),
		"a text that is a map": []byte(`{"content":[{"type":"text","text":{}}]}`),
		"no speaker list":      aliceResult(t, aliceText("**Другие устройства (1):**", spkKitchen)),
		"no speakers at all":   aliceResult(t, "Устройств не найдено."),
		"a count of zero":      aliceResult(t, aliceText("**Колонки с Алисой (0):**")),
		"fewer than counted":   aliceResult(t, aliceText("**Колонки с Алисой (2):**", spkKitchen)),
		"more than counted":    aliceResult(t, aliceText(head, spkKitchen, spkBedroom)),
		"two speaker lists":    aliceResult(t, aliceText(head, spkKitchen, "", head, spkBedroom)),
		"one id twice":         aliceResult(t, aliceText("**Колонки с Алисой (2):**", spkKitchen, spkKitchen)),
		"a line of other text": aliceResult(t, aliceText(head, "Kitchen speaker")),
		"no id":                aliceResult(t, aliceText(head, "- **Kitchen speaker** (Комната: Kitchen, Статус: online)")),
		"an id with a space":   aliceResult(t, aliceText(head, "- **Kitchen speaker** (Комната: Kitchen, ID: `spk kitchen 0001`, Статус: online)")),
		"a short id":           aliceResult(t, aliceText(head, "- **Kitchen speaker** (Комната: Kitchen, ID: `spk`, Статус: online)")),
		"no name":              aliceResult(t, aliceText(head, "- **** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)")),
		"no room":              aliceResult(t, aliceText(head, "- **Kitchen speaker** (Комната: , ID: `spk-kitchen-0001`, Статус: online)")),
		// A name that holds a field mark could move the id.
		"a name with an id mark":  aliceResult(t, aliceText(head, "- **Kitchen, ID: `spk-bedroom-0002`, Статус: x** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)")),
		"a room with a mark":      aliceResult(t, aliceText(head, "- **Kitchen speaker** (Комната: Kitchen** (Комната: Hall, ID: `spk-kitchen-0001`, Статус: online)")),
		"text before the list":    aliceResult(t, "x\n"+aliceText(head, spkKitchen)),
		"no title":                aliceResult(t, head+"\n"+spkKitchen),
		"a speaker after the end": aliceResult(t, aliceText(head, spkKitchen, "", spkBedroom)),
		"a second head later":     aliceResult(t, aliceText(head, spkKitchen, "", "**Колонки с Алисой (1):**")),
		// A name with line breaks: two speaker lines of its own making that
		// meet the count, then an empty line that ends the list before the
		// rest of its real line and the real second speaker. The first
		// forged line gives the bedroom speaker's id another room and name.
		"a name that ends the list early": aliceResult(t, aliceText("**Колонки с Алисой (2):**",
			"- **X** (Комната: Hall, ID: `spk-bedroom-0002`, Статус: on)",
			"- **Y** (Комната: Hall, ID: `spk-forged-0009`, Статус: on)",
			"",
			"Z** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)",
			spkBedroom)),
		// The same with the real second speaker lost: the tail of the real
		// first line alone gives it away.
		"a name that ends the list early, one speaker": aliceResult(t, aliceText(head,
			"- **X** (Комната: Hall, ID: `spk-forged-0009`, Статус: on)",
			"",
			"Z** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)")),
		// A name that holds a whole second line.
		"a name with a line": aliceResult(t, aliceText("**Колонки с Алисой (2):**", "- **Kitchen speaker** (Комната: Kitchen, ID: `spk-kitchen-0001`, Статус: online)\n"+spkBedroom+" x** (Комната: Hall, ID: `spk-hall-0000004`, Статус: online)")),
	}
	for name, out := range results {
		ep := &aliceEP{server: "alice", out: out}
		r, err := NewAliceSpeakers(alicePin(), ep)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Speakers(context.Background(), SpeakerRequest{Server: "alice"})
		if !errors.Is(err, ErrSpeakersUnreadable) || got != nil {
			t.Errorf("%s: %+v, %v; want ErrSpeakersUnreadable and no list", name, got, err)
		}
		if err != nil && (strings.Contains(err.Error(), "Kitchen") || strings.Contains(err.Error(), "spk-")) {
			t.Errorf("%s: the error quotes the result: %v", name, err)
		}
	}
	ep := &aliceEP{server: "alice", out: aliceResult(t, aliceText(head, spkKitchen)), err: errors.New("injected call failure")}
	r, err := NewAliceSpeakers(alicePin(), ep)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := r.Speakers(context.Background(), SpeakerRequest{Server: "alice"}); !errors.Is(err, ErrSpeakersUnreadable) || got != nil {
		t.Fatalf("a failed call: %+v, %v", got, err)
	}
	if got, err := r.Speakers(context.Background(), SpeakerRequest{Server: "tg"}); !errors.Is(err, ErrSpeakersUnreadable) || got != nil || len(ep.calls) != 1 {
		t.Fatalf("another server's request: %+v, %v, calls %v", got, err, ep.calls)
	}
}

func TestNewAliceSpeakers_NeedsThePinnedRead(t *testing.T) {
	write := alicePin()
	write.Servers["alice"].Tools["alice_list_devices"] = catalog.PinnedTool{Tier: catalog.TierApprove, Class: catalog.ClassWrite}
	for name, c := range map[string]struct {
		pin *catalog.Pin
		ep  MCPEndpoint
	}{
		"no pin":             {nil, &aliceEP{server: "alice"}},
		"no endpoint":        {alicePin(), nil},
		"another server":     {alicePin(), &aliceEP{server: "tg"}},
		"tool not pinned":    {&catalog.Pin{Servers: map[string]catalog.ServerPin{"alice": {}}}, &aliceEP{server: "alice"}},
		"tool is not a read": {write, &aliceEP{server: "alice"}},
	} {
		if r, err := NewAliceSpeakers(c.pin, c.ep); err == nil || r != nil {
			t.Errorf("%s: built a reader", name)
		}
	}
}
