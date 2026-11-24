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

// alice_speakers.go reads a connection's speakers through the pinned read
// tool alice_list_devices (#1322 slice P2-S6). The tool answers with text
// written for a model, so the parse is of one exact shape and anything
// else is ErrSpeakersUnreadable: a device or room name is the account
// owner's text and could otherwise forge a line, an id or a count.
//
// The server reports no home, so Speaker.Home is always "" here and a card
// built from this reader says the home was not reported.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

const (
	aliceServer        = "alice"
	aliceListTool      = "alice_list_devices"
	aliceListArgs      = `{"only_speakers":true}`
	maxAliceSpeakers   = 64
	aliceSpeakerPrefix = "- **"
)

// The fixed parts of a speaker line, in order:
//
//   - **<name>** (Комната: <room>, ID: `<id>`, Статус: <state>)
//
// Each must occur exactly once in the line, so a name or a room that
// holds one of them makes the line unreadable instead of moving a field.
var aliceSpeakerMarks = []string{"** (Комната: ", ", ID: `", "`, Статус: "}

var (
	aliceSpeakersHead = regexp.MustCompile(`^\*\*Колонки с Алисой \((\d{1,3})\):\*\*$`)
	// aliceDeviceID is the shape of a device id: no space, no markup, and
	// nothing a name is likely to be.
	aliceDeviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{7,63}$`)
)

// AliceSpeakers is the SpeakerReader of the alice server.
type AliceSpeakers struct {
	ep MCPEndpoint
}

var _ SpeakerReader = (*AliceSpeakers)(nil)

// NewAliceSpeakers builds the reader over the alice endpoint. pin must
// list alice_list_devices as an auto-tier read: the reader calls nothing
// else.
func NewAliceSpeakers(pin *catalog.Pin, ep MCPEndpoint) (*AliceSpeakers, error) {
	if pin == nil || ep == nil || ep.Server() != aliceServer {
		return nil, errors.New("pa connector: alice speakers need the pin and the alice endpoint")
	}
	t, ok := pin.Servers[aliceServer].Tools[aliceListTool]
	if !ok || t.Tier != catalog.TierAuto || t.Class != catalog.ClassRead {
		return nil, fmt.Errorf("pa connector: %s is not a pinned auto read", aliceListTool)
	}
	return &AliceSpeakers{ep: ep}, nil
}

// Speakers implements SpeakerReader with one tools/call. It is not
// retried: a rejected token, a failed call and a tool error all refuse the
// card.
func (r *AliceSpeakers) Speakers(ctx context.Context, req SpeakerRequest) ([]Speaker, error) {
	if req.Server != aliceServer {
		return nil, fmt.Errorf("%w: not the alice server", ErrSpeakersUnreadable)
	}
	raw, err := r.ep.CallTool(ctx, req.Token, aliceListTool, json.RawMessage(aliceListArgs))
	if err != nil {
		return nil, fmt.Errorf("%w: %s failed", ErrSpeakersUnreadable, aliceListTool)
	}
	return parseAliceSpeakers(raw)
}

// parseAliceSpeakers reads an alice_list_devices tools/call result. Nothing
// of the result is quoted in an error.
func parseAliceSpeakers(raw []byte) ([]Speaker, error) {
	bad := func(what string) ([]Speaker, error) {
		return nil, fmt.Errorf("%w: %s", ErrSpeakersUnreadable, what)
	}
	var res struct {
		IsError *bool `json:"isError"`
		Content []struct {
			Type string           `json:"type"`
			Text *json.RawMessage `json:"text"`
		} `json:"content"`
	}
	if t := bytes.TrimSpace(raw); len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &res) != nil {
		return bad("result is not an object")
	}
	if res.IsError != nil && *res.IsError {
		return bad("tool error")
	}
	if len(res.Content) != 1 || res.Content[0].Type != "text" || res.Content[0].Text == nil {
		return bad("result is not one text")
	}
	var text string
	if t := *res.Content[0].Text; len(t) == 0 || t[0] != '"' || json.Unmarshal(t, &text) != nil {
		return bad("result is not one text")
	}
	lines := strings.Split(text, "\n")
	head, want := -1, 0
	for i, l := range lines {
		m := aliceSpeakersHead.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if head >= 0 {
			return bad("two speaker lists")
		}
		head = i
		want, _ = strconv.Atoi(m[1])
	}
	if head < 0 {
		return bad("no speaker list")
	}
	if want < 1 || want > maxAliceSpeakers {
		// No speaker is not a list a target can be in.
		return bad("speaker count")
	}
	var out []Speaker
	seen := map[string]bool{}
	for _, l := range lines[head+1:] {
		if l == "" {
			break
		}
		s, ok := parseAliceSpeakerLine(l)
		if !ok || seen[s.ID] {
			return bad("speaker line")
		}
		seen[s.ID] = true
		out = append(out, s)
	}
	// The server's own count: a line a name forged, or one it lost, shows.
	if len(out) != want {
		return bad("speaker count does not match the list")
	}
	return out, nil
}

func parseAliceSpeakerLine(l string) (Speaker, bool) {
	rest, ok := strings.CutPrefix(l, aliceSpeakerPrefix)
	if !ok || !strings.HasSuffix(rest, ")") {
		return Speaker{}, false
	}
	rest = strings.TrimSuffix(rest, ")")
	fields := make([]string, 0, len(aliceSpeakerMarks)+1)
	for _, mark := range aliceSpeakerMarks {
		if strings.Count(l, mark) != 1 {
			return Speaker{}, false
		}
		before, after, found := strings.Cut(rest, mark)
		if !found {
			return Speaker{}, false
		}
		fields = append(fields, before)
		rest = after
	}
	name, room, id := fields[0], fields[1], fields[2]
	if name == "" || room == "" || rest == "" || !aliceDeviceID.MatchString(id) {
		return Speaker{}, false
	}
	if strings.TrimSpace(name) != name || strings.TrimSpace(room) != room {
		return Speaker{}, false
	}
	return Speaker{ID: id, Name: name, Room: room}, true
}
