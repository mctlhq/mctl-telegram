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

// alice_music.go is what an alice_play_music call must pass before it gets
// a card (#1322 slice P2-S14b, threat model T6).
//
// The tool starts music on one speaker from a short query. The server
// sends the speaker one text command, always its fixed words followed by
// the query as written (mctl-alice src/tools/music-query.ts:
// PLAY_MUSIC_PREFIX + query), through the capability an arbitrary voice
// command uses. What keeps it from being alice_send_command is the rule
// set the query must pass, so that rule set is held here too and applied
// before a card is made:
//
//   - the query passes musicQueryProblem, a port of the server's rule of
//     the same name. testdata/alice_music_queries.json holds the cases of
//     the server's own tests, and TestMusicQuery_AgreesWithUpstreamCases
//     runs them, so a rule changed on one side shows as a failing case;
//   - the pin caps the query at catalog.MaxMusicQuery characters, the
//     server's number; a pin with another cap has no card path;
//   - the target is the exact id of a speaker that a read made for the
//     card lists. A name, a room and an omitted device are refused;
//   - the arguments are device and query, both strings, and nothing else.
//
// Every check refuses. The query is never trimmed, normalised or
// rewritten: the bytes the principal approves are the bytes that are sent.
//
// The card shows the speaker, the query and the whole command. The fixed
// words are this file's copy of the server's constant: the pin binds the
// tool's schema, description and annotations, none of which state them.
// The copy is held to the server's rule file as it is at the commit the
// pin names (testdata/alice_music_query.ts, checked by
// TestS2D4_MusicRulesMatchThePinnedUpstream, #1322 P2-S15c): the fixed
// words, the numbers, the class of characters and both word lists. A
// server deployed from another commit than the pin names is not seen by
// that check, and one that changed only those words would send another
// command than the card shows (recorded as a gap of S2-D4).
//
// The tool is never lowered: no standing permission has a rule for it, the
// pin and catalog.IsNeverLowerable both say never, and Cards.Emit looks no
// permission up for it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

const (
	musicTool      = "alice_play_music"
	musicDeviceArg = "device"
	musicQueryArg  = "query"
	// musicCommandPrefix is the fixed start of the command the server
	// hands the speaker (PLAY_MUSIC_PREFIX). It is data, not prose.
	musicCommandPrefix = "включи музыку "
	// maxMusicQueryWords is the server's MAX_MUSIC_QUERY_WORDS.
	maxMusicQueryWords = 8
)

// ReasonQueryNotAllowed: the query of a music request is not one the
// server's rule set accepts.
const ReasonQueryNotAllowed = "query_not_allowed"

// The names the assistant answers to: whole words, compared in lower case
// with ё as е.
var musicWakeWords = map[string]bool{
	"алиса": true, "алису": true, "алисе": true, "алисой": true, "яндекс": true,
	"alice": true, "alisa": true, "alisu": true, "alise": true, "alisoy": true, "yandex": true, "yandeks": true,
}

// How a Russian request to the assistant starts: the stems of imperative
// verbs. A word that begins with one is refused, whatever its ending.
var musicCommandStems = []string{
	"включ", "выключ", "отключ", "подключ", "переключ", "вруб", "выруб",
	"откро", "откры", "закро", "закры", "заблокир", "разблокир",
	"купи", "закаж", "заказ", "оплат", "переведи", "перевест",
	"позвон", "набери", "вызов", "вызв", "отправ", "напиш", "скаж", "расскаж", "прочит",
	"установ", "постав", "запус", "останов", "удал", "сдела", "добав", "убав", "прибав",
	"напомн", "активир", "запомн", "отмен", "прекрат",
	"погас", "потуш", "зажг", "зажиг", "убер", "найди", "выйди",
	"стоп", "хватит", "громче", "тише",
	"заведи", "разбуди", "повтор", "пауз", "следующ", "предыдущ",
}

// isRussianLetter is the server's class [а-яёА-ЯЁ]: the Russian alphabet
// and no other Cyrillic letter.
func isRussianLetter(r rune) bool {
	return (r >= 'а' && r <= 'я') || (r >= 'А' && r <= 'Я') || r == 'ё' || r == 'Ё'
}

func isMusicMark(r rune) bool { return r == ' ' || r == '\'' || r == '&' || r == '-' }

// musicQueryProblem says why query is refused, or "" when it may be sent.
// It is the server's musicQueryProblem, check for check and in its order.
func musicQueryProblem(query string) string {
	if query == "" {
		return "empty"
	}
	if !utf8.ValidString(query) {
		return "not valid text"
	}
	// The server counts UTF-16 units first, then code points.
	units := 0
	for _, r := range query {
		units++
		if r > 0xFFFF {
			units++
		}
	}
	if units > catalog.MaxMusicQuery*2 || utf8.RuneCountInString(query) > catalog.MaxMusicQuery {
		return "too long"
	}
	for _, r := range query {
		switch {
		case unicode.Is(unicode.Latin, r), isRussianLetter(r), r >= '0' && r <= '9', isMusicMark(r):
		default:
			return "a character that is not allowed"
		}
	}
	if !norm.NFKC.IsNormalString(query) {
		return "not in composed form"
	}
	if strings.HasPrefix(query, " ") || strings.HasSuffix(query, " ") || strings.Contains(query, "  ") {
		return "spaces"
	}
	if !strings.ContainsFunc(query, func(r rune) bool { return unicode.IsLetter(r) || (r >= '0' && r <= '9') }) {
		return "no letter or digit"
	}
	words := strings.FieldsFunc(query, isMusicMark)
	if len(words) > maxMusicQueryWords {
		return "too many words"
	}
	for _, w := range words {
		// One letter lowers differently in the server's runtime: the
		// dotted capital I becomes "i" here and "i" with a combining dot
		// there. Here it can therefore complete a wake word the server
		// would not see, which only refuses more.
		lower := strings.ReplaceAll(strings.ToLower(w), "ё", "е")
		latin := strings.ContainsFunc(lower, func(r rune) bool { return unicode.Is(unicode.Latin, r) })
		cyrillic := strings.ContainsFunc(lower, isRussianLetter)
		if latin && cyrillic {
			return "a word mixes Latin and Cyrillic letters"
		}
		if musicWakeWords[lower] {
			return "the assistant's name"
		}
		for _, stem := range musicCommandStems {
			if strings.HasPrefix(lower, stem) {
				return "a command word"
			}
		}
	}
	return ""
}

// musicCall is a music request that passed the checks that need no server.
type musicCall struct {
	device, query string
}

// command is the whole text the speaker receives.
func (m musicCall) command() string { return musicCommandPrefix + m.query }

// musicArgs reads device and query from the canonical arguments. They are
// decoded to be read only: what is sealed and sent is the canonical bytes.
func musicArgs(canonical []byte) (call musicCall, hasDevice bool, err error) {
	var args map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &args); err != nil || args == nil {
		return call, false, errors.New("arguments are not an object")
	}
	for name := range args {
		if name != musicDeviceArg && name != musicQueryArg {
			return call, false, errors.New("an argument a music card cannot show")
		}
	}
	var ok bool
	if call.query, ok = stringArg(args, musicQueryArg); !ok {
		return call, false, errors.New("query is not a string")
	}
	if _, present := args[musicDeviceArg]; !present {
		return call, false, nil
	}
	if call.device, ok = stringArg(args, musicDeviceArg); !ok {
		return call, false, errors.New("device is not a string")
	}
	return call, true, nil
}

// precheckMusic runs the checks of a music request that read nothing but
// the call and the pin.
func precheckMusic(tool string, pinned catalog.PinnedTool, canonical []byte) (musicCall, *refusal) {
	if tool != musicTool || pinned.Class != catalog.ClassWrite || pinned.Lowerable != catalog.LowerableNever {
		return musicCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	// The pin's cap is the number the rule set below counts to. A pin
	// with another cap, or none, has no card path.
	if pinned.Constraints == nil || pinned.Constraints.TextCap[musicQueryArg] != catalog.MaxMusicQuery {
		return musicCall{}, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	call, hasDevice, err := musicArgs(canonical)
	if err != nil {
		return musicCall{}, &refusal{ReasonBadRequest, http.StatusBadRequest}
	}
	// Refused, never trimmed or rewritten: the server would refuse the
	// same query, and a query it would accept after a rewrite is not the
	// one on the card.
	if musicQueryProblem(call.query) != "" {
		return musicCall{}, &refusal{ReasonQueryNotAllowed, http.StatusUnprocessableEntity}
	}
	if !hasDevice || call.device == "" {
		return musicCall{}, &refusal{ReasonDeviceNotListed, http.StatusUnprocessableEntity}
	}
	return call, nil
}

// musicTarget reads the connection's speakers and returns what the card of
// call shows and the detail to seal with its arguments. The device must be
// the id of a listed speaker.
func (c *Cards) musicTarget(ctx context.Context, req CardRequest, call musicCall) (m safetext.Music, detail []byte, ref *refusal) {
	reader := c.cfg.Speakers[req.Server]
	if reader == nil {
		return m, nil, &refusal{ReasonNoWritePath, http.StatusForbidden}
	}
	target, ref := listedSpeaker(ctx, reader, req, call.device)
	if ref != nil {
		return m, nil, ref
	}
	detail, err := json.Marshal(cardDetail{Speaker: target})
	if err != nil {
		return m, nil, &refusal{ReasonInternal, http.StatusInternalServerError}
	}
	return safetext.Music{
		Home: target.Home, Room: target.Room, Name: target.Name, ID: target.ID,
		Query: call.query, Command: call.command(),
	}, detail, nil
}

// musicOf rebuilds what a music card shows from the approval's sealed
// arguments and detail. The query and the device id come from the
// arguments, the bytes the executor sends, through the checks the card was
// made under; the detail must name the same device.
func musicOf(tool string, pinned catalog.PinnedTool, args, detail []byte) (safetext.Music, error) {
	call, ref := precheckMusic(tool, pinned, args)
	if ref != nil {
		return safetext.Music{}, errors.New("pa card: music arguments unreadable")
	}
	var cd cardDetail
	dec := json.NewDecoder(strings.NewReader(string(detail)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cd); err != nil || cd.Speaker == nil || cd.Scenario != nil {
		return safetext.Music{}, errors.New("pa card: music detail unreadable")
	}
	if cd.Speaker.ID != call.device || cd.Speaker.Name == "" || cd.Speaker.Kind != detailKindSpeaker {
		return safetext.Music{}, errors.New("pa card: music detail does not match the arguments")
	}
	return safetext.Music{
		Home: cd.Speaker.Home, Room: cd.Speaker.Room, Name: cd.Speaker.Name, ID: call.device,
		Query: call.query, Command: call.command(),
	}, nil
}
