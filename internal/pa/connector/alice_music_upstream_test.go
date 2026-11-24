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
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// The music rules of alice_music.go are a copy of the server's, and the
// catalog pin does not cover them: it hashes the tool's schema,
// description and annotations, and none of those state the fixed words of
// the command or the word lists (#1322 P2-S15c; S2-D4). What covers them
// is the file below: the server's rule file as it is at the commit the pin
// names, kept whole.
const (
	// musicUpstreamFile is src/tools/music-query.ts of mctlhq/mctl-alice
	// at musicUpstreamCommit, byte for byte.
	musicUpstreamFile = "testdata/alice_music_query.ts"
	// musicUpstreamCommit is the commit the snapshot was taken at. It
	// must be the one the Phase 2 pin names for the alice server, so a
	// pin moved to another commit fails here until the snapshot is taken
	// again and the port re-read against it.
	musicUpstreamCommit = "5f6755b7ae9e8764952dad4e5cb7eaabc78ca48c"
	// musicUpstreamSHA256 is the snapshot's digest. The rule function
	// itself cannot be compared with its port by a program; a snapshot
	// that changes in any byte fails here, and whoever updates this
	// number re-reads musicQueryProblem against the new file.
	musicUpstreamSHA256 = "ac41a9ec80259ca52af202278c13d4f8bed326dbdf86f7d0b023843d42dbbd19"
	// musicUpstreamClass is the server's class of a query's characters,
	// the one isRussianLetter, isMusicMark and the Latin script check
	// implement by hand; musicUpstreamSplit is how it splits words.
	musicUpstreamClass = `/^[\p{Script=Latin}а-яёА-ЯЁ0-9 '&-]+$/u`
	musicUpstreamSplit = `query.split(/[ '&-]+/u)`
)

// upstreamMusic is what the snapshot declares. A declaration that cannot
// be found fails the test: "could not read" is never "equal".
type upstreamMusic struct {
	maxLength, maxWords int
	prefix, class       string
	wakeWords, stems    []string
}

func readUpstreamMusic(t *testing.T) (upstreamMusic, []byte) {
	t.Helper()
	raw, err := os.ReadFile(musicUpstreamFile)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	one := func(what, pattern string) string {
		t.Helper()
		m := regexp.MustCompile(pattern).FindAllStringSubmatch(src, -1)
		if len(m) != 1 {
			t.Fatalf("the snapshot declares %s %d times, want once", what, len(m))
		}
		return m[0][1]
	}
	number := func(what, name string) int {
		t.Helper()
		n, err := strconv.Atoi(one(what, `(?m)^export const `+name+` = ([0-9]+);$`))
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return n
	}
	// The strings of a list literal: every element is a plain quoted
	// word, and anything else in the literal fails.
	words := func(what, literal string) []string {
		t.Helper()
		var out []string
		for _, el := range strings.Split(literal, ",") {
			el = strings.TrimSpace(el)
			if el == "" {
				continue
			}
			if !regexp.MustCompile(`^"[a-zа-яё]+"$`).MatchString(el) {
				t.Fatalf("%s: the element %s is not a plain word", what, el)
			}
			out = append(out, strings.Trim(el, `"`))
		}
		if len(out) == 0 {
			t.Fatalf("%s: no element", what)
		}
		return out
	}
	u := upstreamMusic{
		maxLength: number("the longest query", "MAX_MUSIC_QUERY_LENGTH"),
		maxWords:  number("the most words", "MAX_MUSIC_QUERY_WORDS"),
		prefix:    one("the command prefix", `(?m)^export const PLAY_MUSIC_PREFIX = "([^"\\]*)";$`),
		class:     one("the allowed class", `(?m)^const ALLOWED_QUERY = (.+);$`),
		wakeWords: words("the wake words", one("the wake words", `(?m)^const WAKE_WORDS = new Set\(\[([^\]]*)\]\);$`)),
		stems:     words("the command stems", one("the command stems", `(?s)\nconst COMMAND_STEMS = \[\n(.*?)\n\];\n`)),
	}
	return u, raw
}

// TestS2D4_MusicRulesMatchThePinnedUpstream (#1322 P2-S15c) runs with
// every test in CI. The snapshot is the server's rule file at the commit
// the pin names, unchanged since it was taken; and the fixed words of the
// command, the two numbers, the class of characters, the wake words and
// the command stems of alice_music.go are the ones that file declares.
func TestS2D4_MusicRulesMatchThePinnedUpstream(t *testing.T) {
	u, raw := readUpstreamMusic(t)

	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	if up := p2.Servers[aliceServer].Upstream; !strings.HasPrefix(up, "mctlhq/mctl-alice@"+musicUpstreamCommit+" ") {
		t.Errorf("the pin's alice upstream is %q: the music snapshot is of %s; take %s again at the pin's commit and re-read the port", up, musicUpstreamCommit, musicUpstreamFile)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != musicUpstreamSHA256 {
		t.Errorf("%s has the digest %s, not the recorded %s: re-read musicQueryProblem against the file before recording a new digest", musicUpstreamFile, got, musicUpstreamSHA256)
	}
	if c := loadMusicCases(t); !strings.Contains(c.Source, " at "+musicUpstreamCommit[:8]+" ") {
		t.Errorf("the cases are from %q, not from %s", c.Source, musicUpstreamCommit[:8])
	}

	if u.prefix != musicCommandPrefix {
		t.Errorf("the command starts with %q upstream and with %q here", u.prefix, musicCommandPrefix)
	}
	if u.maxLength != catalog.MaxMusicQuery || u.maxWords != maxMusicQueryWords {
		t.Errorf("upstream allows %d characters and %d words, this build %d and %d", u.maxLength, u.maxWords, catalog.MaxMusicQuery, maxMusicQueryWords)
	}
	if u.class != musicUpstreamClass || strings.Count(string(raw), musicUpstreamSplit) != 1 {
		t.Errorf("upstream's class of characters is %s, or its word split is not %s: the port implements %s", u.class, musicUpstreamSplit, musicUpstreamClass)
	}
	ours := slices.Sorted(maps.Keys(musicWakeWords))
	theirs := slices.Clone(u.wakeWords)
	slices.Sort(theirs)
	if !slices.Equal(ours, theirs) || len(u.wakeWords) != len(musicWakeWords) {
		t.Errorf("wake words:\n here     %q\n upstream %q", ours, theirs)
	}
	for w, on := range musicWakeWords {
		if !on {
			t.Errorf("the wake word %q is switched off", w)
		}
	}
	if !slices.Equal(musicCommandStems, u.stems) {
		t.Errorf("command stems:\n here     %q\n upstream %q", musicCommandStems, u.stems)
	}
}
