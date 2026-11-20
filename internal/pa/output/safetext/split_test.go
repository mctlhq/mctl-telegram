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

package safetext

import (
	"strings"
	"testing"
)

func TestSplit(t *testing.T) {
	s := strings.Repeat("a", 10) + "\n" + strings.Repeat("b", 10)
	got := split(s, 15)
	if len(got) != 2 || got[0] != strings.Repeat("a", 10)+"\n" || got[1] != strings.Repeat("b", 10) {
		t.Fatalf("got %q", got)
	}
	// A rune outside the BMP counts as two UTF-16 units and is never cut.
	emoji := strings.Repeat("\U0001F600", 5)
	for _, p := range split(emoji, 3) {
		if UTF16Len(p) > 3 || !strings.HasPrefix(p, "\U0001F600") {
			t.Fatalf("bad part %q", p)
		}
	}
}
