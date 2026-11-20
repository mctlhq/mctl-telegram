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
	"unicode/utf16"
	"unicode/utf8"
)

// MaxPartUTF16 is the Bot API limit on message text, in UTF-16 units. No
// part of a Text is longer.
const MaxPartUTF16 = 4096

// UTF16Len returns the length of s in UTF-16 units, the unit of the Bot API
// text limits.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		n += utf16.RuneLen(r)
	}
	return n
}

// split cuts s into parts of at most max UTF-16 units, never inside a rune,
// preferring the last newline, then the last space, in the second half of a
// part. Whitespace-only parts are dropped, as the Bot API refuses them.
// A cut can turn the tail of a token into a new token (4095 x "x" followed
// by "a1.2.3.4/..." leaves "1.2.3.4/..." in the next part), so Render
// neutralises every part again after splitting.
func split(s string, max int) []string {
	var parts []string
	for UTF16Len(s) > max {
		cut, n := 0, 0
		for i, r := range s {
			w := utf16.RuneLen(r)
			if n+w > max {
				break
			}
			n += w
			cut = i + utf8.RuneLen(r)
		}
		head := s[:cut]
		if i := strings.LastIndexByte(head, '\n'); i > cut/2 {
			cut = i + 1
		} else if i := strings.LastIndexByte(head, ' '); i > cut/2 {
			cut = i + 1
		}
		if strings.TrimSpace(s[:cut]) != "" {
			parts = append(parts, s[:cut])
		}
		s = s[cut:]
	}
	if strings.TrimSpace(s) != "" {
		parts = append(parts, s)
	}
	return parts
}
