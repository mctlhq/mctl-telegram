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

package catalog

import (
	"errors"
	"testing"
)

// TestCanonicalArgsSHA256: two encodings of one value hash the same, and
// every input that is ambiguous or not one JSON object is an error, never a
// hash. An approval binds this hash (threat model T7), so an ambiguity here
// would let the card show one call and the executor send another.
func TestCanonicalArgsSHA256(t *testing.T) {
	a, err := CanonicalArgsSHA256([]byte(` { "b" : [1, {"y":"é","x":true}], "a":"<&>" } `))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalArgsSHA256([]byte(`{"a":"<&>","b":[1,{"x":true,"y":"é"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a != b || !sha256HexRE.MatchString(a) {
		t.Fatalf("equivalent encodings hash %s and %s", a, b)
	}
	c, err := CanonicalArgs([]byte(`{"b":1,"a":2}`))
	if err != nil || string(c) != `{"a":2,"b":1}` {
		t.Fatalf("CanonicalArgs = %s, %v", c, err)
	}
	// Keys that differ only in case are refused (below), but distinct keys
	// that merely share letters are not.
	if _, err := CanonicalArgs([]byte(`{"level":1,"levels":2}`)); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}
	if d, _ := CanonicalArgsSHA256([]byte(`{"a":1.0}`)); d == mustHash(t, `{"a":1}`) {
		t.Fatal("1.0 and 1 hash the same; the hash must bind the literal sent")
	}

	bad := map[string]string{
		"duplicate key":           `{"a":1,"a":2}`,
		"nested duplicate key":    `{"x":{"a":1,"a":1}}`,
		"duplicate key in array":  `{"x":[{"a":1},{"b":1,"b":2}]}`,
		"case variant key":        `{"level":1,"Level":10}`,
		"nested case variant key": `{"x":{"Device":"a","dEVICE":"b"}}`,
		"kelvin sign key":         `{"\u212aind":1,"kind":2}`,
		"long s key":              `{"\u017fcene":1,"scene":2}`,
		"array":                   `[{"a":1}]`,
		"number":                  `1`,
		"string":                  `"x"`,
		"null":                    `null`,
		"empty":                   ``,
		"overflow":                `{"a":1e999}`,
		"negative overflow":       `{"a":-1e999}`,
		"nested overflow":         `{"a":[1,2e400]}`,
		"invalid UTF-8":           "{\"a\":\"\xff\"}",
		"lone surrogate":          `{"a":"\ud800"}`,
		"lone surrogate in a key": `{"\udc00":1}`,
		"trailing data":           `{"a":1}{}`,
		"trailing bracket":        `{"a":1}]`,
		"malformed":               `{"a":}`,
	}
	for name, raw := range bad {
		t.Run(name, func(t *testing.T) {
			h, err := CanonicalArgsSHA256([]byte(raw))
			if !errors.Is(err, ErrInvalidArgs) || h != "" {
				t.Fatalf("CanonicalArgsSHA256(%q) = %q, %v; want ErrInvalidArgs", raw, h, err)
			}
		})
	}
}

func mustHash(t *testing.T, raw string) string {
	t.Helper()
	h, err := CanonicalArgsSHA256([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	return h
}
