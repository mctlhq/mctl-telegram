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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// canonicalJSON re-encodes a JSON value so that two encodings of the same
// value compare equal: object keys sorted (encoding/json sorts map keys),
// insignificant whitespace removed, numbers kept as their literal text,
// no HTML escaping. It
// refuses trailing data and anything that is not a single JSON value.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	// Only a clean EOF ends the input. A closing bracket or any other
	// token after the value makes Token return a syntax error, which is
	// trailing data too.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// canonicalObject is canonicalJSON restricted to a JSON object.
func canonicalObject(raw []byte) ([]byte, error) {
	c, err := canonicalJSON(raw)
	if err != nil {
		return nil, err
	}
	if len(c) == 0 || c[0] != '{' {
		return nil, fmt.Errorf("want a JSON object, got %.20q", c)
	}
	return c, nil
}

// ErrInvalidArgs is wrapped by every CanonicalArgs failure.
var ErrInvalidArgs = errors.New("pa catalog: invalid tool arguments")

// CanonicalArgs returns the canonical encoding of a tool call's arguments,
// the form an approval binds (threat model T6, T7) and the executor sends.
// It is canonicalObject with the ambiguities that would let two different
// inputs share one hash refused instead of resolved:
//
//   - a duplicate object key, at any depth, including keys that differ
//     only in case (encoding/json keeps the last one silently and matches
//     struct fields case-insensitively, so {"a":1,"a":2} and {"a":2} would
//     hash the same while a reader of the first sees a 1, and a Go
//     receiver would merge {"level":1,"Level":10});
//   - a number that does not fit a finite float64 (1e999), which a
//     receiver cannot represent as the value the card showed;
//   - invalid UTF-8 or an escape that decodes to U+FFFD (a lone surrogate),
//     which encoding/json replaces silently;
//   - anything but exactly one JSON object.
func CanonicalArgs(raw []byte) ([]byte, error) {
	if err := strictJSON(raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgs, err)
	}
	c, err := canonicalObject(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArgs, err)
	}
	return c, nil
}

// CanonicalArgsSHA256 is the hex SHA-256 of CanonicalArgs(raw).
func CanonicalArgsSHA256(raw []byte) (string, error) {
	c, err := CanonicalArgs(raw)
	if err != nil {
		return "", err
	}
	return sha256Hex(c), nil
}

// strictJSON checks that raw is exactly one JSON value with no duplicate
// object key (keys equal under case folding count as duplicates), no
// non-finite number and no replaced character. It only
// checks; canonicalJSON encodes.
func strictJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := strictValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

func strictValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return errors.New("object key is not a string")
				}
				if err := strictString(key); err != nil {
					return err
				}
				// encoding/json matches a struct field to a key
				// case-insensitively and keeps the last match, so
				// "lowerable" and "Lowerable" are one field to a decoder
				// and two keys to a reader: refuse them as duplicates.
				fk := foldKey(key)
				if _, dup := seen[fk]; dup {
					return fmt.Errorf("duplicate key %.40q", key)
				}
				seen[fk] = struct{}{}
				if err := strictValue(dec); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := strictValue(dec); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected %v", v)
		}
		// The closing delimiter; Token checks that it matches.
		if _, err := dec.Token(); err != nil {
			return err
		}
	case string:
		return strictString(v)
	case json.Number:
		f, err := strconv.ParseFloat(v.String(), 64)
		if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
			return fmt.Errorf("number %.40s is not a finite float64", v.String())
		}
	case bool, nil:
	default:
		return fmt.Errorf("unexpected token %T", tok)
	}
	return nil
}

// foldKey maps s to one representative of its case-folding class: two
// strings have the same foldKey exactly when strings.EqualFold says they
// are equal. Each rune becomes the smallest rune of its unicode.SimpleFold
// orbit, the same fold encoding/json applies (its foldRune), which also
// catches the Kelvin sign and the long s, folded to K and S.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}

func strictString(s string) error {
	if !utf8.ValidString(s) || bytes.ContainsRune([]byte(s), utf8.RuneError) {
		return errors.New("string has an invalid or replaced character")
	}
	return nil
}

// canonicalAnnotations normalises an annotations value. A missing or null
// annotations field and an empty object mean the same thing, so all three
// canonicalise to "{}". Anything else must be an object.
func canonicalAnnotations(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []byte("{}"), nil
	}
	return canonicalObject(trimmed)
}

// sha256Hex is the hex SHA-256 of b.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
