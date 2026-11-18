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
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	if _, err := dec.Token(); err == nil {
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
