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
	"encoding/json"
	"errors"
	"fmt"
)

// ErrMalformedListing is wrapped by every tools/list parse failure. A
// malformed listing is a failed read (I9): it never yields an empty or
// partial tool set.
var ErrMalformedListing = errors.New("pa catalog: malformed tools/list")

// liveTool is one tool of a live tools/list, reduced to what the pin
// compares. Everything here is untrusted server text.
type liveTool struct {
	descriptionSHA256 string
	inputSchemaSHA256 string
	annotations       []byte // canonical
}

// listing is a complete, parsed tools/list.
type listing struct {
	tools map[string]liveTool
}

// wirePage is the result object of one tools/list response.
type wirePage struct {
	Tools      *[]json.RawMessage `json:"tools"`
	NextCursor *string            `json:"nextCursor"`
}

type wireTool struct {
	Name        *string         `json:"name"`
	Description *string         `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations json.RawMessage `json:"annotations"`
}

// parseListing parses every page of one tools/list, in order. Each page is
// the JSON-RPC result object. The listing is complete only if every page but
// the last carries a nextCursor and the last carries none: a cut-off
// pagination is a failed read, not a shorter list.
//
// An empty "tools" array is the server's documented absence signal and
// parses to an empty listing; a missing or null "tools" is malformed.
func parseListing(pages [][]byte) (listing, error) {
	if len(pages) == 0 {
		return listing{}, fmt.Errorf("%w: no pages", ErrMalformedListing)
	}
	out := listing{tools: map[string]liveTool{}}
	for i, raw := range pages {
		var page wirePage
		if err := json.Unmarshal(bytes.TrimSpace(raw), &page); err != nil {
			return listing{}, fmt.Errorf("%w: page %d: %v", ErrMalformedListing, i, err)
		}
		if page.Tools == nil {
			return listing{}, fmt.Errorf("%w: page %d has no tools array", ErrMalformedListing, i)
		}
		last := i == len(pages)-1
		hasCursor := page.NextCursor != nil && *page.NextCursor != ""
		if last && hasCursor {
			return listing{}, fmt.Errorf("%w: last page has a nextCursor; listing incomplete", ErrMalformedListing)
		}
		if !last && !hasCursor {
			return listing{}, fmt.Errorf("%w: page %d ends the listing but more pages follow", ErrMalformedListing, i)
		}
		for j, rawTool := range *page.Tools {
			name, lt, err := parseTool(rawTool)
			if err != nil {
				return listing{}, fmt.Errorf("%w: page %d tool %d: %v", ErrMalformedListing, i, j, err)
			}
			if _, dup := out.tools[name]; dup {
				return listing{}, fmt.Errorf("%w: tool %q listed twice", ErrMalformedListing, name)
			}
			out.tools[name] = lt
		}
	}
	return out, nil
}

func parseTool(raw json.RawMessage) (string, liveTool, error) {
	var w wireTool
	if err := json.Unmarshal(raw, &w); err != nil {
		return "", liveTool{}, err
	}
	if w.Name == nil || *w.Name == "" {
		return "", liveTool{}, errors.New("tool without a name")
	}
	schema, err := canonicalObject(w.InputSchema)
	if err != nil {
		return "", liveTool{}, fmt.Errorf("inputSchema: %v", err)
	}
	ann, err := canonicalAnnotations(w.Annotations)
	if err != nil {
		return "", liveTool{}, fmt.Errorf("annotations: %v", err)
	}
	desc := ""
	if w.Description != nil {
		desc = *w.Description
	}
	return *w.Name, liveTool{
		descriptionSHA256: sha256Hex([]byte(desc)),
		inputSchemaSHA256: sha256Hex(schema),
		annotations:       ann,
	}, nil
}
