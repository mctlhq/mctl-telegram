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

// Package catalog is the Personal Assistant's catalog pin (threat model T8,
// invariant I7; issue #1315).
//
// The pin is a committed file, pin.json, that lists per catalog server the
// tools the assistant may call. Each entry records the tool's name, its input
// schema and the schema's hash, the hash of the server's description, the
// server's annotations, and the catalog's own policy for the tool: tier,
// class, lowerable and the catalog-authored description the model is shown.
//
// A live tools/list is compared with the pin by Pin.Observe:
//
//   - a tool that is new, renamed or changed (schema, description or
//     annotations) is denied, and every other pinned tool keeps working;
//   - a failed or malformed tools/list makes the whole server unavailable.
//     It is an error state, never an empty tool set (I9);
//   - a tool outside the pin is refused even when the model names it;
//   - the model receives the catalog's descriptions and the pinned schemas,
//     never the server's tool descriptions, which are only hashed. The
//     property descriptions inside a pinned input_schema are server-authored
//     text, but they are committed in pin.json, reviewed there, and any
//     change to them changes the schema hash and denies the tool.
//
// Only name, description, inputSchema and annotations are compared. A
// tool's title, outputSchema and _meta are not, because none of them is
// given to the model or used by the executor.
//
// The pin is regenerated from its upstream sources with
//
//	go test ./internal/pa/catalog -run TestPinMatchesUpstream -update-pin
//
// which rewrites the server-derived fields and keeps the hand-authored ones,
// so a change to a pinned tool fails CI until the pin is updated in a
// reviewed diff, the same way ADR 0007's tool surface snapshot works.
//
// Nothing in this package performs I/O at run time other than reading the
// embedded pin. Nothing calls it from server startup yet.
package catalog
