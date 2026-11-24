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

import "github.com/mctlhq/mctl-telegram/internal/pa/catalog"

// CardPath reports whether a call of server/tool can end in a card with
// this configuration: the tool is approve-tier in the pin, a fresh surface
// is wired, and the reader its card needs exists. It follows Emit's own
// branches and reads nothing from a server.
//
// The wiring (#1320 slice P2-S14) asks it twice: at startup, where a tool
// it means to offer without a card path refuses the start, and for the
// tool set of a claim, so that a model is never offered a tool every call
// of which would be refused with ReasonNoWritePath.
func (c *Cards) CardPath(server, tool string) bool {
	if c == nil || c.cfg.Fresh == nil {
		return false
	}
	pinned, ok := c.approveTool(server, tool)
	if !ok {
		return false
	}
	if pinned.Class == catalog.ClassDisclosure {
		spec, known := disclosureTools[tool]
		// The one text cap every disclosure card is built for
		// (precheckDisclosure).
		capped := pinned.Constraints != nil && pinned.Constraints.TextCap[spec.textArg] == catalog.MaxDisclosureText
		return known && capped && c.cfg.Speakers[server] != nil
	}
	if pinned.Class != catalog.ClassWrite {
		return false
	}
	if _, ok := scenarioTools[tool]; ok {
		return c.cfg.Scenarios[server] != nil
	}
	if tool == musicTool {
		// Its own card (alice_music.go), built from the speaker read.
		return c.cfg.Speakers[server] != nil
	}
	if spec, ok := deviceWriteTools[tool]; ok {
		if spec.light {
			return c.cfg.Lights[server] != nil
		}
		return c.cfg.Speakers[server] != nil
	}
	// A Phase 2 write outside those tables has no card (Emit refuses it);
	// any other approve-tier write gets the plain card.
	return !catalog.Phase2Tool(tool)
}
