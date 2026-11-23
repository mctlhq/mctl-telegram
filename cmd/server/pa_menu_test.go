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

package main

import (
	"slices"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa"
)

// The menu lists exactly the commands the server answers: the linking ones
// only when a linking flow runs, and every name is a real pa command.
func TestPAMenu(t *testing.T) {
	names := func(linking bool) []string {
		var out []string
		for _, c := range paMenu(linking) {
			out = append(out, "/"+c.Name)
		}
		return out
	}
	base := []string{pa.CommandNew, pa.CommandForget, pa.CommandConsent}
	if got := names(false); !slices.Equal(got, base) {
		t.Fatalf("menu without linking %v, want %v", got, base)
	}
	full := append(base, pa.CommandConnect, pa.CommandConnections, pa.CommandDisconnect)
	if got := names(true); !slices.Equal(got, full) {
		t.Fatalf("menu with linking %v, want %v", got, full)
	}
}
