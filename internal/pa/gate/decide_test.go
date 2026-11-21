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

package gate

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

var errRead = errors.New("injected read error")

// open is an input every rule lets through to a lowering: writes on, the
// principal enabled, a lowerable write, a clean conversation and a matching
// standing permission.
func open() Input {
	return Input{
		Writes: true, Tool: "alice_set_light", Class: catalog.ClassWrite, Lowerable: catalog.LowerableYes,
		PermissionMatch: true,
	}
}

// TestDecideOrder is the order table of Decide: each row breaks exactly the
// rules it names on top of open(), and the first rule in order decides.
// Every branch has a row whose verdict changes when that branch is removed.
func TestDecideOrder(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Input)
		want Decision
	}{
		{"all clear lowers", func(*Input) {}, Decision{OutcomeLowered, ReasonPermission}},
		{"conditional lowers", func(in *Input) {
			in.Tool, in.Lowerable, in.ConditionMet = "alice_control_device", catalog.LowerableConditional, true
		},
			Decision{OutcomeLowered, ReasonPermission}},
		{"a yes write ignores the condition", func(in *Input) { in.ConditionMet, in.ConditionErr = false, errRead },
			Decision{OutcomeLowered, ReasonPermission}},

		// 1. writes
		{"writes off", func(in *Input) { in.Writes = false }, Decision{OutcomeNever, ReasonWritesOff}},
		{"writes unreadable", func(in *Input) { in.WritesErr = errRead }, Decision{OutcomeNever, ReasonWritesOff}},
		{"writes off beats a disabled principal", func(in *Input) { in.Writes, in.PrincipalDisabled = false, true },
			Decision{OutcomeNever, ReasonWritesOff}},
		{"writes off beats a disclosure", func(in *Input) { in.Writes, in.Class = false, catalog.ClassDisclosure },
			Decision{OutcomeNever, ReasonWritesOff}},

		// 2. principal
		{"principal disabled", func(in *Input) { in.PrincipalDisabled = true }, Decision{OutcomeNever, ReasonPrincipalDisabled}},
		{"principal unreadable", func(in *Input) { in.PrincipalErr = errRead }, Decision{OutcomeNever, ReasonPrincipalDisabled}},
		{"principal beats a disclosure", func(in *Input) { in.PrincipalDisabled, in.Class = true, catalog.ClassDisclosure },
			Decision{OutcomeNever, ReasonPrincipalDisabled}},
		{"principal beats a bad class", func(in *Input) { in.PrincipalDisabled, in.Class = true, catalog.ClassRead },
			Decision{OutcomeNever, ReasonPrincipalDisabled}},

		// 3. class
		{"a read", func(in *Input) { in.Class = catalog.ClassRead }, Decision{OutcomeNever, ReasonNotAWrite}},
		{"no class", func(in *Input) { in.Class = "" }, Decision{OutcomeNever, ReasonNotAWrite}},

		// 4. disclosure
		{"disclosure", func(in *Input) {
			in.Tool, in.Class, in.Lowerable = "alice_say_phrase", catalog.ClassDisclosure, catalog.LowerableNever
		},
			Decision{OutcomeCard, ReasonDisclosure}},
		{"disclosure with a permission and clean", func(in *Input) { in.Tool, in.Class = "some_disclosure", catalog.ClassDisclosure },
			Decision{OutcomeCard, ReasonDisclosure}},

		// 5. never lowerable
		{"pin says never", func(in *Input) { in.Lowerable = catalog.LowerableNever }, Decision{OutcomeCard, ReasonNeverLowerable}},
		{"unknown lowerable", func(in *Input) { in.Lowerable = "maybe" }, Decision{OutcomeCard, ReasonNeverLowerable}},
		{"threat model says never", func(in *Input) { in.Tool = "alice_control_room" }, Decision{OutcomeCard, ReasonNeverLowerable}},
		{"never lowerable beats taint", func(in *Input) { in.Lowerable, in.Tainted = catalog.LowerableNever, true },
			Decision{OutcomeCard, ReasonNeverLowerable}},
		// The threat model's list decides ahead of taint too, even where
		// the pin entry says "yes": rule 5 is one rule, not two.
		{"threat model never beats taint", func(in *Input) { in.Tool, in.Tainted = "alice_control_room", true },
			Decision{OutcomeCard, ReasonNeverLowerable}},
		{"threat model never beats unreadable taint", func(in *Input) { in.Tool, in.TaintErr = "alice_trigger_scenario", errRead },
			Decision{OutcomeCard, ReasonNeverLowerable}},

		// 6. taint
		{"tainted", func(in *Input) { in.Tainted = true }, Decision{OutcomeCard, ReasonTainted}},
		{"taint unreadable", func(in *Input) { in.TaintErr = errRead }, Decision{OutcomeCard, ReasonTainted}},

		// 7. condition of a conditional tool
		{"condition unmet", func(in *Input) {
			in.Tool, in.Lowerable, in.ConditionMet = "alice_control_device", catalog.LowerableConditional, false
		},
			Decision{OutcomeCard, ReasonConditionUnmet}},
		{"condition unreadable", func(in *Input) {
			in.Tool, in.Lowerable, in.ConditionMet, in.ConditionErr = "alice_media_control", catalog.LowerableConditional, true, errRead
		},
			Decision{OutcomeCard, ReasonConditionUnmet}},
		{"taint beats an unmet condition", func(in *Input) {
			in.Tool, in.Lowerable, in.Tainted = "alice_control_device", catalog.LowerableConditional, true
		},
			Decision{OutcomeCard, ReasonTainted}},
		{"unmet condition beats a permission", func(in *Input) {
			in.Tool, in.Lowerable, in.PermissionMatch = "alice_media_control", catalog.LowerableConditional, true
		},
			Decision{OutcomeCard, ReasonConditionUnmet}},

		// 8, 9. permission
		{"no permission", func(in *Input) { in.PermissionMatch = false }, Decision{OutcomeCard, ReasonNoPermission}},
		{"permissions unreadable", func(in *Input) { in.PermissionErr = errRead }, Decision{OutcomeCard, ReasonNoPermission}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := open()
			c.edit(&in)
			if got := Decide(in); got != c.want {
				t.Fatalf("Decide = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestDecideNeverLowersWithoutEveryCondition: over every combination of
// the boolean observations, for a conditional tool, a call is lowered only
// when every one of them is the safe value.
func TestDecideNeverLowersWithoutEveryCondition(t *testing.T) {
	for mask := 0; mask < 1<<10; mask++ {
		bit := func(i int) bool { return mask&(1<<i) != 0 }
		in := open()
		in.Tool, in.Lowerable = "alice_control_device", catalog.LowerableConditional
		in.ConditionMet = !bit(8)
		if bit(9) {
			in.ConditionErr = errRead
		}
		in.Writes = !bit(0)
		if bit(1) {
			in.WritesErr = errRead
		}
		in.PrincipalDisabled = bit(2)
		if bit(3) {
			in.PrincipalErr = errRead
		}
		in.Tainted = bit(4)
		if bit(5) {
			in.TaintErr = errRead
		}
		in.PermissionMatch = !bit(6)
		if bit(7) {
			in.PermissionErr = errRead
		}
		got := Decide(in)
		if (got.Outcome == OutcomeLowered) != (mask == 0) {
			t.Fatalf("mask %010b: %+v", mask, got)
		}
		if (bit(0) || bit(1) || bit(2) || bit(3)) && got.Outcome != OutcomeNever {
			t.Fatalf("mask %010b: %+v, want never", mask, got)
		}
	}
}

// TestNoPrincipalStatusFailsClosed: the stub reports every principal
// disabled with an error, and Decide treats that as never.
func TestNoPrincipalStatusFailsClosed(t *testing.T) {
	var ps PrincipalStatus = NoPrincipalStatus{}
	disabled, err := ps.PrincipalDisabled(context.Background(), 42)
	if !errors.Is(err, ErrPrincipalStatusUnavailable) || !disabled {
		t.Fatalf("stub = %v, %v", disabled, err)
	}
	in := open()
	in.PrincipalErr = err
	if got := Decide(in); got.Outcome != OutcomeNever {
		t.Fatalf("Decide with the stub = %+v", got)
	}
	// Even a stub that said "not disabled" alongside its error is decided
	// by the error.
	in.PrincipalDisabled = false
	if got := Decide(in); got != (Decision{OutcomeNever, ReasonPrincipalDisabled}) {
		t.Fatalf("error with disabled=false: %+v", got)
	}
}
