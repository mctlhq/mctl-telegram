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
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestLoadPinPhase2: the committed Phase 2 pin validates, holds exactly the
// T6 table on alice with the T6 classes, keeps the Phase 1 reads unchanged,
// and is still refused by the Phase 1 loader.
func TestLoadPinPhase2(t *testing.T) {
	p2, err := LoadPinPhase2()
	if err != nil {
		t.Fatalf("LoadPinPhase2: %v", err)
	}
	p1, err := LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	for server, sp := range p1.Servers {
		for name, pt := range sp.Tools {
			if got := p2.Servers[server].Tools[name]; !reflect.DeepEqual(got, pt) {
				t.Errorf("%s/%s differs from the Phase 1 pin", server, name)
			}
		}
	}
	writes := 0
	for server, sp := range p2.Servers {
		for name, pt := range sp.Tools {
			if pt.Class == ClassRead {
				if _, ok := p1.Servers[server].Tools[name]; !ok {
					t.Errorf("%s/%s is a read the Phase 1 pin does not have", server, name)
				}
				continue
			}
			writes++
			want := phase2Policy[name]
			if server != "alice" || pt.Class != want.class || pt.Tier != TierApprove {
				t.Errorf("%s/%s = %s/%s", server, name, pt.Class, pt.Tier)
			}
		}
	}
	if writes != len(phase2Policy) {
		t.Errorf("%d writes pinned, want the %d of T6", writes, len(phase2Policy))
	}
	if err := p2.ValidatePhase1(); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("ValidatePhase1(phase 2 pin) = %v, want ErrInvalidPin", err)
	}
	// The committed Phase 2 pin is accepted by its upstream listing: every
	// tool is usable (green on a converged input).
	now := time.Now()
	for server, page := range upstreamPages(t) {
		s := p2.Observe(server, [][]byte{page}, nil, now)
		if s.Err() != nil {
			t.Fatal(s.Err())
		}
		for _, d := range s.Denied() {
			if _, pinned := p2.Servers[server].Tools[d.Name]; pinned {
				t.Errorf("%s/%s denied by its own upstream: %v", server, d.Name, d.Reasons)
			}
		}
	}
}

// phase2Pin is the committed Phase 2 pin, parsed but not phase-validated,
// for tests to break one field at a time.
func phase2Pin(t *testing.T) *Pin {
	t.Helper()
	p, err := ParsePin(pinPhase2JSON)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func editTool(p *Pin, server, name string, f func(*PinnedTool)) {
	pt := p.Servers[server].Tools[name]
	if pt.Constraints != nil {
		c := *pt.Constraints
		pt.Constraints = &c
	}
	f(&pt)
	p.Servers[server].Tools[name] = pt
}

// TestValidatePhase2Rules: each rule of ValidatePhase2 refuses its own
// violation, on an otherwise valid Phase 2 pin.
func TestValidatePhase2Rules(t *testing.T) {
	if err := phase2Pin(t).ValidatePhase2(); err != nil {
		t.Fatalf("committed Phase 2 pin: %v", err)
	}
	cases := []struct {
		name   string
		server string
		tool   string
		edit   func(*PinnedTool)
		ok     bool
	}{
		{"disclosure lowerable", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Lowerable = LowerableYes }, false},
		{"disclosure conditional", "alice", "alice_send_command", func(pt *PinnedTool) { pt.Lowerable = LowerableConditional }, false},
		{"write auto", "alice", "alice_set_light", func(pt *PinnedTool) { pt.Tier = TierAuto }, false},
		{"disclosure auto", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Tier = TierAuto }, false},
		{"control_room lowerable", "alice", "alice_control_room", func(pt *PinnedTool) { pt.Lowerable = LowerableYes }, false},
		{"trigger_scenario conditional", "alice", "alice_trigger_scenario", func(pt *PinnedTool) {
			pt.Lowerable = LowerableConditional
			pt.Constraints = &Constraints{AllowedTypePrefixes: []string{"devices.types.light"}}
		}, false},
		{"say_phrase as write", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Class = ClassWrite }, false},
		{"set_light as disclosure", "alice", "alice_set_light", func(pt *PinnedTool) {
			pt.Class, pt.Lowerable = ClassDisclosure, LowerableNever
			pt.Constraints = &Constraints{TextCap: map[string]int{"device": 10}}
		}, false},
		{"set_volume conditional (looser than T6)", "alice", "alice_set_volume", func(pt *PinnedTool) {
			pt.Lowerable = LowerableConditional
			pt.Constraints.AllowedTypePrefixes = []string{"devices.types.media_device"}
		}, false},
		{"set_light stricter never", "alice", "alice_set_light", func(pt *PinnedTool) { pt.Lowerable = LowerableNever }, true},
		{"media_control stricter never", "alice", "alice_media_control", func(pt *PinnedTool) {
			pt.Lowerable = LowerableNever
			pt.Constraints = nil
		}, true},
		{"disclosure without text cap", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Constraints = nil }, false},
		{"text cap over 1000", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Constraints.TextCap = map[string]int{"phrase": 1001} }, false},
		{"text cap zero", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Constraints.TextCap = map[string]int{"phrase": 0} }, false},
		{"text cap on unknown arg", "alice", "alice_say_phrase", func(pt *PinnedTool) { pt.Constraints.TextCap = map[string]int{"text": 100} }, false},
		{"integer bound on a string", "alice", "alice_set_volume", func(pt *PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]IntBound{"device": {1, 10}}
		}, false},
		{"integer bound min over max", "alice", "alice_set_volume", func(pt *PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]IntBound{"level": {10, 1}}
		}, false},
		{"integer bound on a disclosure", "alice", "alice_say_phrase", func(pt *PinnedTool) {
			pt.Constraints.IntegerBounds = map[string]IntBound{"phrase": {1, 1}}
		}, false},
		{"conditional without condition", "alice", "alice_control_device", func(pt *PinnedTool) { pt.Constraints = nil }, false},
		{"type prefix not allowed", "alice", "alice_control_device", func(pt *PinnedTool) {
			pt.Constraints.AllowedTypePrefixes = []string{"devices.types.socket"}
		}, false},
		{"type prefix too broad", "alice", "alice_control_device", func(pt *PinnedTool) {
			pt.Constraints.AllowedTypePrefixes = []string{"devices.types"}
		}, false},
		{"type prefix repeated", "alice", "alice_control_device", func(pt *PinnedTool) {
			pt.Constraints.AllowedTypePrefixes = []string{"devices.types.light", "devices.types.light"}
		}, false},
		{"type prefix on a yes write", "alice", "alice_set_light", func(pt *PinnedTool) {
			pt.Constraints.AllowedTypePrefixes = []string{"devices.types.light"}
		}, false},
		{"playback value outside the enum", "alice", "alice_media_control", func(pt *PinnedTool) {
			pt.Constraints.PlaybackActions = &EnumSubset{Arg: "action", Values: []string{"play", "search"}}
		}, false},
		{"playback on a non-enum arg", "alice", "alice_media_control", func(pt *PinnedTool) {
			pt.Constraints.PlaybackActions = &EnumSubset{Arg: "device", Values: []string{"play"}}
		}, false},
		{"playback empty", "alice", "alice_media_control", func(pt *PinnedTool) {
			pt.Constraints.PlaybackActions = &EnumSubset{Arg: "action"}
		}, false},
		{"playback narrower subset", "alice", "alice_media_control", func(pt *PinnedTool) {
			pt.Constraints.PlaybackActions = &EnumSubset{Arg: "action", Values: []string{"pause", "stop"}}
		}, true},
		{"write on tg", "tg", "list_dialogs", func(pt *PinnedTool) {
			pt.Tier, pt.Class, pt.Lowerable = TierApprove, ClassWrite, LowerableNever
			pt.Annotations = []byte(`{}`)
		}, false},
		{"constraints on a read", "alice", "alice_list_devices", func(pt *PinnedTool) {
			pt.Constraints = &Constraints{TextCap: map[string]int{"only_speakers": 1}}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := phase2Pin(t)
			editTool(p, c.server, c.tool, c.edit)
			err := p.ValidatePhase2()
			if c.ok && err != nil {
				t.Fatalf("want valid, got %v", err)
			}
			if !c.ok && !errors.Is(err, ErrInvalidPin) {
				t.Fatalf("want ErrInvalidPin, got %v", err)
			}
		})
	}
	// A write T6 does not list is refused even when it is otherwise a
	// well-formed approve-tier write.
	p := phase2Pin(t)
	pt := p.Servers["alice"].Tools["alice_set_light"]
	p.Servers["alice"].Tools["alice_open_lock"] = pt
	if err := p.ValidatePhase2(); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("unlisted write: %v", err)
	}
	// A T6 tool pinned on another server than alice is refused too.
	p = phase2Pin(t)
	p.Servers["tg"].Tools["alice_set_light"] = p.Servers["alice"].Tools["alice_set_light"]
	if err := p.ValidatePhase2(); !errors.Is(err, ErrInvalidPin) {
		t.Fatalf("T6 write on tg: %v", err)
	}
}

// TestValidatePhase2RunsThePolicyItself: ValidatePhase2's own per-tool pass
// refuses a policy violation even when handed a tool Validate never saw.
func TestValidatePhase2RunsThePolicyItself(t *testing.T) {
	pt := phase2Pin(t).Servers["alice"].Tools["alice_control_room"]
	pt.Lowerable = LowerableYes
	if err := validatePhase2Tool("alice", "alice_control_room", pt); err == nil {
		t.Fatal("control_room lowerable accepted by validatePhase2Tool")
	}
	pt = phase2Pin(t).Servers["alice"].Tools["alice_say_phrase"]
	pt.Lowerable = LowerableYes
	if err := validatePhase2Tool("alice", "alice_say_phrase", pt); err == nil {
		t.Fatal("disclosure lowerable accepted by validatePhase2Tool")
	}
}

// TestParsePinRefusesDuplicateKeys: a tool pinned twice, or a policy field
// given twice, is refused instead of the last one silently winning.
func TestParsePinRefusesDuplicateKeys(t *testing.T) {
	for _, raw := range [][]byte{pinJSON, pinPhase2JSON} {
		if _, err := ParsePin(raw); err != nil {
			t.Fatalf("committed pin: %v", err)
		}
	}
	dupField := strings.Replace(string(pinJSON), `"lowerable": "never",`, `"lowerable": "never", "lowerable": "never",`, 1)
	dupTool := strings.Replace(string(pinPhase2JSON), `"alice_set_light": {`, `"alice_set_light": {}, "alice_set_light": {`, 1)
	for name, raw := range map[string]string{"field": dupField, "tool": dupTool} {
		if raw == string(pinJSON) || raw == string(pinPhase2JSON) {
			t.Fatalf("%s: replacement did not apply", name)
		}
		if _, err := ParsePin([]byte(raw)); !errors.Is(err, ErrInvalidPin) {
			t.Errorf("duplicate %s: ParsePin = %v, want ErrInvalidPin", name, err)
		}
	}
}

// TestDeviceTypeAllowed: only the T6 allowlist, matched on a dot boundary;
// an unknown type never matches.
func TestDeviceTypeAllowed(t *testing.T) {
	pfx := []string{"devices.types.light", "devices.types.media_device"}
	for typ, want := range map[string]bool{
		"devices.types.light":            true,
		"devices.types.light.ceiling":    true,
		"devices.types.media_device.tv":  true,
		"devices.types.lightswitch":      false,
		"devices.types.socket":           false,
		"devices.types.thermostat.ac":    false,
		"":                               false,
		"devices.types.light_and_heater": false,
	} {
		if got := DeviceTypeAllowed(pfx, typ); got != want {
			t.Errorf("DeviceTypeAllowed(%q) = %v, want %v", typ, got, want)
		}
	}
	// A prefix outside the allowlist matches nothing, even if passed in.
	if DeviceTypeAllowed([]string{"devices.types.socket"}, "devices.types.socket") {
		t.Error("a non-allowlisted prefix matched")
	}
}

// TestAuthorizeWrites: an approve-tier tool is refused with
// ErrApprovalRequired only when writes are on, and with ErrNoWritePath
// (and not ErrApprovalRequired) otherwise; nothing but a read is ever
// granted; drift still wins over the write check.
func TestAuthorizeWrites(t *testing.T) {
	p, err := LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	page := upstreamPages(t)["alice"]
	s := p.Observe("alice", [][]byte{page}, nil, t0)
	for _, tool := range []string{"alice_set_light", "alice_say_phrase", "alice_control_room", "alice_media_control"} {
		g, err := s.AuthorizeWrites(tool, t0, true)
		if !errors.Is(err, ErrApprovalRequired) || g != (Grant{}) {
			t.Errorf("%s writes on: %+v, %v; want ErrApprovalRequired", tool, g, err)
		}
		for name, f := range map[string]func() (Grant, error){
			"AuthorizeWrites(false)": func() (Grant, error) { return s.AuthorizeWrites(tool, t0, false) },
			"Authorize":              func() (Grant, error) { return s.Authorize(tool, t0) },
		} {
			g, err := f()
			if !errors.Is(err, ErrNoWritePath) || errors.Is(err, ErrApprovalRequired) || g != (Grant{}) {
				t.Errorf("%s %s: %+v, %v; want ErrNoWritePath only", tool, name, g, err)
			}
		}
	}
	// ErrApprovalRequired is still a "no write path" to every Phase 1
	// caller that only knows that error.
	if !errors.Is(ErrApprovalRequired, ErrNoWritePath) {
		t.Fatal("ErrApprovalRequired does not wrap ErrNoWritePath")
	}
	for _, writes := range []bool{false, true} {
		g, err := s.AuthorizeWrites("alice_list_devices", t0, writes)
		if err != nil || g.Class != ClassRead || g.Tool != "alice_list_devices" {
			t.Fatalf("read with writes=%v: %+v, %v", writes, g, err)
		}
	}
	changed := mutatePage(t, page, func(tools []map[string]any) []map[string]any {
		findTool(t, tools, "alice_set_light")["description"] = "changed"
		return tools
	})
	s = p.Observe("alice", [][]byte{changed}, nil, t0)
	if _, err := s.AuthorizeWrites("alice_set_light", t0, true); !errors.Is(err, ErrToolChanged) {
		t.Fatalf("changed write: %v, want ErrToolChanged", err)
	}
	if _, err := s.AuthorizeWrites("alice_set_light", t0.Add(2*ReadListingTTL), true); !errors.Is(err, ErrListingStale) {
		t.Fatalf("stale listing: %v, want ErrListingStale", err)
	}
}
