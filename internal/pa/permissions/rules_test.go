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

package permissions

// Tests of the per-tool rules (#1322 slice P2-S11): the grant-time rule
// (S2-D5) and what a standing permission covers (S2-I9, S2-D1).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

const (
	speakerType = "devices.types.media_device.speaker"
	lightType   = "devices.types.light"
)

// phase2Policy is the ToolPolicy of the real Phase 2 pin.
func phase2Policy(t *testing.T) PinPolicy {
	t.Helper()
	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	return PinPolicy{Pin: pin}
}

// TestS2D5_GrantRuleRefusals: Rules refuses every grant shape S2-D5 names,
// each for its own reason, and admits the three shapes that have a rule.
func TestS2D5_GrantRuleRefusals(t *testing.T) {
	speakers := []Device{{ID: "dev-1", Type: speakerType}, {ID: "dev-2", Type: TypeMediaDevice}}
	lights := []Device{{ID: "dev-3", Type: lightType}, {ID: "dev-4", Type: lightType + ".strip"}}
	for _, ok := range []struct {
		tool    string
		devices []Device
		ceiling int64
	}{
		{"alice_set_volume", speakers, 1},
		{"alice_set_volume", speakers, 10},
		{"alice_media_control", speakers, NoCeiling},
		{"alice_set_light", lights, NoCeiling},
	} {
		if err := (Rules{}).CheckGrant(ok.tool, ok.devices, ok.ceiling); err != nil {
			t.Errorf("%s with ceiling %d: %v", ok.tool, ok.ceiling, err)
		}
	}
	cases := []struct {
		name    string
		tool    string
		devices []Device
		ceiling int64
		want    error
	}{
		{"control room", "alice_control_room", lights, NoCeiling, ErrRuleNoTool},
		{"trigger scenario", "alice_trigger_scenario", lights, NoCeiling, ErrRuleNoTool},
		{"control device", "alice_control_device", lights, NoCeiling, ErrRuleNoTool},
		{"say phrase", "alice_say_phrase", speakers, NoCeiling, ErrRuleNoTool},
		{"send command", "alice_send_command", speakers, NoCeiling, ErrRuleNoTool},
		{"an unknown tool", "alice_absent", speakers, NoCeiling, ErrRuleNoTool},
		{"no devices", "alice_set_volume", nil, 5, ErrRuleDeviceType},
		{"volume of a light", "alice_set_volume", lights, 5, ErrRuleDeviceType},
		{"volume of a speaker and a light", "alice_set_volume", []Device{speakers[0], lights[0]}, 5, ErrRuleDeviceType},
		{"playback of a socket", "alice_media_control", []Device{{ID: "dev-5", Type: "devices.types.socket"}}, NoCeiling, ErrRuleDeviceType},
		{"light of a speaker", "alice_set_light", speakers, NoCeiling, ErrRuleDeviceType},
		{"light of a socket", "alice_set_light", []Device{{ID: "dev-5", Type: "devices.types.socket"}}, NoCeiling, ErrRuleDeviceType},
		{"a type that only contains the word", "alice_set_light", []Device{{ID: "dev-5", Type: "devices.types.socket.light"}}, NoCeiling, ErrRuleDeviceType},
		{"a type that only starts like it", "alice_set_light", []Device{{ID: "dev-5", Type: lightType + "house"}}, NoCeiling, ErrRuleDeviceType},
		{"a device without a type", "alice_set_volume", []Device{{ID: "dev-1"}}, 5, ErrRuleDeviceType},
		{"volume without a ceiling", "alice_set_volume", speakers, NoCeiling, ErrRuleCeiling},
		{"volume ceiling zero", "alice_set_volume", speakers, 0, ErrRuleCeiling},
		{"volume ceiling above the range", "alice_set_volume", speakers, 11, ErrRuleCeiling},
		{"playback with a ceiling", "alice_media_control", speakers, 5, ErrRuleCeiling},
		{"light with a ceiling", "alice_set_light", lights, 50, ErrRuleCeiling},
		{"light with ceiling zero", "alice_set_light", lights, 0, ErrRuleCeiling},
	}
	for _, tc := range cases {
		if err := (Rules{}).CheckGrant(tc.tool, tc.devices, tc.ceiling); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestS2D5_ValidatorWithRules: the whole grant check over the real Phase 2
// pin, with Rules as its rule. A device id the fresh read does not list, a
// device of another type, alice_control_room, alice_trigger_scenario and
// alice_control_device get no grant.
func TestS2D5_ValidatorWithRules(t *testing.T) {
	fresh := devices{list: []Device{
		{ID: "dev-1", Type: speakerType}, {ID: "dev-2", Type: speakerType},
		{ID: "dev-3", Type: lightType}, {ID: "dev-4", Type: "devices.types.socket"},
	}}
	v := &Validator{Policy: phase2Policy(t), Devices: fresh, Rule: Rules{}}
	base := func() Proposal {
		p := proposal()
		p.DeviceIDs, p.Ceiling = []string{"dev-1", "dev-2"}, 5
		return p
	}
	if err := v.Check(context.Background(), 1, base(), now); err != nil {
		t.Fatalf("a volume grant for two speakers: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Proposal)
		want   Reason
	}{
		{"an unlisted device id", func(p *Proposal) { p.DeviceIDs = []string{"dev-1", "dev-9"} }, ReasonUnknownDevice},
		{"a device of another type", func(p *Proposal) { p.DeviceIDs = []string{"dev-1", "dev-3"} }, ReasonRule},
		{"a socket", func(p *Proposal) { p.DeviceIDs = []string{"dev-4"} }, ReasonRule},
		{"no ceiling", func(p *Proposal) { p.Ceiling = NoCeiling }, ReasonRule},
		{"a ceiling above the range", func(p *Proposal) { p.Ceiling = 11 }, ReasonRule},
		{"control room", func(p *Proposal) { p.Tool, p.Ceiling = "alice_control_room", NoCeiling }, ReasonNeverLowerable},
		{"trigger scenario", func(p *Proposal) { p.Tool, p.Ceiling = "alice_trigger_scenario", NoCeiling }, ReasonNeverLowerable},
		{"control device", func(p *Proposal) {
			p.Tool, p.Ceiling, p.DeviceIDs = "alice_control_device", NoCeiling, []string{"dev-3"}
		}, ReasonRule},
		{"say phrase", func(p *Proposal) { p.Tool, p.Ceiling = "alice_say_phrase", NoCeiling }, ReasonDisclosure},
		{"send command", func(p *Proposal) { p.Tool, p.Ceiling = "alice_send_command", NoCeiling }, ReasonDisclosure},
	}
	for _, tc := range cases {
		p := base()
		tc.mutate(&p)
		err := v.Check(context.Background(), 1, p, now)
		if !errors.Is(err, ErrRefused) || ReasonOf(err) != tc.want {
			t.Errorf("%s: %v, want refusal %q", tc.name, err, tc.want)
		}
	}
	// A device read that fails is a refusal, never "nothing to object to".
	blind := &Validator{Policy: phase2Policy(t), Devices: devices{err: errors.New("injected")}, Rule: Rules{}}
	if err := blind.Check(context.Background(), 1, base(), now); ReasonOf(err) != ReasonDevicesUnread {
		t.Errorf("unreadable devices: %v", err)
	}
}

// TestRules_AgreeWithThePhase2Pin: every tool with a rule is a write the
// pin lets a permission lower, is not on the never list, and its ceiling
// range is the range the pin states for the bounded argument. No
// disclosure tool and no never-lowerable tool has a rule.
func TestRules_AgreeWithThePhase2Pin(t *testing.T) {
	pin, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	tools := pin.Servers["alice"].Tools
	for name, r := range toolRules {
		pt, ok := tools[name]
		if !ok || pt.Class != catalog.ClassWrite || catalog.IsNeverLowerable(name) ||
			(pt.Lowerable != catalog.LowerableYes && pt.Lowerable != catalog.LowerableConditional) {
			t.Errorf("%s has a rule but the pin does not make it a lowerable write: %+v", name, pt)
			continue
		}
		if r.typePrefix != TypeMediaDevice && r.typePrefix != TypeLight {
			t.Errorf("%s: device type %q", name, r.typePrefix)
		}
		if r.ceilingArg == "" {
			continue
		}
		if pt.Constraints == nil {
			t.Errorf("%s: the pin has no bounds for %s", name, r.ceilingArg)
			continue
		}
		b, ok := pt.Constraints.IntegerBounds[r.ceilingArg]
		if !ok || b.Min != r.ceilingMin || b.Max != r.ceilingMax {
			t.Errorf("%s: ceiling range %d..%d, the pin bounds %s to %+v", name, r.ceilingMin, r.ceilingMax, r.ceilingArg, b)
		}
		if r.ceilingMax > MaxCeiling {
			t.Errorf("%s: ceiling range ends above MaxCeiling", name)
		}
	}
	for name, pt := range tools {
		has := HasRule(name)
		if has && (pt.Class != catalog.ClassWrite || catalog.IsNeverLowerable(name)) {
			t.Errorf("%s (%s) can be granted", name, pt.Class)
		}
	}
	for _, name := range []string{"alice_say_phrase", "alice_send_command", "alice_control_room",
		"alice_trigger_scenario", "alice_control_device", "alice_absent", ""} {
		if HasRule(name) {
			t.Errorf("%q has a rule", name)
		}
		if _, _, _, ok := CeilingArg(name); ok {
			t.Errorf("%q has a ceiling", name)
		}
	}
	if arg, lo, hi, ok := CeilingArg("alice_set_volume"); !ok || arg != "level" || lo != 1 || hi != 10 {
		t.Errorf("volume ceiling: %q %d..%d %v", arg, lo, hi, ok)
	}
	for _, name := range []string{"alice_media_control", "alice_set_light"} {
		if _, _, _, ok := CeilingArg(name); ok || !HasRule(name) {
			t.Errorf("%s: rule %v, ceiling %v", name, HasRule(name), ok)
		}
	}
}

func volumePermission() (Permission, Call) {
	p := Permission{
		Principal: 1, ID: "prm_1", ConnectionID: "pac_1", AuthorityRevision: 3, Server: "alice", Tool: "alice_set_volume",
		DeviceIDs: []string{"dev-1", "dev-2"}, Ceiling: 5, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	c := Call{
		Principal: 1, ConnectionID: "pac_1", AuthorityRevision: 3, Server: "alice", Tool: "alice_set_volume",
		Device: "dev-1", Ints: map[string]int64{"level": 5},
	}
	return p, c
}

// TestCovers_OnlyTheGrantedCall: a permission covers a call of its
// tool to a listed device at or under its ceiling, and nothing else: not
// one step above the ceiling, not an unlisted device, not after it
// expired or was revoked, not at another revision.
func TestCovers_OnlyTheGrantedCall(t *testing.T) {
	p, c := volumePermission()
	if !p.Covers(c, now) {
		t.Fatal("the granted call is not covered")
	}
	for _, level := range []int64{1, 4, 5} {
		c.Ints = map[string]int64{"level": level}
		if !p.Covers(c, now) {
			t.Errorf("level %d under ceiling 5 is not covered", level)
		}
	}
	cases := []struct {
		name   string
		mutate func(p *Permission, c *Call)
		at     time.Time
	}{
		{"one above the ceiling", func(_ *Permission, c *Call) { c.Ints = map[string]int64{"level": 6} }, now},
		{"far above the ceiling", func(_ *Permission, c *Call) { c.Ints = map[string]int64{"level": 10} }, now},
		{"no level", func(_ *Permission, c *Call) { c.Ints = nil }, now},
		{"another argument only", func(_ *Permission, c *Call) { c.Ints = map[string]int64{"volume": 1} }, now},
		{"an unlisted device", func(_ *Permission, c *Call) { c.Device = "dev-3" }, now},
		{"a prefix of a listed device", func(_ *Permission, c *Call) { c.Device = "dev" }, now},
		{"no device", func(_ *Permission, c *Call) { c.Device = "" }, now},
		{"revoked", func(p *Permission, _ *Call) { p.RevokedAt = now.Add(-time.Minute) }, now},
		{"expired", func(*Permission, *Call) {}, now.Add(time.Hour)},
		{"expired long ago", func(*Permission, *Call) {}, now.Add(48 * time.Hour)},
		{"an older revision", func(p *Permission, _ *Call) { p.AuthorityRevision = 2 }, now},
		{"a newer revision", func(p *Permission, _ *Call) { p.AuthorityRevision = 4 }, now},
		{"another connection", func(_ *Permission, c *Call) { c.ConnectionID = "pac_2" }, now},
		{"another principal", func(_ *Permission, c *Call) { c.Principal = 2 }, now},
		{"another server", func(_ *Permission, c *Call) { c.Server = "tg" }, now},
		{"another tool", func(_ *Permission, c *Call) { c.Tool = "alice_media_control" }, now},
		{"a stored ceiling outside the range", func(p *Permission, _ *Call) { p.Ceiling = 11 }, now},
		{"a stored permission without a ceiling", func(p *Permission, _ *Call) { p.Ceiling = NoCeiling }, now},
		{"an empty permission", func(p *Permission, _ *Call) { *p = Permission{} }, now},
	}
	for _, tc := range cases {
		p, c := volumePermission()
		tc.mutate(&p, &c)
		if p.Covers(c, tc.at) {
			t.Errorf("%s: covered", tc.name)
		}
	}

	// A tool without a ceiling: the device and the tool decide.
	p, c = volumePermission()
	p.Tool, p.Ceiling, c.Tool, c.Ints = "alice_set_light", NoCeiling, "alice_set_light", map[string]int64{"brightness": 100}
	if !p.Covers(c, now) {
		t.Error("a light permission does not cover its device")
	}
	p.Ceiling = 50
	if p.Covers(c, now) {
		t.Error("a light permission with a ceiling covers a call: its ceiling bounds nothing")
	}
}

// TestS2D1_NoPermissionCoversADisclosure: a permission row forced into
// the store for a tool without a rule covers nothing, whatever it lists.
func TestS2D1_NoPermissionCoversADisclosure(t *testing.T) {
	for _, tool := range []string{"alice_say_phrase", "alice_send_command", "alice_control_room",
		"alice_trigger_scenario", "alice_control_device"} {
		for _, ceiling := range []int64{NoCeiling, 5} {
			p, c := volumePermission()
			p.Tool, p.Ceiling, c.Tool = tool, ceiling, tool
			if p.Covers(c, now) {
				t.Errorf("a forced permission of %s (ceiling %d) covers a call", tool, ceiling)
			}
		}
	}
}

// TestCovers_SirenAndAlarmScenesNeedACard: a light's permission covers a
// scene, but never the two that are made to be noticed.
func TestCovers_SirenAndAlarmScenesNeedACard(t *testing.T) {
	p, c := volumePermission()
	p.Tool, c.Tool = "alice_set_light", "alice_set_light"
	p.Ceiling, c.Ints = NoCeiling, nil
	for _, strs := range []map[string]string{
		nil, {"state": "on"}, {"scene": "night"}, {"scene": "party", "state": "on"}, {"state": "siren"}, {"scene": "Siren"},
	} {
		c.Strings = strs
		if !p.Covers(c, now) {
			t.Errorf("%v is not covered", strs)
		}
	}
	for _, strs := range []map[string]string{
		{"scene": "siren"}, {"scene": "alarm"}, {"scene": "alarm", "state": "on"},
	} {
		c.Strings = strs
		if p.Covers(c, now) {
			t.Errorf("%v is covered", strs)
		}
	}
}
