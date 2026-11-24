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

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

var now = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

type policy map[string]catalog.PinnedTool

func (p policy) PinnedTool(server, tool string) (catalog.Class, catalog.Lowerable, bool) {
	t, ok := p[server+"/"+tool]
	return t.Class, t.Lowerable, ok
}

type devices struct {
	list []Device
	err  error
}

func (d devices) ReadDevices(context.Context, int64, string) ([]Device, error) { return d.list, d.err }

type rule struct{ err error }

func (r rule) CheckGrant(string, []Device, int64) error { return r.err }

func testPolicy() policy {
	return policy{
		"alice/alice_set_volume":       {Class: catalog.ClassWrite, Lowerable: catalog.LowerableYes},
		"alice/alice_media_control":    {Class: catalog.ClassWrite, Lowerable: catalog.LowerableConditional},
		"alice/alice_set_light":        {Class: catalog.ClassWrite, Lowerable: catalog.LowerableNever},
		"alice/alice_unmarked":         {Class: catalog.ClassWrite},
		"alice/alice_say_phrase":       {Class: catalog.ClassDisclosure, Lowerable: catalog.LowerableYes},
		"alice/alice_control_room":     {Class: catalog.ClassWrite, Lowerable: catalog.LowerableYes},
		"alice/alice_trigger_scenario": {Class: catalog.ClassWrite, Lowerable: catalog.LowerableYes},
		"alice/alice_list_devices":     {Class: catalog.ClassRead, Lowerable: catalog.LowerableYes},
	}
}

func TestCheckTool(t *testing.T) {
	for tool, want := range map[string]Reason{
		"alice_set_volume":       "",
		"alice_media_control":    "",
		"alice_set_light":        ReasonNeverLowerable,
		"alice_unmarked":         ReasonNeverLowerable,
		"alice_say_phrase":       ReasonDisclosure,
		"alice_control_room":     ReasonNeverLowerable,
		"alice_trigger_scenario": ReasonNeverLowerable,
		"alice_list_devices":     ReasonNotAWrite,
		"alice_absent":           ReasonUnknownTool,
	} {
		err := CheckTool(testPolicy(), "alice", tool)
		if ReasonOf(err) != want || (want == "") != (err == nil) || (err != nil && !errors.Is(err, ErrRefused)) {
			t.Errorf("%s: %v, want reason %q", tool, err, want)
		}
	}
	if err := CheckTool(testPolicy(), "tg", "alice_set_volume"); ReasonOf(err) != ReasonUnknownTool {
		t.Errorf("another server: %v", err)
	}
	if err := CheckTool(nil, "alice", "alice_set_volume"); ReasonOf(err) != ReasonUnknownTool {
		t.Errorf("no policy: %v", err)
	}
	if err := CheckTool(PinPolicy{}, "alice", "alice_set_volume"); ReasonOf(err) != ReasonUnknownTool {
		t.Errorf("no pin: %v", err)
	}
}

func proposal() Proposal {
	return Proposal{ConnectionID: "pac_1", AuthorityRevision: 3, Server: "alice", Tool: "alice_set_volume",
		DeviceIDs: []string{"dev-1", "dev-2"}, Ceiling: 5, ExpiresAtMS: now.Add(MaxTTL).UnixMilli()}
}

func TestValidatorCheck(t *testing.T) {
	fresh := devices{list: []Device{{ID: "dev-1"}, {ID: "dev-2"}, {ID: "dev-3"}}}
	ok := &Validator{Policy: testPolicy(), Devices: fresh, Rule: rule{}}
	if err := ok.Check(context.Background(), 1, proposal(), now); err != nil {
		t.Fatalf("a valid grant: %v", err)
	}
	cases := []struct {
		name   string
		v      *Validator
		mutate func(*Proposal)
		want   Reason
	}{
		{"nil validator", nil, nil, ReasonUnknownTool},
		{"forbidden tool", ok, func(p *Proposal) { p.Tool = "alice_control_room" }, ReasonNeverLowerable},
		{"31 days", ok, func(p *Proposal) { p.ExpiresAtMS = now.Add(31 * 24 * time.Hour).UnixMilli() }, ReasonExpiry},
		{"expired", ok, func(p *Proposal) { p.ExpiresAtMS = now.UnixMilli() }, ReasonExpiry},
		{"no devices", ok, func(p *Proposal) { p.DeviceIDs = nil }, ReasonShape},
		{"unsorted devices", ok, func(p *Proposal) { p.DeviceIDs = []string{"dev-2", "dev-1"} }, ReasonShape},
		{"repeated device", ok, func(p *Proposal) { p.DeviceIDs = []string{"dev-1", "dev-1"} }, ReasonShape},
		{"ceiling too high", ok, func(p *Proposal) { p.Ceiling = MaxCeiling + 1 }, ReasonShape},
		{"no revision", ok, func(p *Proposal) { p.AuthorityRevision = 0 }, ReasonShape},
		{"device not in the read", ok, func(p *Proposal) { p.DeviceIDs = []string{"dev-1", "dev-9"} }, ReasonUnknownDevice},
		{"no reader", &Validator{Policy: testPolicy(), Rule: rule{}}, nil, ReasonDevicesUnread},
		{"read failed", &Validator{Policy: testPolicy(), Devices: devices{err: errors.New("injected")}, Rule: rule{}}, nil, ReasonDevicesUnread},
		{"read returned an empty id", &Validator{Policy: testPolicy(), Devices: devices{list: []Device{{ID: "dev-1"}, {ID: "dev-2"}, {}}}, Rule: rule{}}, nil, ReasonDevicesUnread},
		{"read returned an id twice", &Validator{Policy: testPolicy(), Devices: devices{list: []Device{{ID: "dev-1"}, {ID: "dev-2"}, {ID: "dev-2"}}}, Rule: rule{}}, nil, ReasonDevicesUnread},
		{"read returned nothing", &Validator{Policy: testPolicy(), Devices: devices{}, Rule: rule{}}, nil, ReasonUnknownDevice},
		{"no rule", &Validator{Policy: testPolicy(), Devices: fresh}, nil, ReasonNoRule},
		{"rule objects", &Validator{Policy: testPolicy(), Devices: fresh, Rule: rule{err: errors.New("not a speaker")}}, nil, ReasonRule},
	}
	for _, tc := range cases {
		p := proposal()
		if tc.mutate != nil {
			tc.mutate(&p)
		}
		err := tc.v.Check(context.Background(), 1, p, now)
		if !errors.Is(err, ErrRefused) || ReasonOf(err) != tc.want {
			t.Errorf("%s: %v, want refusal %q", tc.name, err, tc.want)
		}
	}
}

func TestDevicesCodec(t *testing.T) {
	got, err := CanonicalDevices([]string{"dev-2", "dev-1", "dev-2"})
	if err != nil || !slices.Equal(got, []string{"dev-1", "dev-2"}) {
		t.Fatalf("canonical: %v, %v", got, err)
	}
	stored, err := EncodeDevices([]string{"dev-2", "dev-1"})
	if err != nil || stored != `["dev-1","dev-2"]` {
		t.Fatalf("encode: %q, %v", stored, err)
	}
	if back, err := DecodeDevices(stored); err != nil || !slices.Equal(back, got) {
		t.Fatalf("decode: %v, %v", back, err)
	}
	for _, bad := range []string{``, `null`, `[]`, `{}`, `["dev-2","dev-1"]`, `["dev-1","dev-1"]`, `[ "dev-1" ]`, `["a.b"]`, `["dev-1"] x`} {
		if ids, err := DecodeDevices(bad); !errors.Is(err, ErrUnreadable) || ids != nil {
			t.Errorf("decode %q: %v, %v", bad, ids, err)
		}
	}
	many := make([]string, MaxDevices+1)
	for i := range many {
		many[i] = "d" + string(rune('a'+i))
	}
	if _, err := CanonicalDevices(many); ReasonOf(err) != ReasonShape {
		t.Errorf("too many: %v", err)
	}
	for _, bad := range []string{"", "a b", "a.b", "a:b", "a@b", "a/b", "ä"} {
		if _, err := CanonicalDevices([]string{bad}); ReasonOf(err) != ReasonShape {
			t.Errorf("device id %q: %v", bad, err)
		}
	}
}

func TestActions(t *testing.T) {
	p := proposal()
	a, err := GrantAction(p)
	if err != nil || !IsAction(a) {
		t.Fatalf("grant action %q: %v", a, err)
	}
	back, ok := ParseGrantAction(a)
	if !ok || back.Tool != p.Tool || !slices.Equal(back.DeviceIDs, p.DeviceIDs) || back.ExpiresAtMS != p.ExpiresAtMS ||
		back.ConnectionID != p.ConnectionID || back.AuthorityRevision != p.AuthorityRevision || back.Ceiling != p.Ceiling || back.Server != p.Server {
		t.Fatalf("round trip %+v, %v", back, ok)
	}
	for _, bad := range []string{"", "approval_approve", "permission_grant:", "permission_grant:{", `permission_grant:{"t":"x","always":true}`,
		a + "{}", "permission_revoke:prm_1"} {
		if _, ok := ParseGrantAction(bad); ok {
			t.Errorf("%q parses as a grant", bad)
		}
	}
	r, err := RevokeAction("prm_1")
	if err != nil || !IsAction(r) {
		t.Fatalf("revoke action %q: %v", r, err)
	}
	if id, ok := ParseRevokeAction(r); !ok || id != "prm_1" {
		t.Fatalf("revoke round trip %q, %v", id, ok)
	}
	for _, bad := range []string{"", "permission_revoke:", "permission_revoke:a b", a, "approval_cancel"} {
		if _, ok := ParseRevokeAction(bad); ok {
			t.Errorf("%q parses as a revoke", bad)
		}
	}
	if _, err := RevokeAction("not an id"); !errors.Is(err, ErrInvalid) {
		t.Errorf("revoke action of a bad id: %v", err)
	}
	for _, other := range []string{"approval_approve", "approval_cancel", "consent_accept:v1:sha", "permission", ""} {
		if IsAction(other) {
			t.Errorf("%q is a /permissions action", other)
		}
	}
}
