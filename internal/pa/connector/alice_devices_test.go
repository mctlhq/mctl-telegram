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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// aliceListing is a full alice_list_devices result as mctl-alice writes it
// from 5f6755b7 on: the text for a model and the structured listing. The
// devices are the synthetic ones of the server's own test of the listing
// (tests/pa-write-surface.test.ts), in its order.
const aliceListing = `{"content":[{"type":"text","text":"### Умный дом Яндекса\n\n**Колонки с Алисой (3):**"}],
 "structuredContent":{"only_speakers":false,"devices":[
  {"id":"spk-00000001","name":"Kitchen speaker","type":"devices.types.smart_speaker.yandex.station.mini","is_speaker":true,"room":"Kitchen","household":"Synthetic Home"},
  {"id":"spk-00000002","name":"Study speaker","type":"devices.types.smart_speaker.yandex.station","is_speaker":true,"room":"Study","household":"Synthetic Home"},
  {"id":"spk-00000003","name":"Porch speaker","type":"devices.types.smart_speaker.yandex.station.micro","is_speaker":true,"room":"Porch","household":"Synthetic Cottage"},
  {"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study","household":"Synthetic Home"},
  {"id":"lgt-00000002","name":"Plain bulb","type":"devices.types.light","is_speaker":false,"room":null,"household":null},
  {"id":"lgt-00000003","name":"lamp lgt-00000002 copy","type":"devices.types.light","is_speaker":false,"room":"Kitchen","household":"Synthetic Home"},
  {"id":"thm-00000001","name":"Heater","type":"devices.types.thermostat","is_speaker":false,"room":"Study","household":"Synthetic Home"},
  {"id":"skt-00000001","name":"Wall socket","type":"devices.types.socket","is_speaker":false,"room":"Kitchen","household":"Synthetic Home"}]}}`

// aliceReleasedListing is the result of the released server (2.18.0): the
// same text and no structured listing.
const aliceReleasedListing = `{"content":[{"type":"text","text":"### Умный дом Яндекса\n\n**Колонки с Алисой (1):**\n- **Kitchen speaker** (Комната: Kitchen, ID: ` + "`spk-00000001`" + `, Статус: онлайн)"}]}`

type aliceEP struct {
	server string
	out    []byte
	err    error
	calls  []string
}

func (e *aliceEP) Server() string { return e.server }
func (e *aliceEP) ListTools(context.Context, connection.Secret) ([][]byte, error) {
	return nil, errors.New("not used")
}
func (e *aliceEP) CallTool(_ context.Context, _ connection.Secret, tool string, args json.RawMessage) ([]byte, error) {
	e.calls = append(e.calls, tool+" "+string(args))
	return e.out, e.err
}

func alicePin() *catalog.Pin {
	return &catalog.Pin{Servers: map[string]catalog.ServerPin{"alice": {Tools: map[string]catalog.PinnedTool{
		"alice_list_devices": {Tier: catalog.TierAuto, Class: catalog.ClassRead},
	}}}}
}

func aliceReader(t *testing.T, out string) (*AliceDevices, *aliceEP) {
	t.Helper()
	ep := &aliceEP{server: "alice", out: []byte(out)}
	r, err := NewAliceDevices(alicePin(), ep, aliceAudit(&fakeSink{ev: &events{}}))
	if err != nil {
		t.Fatal(err)
	}
	return r, ep
}

// aliceAudit is an executor over sink with a fixed clock.
func aliceAudit(sink Sink) *Executor {
	return &Executor{Sink: sink, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }}
}

// TestS2D4_DeviceReadIsAudited (#1322 P2-S15c): a device read is a
// tools/call the server makes on its own, and it leaves the two entries
// of any call in the audit chain: one before the request and one after
// it, naming the connection, the tool, the fixed arguments by digest and
// the answer by digest. The read made for a dispatch names its approval.
// Nothing of the answer is in an entry, and every entry is one the chain
// can store. A read whose first entry cannot be written is not made.
func TestS2D4_DeviceReadIsAudited(t *testing.T) {
	req := SpeakerRequest{Principal: 4242001, ConnectionID: "pac_a", AuthorityRevision: 3, Server: "alice"}
	storable := func(name string, entries []Entry) {
		t.Helper()
		for _, e := range entries {
			rec, err := FormatRecord(e)
			if err != nil {
				t.Fatalf("%s: the chain cannot store %+v: %v", name, e, err)
			}
			for _, leak := range []string{"Kitchen", "spk-0000", "Synthetic"} {
				if strings.Contains(rec, leak) {
					t.Fatalf("%s: the record holds %q of the answer: %s", name, leak, rec)
				}
			}
		}
	}
	for name, tc := range map[string]struct {
		out      string
		callErr  error
		approval string
		status   Status
		digest   bool
		readable bool
	}{
		"a read for a card":             {out: aliceListing, status: StatusOK, digest: true, readable: true},
		"a read at dispatch":            {out: aliceListing, approval: "apr_0123456789abcdef", status: StatusOK, digest: true, readable: true},
		"an answer that cannot be read": {out: `{"content":[]}`, status: StatusToolError, digest: true},
		"a call that failed":            {out: aliceListing, callErr: errors.New("injected"), status: StatusOutcomeUnknown},
	} {
		sink := &fakeSink{ev: &events{}}
		ep := &aliceEP{server: "alice", out: []byte(tc.out), err: tc.callErr}
		r, err := NewAliceDevices(alicePin(), ep, aliceAudit(sink))
		if err != nil {
			t.Fatal(err)
		}
		rq := req
		rq.ApprovalID = tc.approval
		devices, err := r.Devices(context.Background(), rq)
		if tc.readable != (err == nil) || tc.readable != (len(devices) > 0) {
			t.Fatalf("%s: %d devices, %v", name, len(devices), err)
		}
		if !tc.readable && !errors.Is(err, ErrSpeakersUnreadable) {
			t.Fatalf("%s: %v", name, err)
		}
		if len(sink.entries) != 2 {
			t.Fatalf("%s: %d audit entries, want one before the call and one after: %+v", name, len(sink.entries), sink.entries)
		}
		pre, post := sink.entries[0], sink.entries[1]
		want := Entry{
			CallID: pre.CallID, Phase: PhasePreDispatch, Principal: 4242001, ConnectionID: "pac_a", AuthorityRevision: 3,
			Server: "alice", Tool: "alice_list_devices", ArgsSHA256: digest([]byte(`{}`)),
			Tier: catalog.TierAuto, Class: catalog.ClassRead, Taint: TaintClean, ApprovalID: tc.approval,
			Status: StatusDispatching, At: pre.At,
		}
		if pre != want || pre.CallID == "" || pre.At.IsZero() {
			t.Fatalf("%s: pre-dispatch entry\n got %+v\nwant %+v", name, pre, want)
		}
		want.Phase, want.Status, want.At = PhaseResult, tc.status, post.At
		if tc.digest {
			want.ResultSHA256 = digest([]byte(tc.out))
		}
		if post != want || post.At.IsZero() {
			t.Fatalf("%s: result entry\n got %+v\nwant %+v", name, post, want)
		}
		if got := sink.ev.list(); !slices.Equal(got, []string{"append:pre_dispatch:dispatching", "append:result:" + string(tc.status)}) {
			t.Fatalf("%s: order %v", name, got)
		}
		storable(name, sink.entries)
	}

	// The entry before the request cannot be written: no request.
	sink := &fakeSink{ev: &events{}, failOn: PhasePreDispatch}
	ep := &aliceEP{server: "alice", out: []byte(aliceListing)}
	r, err := NewAliceDevices(alicePin(), ep, aliceAudit(sink))
	if err != nil {
		t.Fatal(err)
	}
	if devices, err := r.Devices(context.Background(), req); !errors.Is(err, ErrSpeakersUnreadable) || !errors.Is(err, ErrAuditUnavailable) || devices != nil {
		t.Fatalf("an unwritable audit entry: %+v, %v", devices, err)
	}
	if len(ep.calls) != 0 {
		t.Fatalf("the read was made without its audit entry: %v", ep.calls)
	}

	// A reader is not built without a sink.
	for name, x := range map[string]*Executor{"no executor": nil, "no sink": {}} {
		if _, err := NewAliceDevices(alicePin(), ep, x); err == nil {
			t.Errorf("%s: a reader that records nothing was built", name)
		}
	}
}

// structured is a result whose structuredContent is body.
func structured(body string) string {
	return `{"content":[{"type":"text","text":"x"}],"structuredContent":` + body + `}`
}

// listing is a full structured listing of the given devices.
func listing(devices ...string) string {
	return structured(`{"only_speakers":false,"devices":[` + strings.Join(devices, ",") + `]}`)
}

const (
	kitchenDevice = `{"id":"spk-00000001","name":"Kitchen speaker","type":"devices.types.smart_speaker.yandex.station","is_speaker":true,"room":"Kitchen","household":"Synthetic Home"}`
	lampDevice    = `{"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study","household":"Synthetic Home"}`
)

var aliceReq = SpeakerRequest{Server: "alice"}

// TestAliceDevices_ReadsTheStructuredListing: one call with no arguments
// serves the speakers, the lights and the type of every device, with the
// household, and a room or a household the server does not report is "".
func TestAliceDevices_ReadsTheStructuredListing(t *testing.T) {
	r, ep := aliceReader(t, aliceListing)
	got, err := r.Devices(context.Background(), aliceReq)
	if err != nil {
		t.Fatal(err)
	}
	want := []Device{
		{ID: "spk-00000001", Name: "Kitchen speaker", Room: "Kitchen", Home: "Synthetic Home", Type: "devices.types.smart_speaker.yandex.station.mini", Speaker: true},
		{ID: "spk-00000002", Name: "Study speaker", Room: "Study", Home: "Synthetic Home", Type: "devices.types.smart_speaker.yandex.station", Speaker: true},
		{ID: "spk-00000003", Name: "Porch speaker", Room: "Porch", Home: "Synthetic Cottage", Type: "devices.types.smart_speaker.yandex.station.micro", Speaker: true},
		{ID: "lgt-00000001", Name: "Desk lamp", Room: "Study", Home: "Synthetic Home", Type: "devices.types.light"},
		{ID: "lgt-00000002", Name: "Plain bulb", Type: "devices.types.light"},
		{ID: "lgt-00000003", Name: "lamp lgt-00000002 copy", Room: "Kitchen", Home: "Synthetic Home", Type: "devices.types.light"},
		{ID: "thm-00000001", Name: "Heater", Room: "Study", Home: "Synthetic Home", Type: "devices.types.thermostat"},
		{ID: "skt-00000001", Name: "Wall socket", Room: "Kitchen", Home: "Synthetic Home", Type: "devices.types.socket"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("devices\n got %+v\nwant %+v", got, want)
	}
	if !slices.Equal(ep.calls, []string{`alice_list_devices {}`}) {
		t.Fatalf("calls %v", ep.calls)
	}
	speakers, err := r.Speakers(context.Background(), aliceReq)
	if err != nil {
		t.Fatal(err)
	}
	if ids := speakerIDs(speakers); !slices.Equal(ids, []string{"spk-00000001", "spk-00000002", "spk-00000003"}) {
		t.Fatalf("speakers %v", ids)
	}
	if s := speakers[2]; s != (Speaker{ID: "spk-00000003", Name: "Porch speaker", Room: "Porch", Home: "Synthetic Cottage", Type: "devices.types.smart_speaker.yandex.station.micro"}) {
		t.Fatalf("speaker %+v", s)
	}
	lights, err := r.Lights(context.Background(), aliceReq)
	if err != nil {
		t.Fatal(err)
	}
	if ids := lightIDs(lights); !slices.Equal(ids, []string{"lgt-00000001", "lgt-00000002", "lgt-00000003"}) {
		t.Fatalf("lights %v", ids)
	}
	if l := lights[1]; l != (Light{ID: "lgt-00000002", Name: "Plain bulb", Type: "devices.types.light"}) {
		t.Fatalf("light %+v", l)
	}
	// One read each, and never the speakers-only listing.
	if !slices.Equal(ep.calls, []string{`alice_list_devices {}`, `alice_list_devices {}`, `alice_list_devices {}`}) {
		t.Fatalf("calls %v", ep.calls)
	}
	// The types the server reports are the ones the tools' rules allow.
	for _, d := range got {
		if d.Speaker != permissions.TypeAllowed("alice_set_volume", d.Type) || d.IsLight() != permissions.TypeAllowed("alice_set_light", d.Type) {
			t.Errorf("%s of type %s: speaker %v, light %v disagree with the rules", d.ID, d.Type, d.Speaker, d.IsLight())
		}
	}
	// The Phase 2 pin lists the tool the reader calls as an auto read.
	p2, err := catalog.LoadPinPhase2()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewAliceDevices(p2, ep, aliceAudit(&fakeSink{ev: &events{}})); err != nil {
		t.Fatalf("over the Phase 2 pin: %v", err)
	}
}

func speakerIDs(list []Speaker) []string {
	var out []string
	for _, s := range list {
		out = append(out, s.ID)
	}
	return out
}

func lightIDs(list []Light) []string {
	var out []string
	for _, l := range list {
		out = append(out, l.ID)
	}
	return out
}

// TestAliceDevices_UnreadableIsAnError: a failed call, a result without
// the structured listing and every listing that is not exactly the known
// shape is ErrSpeakersUnreadable from all three reads. It is never a
// shorter list, never an empty one and never ErrNoSuchDevices, and the
// text of the result is not read instead.
func TestAliceDevices_UnreadableIsAnError(t *testing.T) {
	device := func(members string) string { return listing(`{` + members + `}`) }
	const rest = `,"type":"devices.types.light","is_speaker":false,"room":"Study","household":"Synthetic Home"`
	many := make([]string, 0, maxAliceDevices+1)
	for i := range maxAliceDevices + 1 {
		many = append(many, fmt.Sprintf(`{"id":"lgt-%08d","name":"Lamp"%s}`, i, rest))
	}
	results := map[string]string{
		"empty":                          ``,
		"not an object":                  `[]`,
		"null":                           `null`,
		"not JSON":                       `{"structuredContent":`,
		"the released server: text only": aliceReleasedListing,
		"a tool error":                   `{"isError":true,` + aliceListing[1:],
		"isError that is not a boolean":  `{"isError":"false",` + aliceListing[1:],
		"a null listing":                 structured(`null`),
		"a listing that is a list":       structured(`[` + kitchenDevice + `]`),
		"a listing that is a string":     structured(`"devices"`),
		"an empty listing object":        structured(`{}`),
		"no only_speakers":               structured(`{"devices":[` + kitchenDevice + `]}`),
		"the speakers-only listing":      structured(`{"only_speakers":true,"devices":[` + kitchenDevice + `]}`),
		"only_speakers null":             structured(`{"only_speakers":null,"devices":[` + kitchenDevice + `]}`),
		"no devices member":              structured(`{"only_speakers":false}`),
		"null devices":                   structured(`{"only_speakers":false,"devices":null}`),
		"devices that is an object":      structured(`{"only_speakers":false,"devices":{}}`),
		"devices that is a string":       structured(`{"only_speakers":false,"devices":""}`),
		"a device that is a string":      listing(kitchenDevice, `"lgt-00000001"`),
		"a null device":                  listing(kitchenDevice, `null`),
		"a device that is a list":        listing(kitchenDevice, `[]`),
		"one id twice":                   listing(kitchenDevice, kitchenDevice),
		"one id, two kinds":              listing(kitchenDevice, strings.Replace(lampDevice, "lgt-00000001", "spk-00000001", 1)),
		"no id":                          device(`"name":"Desk lamp"` + rest),
		"a null id":                      device(`"id":null,"name":"Desk lamp"` + rest),
		"an id that is a number":         device(`"id":7,"name":"Desk lamp"` + rest),
		"an empty id":                    device(`"id":"","name":"Desk lamp"` + rest),
		"an id with a space":             device(`"id":"lgt 00000001","name":"Desk lamp"` + rest),
		"an id with a line break":        device(`"id":"lgt-00000001\n","name":"Desk lamp"` + rest),
		"an id of 129 characters":        device(`"id":"` + strings.Repeat("a", 129) + `","name":"Desk lamp"` + rest),
		"no name":                        device(`"id":"lgt-00000001"` + rest),
		"a null name":                    device(`"id":"lgt-00000001","name":null` + rest),
		"an empty name":                  device(`"id":"lgt-00000001","name":""` + rest),
		"a name of two lines":            device(`"id":"lgt-00000001","name":"Desk lamp\nRoom: Hall"` + rest),
		"a name with a space around it":  device(`"id":"lgt-00000001","name":" Desk lamp"` + rest),
		"a name that is a number":        device(`"id":"lgt-00000001","name":5` + rest),
		"a name that is too long":        device(`"id":"lgt-00000001","name":"` + strings.Repeat("a", maxAliceField+1) + `"` + rest),
		"no is_speaker":                  device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","room":"Study","household":"Synthetic Home"`),
		"is_speaker null":                device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":null,"room":"Study","household":"Synthetic Home"`),
		"is_speaker as a string":         device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":"false","room":"Study","household":"Synthetic Home"`),
		"is_speaker as a number":         device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":0,"room":"Study","household":"Synthetic Home"`),
		"a type that is a number":        device(`"id":"lgt-00000001","name":"Desk lamp","type":5,"is_speaker":false,"room":"Study","household":"Synthetic Home"`),
		"a type that is a list":          device(`"id":"lgt-00000001","name":"Desk lamp","type":["devices.types.light"],"is_speaker":false,"room":"Study","household":"Synthetic Home"`),
		"a type with a space around it":  device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light ","is_speaker":false,"room":"Study","household":"Synthetic Home"`),
		"no room member":                 device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"household":"Synthetic Home"`),
		"an empty room":                  device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"","household":"Synthetic Home"`),
		"a room that is a number":        device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":3,"household":"Synthetic Home"`),
		"a room of two lines":            device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study\nHome: Bob home","household":"Synthetic Home"`),
		"no household member":            device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study"`),
		"an empty household":             device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study","household":""`),
		"a household that is an object":  device(`"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light","is_speaker":false,"room":"Study","household":{"name":"Synthetic Home"}`),
		"a bad device after good ones":   listing(kitchenDevice, lampDevice, `{"id":"skt-00000001"}`),
		"more devices than the bound":    listing(many...),
	}
	for name, out := range results {
		r, ep := aliceReader(t, out)
		devices, err := r.Devices(context.Background(), aliceReq)
		if !errors.Is(err, ErrSpeakersUnreadable) || devices != nil {
			t.Errorf("%s: devices %+v, %v", name, devices, err)
		}
		speakers, err := r.Speakers(context.Background(), aliceReq)
		if !errors.Is(err, ErrSpeakersUnreadable) || errors.Is(err, ErrNoSuchDevices) || speakers != nil {
			t.Errorf("%s: speakers %+v, %v", name, speakers, err)
		}
		lights, err := r.Lights(context.Background(), aliceReq)
		if !errors.Is(err, ErrSpeakersUnreadable) || errors.Is(err, ErrNoSuchDevices) || lights != nil {
			t.Errorf("%s: lights %+v, %v", name, lights, err)
		}
		// One call per read: nothing is retried or asked another way.
		if !slices.Equal(ep.calls, []string{`alice_list_devices {}`, `alice_list_devices {}`, `alice_list_devices {}`}) {
			t.Errorf("%s: calls %v", name, ep.calls)
		}
		// Nothing of the result is quoted in the error.
		if err != nil && (strings.Contains(err.Error(), "Desk lamp") || strings.Contains(err.Error(), "spk-")) {
			t.Errorf("%s: the error quotes the result: %v", name, err)
		}
	}
	// A failed call, with or without a body.
	for name, ep := range map[string]*aliceEP{
		"the call failed":           {server: "alice", err: errors.New("injected")},
		"the call failed with data": {server: "alice", out: []byte(aliceListing), err: errors.New("injected")},
	} {
		r, err := NewAliceDevices(alicePin(), ep, aliceAudit(&fakeSink{ev: &events{}}))
		if err != nil {
			t.Fatal(err)
		}
		if devices, err := r.Devices(context.Background(), aliceReq); !errors.Is(err, ErrSpeakersUnreadable) || devices != nil {
			t.Errorf("%s: %+v, %v", name, devices, err)
		}
	}
	// Another server is never asked.
	r, ep := aliceReader(t, aliceListing)
	if _, err := r.Devices(context.Background(), SpeakerRequest{Server: "tg"}); !errors.Is(err, ErrSpeakersUnreadable) || len(ep.calls) != 0 {
		t.Fatalf("another server: %v, calls %v", err, ep.calls)
	}
}

// TestAliceDevices_NoDeviceOfTheKindIsNotUnreadable: a listing read in
// full that holds no speaker, no light or no device at all is a listing.
// The kind that is missing is ErrNoSuchDevices, which is not unreadable,
// and it is never an empty list without an error.
func TestAliceDevices_NoDeviceOfTheKindIsNotUnreadable(t *testing.T) {
	for name, tc := range map[string]struct {
		out              string
		devices          int
		speakers, lights bool
	}{
		"no device at all": {listing(), 0, false, false},
		"only a speaker":   {listing(kitchenDevice), 1, true, false},
		"only a light":     {listing(lampDevice), 1, false, true},
		"a member the reader does not know": {listing(`{"id":"lgt-00000001","name":"Desk lamp","type":"devices.types.light",` +
			`"is_speaker":false,"room":"Study","household":"Synthetic Home","online":true}`), 1, false, true},
	} {
		r, _ := aliceReader(t, tc.out)
		devices, err := r.Devices(context.Background(), aliceReq)
		if err != nil || devices == nil || len(devices) != tc.devices {
			t.Errorf("%s: devices %+v, %v", name, devices, err)
		}
		speakers, err := r.Speakers(context.Background(), aliceReq)
		if tc.speakers != (err == nil) || (err != nil && (!errors.Is(err, ErrNoSuchDevices) || errors.Is(err, ErrSpeakersUnreadable) || speakers != nil)) {
			t.Errorf("%s: speakers %+v, %v", name, speakers, err)
		}
		lights, err := r.Lights(context.Background(), aliceReq)
		if tc.lights != (err == nil) || (err != nil && (!errors.Is(err, ErrNoSuchDevices) || errors.Is(err, ErrSpeakersUnreadable) || lights != nil)) {
			t.Errorf("%s: lights %+v, %v", name, lights, err)
		}
	}
}

// TestAliceDevices_KindsDoNotCross: a speaker is a device of the smart
// speaker type that the server also calls a speaker, a light is a device of
// the light type that is not a speaker, and a type is matched whole or up
// to a dot: neither reader serves the other kind, a television with the
// assistant is no target (D12), and a type that only starts with the
// letters of "light" is no light.
func TestAliceDevices_KindsDoNotCross(t *testing.T) {
	dev := func(id, typ string, speaker bool) string {
		t := `null`
		if typ != "" {
			t = `"` + typ + `"`
		}
		return fmt.Sprintf(`{"id":%q,"name":"Device","type":%s,"is_speaker":%v,"room":null,"household":null}`, id, t, speaker)
	}
	r, _ := aliceReader(t, listing(
		dev("spk-00000001", "devices.types.smart_speaker.yandex.station", true),
		dev("spk-00000002", "devices.types.light", true), // a speaker by capability with a light's type
		dev("spk-00000003", "", true),
		dev("spk-00000004", "devices.types.media_device.tv", true), // a television with the assistant
		dev("spk-00000005", "devices.types.smart_speakerphone", true),
		dev("spk-00000006", "devices.types.smart_speaker", true),
		dev("lgt-00000001", "devices.types.light", false),
		dev("lgt-00000002", "devices.types.light.ceiling", false),
		dev("lgt-00000003", "devices.types.lighting", false),
		dev("lgt-00000004", "devices.types.light_strip", false),
		dev("lgt-00000005", "devices.types.lightx.bulb", false),
		dev("lgt-00000006", "", false),
		dev("lgt-00000007", "x.devices.types.light", false),
		dev("lgt-00000008", "devices.types.smart_speaker.yandex.station", false), // a speaker's type the server does not call a speaker
		dev("lgt-00000009", "devices.types.light.", false),
	))
	speakers, err := r.Speakers(context.Background(), aliceReq)
	if err != nil {
		t.Fatal(err)
	}
	if ids := speakerIDs(speakers); !slices.Equal(ids, []string{"spk-00000001", "spk-00000006"}) {
		t.Fatalf("speakers %v", ids)
	}
	lights, err := r.Lights(context.Background(), aliceReq)
	if err != nil {
		t.Fatal(err)
	}
	if ids := lightIDs(lights); !slices.Equal(ids, []string{"lgt-00000001", "lgt-00000002", "lgt-00000009"}) {
		t.Fatalf("lights %v", ids)
	}
}

type grantConns struct {
	conn    connection.Connection
	getErr  error
	token   connection.Connection
	tokErr  error
	revs    []int64
	secrets string
}

func (g *grantConns) Get(_ context.Context, principal int64, id string) (connection.Connection, error) {
	if g.getErr != nil {
		return connection.Connection{}, g.getErr
	}
	return g.conn, nil
}

func (g *grantConns) AccessToken(_ context.Context, _ int64, _ string, rev int64) (connection.Secret, connection.Connection, error) {
	g.revs = append(g.revs, rev)
	if g.tokErr != nil {
		return connection.Secret{}, connection.Connection{}, g.tokErr
	}
	return connection.NewSecret(g.secrets), g.token, nil
}

type listerFunc func(SpeakerRequest) ([]Device, error)

func (f listerFunc) Devices(_ context.Context, req SpeakerRequest) ([]Device, error) { return f(req) }

// TestGrantDevices_ReadsThroughThePrincipalsConnection: a grant's device
// read goes through the principal's own active alice connection of the
// catalog's scope, with the token of the revision just read, and returns
// every listed device with its type. Any other connection, and a read
// that failed, is an error: never an empty list.
func TestGrantDevices_ReadsThroughThePrincipalsConnection(t *testing.T) {
	const alice, bob = int64(1001), int64(1002)
	scope, ok := connection.CanonicalScope(connection.ServerAlice)
	if !ok {
		t.Fatal("no scope for alice")
	}
	good := connection.Connection{
		ID: "con_alice", Principal: alice, Server: connection.ServerAlice, State: connection.StateActive,
		GrantedScope: scope, AuthorityRevision: 7,
	}
	devices := []Device{
		{ID: "spk-00000001", Name: "Kitchen speaker", Type: "devices.types.smart_speaker.yandex.station", Speaker: true},
		{ID: "lgt-00000001", Name: "Desk lamp", Type: "devices.types.light"},
		{ID: "thm-00000001", Name: "Heater"},
	}
	var asked []SpeakerRequest
	lister := listerFunc(func(req SpeakerRequest) ([]Device, error) {
		asked = append(asked, req)
		return devices, nil
	})
	conns := &grantConns{conn: good, token: good, secrets: "synthetic-access-token"}
	g, err := NewGrantDevices(lister, conns)
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.ReadDevices(context.Background(), alice, "con_alice")
	if err != nil {
		t.Fatal(err)
	}
	want := []permissions.Device{
		{ID: "spk-00000001", Type: "devices.types.smart_speaker.yandex.station"},
		{ID: "lgt-00000001", Type: "devices.types.light"},
		{ID: "thm-00000001"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("devices %+v", got)
	}
	if len(asked) != 1 || asked[0].Principal != alice || asked[0].ConnectionID != "con_alice" || asked[0].AuthorityRevision != 7 ||
		asked[0].Server != "alice" || asked[0].Token.Reveal() != "synthetic-access-token" || !slices.Equal(conns.revs, []int64{7}) {
		t.Fatalf("asked %+v, revisions %v", asked, conns.revs)
	}

	with := func(mutate func(*connection.Connection)) connection.Connection {
		c := good
		mutate(&c)
		return c
	}
	for name, tc := range map[string]*grantConns{
		"the connection is unreadable": {getErr: errors.New("injected")},
		"another principal's":          {conn: with(func(c *connection.Connection) { c.Principal = bob }), token: good},
		"another id":                   {conn: with(func(c *connection.Connection) { c.ID = "con_other" }), token: good},
		"another server":               {conn: with(func(c *connection.Connection) { c.Server = connection.ServerTG }), token: good},
		"not active":                   {conn: with(func(c *connection.Connection) { c.State = connection.StateRevoked }), token: good},
		"no token":                     {conn: good, tokErr: errors.New("injected")},
		"a token of another server":    {conn: good, token: with(func(c *connection.Connection) { c.Server = connection.ServerTG })},
		"a token of another revision":  {conn: good, token: with(func(c *connection.Connection) { c.AuthorityRevision = 8 })},
		"a token of another principal": {conn: good, token: with(func(c *connection.Connection) { c.Principal = bob })},
		"another scope":                {conn: good, token: with(func(c *connection.Connection) { c.GrantedScope = scope + " iot:control" })},
		"no scope":                     {conn: good, token: with(func(c *connection.Connection) { c.GrantedScope = "" })},
	} {
		asked = nil
		tc.secrets = "synthetic-access-token"
		g, err := NewGrantDevices(lister, tc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := g.ReadDevices(context.Background(), alice, "con_alice")
		if !errors.Is(err, ErrSpeakersUnreadable) || got != nil || len(asked) != 0 {
			t.Errorf("%s: %+v, %v, %d reads", name, got, err, len(asked))
		}
	}
	// A read that failed is the read's error, and a listing with no
	// device is a list of none.
	failing := listerFunc(func(SpeakerRequest) ([]Device, error) { return nil, ErrSpeakersUnreadable })
	g, _ = NewGrantDevices(failing, conns)
	if got, err := g.ReadDevices(context.Background(), alice, "con_alice"); !errors.Is(err, ErrSpeakersUnreadable) || got != nil {
		t.Fatalf("a failed read: %+v, %v", got, err)
	}
	none := listerFunc(func(SpeakerRequest) ([]Device, error) { return []Device{}, nil })
	g, _ = NewGrantDevices(none, conns)
	if got, err := g.ReadDevices(context.Background(), alice, "con_alice"); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no device: %+v, %v", got, err)
	}
	if _, err := NewGrantDevices(nil, conns); err == nil {
		t.Fatal("a reader without a lister")
	}
	if _, err := NewGrantDevices(lister, nil); err == nil {
		t.Fatal("a reader without connections")
	}
}
