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

// alice_devices.go reads a connection's devices through the pinned read
// tool alice_list_devices (#1322 slices P2-S6 and P2-S14b; S2-D2, S2-D4,
// S2-D5). The tool answers with a text written for a model and, next to
// it, structuredContent written for a program: every device with its id,
// name, raw type, room and household. This file reads the structured
// listing only.
//
// The rule when the structured listing is absent or not of the exact shape
// below: the devices are unreadable (ErrSpeakersUnreadable), which refuses
// the card, the grant or the dispatch that asked. It is never an empty
// list, and there is no fallback to the text: a second parser would hide
// the drift this one exists to show. A server that does not send the
// listing (mctl-alice up to 2.18.0) therefore gets no device call from the
// assistant at all.
//
// Everything a device holds is the account owner's text or the server's.
// It is shown to the principal on a card and compared at dispatch; it is
// never handed to the model.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

const (
	aliceServer   = "alice"
	aliceListTool = "alice_list_devices"
	// aliceListArgs asks for every device: one read serves speakers,
	// lights and the type of anything else.
	aliceListArgs = `{}`
	// maxAliceDevices bounds one listing. A longer one is unreadable, not
	// cut: a target past the cut would read as "not listed".
	maxAliceDevices = 512
	// maxAliceField bounds a name, a room, a household and a type.
	maxAliceField = 256
)

// aliceDeviceID is the shape of a device id, the one the server itself
// requires of an exact id (mctl-alice DEVICE_ID_PATTERN): no space, no
// markup, at most 128 characters.
var aliceDeviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// Device is one device as the server lists it.
type Device struct {
	// ID is the device id, the only form of a target a card accepts.
	ID string
	// Name is required. Room and Home are "" when the server reports
	// none; a card then says so.
	Name, Room, Home string
	// Type is the device type as the server reports it
	// ("devices.types.light"), or "" when it reports none. A user can
	// relabel a device, so the type is never the only basis for lowering.
	Type string
	// Speaker is the server's own answer to "is this a speaker with the
	// assistant": by type or by capability.
	Speaker bool
}

// IsLight reports whether d is a light by its type: the type is
// devices.types.light or continues it after a dot. A speaker is never a
// light.
func (d Device) IsLight() bool {
	return !d.Speaker && permissions.TypeHasPrefix(d.Type, permissions.TypeLight)
}

// DeviceLister reads every device of one connection from its server, now,
// under the rules of SpeakerReader: never from a cache, and an error for
// anything but a complete listing it could parse. A listing that holds no
// device is a listing; a listing that could not be read is an error.
type DeviceLister interface {
	Devices(ctx context.Context, req SpeakerRequest) ([]Device, error)
}

// ErrNoSuchDevices is a listing that was read in full and holds no device
// of the kind asked for. It is not ErrSpeakersUnreadable: the target is
// then known to be absent.
var ErrNoSuchDevices = errors.New("pa connector: no device of this kind is listed")

// AliceDevices is the device reader of the alice server: a DeviceLister, a
// SpeakerReader and a LightReader over one tool.
type AliceDevices struct {
	ep MCPEndpoint
	// audit records every read: see Devices.
	audit *Executor
}

var (
	_ DeviceLister  = (*AliceDevices)(nil)
	_ SpeakerReader = (*AliceDevices)(nil)
	_ LightReader   = (*AliceDevices)(nil)
)

// NewAliceDevices builds the reader over the alice endpoint. pin must list
// alice_list_devices as an auto-tier read: the reader calls nothing else.
// audit is the executor whose sink records the reads; a reader without
// one is not built, so no read goes unrecorded.
func NewAliceDevices(pin *catalog.Pin, ep MCPEndpoint, audit *Executor) (*AliceDevices, error) {
	if pin == nil || ep == nil || ep.Server() != aliceServer {
		return nil, errors.New("pa connector: alice devices need the pin and the alice endpoint")
	}
	if audit == nil || audit.Sink == nil {
		return nil, errors.New("pa connector: alice devices need an audit sink")
	}
	t, ok := pin.Servers[aliceServer].Tools[aliceListTool]
	if !ok || t.Tier != catalog.TierAuto || t.Class != catalog.ClassRead {
		return nil, fmt.Errorf("pa connector: %s is not a pinned auto read", aliceListTool)
	}
	return &AliceDevices{ep: ep, audit: audit}, nil
}

// Devices implements DeviceLister with one tools/call. It is not retried:
// a rejected token, a failed call and a tool error all are unreadable.
//
// The read is a tools/call the server makes on its own, for a card, for
// a grant or right before a dispatch, and it is recorded in the audit
// chain like any call (#1322 P2-S15c; S2-D4): a pre-dispatch entry before
// the request and a result entry after it, with the connection, the tool,
// the digest of the fixed arguments and the digest of the answer, and
// never the answer itself. The read made for a dispatch carries the
// approval it is made for. A read whose pre-dispatch entry cannot be
// written is not made (I9, T12): the devices are then unreadable.
//
// The entry's taint is clean: the arguments are a constant of this file,
// so nothing of a conversation shapes the request, and the answer is
// never handed to the model.
func (r *AliceDevices) Devices(ctx context.Context, req SpeakerRequest) ([]Device, error) {
	if req.Server != aliceServer {
		return nil, fmt.Errorf("%w: not the alice server", ErrSpeakersUnreadable)
	}
	callID, err := newCallID()
	if err != nil {
		return nil, fmt.Errorf("%w: no call id", ErrSpeakersUnreadable)
	}
	base := Entry{
		CallID: callID, Principal: req.Principal,
		ConnectionID: req.ConnectionID, AuthorityRevision: req.AuthorityRevision,
		Server: aliceServer, Tool: aliceListTool, ArgsSHA256: digest([]byte(aliceListArgs)),
		Tier: catalog.TierAuto, Class: catalog.ClassRead, Taint: TaintClean,
		ApprovalID: recordable(req.ApprovalID, invalidMarker),
	}
	pre := base
	pre.Phase, pre.Status, pre.At = PhasePreDispatch, StatusDispatching, r.audit.now()
	if err := r.audit.Sink.Append(ctx, pre); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSpeakersUnreadable, ErrAuditUnavailable)
	}
	var devices []Device
	_, _ = r.audit.dispatchRecorded(ctx, base, func(ctx context.Context) (Result, error) {
		raw, callErr := r.ep.CallTool(ctx, req.Token, aliceListTool, json.RawMessage(aliceListArgs))
		if callErr != nil {
			err = fmt.Errorf("%w: %s failed", ErrSpeakersUnreadable, aliceListTool)
			return Result{}, err
		}
		devices, err = parseAliceDevices(raw)
		// An answer that cannot be read is recorded as the tool's error,
		// with its digest: the request was made and answered.
		return Result{Output: raw, ToolError: err != nil}, nil
	})
	if err != nil {
		return nil, err
	}
	return devices, nil
}

// Speakers implements SpeakerReader: the listed devices the server calls
// speakers. A listing without one is ErrNoSuchDevices.
func (r *AliceDevices) Speakers(ctx context.Context, req SpeakerRequest) ([]Speaker, error) {
	devices, err := r.Devices(ctx, req)
	if err != nil {
		return nil, err
	}
	var out []Speaker
	for _, d := range devices {
		if d.Speaker {
			out = append(out, Speaker{ID: d.ID, Name: d.Name, Room: d.Room, Home: d.Home, Type: d.Type})
		}
	}
	if len(out) == 0 {
		return nil, ErrNoSuchDevices
	}
	return out, nil
}

// Lights implements LightReader: the listed devices that are lights by
// type (Device.IsLight). A listing without one is ErrNoSuchDevices.
func (r *AliceDevices) Lights(ctx context.Context, req SpeakerRequest) ([]Light, error) {
	devices, err := r.Devices(ctx, req)
	if err != nil {
		return nil, err
	}
	var out []Light
	for _, d := range devices {
		if d.IsLight() {
			out = append(out, Light{ID: d.ID, Name: d.Name, Room: d.Room, Home: d.Home, Type: d.Type})
		}
	}
	if len(out) == 0 {
		return nil, ErrNoSuchDevices
	}
	return out, nil
}

// A JSON object is decoded into a map of raw members, never into a struct
// of pointers: there a member set to null and a member that is absent both
// read as nil, and the listing gives the two different meanings.

// jsonString reads the member as a JSON string. ok is false for anything
// else: an absent member and null included.
func jsonString(members map[string]json.RawMessage, name string) (string, bool) {
	raw, present := members[name]
	if !present || len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// jsonIs reports whether the member is present and is exactly the literal.
func jsonIs(members map[string]json.RawMessage, name, literal string) bool {
	raw, present := members[name]
	return present && string(bytes.TrimSpace(raw)) == literal
}

// aliceLabel reads a name, a room or a household: a string of one line,
// with no space around it, that is not empty and not over maxAliceField.
func aliceLabel(members map[string]json.RawMessage, name string) (string, bool) {
	s, ok := jsonString(members, name)
	if !ok || s == "" || len(s) > maxAliceField || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\r\n") {
		return "", false
	}
	return s, true
}

// aliceOptional reads a member the server sets to null when it has nothing
// to report: null is "", a label is itself, anything else, an absent
// member and an empty string included, is not readable.
func aliceOptional(members map[string]json.RawMessage, name string) (string, bool) {
	if jsonIs(members, name, "null") {
		return "", true
	}
	return aliceLabel(members, name)
}

// parseAliceDevices reads the structuredContent of an alice_list_devices
// tools/call result. Nothing of the result is quoted in an error.
//
// The shape is exact. The result is an object that is not a tool error;
// structuredContent is an object whose only_speakers is false (the listing
// asked for is the full one) and whose devices is an array; every device
// has a well-formed id that no other device has, a name, a boolean
// is_speaker, and the members room and household, each a label or null. A
// type is a string or is not reported (absent or null); a type of another
// JSON type is not readable. A member this file does not know is ignored:
// the server may add one.
func parseAliceDevices(raw []byte) ([]Device, error) {
	bad := func(what string) ([]Device, error) {
		return nil, fmt.Errorf("%w: %s", ErrSpeakersUnreadable, what)
	}
	object := func(raw []byte) (map[string]json.RawMessage, bool) {
		var m map[string]json.RawMessage
		t := bytes.TrimSpace(raw)
		if len(t) == 0 || t[0] != '{' || json.Unmarshal(t, &m) != nil || m == nil {
			return nil, false
		}
		return m, true
	}
	res, ok := object(raw)
	if !ok {
		return bad("result is not an object")
	}
	if _, present := res["isError"]; present && !jsonIs(res, "isError", "false") {
		return bad("tool error")
	}
	// A server that does not send the listing, or sends null: not "no
	// devices".
	listed, ok := object(res["structuredContent"])
	if !ok {
		return bad("no structured listing")
	}
	if !jsonIs(listed, "only_speakers", "false") {
		return bad("structured listing is not the full one")
	}
	var items []json.RawMessage
	if t := bytes.TrimSpace(listed["devices"]); len(t) == 0 || t[0] != '[' || json.Unmarshal(t, &items) != nil {
		return bad("structured listing has no device array")
	}
	if len(items) > maxAliceDevices {
		return bad("too many devices")
	}
	out := make([]Device, 0, len(items))
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		l, ok := object(item)
		if !ok {
			return bad("device is not an object")
		}
		var d Device
		if d.ID, ok = jsonString(l, "id"); !ok || !aliceDeviceID.MatchString(d.ID) {
			return bad("device id")
		}
		if seen[d.ID] {
			// One id, two devices: the listing cannot say which is meant.
			return bad("device id is listed twice")
		}
		seen[d.ID] = true
		if d.Name, ok = aliceLabel(l, "name"); !ok {
			return bad("device name")
		}
		switch {
		case jsonIs(l, "is_speaker", "true"):
			d.Speaker = true
		case jsonIs(l, "is_speaker", "false"):
		default:
			return bad("device kind")
		}
		if _, present := l["type"]; present && !jsonIs(l, "type", "null") {
			if d.Type, ok = jsonString(l, "type"); !ok || len(d.Type) > maxAliceField || strings.TrimSpace(d.Type) != d.Type {
				return bad("device type")
			}
		}
		if d.Room, ok = aliceOptional(l, "room"); !ok {
			return bad("device room")
		}
		if d.Home, ok = aliceOptional(l, "household"); !ok {
			return bad("device household")
		}
		out = append(out, d)
	}
	return out, nil
}

// GrantTokens gives the grant reader the connection and its access token
// (*connection.Manager).
type GrantTokens interface {
	Get(ctx context.Context, principal int64, id string) (connection.Connection, error)
	AccessToken(ctx context.Context, principal int64, id string, boundRevision int64) (connection.Secret, connection.Connection, error)
}

// GrantDevices is the permissions.DeviceReader of the alice server: the
// devices a grant may list, each with its type, read through the
// connection the grant names. Like every read here it answers from no
// cache, and whatever it could not read is an error.
type GrantDevices struct {
	lister DeviceLister
	conns  GrantTokens
}

var _ permissions.DeviceReader = (*GrantDevices)(nil)

// NewGrantDevices builds the grant reader over a device lister of the
// alice server.
func NewGrantDevices(lister DeviceLister, conns GrantTokens) (*GrantDevices, error) {
	if lister == nil || conns == nil {
		return nil, errors.New("pa connector: grant devices need a device lister and the connections")
	}
	return &GrantDevices{lister: lister, conns: conns}, nil
}

// ReadDevices implements permissions.DeviceReader. The connection must be
// the principal's, active, of the alice server and of the scope the
// catalog expects; the token is the one of the revision just read.
func (g *GrantDevices) ReadDevices(ctx context.Context, principal int64, connectionID string) ([]permissions.Device, error) {
	c, err := g.conns.Get(ctx, principal, connectionID)
	if err != nil {
		return nil, fmt.Errorf("%w: connection", ErrSpeakersUnreadable)
	}
	if c.ID != connectionID || c.Principal != principal || string(c.Server) != aliceServer || c.State != connection.StateActive {
		return nil, fmt.Errorf("%w: not an active alice connection", ErrSpeakersUnreadable)
	}
	token, conn, err := g.conns.AccessToken(ctx, principal, connectionID, c.AuthorityRevision)
	if err != nil {
		return nil, fmt.Errorf("%w: token", ErrSpeakersUnreadable)
	}
	// A token is never sent to another provider's endpoint (S1-X3).
	if conn.ID != connectionID || conn.Principal != principal || string(conn.Server) != aliceServer ||
		conn.AuthorityRevision != c.AuthorityRevision {
		return nil, fmt.Errorf("%w: connection changed", ErrSpeakersUnreadable)
	}
	// The read set, or the write set of a connection that asked for it:
	// a grant is given on a write connection, and both carry every read
	// scope (connection.ScopeAccepted).
	if !connection.ScopeAccepted(conn) {
		return nil, fmt.Errorf("%w: scope", ErrSpeakersUnreadable)
	}
	devices, err := g.lister.Devices(ctx, SpeakerRequest{
		Principal: principal, ConnectionID: connectionID, AuthorityRevision: conn.AuthorityRevision,
		Server: aliceServer, Token: token,
	})
	if err != nil {
		return nil, err
	}
	out := make([]permissions.Device, 0, len(devices))
	for _, d := range devices {
		out = append(out, permissions.Device{ID: d.ID, Type: d.Type})
	}
	return out, nil
}
