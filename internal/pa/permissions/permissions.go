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

// Package permissions is the Personal Assistant's standing permission
// (#1320 slice P2-S10; threat model T7 "Standing permissions", I5): what
// one is, what may be granted, and how a grant waits in a callback for the
// principal's confirmation.
//
// A standing permission lets one lowerable tool run on listed devices
// without a card, for at most MaxTTL, for one connection at one authority
// revision. It is created only by the /permissions command, confirmed with
// a button the principal presses; no tool, route or model output creates
// one (S2-A8).
//
// The package is pure: stores and the bot live elsewhere. Nothing consults
// a permission at dispatch yet (P2-S11), and no deployed wiring builds a
// Validator, so the package is inert in a running service.
package permissions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

const (
	// MaxTTL is the longest a standing permission lives (threat model T7).
	MaxTTL = 30 * 24 * time.Hour
	// DefaultTTL is the expiry /permissions grants with. The threat model
	// fixes only the maximum; the default is an open owner decision.
	DefaultTTL = MaxTTL
	// ScreenTTL is how long a grant or revoke screen's button works. It
	// also bounds the age of the device read a grant was checked against.
	ScreenTTL = 5 * time.Minute
	// MaxDevices bounds the device ids of one permission.
	MaxDevices = 10
	// MaxActive bounds a principal's active permissions.
	MaxActive = 10
	// NoCeiling is the Ceiling of a permission without a value ceiling.
	NoCeiling int64 = -1
	// MaxCeiling bounds a ceiling; device units are small numbers.
	MaxCeiling int64 = 1000
)

// Errors. ErrRefused wraps every "this grant is not allowed"; ErrUnreadable
// every failed read, which is never "nothing there" (I9).
var (
	ErrRefused    = errors.New("pa permissions: grant refused")
	ErrUnreadable = errors.New("pa permissions: unreadable")
	ErrNotFound   = errors.New("pa permissions: no such permission")
	ErrInvalid    = errors.New("pa permissions: invalid argument")
)

// Reason says why a grant was refused. It is for logs and tests; the
// principal is shown one fixed text.
type Reason string

const (
	ReasonUnknownTool      Reason = "unknown_tool"
	ReasonNotAWrite        Reason = "not_a_write"
	ReasonDisclosure       Reason = "disclosure"
	ReasonNeverLowerable   Reason = "never_lowerable"
	ReasonShape            Reason = "shape"
	ReasonExpiry           Reason = "expiry"
	ReasonDevicesUnread    Reason = "devices_unreadable"
	ReasonUnknownDevice    Reason = "unknown_device"
	ReasonNoRule           Reason = "no_device_rule"
	ReasonRule             Reason = "device_rule"
	ReasonConnectionChange Reason = "connection_changed"
	ReasonTooMany          Reason = "too_many"
)

// Refusal is an ErrRefused with its reason.
type Refusal struct{ Reason Reason }

func (r *Refusal) Error() string { return "pa permissions: grant refused: " + string(r.Reason) }

// Unwrap makes errors.Is(err, ErrRefused) true.
func (r *Refusal) Unwrap() error { return ErrRefused }

// Refuse returns the refusal for reason.
func Refuse(reason Reason) error { return &Refusal{Reason: reason} }

// ReasonOf returns the reason of a refusal, or "".
func ReasonOf(err error) Reason {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// Permission is one standing permission row.
type Permission struct {
	Principal         int64
	ID                string
	ConnectionID      string
	AuthorityRevision int64
	Server            string
	Tool              string
	// DeviceIDs is sorted and without duplicates (CanonicalDevices).
	DeviceIDs []string
	// Ceiling is the highest value the permission covers, in device
	// units, or NoCeiling.
	Ceiling   int64
	CreatedAt time.Time
	ExpiresAt time.Time
	// RevokedAt is zero while the permission is not revoked.
	RevokedAt time.Time
}

// Proposal is a grant the principal was shown and has not confirmed yet.
// It waits in the action of the grant screen's callback (GrantAction).
type Proposal struct {
	ConnectionID      string   `json:"c"`
	AuthorityRevision int64    `json:"r"`
	Server            string   `json:"s"`
	Tool              string   `json:"t"`
	DeviceIDs         []string `json:"d"`
	Ceiling           int64    `json:"k"`
	ExpiresAtMS       int64    `json:"e"`
}

// ConnectionRef is an active connection as a grant binds it.
type ConnectionRef struct {
	ID                string
	Server            string
	AuthorityRevision int64
}

// deviceIDRE is the alphabet of a device id a permission may list. A dot,
// colon or @ is left out on purpose: the grant screen shows the ids
// exactly, and those would be defanged there.
var deviceIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// idRE is the alphabet of a permission, connection or callback id.
var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// ValidID reports whether id can be a permission id.
func ValidID(id string) bool { return idRE.MatchString(id) }

// CanonicalDevices returns ids sorted and without duplicates, or a shape
// refusal: none, too many, or an id outside the alphabet.
func CanonicalDevices(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, Refuse(ReasonShape)
	}
	out := slices.Clone(ids)
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxDevices {
		return nil, Refuse(ReasonShape)
	}
	for _, id := range out {
		if !deviceIDRE.MatchString(id) {
			return nil, Refuse(ReasonShape)
		}
	}
	return out, nil
}

// EncodeDevices is the stored form of device ids: a JSON array of the
// canonical list.
func EncodeDevices(ids []string) (string, error) {
	canon, err := CanonicalDevices(ids)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(canon)
	if err != nil {
		return "", fmt.Errorf("%w: device ids: %v", ErrInvalid, err)
	}
	return string(b), nil
}

// DecodeDevices reads the stored form. Anything that is not the canonical
// encoding of a valid list is unreadable, never an empty list (I9).
func DecodeDevices(stored string) ([]string, error) {
	var ids []string
	if err := json.Unmarshal([]byte(stored), &ids); err != nil {
		return nil, fmt.Errorf("%w: device ids: %v", ErrUnreadable, err)
	}
	again, err := EncodeDevices(ids)
	if err != nil || again != stored {
		return nil, fmt.Errorf("%w: device ids are not canonical", ErrUnreadable)
	}
	return ids, nil
}

// CheckShape checks everything about a grant that needs no lookup: ids,
// device list, ceiling and an expiry after now and at most MaxTTL away.
func CheckShape(p Proposal, now time.Time) error {
	if !idRE.MatchString(p.ConnectionID) || p.AuthorityRevision <= 0 || p.Server == "" || p.Tool == "" {
		return Refuse(ReasonShape)
	}
	canon, err := CanonicalDevices(p.DeviceIDs)
	if err != nil {
		return err
	}
	if !slices.Equal(canon, p.DeviceIDs) {
		return Refuse(ReasonShape)
	}
	if p.Ceiling < NoCeiling || p.Ceiling > MaxCeiling {
		return Refuse(ReasonShape)
	}
	nowMS := now.UnixMilli()
	if p.ExpiresAtMS <= nowMS || p.ExpiresAtMS > nowMS+MaxTTL.Milliseconds() {
		return Refuse(ReasonExpiry)
	}
	return nil
}

// ToolPolicy answers what the catalog pin says about a tool. ok is false
// for a tool the pin does not have.
type ToolPolicy interface {
	PinnedTool(server, tool string) (class catalog.Class, lowerable catalog.Lowerable, ok bool)
}

// PinPolicy is the ToolPolicy of a catalog pin. Standing permissions exist
// for Phase 2 tools only, so the pin it is given is the Phase 2 pin, which
// no deployed wiring loads (TestNoRuntimePhase2Use).
type PinPolicy struct{ Pin *catalog.Pin }

// PinnedTool implements ToolPolicy.
func (p PinPolicy) PinnedTool(server, tool string) (catalog.Class, catalog.Lowerable, bool) {
	if p.Pin == nil {
		return "", "", false
	}
	sp, ok := p.Pin.Servers[server]
	if !ok {
		return "", "", false
	}
	pt, ok := sp.Tools[tool]
	if !ok {
		return "", "", false
	}
	return pt.Class, pt.Lowerable, true
}

// CheckTool refuses every tool a standing permission may never cover
// (threat model T6, T7; I5): one the pin does not have, a read, a
// disclosure tool, a tool the pin makes never lowerable, and the tools the
// threat model names never lowerable whatever a pin says
// (alice_control_room and alice_trigger_scenario among them). A nil policy
// refuses everything.
func CheckTool(policy ToolPolicy, server, tool string) error {
	if policy == nil {
		return Refuse(ReasonUnknownTool)
	}
	class, lowerable, ok := policy.PinnedTool(server, tool)
	switch {
	case !ok:
		return Refuse(ReasonUnknownTool)
	case class == catalog.ClassDisclosure:
		return Refuse(ReasonDisclosure)
	case class != catalog.ClassWrite:
		return Refuse(ReasonNotAWrite)
	case catalog.IsNeverLowerable(tool):
		return Refuse(ReasonNeverLowerable)
	case lowerable != catalog.LowerableYes && lowerable != catalog.LowerableConditional:
		return Refuse(ReasonNeverLowerable)
	}
	return nil
}

// Device is one device of a fresh device read.
type Device struct {
	ID string
	// Type is the device type as the server reports it. A user can relabel
	// it, so it is never the only basis for lowering (T6).
	Type string
}

// DeviceReader reads the principal's devices from the server, now, over
// the connection. An error, or a list it could not parse, is an error:
// never an empty list.
type DeviceReader interface {
	ReadDevices(ctx context.Context, principal int64, connectionID string) ([]Device, error)
}

// GrantRule is the tool-specific half of grant validation: which device
// types a tool may be lowered for, and whether it needs a ceiling. The
// rules arrive with P2-S11; without one every grant is refused.
type GrantRule interface {
	CheckGrant(tool string, devices []Device, ceiling int64) error
}

// Validator checks a proposed grant before its screen is shown.
type Validator struct {
	Policy  ToolPolicy
	Devices DeviceReader
	// Rule is optional; nil refuses every grant (ReasonNoRule).
	Rule GrantRule
}

// Check runs every check of a grant: the tool, the shape, then a fresh
// device read that must contain every listed device id, then the rule. A
// failed or malformed device read refuses (ReasonDevicesUnread); it is
// never "no devices to object to".
func (v *Validator) Check(ctx context.Context, principal int64, p Proposal, now time.Time) error {
	if v == nil {
		return Refuse(ReasonUnknownTool)
	}
	if err := CheckTool(v.Policy, p.Server, p.Tool); err != nil {
		return err
	}
	if err := CheckShape(p, now); err != nil {
		return err
	}
	if v.Devices == nil {
		return Refuse(ReasonDevicesUnread)
	}
	fresh, err := v.Devices.ReadDevices(ctx, principal, p.ConnectionID)
	if err != nil {
		return fmt.Errorf("%w: %v", Refuse(ReasonDevicesUnread), err)
	}
	byID := make(map[string]Device, len(fresh))
	for _, d := range fresh {
		if d.ID == "" {
			return Refuse(ReasonDevicesUnread)
		}
		if _, dup := byID[d.ID]; dup {
			// One id, two devices: the read cannot say which is meant.
			return Refuse(ReasonDevicesUnread)
		}
		byID[d.ID] = d
	}
	listed := make([]Device, 0, len(p.DeviceIDs))
	for _, id := range p.DeviceIDs {
		d, ok := byID[id]
		if !ok {
			return Refuse(ReasonUnknownDevice)
		}
		listed = append(listed, d)
	}
	if v.Rule == nil {
		return Refuse(ReasonNoRule)
	}
	if err := v.Rule.CheckGrant(p.Tool, listed, p.Ceiling); err != nil {
		return fmt.Errorf("%w: %v", Refuse(ReasonRule), err)
	}
	return nil
}

// The pa_callbacks actions of the /permissions screens. A grant's action
// carries the whole proposal, so the confirmation creates exactly what the
// screen showed; a revoke's carries the permission id. Both rows are keyed
// by the principal the screen was sent to.
const (
	grantActionPrefix  = "permission_grant:"
	revokeActionPrefix = "permission_revoke:"
)

// IsAction reports whether a callback action belongs to /permissions.
func IsAction(action string) bool {
	return strings.HasPrefix(action, grantActionPrefix) || strings.HasPrefix(action, revokeActionPrefix)
}

// GrantAction is the callback action that confirms p.
func GrantAction(p Proposal) (string, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("%w: proposal: %v", ErrInvalid, err)
	}
	return grantActionPrefix + string(b), nil
}

// ParseGrantAction reads a grant action. ok is false for any other action
// and for one that does not decode exactly.
func ParseGrantAction(action string) (Proposal, bool) {
	raw, found := strings.CutPrefix(action, grantActionPrefix)
	if !found {
		return Proposal{}, false
	}
	var p Proposal
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || dec.More() {
		return Proposal{}, false
	}
	return p, true
}

// RevokeAction is the callback action that revokes permission id.
func RevokeAction(id string) (string, error) {
	if !ValidID(id) {
		return "", fmt.Errorf("%w: permission id", ErrInvalid)
	}
	return revokeActionPrefix + id, nil
}

// ParseRevokeAction reads a revoke action.
func ParseRevokeAction(action string) (string, bool) {
	id, found := strings.CutPrefix(action, revokeActionPrefix)
	if !found || !ValidID(id) {
		return "", false
	}
	return id, true
}
