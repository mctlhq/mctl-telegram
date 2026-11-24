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

// rules.go says what a standing permission of each tool means (#1322 slice
// P2-S11; threat model T6, T7, S2-D5): which device types it may list,
// what its ceiling bounds, and when it covers one call.
//
// A tool without a rule can be neither granted nor lowered. Three tools
// have one:
//
//   - alice_set_volume: media devices; a ceiling is required and is the
//     highest "level" (device units, 1 to 10) the permission covers;
//   - alice_media_control: media devices; no ceiling;
//   - alice_set_light: lights; no ceiling.
//
// alice_control_device has none: the server lists no id for a device that
// is not a speaker, so its type cannot be read, at a grant or at dispatch.
// alice_control_room and alice_trigger_scenario are never lowerable.
//
// The package stays pure and inert: Rules is a value a Validator may be
// given, and Covers is called by the card emitter and the write executor,
// which no deployed wiring constructs.

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// The device types a rule allows, as the server reports them. A type
// matches when it is the prefix itself or continues it after a dot
// ("devices.types.light.strip"); a type that merely contains the word does
// not ("devices.types.socket.light").
const (
	TypeMediaDevice = "devices.types.media_device"
	TypeLight       = "devices.types.light"
)

// Errors of Rules.CheckGrant, one per refused shape.
var (
	// ErrRuleNoTool: the tool has no rule, so it cannot be granted.
	ErrRuleNoTool = errors.New("pa permissions: tool has no lowering rule")
	// ErrRuleDeviceType: a listed device is not of the type the tool may
	// be lowered for, or its type is unknown.
	ErrRuleDeviceType = errors.New("pa permissions: device type is not allowed for this tool")
	// ErrRuleCeiling: the ceiling is missing where the tool needs one,
	// outside the tool's range, or given for a tool that has none.
	ErrRuleCeiling = errors.New("pa permissions: ceiling is not valid for this tool")
)

// toolRule is the rule of one tool.
type toolRule struct {
	// typePrefix is the device type every listed device must have.
	typePrefix string
	// ceilingArg is the integer argument the ceiling bounds; "" for a tool
	// whose permission has no ceiling. ceilingMin and ceilingMax are the
	// range a ceiling may be in: the range the pin states for the argument.
	ceilingArg             string
	ceilingMin, ceilingMax int64
}

var toolRules = map[string]toolRule{
	"alice_set_volume":    {typePrefix: TypeMediaDevice, ceilingArg: "level", ceilingMin: 1, ceilingMax: 10},
	"alice_media_control": {typePrefix: TypeMediaDevice},
	"alice_set_light":     {typePrefix: TypeLight},
}

// ruleOf returns the rule of tool. A tool the threat model makes never
// lowerable has none, whatever the table says.
func ruleOf(tool string) (toolRule, bool) {
	if catalog.IsNeverLowerable(tool) {
		return toolRule{}, false
	}
	r, ok := toolRules[tool]
	return r, ok
}

// HasRule reports whether tool can be granted and lowered at all.
func HasRule(tool string) bool {
	_, ok := ruleOf(tool)
	return ok
}

// CeilingArg returns the integer argument a ceiling of tool bounds and the
// range a ceiling may be in. ok is false for a tool whose permission has
// no ceiling, and for a tool without a rule.
func CeilingArg(tool string) (arg string, lo, hi int64, ok bool) {
	r, found := ruleOf(tool)
	if !found || r.ceilingArg == "" {
		return "", 0, 0, false
	}
	return r.ceilingArg, r.ceilingMin, r.ceilingMax, true
}

// typeAllowed is the exact, dotted-prefix match of a device type.
func typeAllowed(prefix, deviceType string) bool {
	return deviceType != "" && (deviceType == prefix || strings.HasPrefix(deviceType, prefix+"."))
}

// ceilingValid reports whether ceiling is one a permission of the rule's
// tool may hold.
func (r toolRule) ceilingValid(ceiling int64) bool {
	if r.ceilingArg == "" {
		return ceiling == NoCeiling
	}
	return ceiling >= r.ceilingMin && ceiling <= r.ceilingMax
}

// Rules is the GrantRule of the lowerable tools (S2-D5). The zero value is
// ready to use.
type Rules struct{}

var _ GrantRule = Rules{}

// CheckGrant implements GrantRule. devices are the listed devices as a
// fresh read returned them. It refuses:
//
//   - a tool without a rule (ErrRuleNoTool): alice_control_device,
//     alice_control_room, alice_trigger_scenario and anything unknown;
//   - an empty device list, and a device whose type is not the tool's, or
//     is empty (ErrRuleDeviceType);
//   - for a tool with a ceiling, a grant without one or with one outside
//     the tool's range; for any other tool, a grant that names a ceiling:
//     the screen would show a limit that limits nothing (ErrRuleCeiling).
func (Rules) CheckGrant(tool string, devices []Device, ceiling int64) error {
	r, ok := ruleOf(tool)
	if !ok {
		return ErrRuleNoTool
	}
	if len(devices) == 0 {
		return ErrRuleDeviceType
	}
	for _, d := range devices {
		if !typeAllowed(r.typePrefix, d.Type) {
			return ErrRuleDeviceType
		}
	}
	if !r.ceilingValid(ceiling) {
		return ErrRuleCeiling
	}
	return nil
}

// Call is one proposed call, as the code that read it from the checked
// argument bytes describes it.
type Call struct {
	Principal    int64
	ConnectionID string
	// AuthorityRevision is the connection's revision as it was just read.
	AuthorityRevision int64
	Server            string
	Tool              string
	// Device is the device id the call targets, byte for byte.
	Device string
	// Ints are the integer arguments the call sets, by argument name.
	Ints map[string]int64
}

// Covers reports whether p lets c run without a card at now. Every
// condition must hold:
//
//   - p is not revoked, expires after now and was granted at exactly the
//     revision the connection has (S2-A9);
//   - p is this principal's, for this connection, server and tool;
//   - the tool has a rule, and p's ceiling is one the rule allows;
//   - the device id is listed in p;
//   - for a tool with a ceiling, the call sets the bounded argument and
//     its value is not above the ceiling.
//
// A row this build does not understand covers nothing.
func (p Permission) Covers(c Call, now time.Time) bool {
	if !p.RevokedAt.IsZero() || !p.ExpiresAt.After(now) {
		return false
	}
	if p.Principal <= 0 || p.Principal != c.Principal || p.ConnectionID == "" || p.ConnectionID != c.ConnectionID ||
		p.AuthorityRevision <= 0 || p.AuthorityRevision != c.AuthorityRevision ||
		p.Server == "" || p.Server != c.Server || p.Tool != c.Tool {
		return false
	}
	r, ok := ruleOf(c.Tool)
	if !ok || !r.ceilingValid(p.Ceiling) {
		return false
	}
	if c.Device == "" || !slices.Contains(p.DeviceIDs, c.Device) {
		return false
	}
	if r.ceilingArg != "" {
		v, set := c.Ints[r.ceilingArg]
		if !set || v > p.Ceiling {
			return false
		}
	}
	return true
}
