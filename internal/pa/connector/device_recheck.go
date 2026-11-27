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

// device_recheck.go is the device read the write executor makes right
// before it sends (#1322 slice P2-S14b; S2-D2, S2-D4, S2-D5).
//
// A card names a device by what a read made for the card reported: its id,
// name, room, home, type and kind (a speaker or a light). That is sealed
// into the approval next to the arguments. An approval lives for minutes,
// and in that time a device can be removed, renamed, moved to another room
// or home, or relabelled as another type. So the executor reads the
// connection's devices once more, after the pre-dispatch transaction
// consumed the receipt and right before the request, and sends nothing
// unless the device with that id is still listed and every one of those
// values is the one the card was made from. One read per dispatch; it is
// never answered from a cache. A dispatch refused here has spent its
// approval: the principal is told it was not carried out and asks again.
//
// A call a standing permission covers has no card, and the same read
// stands between the emitter's checks and the call: the emitter hands the
// executor the target it read (LoweredCall.Target), and the executor
// compares its own read with it and asks the tool's rule about the type it
// read itself. A device that changed is not sent (ReasonDeviceChanged).
//
// Whatever cannot be read refuses: no reader for the server
// (ReasonNoWritePath), a failed or malformed read
// (ReasonDevicesUnreadable), a sealed target this build cannot read
// (ReasonApprovalUnreadable). A device that is not in a listing read in
// full is ReasonDeviceNotListed.
//
// A scenario's steps are read again in the same place by recheckScenario
// (scenario.go). No tool reports a scenario's steps, so no reader of them
// exists outside tests and a deployed executor refuses there.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/pa/approval"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// targetsDevice reports whether a call of tool goes to one device a card
// names, and so is read again at dispatch.
func targetsDevice(tool string) bool {
	if _, ok := deviceWriteTools[tool]; ok {
		return true
	}
	if _, ok := disclosureTools[tool]; ok {
		return true
	}
	return tool == musicTool
}

// deviceArgOf is the argument of tool that holds the device id.
func deviceArgOf(tool string) string {
	if spec, ok := deviceWriteTools[tool]; ok {
		return spec.deviceArg
	}
	if spec, ok := disclosureTools[tool]; ok {
		return spec.deviceArg
	}
	return musicDeviceArg
}

// sealedTarget reads the device a card of tool was made from out of the
// detail sealed with it.
func sealedTarget(tool string, detail []byte) (*detailSpeaker, error) {
	if len(detail) == 0 {
		return nil, errors.New("pa write: no sealed target")
	}
	dec := json.NewDecoder(strings.NewReader(string(detail)))
	dec.DisallowUnknownFields()
	var t *detailSpeaker
	if _, ok := deviceWriteTools[tool]; ok {
		var wd writeDetail
		if err := dec.Decode(&wd); err != nil {
			return nil, errors.New("pa write: sealed target unreadable")
		}
		t = wd.Device
	} else {
		var cd cardDetail
		if err := dec.Decode(&cd); err != nil || cd.Scenario != nil {
			return nil, errors.New("pa write: sealed target unreadable")
		}
		t = cd.Speaker
	}
	if t == nil || t.ID == "" || t.Name == "" || (t.Kind != detailKindSpeaker && t.Kind != detailKindLight) {
		return nil, errors.New("pa write: sealed target unreadable")
	}
	return t, nil
}

// lowerableTarget reports whether the device a write's card would name,
// as the read made for it reported it, is of a type the tool's rule lets
// a standing permission cover.
func lowerableTarget(tool string, detail []byte) bool {
	t, err := sealedTarget(tool, detail)
	return err == nil && permissions.TypeAllowed(tool, t.Type)
}

// kindOf is the kind a card would give d: a speaker, a light, or "" for a
// device no card names.
func kindOf(d Device) string {
	switch {
	case d.Speaker:
		return detailKindSpeaker
	case d.IsLight():
		return detailKindLight
	}
	return ""
}

// recheckTarget is the read described in the file comment. It returns the
// reason the dispatch is refused for, or "". args are the bytes that will
// be sent and detail what was sealed with them; lowered says no card was
// approved for the call.
func (w *WriteExecutor) recheckTarget(ctx context.Context, a approval.Approval, token connection.Secret, args, detail []byte, lowered bool) string {
	var decoded map[string]json.RawMessage
	if json.Unmarshal(args, &decoded) != nil || digest(args) != a.ArgsSHA {
		return ReasonArgsChanged
	}
	sealed, err := sealedTarget(a.Tool, detail)
	if err != nil {
		return ReasonApprovalUnreadable
	}
	// The id that is sent is the one the card named.
	if device, ok := stringArg(decoded, deviceArgOf(a.Tool)); !ok || device == "" || device != sealed.ID {
		return ReasonApprovalUnreadable
	}
	lister := w.cfg.Devices[a.Server]
	if lister == nil {
		return ReasonNoWritePath
	}
	devices, err := lister.Devices(ctx, SpeakerRequest{
		Principal: a.Principal, ConnectionID: a.ConnectionID, AuthorityRevision: a.AuthorityRevision,
		Server: a.Server, Token: token, ApprovalID: a.ID,
	})
	if err != nil {
		// Could not read is not "the device is gone".
		return ReasonDevicesUnreadable
	}
	var now *Device
	seen := make(map[string]bool, len(devices))
	for i := range devices {
		d := &devices[i]
		if d.ID == "" || d.Name == "" || seen[d.ID] {
			return ReasonDevicesUnreadable
		}
		seen[d.ID] = true
		// The id, byte for byte.
		if d.ID == sealed.ID {
			now = d
		}
	}
	if now == nil {
		return ReasonDeviceNotListed
	}
	if kindOf(*now) != sealed.Kind || now.Name != sealed.Name || now.Room != sealed.Room ||
		now.Home != sealed.Home || now.Type != sealed.Type {
		return ReasonDeviceChanged
	}
	// No card stands behind a lowered call, so the type just read is put
	// to the tool's rule here as well, whatever the caller read.
	if lowered && !permissions.TypeAllowed(a.Tool, now.Type) {
		return ReasonDeviceChanged
	}
	return ""
}
