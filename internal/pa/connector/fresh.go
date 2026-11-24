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

// fresh.go is the FreshSurface of the write executor (#1320 slice P2-S4;
// threat model T7 "Approval-time drift", I8, I9; S2-A5, S2-A6): the tool
// definition an approved call is checked against is listed from the server
// for that one dispatch.

import (
	"context"
	"errors"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// PinFresh answers FreshTool with one tools/list per call, through the
// server's endpoint and so under its egress rules (I8), compared with the
// pin. It has no state: the read path's 60 s listing cache
// (Dispatcher.surface, catalog.ReadListingTTL) is not consulted and nothing
// here keeps a listing, so an answer is never older than the dispatch that
// asked and a failed listing has nothing to fall back to.
type PinFresh struct {
	pin       *catalog.Pin
	endpoints map[string]MCPEndpoint
}

// NewPinFresh refuses a nil pin and an endpoint filed under another name.
// A pinned server without an endpoint is allowed: its writes are refused.
func NewPinFresh(pin *catalog.Pin, endpoints map[string]MCPEndpoint) (*PinFresh, error) {
	if pin == nil {
		return nil, errors.New("pa connector: fresh surface needs a pin")
	}
	eps := make(map[string]MCPEndpoint, len(endpoints))
	for name, ep := range endpoints {
		if ep == nil || ep.Server() != name {
			return nil, fmt.Errorf("pa connector: fresh surface endpoint %q does not serve that name", name)
		}
		eps[name] = ep
	}
	return &PinFresh{pin: pin, endpoints: eps}, nil
}

var _ FreshSurface = (*PinFresh)(nil)

// FreshTool implements FreshSurface. The pin is asked first, so a tool it
// does not have, or one that is not an approve-tier write or disclosure,
// is refused before the token goes anywhere. Then the server is listed,
// every page, and the tool read out of that listing: a listing that failed,
// is malformed or is cut off, a missing tool and a tool that differs from
// its pin are all errors (catalog.Pin.ObserveTool). The hashes returned are
// those of the listing.
func (f *PinFresh) FreshTool(ctx context.Context, req FreshRequest) (FreshTool, error) {
	if f == nil || f.pin == nil {
		return FreshTool{}, fmt.Errorf("%w: no fresh surface", catalog.ErrServerUnavailable)
	}
	pinned, err := f.pin.ToolDefinition(req.Server, req.Tool)
	if err != nil {
		return FreshTool{}, err
	}
	if pinned.Tier != catalog.TierApprove || (pinned.Class != catalog.ClassWrite && pinned.Class != catalog.ClassDisclosure) {
		return FreshTool{}, catalog.ErrNoWritePath
	}
	ep := f.endpoints[req.Server]
	if ep == nil {
		return FreshTool{}, fmt.Errorf("%w: no endpoint", catalog.ErrServerUnavailable)
	}
	pages, fetchErr := ep.ListTools(ctx, req.Token)
	def, err := f.pin.ObserveTool(req.Server, req.Tool, pages, fetchErr)
	if err != nil {
		return FreshTool{}, err
	}
	// ToolDefinition found the tool in the pin above.
	rule := f.pin.Servers[req.Server].Tools[req.Tool]
	return FreshTool{
		SchemaSHA:      def.SchemaSHA256,
		DescriptionSHA: def.DescriptionSHA256,
		AnnotationSHA:  def.AnnotationsSHA256,
		Tier:           def.Tier,
		Class:          def.Class,
		Lowerable:      rule.Lowerable,
		Constraints:    rule.Constraints,
	}, nil
}
