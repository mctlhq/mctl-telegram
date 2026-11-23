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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ReadListingTTL is how long an observed tools/list stays valid for a read
// (threat model T8). An older observation refuses every call until the
// executor lists the server again.
const ReadListingTTL = 60 * time.Second

// Errors from Surface. None carries server-supplied text.
var (
	// ErrServerUnavailable: the server's tools/list failed or was
	// malformed. Every tool of that server is unavailable (I9).
	ErrServerUnavailable = errors.New("pa catalog: server unavailable")
	// ErrUnknownServer: the server is not in the pin.
	ErrUnknownServer = errors.New("pa catalog: server not in the catalog")
	// ErrListingStale: the observation is older than ReadListingTTL.
	ErrListingStale = errors.New("pa catalog: tools/list observation expired")
	// ErrNotPinned: the tool is not in the pin, whatever the model says.
	ErrNotPinned = errors.New("pa catalog: tool is not in the catalog")
	// ErrToolChanged: the pinned tool differs from its pin on the server,
	// or is missing there.
	ErrToolChanged = errors.New("pa catalog: tool changed on the server")
	// ErrNoWritePath: the tool is not an auto read. Phase 1 has no path
	// that dispatches anything else (I5).
	ErrNoWritePath = errors.New("pa catalog: tool needs an approval path that does not exist")
	// ErrApprovalRequired: the tool is an approve-tier write or disclosure
	// and writes are on, so the call needs an approval or a standing
	// permission before it may run (I5). It wraps ErrNoWritePath, so a
	// caller that has no approval path, as every Phase 1 caller, refuses it
	// exactly as before.
	ErrApprovalRequired = fmt.Errorf("%w: approval required", ErrNoWritePath)
)

// DenyReason says why a tool the server lists, or the pin names, is denied.
type DenyReason string

const (
	DenyNotPinned          DenyReason = "not_pinned"
	DenyMissing            DenyReason = "missing_on_server"
	DenyChangedSchema      DenyReason = "changed_schema"
	DenyChangedDescription DenyReason = "changed_description"
	DenyChangedAnnotations DenyReason = "changed_annotations"
)

// DeniedTool is a tool that cannot be used, with every reason found.
type DeniedTool struct {
	Name    string
	Reasons []DenyReason
}

// ModelTool is what the model is shown for one usable tool: the catalog's
// own description and the pinned input schema. Tool-level server
// descriptions never reach the model (threat model T8, "tool poisoning");
// the property descriptions inside the pinned schema are server-authored
// but frozen by pin review.
type ModelTool struct {
	Name        string
	Description string
	InputSchema json.RawMessage
}

// Grant is the pin's verdict for one call that may be dispatched.
type Grant struct {
	Server    string
	Tool      string
	Tier      Tier
	Class     Class
	Lowerable Lowerable
}

// Surface is one server's tools/list compared with the pin at one moment.
// It is immutable; build it with Pin.Observe.
type Surface struct {
	server     string
	observedAt time.Time
	err        error // non-nil: the whole server is unavailable
	pinned     map[string]PinnedTool
	usable     map[string]struct{}
	denied     map[string][]DenyReason
}

// Observe compares one server's live tools/list with the pin. pages are the
// JSON-RPC result objects of every tools/list page, in order. fetchErr is
// the error of fetching them, if any. A fetch error, a malformed page, an
// incomplete pagination or an unknown server yields a Surface that is
// unavailable as a whole: never one with an empty tool set.
func (p *Pin) Observe(server string, pages [][]byte, fetchErr error, observedAt time.Time) *Surface {
	s := &Surface{server: server, observedAt: observedAt}
	sp, ok := p.Servers[server]
	if !ok {
		s.err = ErrUnknownServer
		return s
	}
	s.pinned = sp.Tools
	if fetchErr != nil {
		s.err = fmt.Errorf("%w: tools/list failed: %w", ErrServerUnavailable, fetchErr)
		return s
	}
	live, err := parseListing(pages)
	if err != nil {
		s.err = fmt.Errorf("%w: %w", ErrServerUnavailable, err)
		return s
	}
	s.usable = map[string]struct{}{}
	s.denied = map[string][]DenyReason{}
	for name, pt := range sp.Tools {
		lt, ok := live.tools[name]
		if !ok {
			s.denied[name] = []DenyReason{DenyMissing}
			continue
		}
		var reasons []DenyReason
		if lt.inputSchemaSHA256 != pt.InputSchemaSHA256 {
			reasons = append(reasons, DenyChangedSchema)
		}
		if lt.descriptionSHA256 != pt.DescriptionSHA256 {
			reasons = append(reasons, DenyChangedDescription)
		}
		// Validate already proved the pinned annotations canonicalise.
		pinnedAnn, _ := canonicalAnnotations(pt.Annotations)
		if !bytes.Equal(lt.annotations, pinnedAnn) {
			reasons = append(reasons, DenyChangedAnnotations)
		}
		if len(reasons) > 0 {
			s.denied[name] = reasons
			continue
		}
		s.usable[name] = struct{}{}
	}
	for name := range live.tools {
		if _, ok := sp.Tools[name]; !ok {
			s.denied[name] = []DenyReason{DenyNotPinned}
		}
	}
	return s
}

// Server returns the server this surface describes.
func (s *Surface) Server() string { return s.server }

// Err returns nil when the server's listing was read and parsed, and the
// reason otherwise. A non-nil Err means every tool is unavailable.
func (s *Surface) Err() error { return s.err }

func (s *Surface) fresh(now time.Time) error {
	if s.err != nil {
		return s.err
	}
	// An observation stamped in the future is not trusted to be fresh.
	if s.observedAt.After(now) || now.Sub(s.observedAt) > ReadListingTTL {
		return ErrListingStale
	}
	return nil
}

// ModelTools returns the tools the model may be offered, sorted by name,
// with catalog descriptions and pinned schemas. It fails when the server is
// unavailable or the observation is stale; it never reports that as an
// empty list.
func (s *Surface) ModelTools(now time.Time) ([]ModelTool, error) {
	if err := s.fresh(now); err != nil {
		return nil, err
	}
	out := make([]ModelTool, 0, len(s.usable))
	for name := range s.usable {
		mt, err := modelTool(name, s.pinned[name])
		if err != nil {
			return nil, err
		}
		out = append(out, mt)
	}
	slices.SortFunc(out, func(a, b ModelTool) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out, nil
}

// modelTool is what the model is shown for one pinned tool: the catalog
// description and the canonical pinned schema. Nothing server-authored at
// call time reaches it.
func modelTool(name string, pt PinnedTool) (ModelTool, error) {
	schema, err := canonicalObject(pt.InputSchema)
	if err != nil {
		return ModelTool{}, fmt.Errorf("pa catalog: pinned schema of %s: %w", name, err)
	}
	return ModelTool{Name: name, Description: pt.CatalogDescription, InputSchema: schema}, nil
}

// ModelTool returns the model's view of one pinned tool, from the pin
// alone (the run loop's claim, #1318 slice C3). It is the entry
// Surface.ModelTools gives for the same tool; it does not say the tool is
// usable now, which only a fresh Surface does at dispatch.
func (p *Pin) ModelTool(server, tool string) (ModelTool, error) {
	sp, ok := p.Servers[server]
	if !ok {
		return ModelTool{}, ErrUnknownServer
	}
	pt, ok := sp.Tools[tool]
	if !ok {
		return ModelTool{}, ErrNotPinned
	}
	return modelTool(tool, pt)
}

// Denied returns the tools that cannot be used and why, sorted by name, for
// the "tool X is unavailable: it changed on the server" message. It is empty
// only when the listing was read; check Err first.
func (s *Surface) Denied() []DeniedTool {
	out := make([]DeniedTool, 0, len(s.denied))
	for name, r := range s.denied {
		out = append(out, DeniedTool{Name: name, Reasons: slices.Clone(r)})
	}
	slices.SortFunc(out, func(a, b DeniedTool) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return 0
	})
	return out
}

// Authorize decides whether a call to tool may be dispatched. The name is
// whatever the model proposed; it is looked up in the pin first, so a tool
// outside the pin is refused even if the server lists it. Phase 1 grants
// auto reads only: it is AuthorizeWrites with writes off.
func (s *Surface) Authorize(tool string, now time.Time) (Grant, error) {
	return s.AuthorizeWrites(tool, now, false)
}

// AuthorizeWrites is Authorize with the PA_WRITES_ENABLED switch (threat
// model T11). It grants auto reads only, whatever writes says. An
// approve-tier write or disclosure is refused with ErrApprovalRequired when
// writes is true and with ErrNoWritePath otherwise; neither ever grants.
// No runtime code passes true (P2-S1).
func (s *Surface) AuthorizeWrites(tool string, now time.Time, writes bool) (Grant, error) {
	if err := s.fresh(now); err != nil {
		return Grant{}, err
	}
	pt, ok := s.pinned[tool]
	if !ok {
		return Grant{}, ErrNotPinned
	}
	if _, ok := s.usable[tool]; !ok {
		return Grant{}, ErrToolChanged
	}
	if pt.Tier == TierAuto && pt.Class == ClassRead {
		return Grant{Server: s.server, Tool: tool, Tier: pt.Tier, Class: pt.Class, Lowerable: pt.Lowerable}, nil
	}
	if writes && pt.Tier == TierApprove && (pt.Class == ClassWrite || pt.Class == ClassDisclosure) {
		return Grant{}, ErrApprovalRequired
	}
	return Grant{}, ErrNoWritePath
}
