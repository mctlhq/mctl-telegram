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
	"fmt"
	"strings"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// ExternalToolsFlagEnv switches every PA MCP call off (threat model T11).
const ExternalToolsFlagEnv = "PA_EXTERNAL_TOOLS_ENABLED"

// EnvFlags reads the dispatch switches from the environment on every call,
// so turning one off takes effect at the next dispatch (S1-F4). Missing or
// empty is off; anything but "true" or "false" is an error, which refuses
// the call.
func EnvFlags(getenv func(string) string) func() (Flags, error) {
	return func() (Flags, error) {
		var ext bool
		switch v := strings.TrimSpace(getenv(ExternalToolsFlagEnv)); v {
		case "", "false":
		case "true":
			ext = true
		default:
			return Flags{}, fmt.Errorf("pa connector: %s must be true or false", ExternalToolsFlagEnv)
		}
		servers, err := linking.LoadServerFlags(getenv)
		if err != nil {
			return Flags{}, err
		}
		out := Flags{ExternalTools: ext, Servers: map[string]bool{}}
		for s, on := range servers {
			out.Servers[string(s)] = on
		}
		return out, nil
	}
}

// FenceAudit records the connection manager's fence events (S1-C7) in the
// principal's hash-chained audit log, next to the call's own result entry.
// It implements connection.FenceAuditor.
type FenceAudit struct {
	Sink Sink
	Now  func() time.Time
}

// fenceTool is the tool field of a fence record: the event belongs to the
// connection, not to one tool.
const fenceTool = "-"

// RecordFenced implements connection.FenceAuditor.
func (f FenceAudit) RecordFenced(ctx context.Context, ev connection.FenceEvent) error {
	if f.Sink == nil {
		return fmt.Errorf("%w: no sink", ErrUnrecordable)
	}
	callID, err := newCallID()
	if err != nil {
		return fmt.Errorf("%w: call id: %v", ErrUnrecordable, err)
	}
	now := time.Now()
	if f.Now != nil {
		now = f.Now()
	}
	reason := "fence_" + ev.Reason
	if !reasonRE.MatchString(reason) {
		reason = "fence_" + ReasonInternal
	}
	server := string(ev.Server)
	if _, ok := connection.AllowedScopes(ev.Server); !ok {
		server = invalidServer
	}
	return f.Sink.Append(ctx, Entry{
		CallID:            callID,
		Phase:             PhaseResult,
		Principal:         ev.Principal,
		ConnectionID:      recordable(ev.ConnectionID, unboundConnection),
		AuthorityRevision: ev.BoundRevision,
		Server:            server,
		Tool:              fenceTool,
		ArgsSHA256:        digest(nil),
		Taint:             TaintExternal,
		Status:            StatusFenced,
		Reason:            reason,
		At:                now,
	})
}

var _ connection.FenceAuditor = FenceAudit{}
