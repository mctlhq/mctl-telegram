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

// WritesFlagEnv makes every PA write and disclosure "never" when off
// (threat model T11). Nothing dispatches a write yet (P2-S1).
const WritesFlagEnv = "PA_WRITES_ENABLED"

// EnvFlags reads the dispatch switches from the environment on every call,
// so turning one off takes effect at the next dispatch (S1-F4). Missing or
// empty is off; anything but "true" or "false" is unreadable, and an
// unreadable switch turns off exactly its own layer (threat model T11,
// S1-F1), never more and never less:
//
//   - PA_EXTERNAL_TOOLS_ENABLED gates every call, so an unreadable value is
//     an error that refuses the whole dispatch;
//   - PA_WRITES_ENABLED gates writes and disclosures only: an unreadable
//     value sets Writes false and WritesErr, and reads are unaffected;
//   - PA_SERVER_<NAME>_ENABLED gates one server: an unreadable value turns
//     that server off and records ServerErrs, and the others are unaffected.
//
// An unreadable switch is unknown, not off, so its error is recorded
// (WritesErr, ServerErrs) rather than folded into a plain false. Nothing
// reads those errors yet: they are kept for the slice that wires the gate
// (gate.Input.WritesErr) and for tests. Today the dispatcher looks only at
// the bools, so a malformed server flag is refused, and audited, exactly
// like an off one, as ReasonFlagOff.
func EnvFlags(getenv func(string) string) func() (Flags, error) {
	return func() (Flags, error) {
		ext, err := boolFlag(getenv, ExternalToolsFlagEnv)
		if err != nil {
			return Flags{}, err
		}
		out := Flags{ExternalTools: ext, Servers: map[string]bool{}, ServerErrs: map[string]error{}}
		// boolFlag and ServerFlag return false with their error.
		out.Writes, out.WritesErr = boolFlag(getenv, WritesFlagEnv)
		for _, s := range linking.FlagServers() {
			on, err := linking.ServerFlag(getenv, s)
			if err != nil {
				out.ServerErrs[string(s)] = err
			}
			out.Servers[string(s)] = on
		}
		return out, nil
	}
}

// boolFlag reads one switch: missing or empty is false, "true" and "false"
// are themselves, anything else is an error.
func boolFlag(getenv func(string) string, name string) (bool, error) {
	switch v := strings.TrimSpace(getenv(name)); v {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("pa connector: %s must be true or false", name)
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
