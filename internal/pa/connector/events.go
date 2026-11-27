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
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/auditevent"
)

// AuditEventStore is the queue of audit events that are not tool calls
// (*db.Store): a permission granted or revoked, an approval cancelled.
type AuditEventStore interface {
	DrainPAAuditEvents(ctx context.Context, limit int, render func(auditevent.Event) (db.ToolCall, error)) (db.PAAuditDrain, error)
	CountPAAuditEvents(ctx context.Context) (int64, error)
}

// AuditEventMetrics is what the sweeper reports (*metrics.Registry).
type AuditEventMetrics interface {
	SetPAAuditEventsQueued(n int64)
	ForgetPAAuditEventsQueued()
	CountPAAuditEventProblem(problem string, n int)
}

// The closed label set of mctl_pa_audit_event_sweep_problems_total: a pass
// that could not read or count the queue, an event that was not appended
// and is still queued, and an event dropped because its principal has no
// users row.
const (
	AuditProblemQueueUnreadable = "queue_unreadable"
	AuditProblemAppendFailed    = "append_failed"
	AuditProblemDropped         = "dropped"
)

// AuditEventProblems lists them, to create each series at 0.
var AuditEventProblems = []string{AuditProblemQueueUnreadable, AuditProblemAppendFailed, AuditProblemDropped}

const (
	// AuditEventSweepInterval is how often queued events are appended to
	// the audit chain: an event is in the chain within about this long of
	// the change it records.
	AuditEventSweepInterval = time.Minute
	// AuditEventSweepLimit bounds one pass. A pass that fills it leaves
	// the rest for the next.
	AuditEventSweepLimit = 200
)

// AuditEventRow renders the audit row of one event, as StoreSink renders
// a tool call's: tool_name "pa:<server>/<tool>", the event's digest record
// in peer_redacted, the event kind as status, call_path "pa", no error
// text. The record opens with auditevent.RecordVersion, not "pa/v1".
func AuditEventRow(e auditevent.Event) (db.ToolCall, error) {
	record, err := e.Record()
	if err != nil {
		return db.ToolCall{}, fmt.Errorf("%w: %v", ErrUnrecordable, err)
	}
	return db.ToolCall{
		Tool:         AuditToolPrefix + e.Server + "/" + e.Tool,
		PeerRedacted: record,
		Status:       string(e.Kind),
		CallPath:     AuditCallPath,
	}, nil
}

// AuditEventSweeper appends the queued events to the audit chain (threat
// model T12; S2-A8, S2-C9). The change that queued an event has already
// committed, so nothing waits for the sweeper; an event it cannot append
// stays queued and is tried again.
type AuditEventSweeper struct {
	Store AuditEventStore
	// Metrics is optional.
	Metrics AuditEventMetrics
}

// SweepOnce runs one pass. The error is that of a queue that could not be
// read, or of events that could not be appended and are still queued: a
// pass is never reported clean while a row it tried is left behind.
func (s AuditEventSweeper) SweepOnce(ctx context.Context) (db.PAAuditDrain, error) {
	if s.Store == nil {
		return db.PAAuditDrain{}, errors.New("pa audit event sweep: no store")
	}
	res, err := s.Store.DrainPAAuditEvents(ctx, AuditEventSweepLimit, AuditEventRow)
	countErr := s.report(ctx, res, err)
	if err != nil {
		return res, err
	}
	if res.Failed > 0 {
		return res, fmt.Errorf("pa audit event sweep: %d events not appended, still queued", res.Failed)
	}
	return res, countErr
}

// report publishes one pass: its problems, and how many events are queued
// after it. The error is that of a queue that could not be counted. A pass
// cut off by ctx ending reports nothing: a shutdown is no problem of the
// queue.
func (s AuditEventSweeper) report(ctx context.Context, res db.PAAuditDrain, drainErr error) error {
	if s.Metrics == nil || ctx.Err() != nil {
		return nil
	}
	s.Metrics.CountPAAuditEventProblem(AuditProblemAppendFailed, res.Failed)
	s.Metrics.CountPAAuditEventProblem(AuditProblemDropped, res.Dropped)
	var (
		queued int64
		err    = drainErr
	)
	if err == nil {
		queued, err = s.Store.CountPAAuditEvents(ctx)
	}
	if err != nil {
		if ctx.Err() == nil {
			s.Metrics.CountPAAuditEventProblem(AuditProblemQueueUnreadable, 1)
			s.Metrics.ForgetPAAuditEventsQueued()
		}
		return fmt.Errorf("pa audit event sweep: queue not counted: %w", err)
	}
	s.Metrics.SetPAAuditEventsQueued(queued)
	return nil
}

// Run sweeps every interval (AuditEventSweepInterval if 0) until ctx ends,
// starting with one pass at once.
func (s AuditEventSweeper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = AuditEventSweepInterval
	}
	if s.Metrics != nil {
		// Each series exists at 0, so that increase() sees the first one.
		for _, p := range AuditEventProblems {
			s.Metrics.CountPAAuditEventProblem(p, 0)
		}
	}
	pass := func() {
		res, err := s.SweepOnce(ctx)
		if err != nil {
			slog.Error("pa audit event sweep failed", "appended", res.Appended, "failed", res.Failed, "err", err)
			return
		}
		if res.Appended > 0 || res.Dropped > 0 {
			slog.Info("pa audit event sweep", "appended", res.Appended, "dropped", res.Dropped)
		}
	}
	pass()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}
