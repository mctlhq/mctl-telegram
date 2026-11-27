// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/pa/auditevent"
)

type fakeEventQueue struct {
	res    db.PAAuditDrain
	err    error
	limit  int
	render func(auditevent.Event) (db.ToolCall, error)

	queued   int64
	countErr error
}

func (f *fakeEventQueue) CountPAAuditEvents(context.Context) (int64, error) {
	return f.queued, f.countErr
}

func (f *fakeEventQueue) DrainPAAuditEvents(_ context.Context, limit int, render func(auditevent.Event) (db.ToolCall, error)) (db.PAAuditDrain, error) {
	f.limit, f.render = limit, render
	return f.res, f.err
}

// TestS2A8_AuditEventSweepReportsWhatItLeft: a pass that left an event
// queued, or could not read the queue, is an error, never a clean pass;
// and the row the sweeper renders is a "pa:" audit row whose status is the
// event kind and whose record is the event's, with no error text.
func TestS2A8_AuditEventSweepReportsWhatItLeft(t *testing.T) {
	ctx := context.Background()
	if _, err := (AuditEventSweeper{}).SweepOnce(ctx); err == nil {
		t.Fatal("a sweep without a store passed")
	}
	q := &fakeEventQueue{res: db.PAAuditDrain{Appended: 3}}
	res, err := AuditEventSweeper{Store: q}.SweepOnce(ctx)
	if err != nil || res.Appended != 3 || q.limit != AuditEventSweepLimit {
		t.Fatalf("clean pass: %+v, %v, limit %d", res, err, q.limit)
	}
	q.res = db.PAAuditDrain{Appended: 2, Failed: 1}
	if res, err := (AuditEventSweeper{Store: q}).SweepOnce(ctx); err == nil || res.Failed != 1 {
		t.Fatalf("a pass that left one event queued: %+v, %v", res, err)
	}
	q.res, q.err = db.PAAuditDrain{}, errors.New("injected: queue unreadable")
	if _, err := (AuditEventSweeper{Store: q}).SweepOnce(ctx); err == nil {
		t.Fatal("an unreadable queue was a clean pass")
	}

	e := auditevent.Event{Principal: 4242001, Kind: auditevent.PermissionRevoked, Subject: "prm_1", Server: "alice",
		Tool: "alice_set_volume", ConnectionID: "pac_1", AuthorityRevision: 5, Reason: auditevent.ReasonByPrincipal, AtMS: 1000}
	row, err := q.render(e)
	if err != nil {
		t.Fatal(err)
	}
	want := db.ToolCall{Tool: "pa:alice/alice_set_volume", Status: "permission_revoked", CallPath: AuditCallPath,
		PeerRedacted: "pa-event/v1 event=permission_revoked principal=4242001 server=alice tool=alice_set_volume conn=pac_1 rev=5 permission=prm_1 approval=- args=- reason=by_principal at=1000"}
	if row != want {
		t.Fatalf("audit row:\n %+v\nwant:\n %+v", row, want)
	}
	if !strings.HasPrefix(row.PeerRedacted, auditevent.RecordVersion+" ") || strings.HasPrefix(row.PeerRedacted, "pa/v1 ") {
		t.Fatalf("the record does not open with its own version: %s", row.PeerRedacted)
	}
	e.Tool = "alice set volume"
	if _, err := q.render(e); !errors.Is(err, ErrUnrecordable) {
		t.Fatalf("an event that does not render: %v, want ErrUnrecordable", err)
	}
}

// TestS2A8_AuditEventSweepIsCounted: each pass publishes the queue it left
// and what it could not do. A queue that could not be read or counted has
// no gauge, never 0; a pass cut off by shutdown publishes nothing.
func TestS2A8_AuditEventSweepIsCounted(t *testing.T) {
	ctx := context.Background()
	reg := metrics.New()
	q := &fakeEventQueue{res: db.PAAuditDrain{Appended: 1, Failed: 2, Dropped: 3}, queued: 2}
	s := AuditEventSweeper{Store: q, Metrics: reg}
	problem := func(p string) float64 {
		return testutil.ToFloat64(reg.PAAuditEventSweepProblems.WithLabelValues(p))
	}
	check := func(when string, unreadable, failed, dropped float64) {
		t.Helper()
		got := []float64{problem(AuditProblemQueueUnreadable), problem(AuditProblemAppendFailed), problem(AuditProblemDropped)}
		if want := []float64{unreadable, failed, dropped}; !slices.Equal(got, want) {
			t.Fatalf("%s: problems %v, want %v", when, got, want)
		}
	}
	gauge := func(when string, series int, value float64) {
		t.Helper()
		if n := testutil.CollectAndCount(reg.PAAuditEventsQueued); n != series {
			t.Fatalf("%s: %d queue series, want %d", when, n, series)
		}
		if series == 1 {
			if v := testutil.ToFloat64(reg.PAAuditEventsQueued.WithLabelValues()); v != value {
				t.Fatalf("%s: queue %v, want %v", when, v, value)
			}
		}
	}
	gauge("before any pass", 0, 0)
	if _, err := s.SweepOnce(ctx); err == nil {
		t.Fatal("a pass that left events was clean")
	}
	check("failed appends", 0, 2, 3)
	gauge("failed appends", 1, 2)

	q.res, q.countErr = db.PAAuditDrain{}, errors.New("injected: count")
	if _, err := s.SweepOnce(ctx); err == nil {
		t.Fatal("a pass that could not count the queue was clean")
	}
	check("count failed", 1, 2, 3)
	gauge("count failed", 0, 0)

	q.countErr, q.queued = nil, 0
	if _, err := s.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	gauge("emptied", 1, 0)

	q.err = errors.New("injected: queue unreadable")
	if _, err := s.SweepOnce(ctx); err == nil {
		t.Fatal("an unreadable queue was a clean pass")
	}
	check("queue unreadable", 2, 2, 3)
	gauge("queue unreadable", 0, 0)

	done, cancel := context.WithCancel(ctx)
	cancel()
	_, _ = s.SweepOnce(done)
	check("shutting down", 2, 2, 3)

	// Run creates every series at 0 before its first pass.
	fresh := metrics.New()
	AuditEventSweeper{Store: &fakeEventQueue{}, Metrics: fresh}.Run(done, time.Hour)
	if n := testutil.CollectAndCount(fresh.PAAuditEventSweepProblems); n != len(AuditEventProblems) || len(AuditEventProblems) != 3 {
		t.Fatalf("%d problem series after Run, want one per problem", n)
	}
}
