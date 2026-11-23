package sweeper

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
)

// sweepOnlyStore answers SweepPAState with a fixed result.
type sweepOnlyStore struct {
	convo.Store
	r convo.SweepResult
}

func (s sweepOnlyStore) SweepPAState(context.Context, time.Time, time.Time) (convo.SweepResult, error) {
	return s.r, nil
}

// A pass that deleted only linking secrets still logs, with their count
// (#1338).
func TestPAStateSweepOnce_LogsLinkSecrets(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	PAStateSweepOnce(context.Background(), sweepOnlyStore{r: convo.SweepResult{LinkSecrets: 3}}, time.Now())
	if out := buf.String(); !strings.Contains(out, "pa state sweep") || !strings.Contains(out, "link_secrets=3") {
		t.Fatalf("sweep log = %q, want the pass logged with link_secrets=3", out)
	}
}

// fakeLinkExpirer records ExpireStale calls.
type fakeLinkExpirer struct {
	limits []int
	r      linking.SweepResult
	err    error
}

func (f *fakeLinkExpirer) ExpireStale(_ context.Context, limit int) (linking.SweepResult, error) {
	f.limits = append(f.limits, limit)
	return f.r, f.err
}

// One linking pass calls ExpireStale with the bounded limit and logs its
// counts; an incomplete pass logs the error with the counts it did reach.
func TestPALinksSweepOnce(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	f := &fakeLinkExpirer{r: linking.SweepResult{Failed: 2, Skipped: 1}}
	if r := PALinksSweepOnce(context.Background(), f); r != f.r {
		t.Fatalf("result %+v, want %+v", r, f.r)
	}
	if len(f.limits) != 1 || f.limits[0] != PALinkSweepLimit {
		t.Fatalf("ExpireStale limits %v, want one call with %d", f.limits, PALinkSweepLimit)
	}
	if out := buf.String(); !strings.Contains(out, "pa link sweep") || !strings.Contains(out, "failed=2") {
		t.Fatalf("log %q, want the pass with failed=2", out)
	}
	buf.Reset()
	f.r, f.err = linking.SweepResult{Errors: 1}, errors.New("store down")
	PALinksSweepOnce(context.Background(), f)
	if out := buf.String(); !strings.Contains(out, "incomplete") || !strings.Contains(out, "errors=1") || !strings.Contains(out, "store down") {
		t.Fatalf("log %q, want the incomplete pass with its error", out)
	}
}

// The linking sweep runs often enough that a pending connection is failed
// within PendingMaxAge plus one interval, not an hour later.
func TestPALinkSweeperInterval_Bound(t *testing.T) {
	if PALinkSweeperInterval > linking.PendingMaxAge/2 {
		t.Fatalf("PALinkSweeperInterval = %s, want at most half of linking.PendingMaxAge (%s)",
			PALinkSweeperInterval, linking.PendingMaxAge)
	}
}
