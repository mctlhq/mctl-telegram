package sweeper

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
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
