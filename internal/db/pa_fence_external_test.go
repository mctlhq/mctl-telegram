package db_test

import (
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa"
)

// The Begin fence of CreatePAConnection holds only while the principal's
// lock row lives, and the lock sweep keeps a row pa.UpdatesRetention
// unused. That must stay far longer than any Begin, or the sweep could drop
// a deletion mark while a Begin admitted before it is still running.
func TestPAPurgeFence_OutlivesBegin(t *testing.T) {
	if pa.UpdatesRetention < time.Hour {
		t.Fatalf("pa.UpdatesRetention = %s: the lock sweep could drop a deletion mark during a Begin", pa.UpdatesRetention)
	}
}
