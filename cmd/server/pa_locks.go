package main

import (
	"context"

	"github.com/mctlhq/mctl-telegram/internal/sweeper"
)

// startPALockSweep starts the principal lock sweep (sweeper.PALocks,
// #1318). Unlike startPAState it takes no config and runs whatever
// PA_ENABLED says: an account deletion keeps an admitted principal's
// pa_principal_locks row as the deletion fence, and a PA turned off within
// pa.UpdatesRetention of that deletion must still delete the row, which
// carries the principal's Telegram id. main calls it unconditionally,
// outside startPAState (TestMainStartsPALockSweepUnconditionally). The
// sweep is the only owner of the statement; the PA state sweep no longer
// deletes lock rows, so with the PA on it does not run twice.
func startPALockSweep(ctx context.Context, store sweeper.PALockSweeper) {
	go sweeper.PALocks(ctx, store)
}
