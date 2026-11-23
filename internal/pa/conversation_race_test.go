package pa

import (
	"context"
	"database/sql"
	"math/rand/v2"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// blockingEnqueuer holds the first EnqueueRun, which runs inside the
// message's dedup transaction after its fragments are written, until
// release is closed. Later calls pass.
type blockingEnqueuer struct {
	entered chan struct{}
	release chan struct{}
	first   bool
}

func (b *blockingEnqueuer) EnqueueRun(ctx context.Context, _ *sql.Tx, _ RunRequest) error {
	if !b.first {
		b.first = true
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// TestConversations_S1N4_ConcurrentWithdraw is S1-N4 under concurrency,
// through the real webhook on Postgres: a message whose transaction is still
// open (consent read, conversation written) races /consent withdraw or
// /forget delivered in parallel. The command must wait for the message and
// then delete what it wrote; without HandleUpdate's per-principal lock it
// commits first under READ COMMITTED and the message's conversation
// survives it. SQLite serialises writers by itself, so this needs Postgres.
func TestConversations_S1N4_ConcurrentWithdraw(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; the race needs Postgres")
	}
	for _, cmd := range []string{"/consent withdraw", "/forget"} {
		t.Run(cmd, func(t *testing.T) {
			ctx := context.Background()
			conn, err := db.Open(ctx, dsn, 5, 2)
			if err != nil {
				t.Skipf("postgres not available: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := db.Migrate(ctx, conn); err != nil {
				t.Fatal(err)
			}
			store := db.NewStore(conn, nil)
			// Fresh synthetic ids: the Postgres database outlives the run.
			alice := 9_000_000_000 + rand.Int64N(1_000_000_000)
			firstUpdate := 8_000_000_000 + rand.Int64N(1_000_000_000)
			clean := func() {
				for _, q := range []string{
					`DELETE FROM pa_fragments WHERE principal = $1`,
					`DELETE FROM pa_conversations WHERE principal = $1`,
					`DELETE FROM pa_callbacks WHERE principal = $1`,
					`DELETE FROM pa_consents WHERE principal = $1`,
					`DELETE FROM pa_principal_locks WHERE principal = $1`,
				} {
					_, _ = conn.Exec(q, alice)
				}
				_, _ = conn.Exec(`DELETE FROM pa_updates WHERE update_id > $1 AND update_id <= $2`, firstUpdate, firstUpdate+100)
			}
			clean()
			t.Cleanup(clean)

			runs := &blockingEnqueuer{entered: make(chan struct{}), release: make(chan struct{})}
			h := newConvoHarnessOn(t, store, runs, firstUpdate)
			h.consent(alice)

			msg := make(chan int, 1)
			go func() { msg <- h.text(alice, "a question") }()
			select {
			case <-runs.entered:
			case code := <-msg:
				t.Fatalf("message finished (%d) without reaching the run loop", code)
			case <-time.After(10 * time.Second):
				t.Fatal("message never reached the run loop")
			}
			if h.conversations(alice) != 0 {
				t.Fatal("the open message transaction is visible outside it")
			}

			command := make(chan int, 1)
			go func() { command <- h.text(alice, cmd) }()
			select {
			case code := <-command:
				close(runs.release)
				<-msg
				t.Fatalf("%s finished (%d) while the message transaction was still open", cmd, code)
			case <-time.After(time.Second):
			}
			close(runs.release)
			if code := <-msg; code != http.StatusOK {
				t.Fatalf("message: %d", code)
			}
			select {
			case code := <-command:
				if code != http.StatusOK {
					t.Fatalf("%s: %d", cmd, code)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s never finished", cmd)
			}
			if f, c := h.fragments(alice), h.conversations(alice); f != 0 || c != 0 {
				t.Fatalf("after %s: %d fragments, %d conversations survive the racing message", cmd, f, c)
			}
		})
	}
}
