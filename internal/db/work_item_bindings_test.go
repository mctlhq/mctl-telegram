package db

import (
	"context"
	"os"
	"testing"
)

// TestWorkItemBindings is T1: dual-dialect store round-trip covering
// upsert-then-get, the thread uniqueness constraint, two threads of one
// user bound to the same work item (both rows kept), TouchWorkItemBindingState
// updating both, SetWorkItemBindingRequest updating only its own thread, and
// ON DELETE CASCADE when the user row goes away.
func TestWorkItemBindings(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		assertWorkItemBindings(t, newTestStore(t))
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		s := newPostgresTestStore(t, dsn)
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM work_item_bindings`) })
		assertWorkItemBindings(t, s)
	})
}

func assertWorkItemBindings(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()

	uid, err := s.EnsureUserByTelegramID(ctx, 700100, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	const chatTGID = int64(700100)
	const issueURL = "https://github.com/mctlhq/mctl-telegram/issues/443"

	// upsert-then-get.
	if err := s.UpsertWorkItemBinding(ctx, WorkItemBinding{
		UserID: uid, ChatTGID: chatTGID, RootTGMessageID: 1,
		WorkItemID: "wi_1", ExternalKey: issueURL,
		LastState: "active", LastStateVersion: 1,
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, found, err := s.GetWorkItemBinding(ctx, uid, chatTGID, 1)
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if got.WorkItemID != "wi_1" || got.ExternalKey != issueURL || got.LastState != "active" {
		t.Fatalf("got = %+v", got)
	}

	// Upsert on the SAME thread key updates in place (the uniqueness
	// constraint on (user_id, chat_tg_id, root_tg_message_id)).
	if err := s.UpsertWorkItemBinding(ctx, WorkItemBinding{
		UserID: uid, ChatTGID: chatTGID, RootTGMessageID: 1,
		WorkItemID: "wi_1", ExternalKey: issueURL,
		LastState: "waiting", LastStateVersion: 2,
	}); err != nil {
		t.Fatalf("upsert again: %v", err)
	}
	got, found, err = s.GetWorkItemBinding(ctx, uid, chatTGID, 1)
	if err != nil || !found || got.LastState != "waiting" || got.LastStateVersion != 2 {
		t.Fatalf("after re-upsert: got=%+v found=%v err=%v", got, found, err)
	}
	var rowCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM work_item_bindings WHERE user_id=$1`, uid).Scan(&rowCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rowCount != 1 {
		t.Fatalf("row count after re-upsert of the same thread = %d, want 1", rowCount)
	}

	// Two threads of one user bound to the SAME work item: both rows kept.
	if err := s.UpsertWorkItemBinding(ctx, WorkItemBinding{
		UserID: uid, ChatTGID: chatTGID, RootTGMessageID: 2,
		WorkItemID: "wi_1", ExternalKey: issueURL,
		LastState: "active", LastStateVersion: 1,
	}); err != nil {
		t.Fatalf("upsert second thread: %v", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM work_item_bindings WHERE user_id=$1 AND work_item_id=$2`, uid, "wi_1").Scan(&rowCount); err != nil {
		t.Fatalf("count by item: %v", err)
	}
	if rowCount != 2 {
		t.Fatalf("rows bound to wi_1 = %d, want 2 (two threads, one item)", rowCount)
	}

	// TouchWorkItemBindingState is item-level: it must update BOTH threads.
	if err := s.TouchWorkItemBindingState(ctx, uid, "wi_1", "completed", 5, "exec_9"); err != nil {
		t.Fatalf("touch state: %v", err)
	}
	for _, rootMsgID := range []int64{1, 2} {
		b, found, err := s.GetWorkItemBinding(ctx, uid, chatTGID, rootMsgID)
		if err != nil || !found {
			t.Fatalf("get thread %d: found=%v err=%v", rootMsgID, found, err)
		}
		if b.LastState != "completed" || b.LastStateVersion != 5 || b.LastExecutionID != "exec_9" {
			t.Fatalf("thread %d after touch = %+v, want completed/5/exec_9", rootMsgID, b)
		}
	}

	// SetWorkItemBindingRequest is thread-level: only the named thread's
	// last_request_id changes.
	if err := s.SetWorkItemBindingRequest(ctx, uid, chatTGID, 1, "xr_1"); err != nil {
		t.Fatalf("set request thread 1: %v", err)
	}
	thread1, _, err := s.GetWorkItemBinding(ctx, uid, chatTGID, 1)
	if err != nil {
		t.Fatalf("get thread 1: %v", err)
	}
	thread2, _, err := s.GetWorkItemBinding(ctx, uid, chatTGID, 2)
	if err != nil {
		t.Fatalf("get thread 2: %v", err)
	}
	if thread1.LastRequestID != "xr_1" {
		t.Fatalf("thread 1 LastRequestID = %q, want xr_1", thread1.LastRequestID)
	}
	if thread2.LastRequestID != "" {
		t.Fatalf("thread 2 LastRequestID = %q, want empty (request is thread-scoped)", thread2.LastRequestID)
	}

	// LatestWorkItemBinding returns the most recently updated row for the
	// chat.
	latest, found, err := s.LatestWorkItemBinding(ctx, uid, chatTGID)
	if err != nil || !found {
		t.Fatalf("latest: found=%v err=%v", found, err)
	}
	if latest.RootTGMessageID != 1 {
		t.Fatalf("latest.RootTGMessageID = %d, want 1 (most recently touched by SetWorkItemBindingRequest)", latest.RootTGMessageID)
	}

	// A never-bound thread reports found=false, not an error.
	_, found, err = s.GetWorkItemBinding(ctx, uid, chatTGID, 999)
	if err != nil {
		t.Fatalf("get missing thread: %v", err)
	}
	if found {
		t.Fatal("get missing thread reported found=true")
	}

	// ON DELETE CASCADE: removing the user removes its bindings. SQLite only
	// enforces this with foreign_keys pragma ON for the connection — assert
	// it there explicitly rather than through the shared newTestStore
	// connection (which, like every other table's cascade in this package,
	// is not exercised against the default SQLite test connection).
	assertWorkItemBindingsCascade(t, s.isPostgres(ctx))
}

func assertWorkItemBindingsCascade(t *testing.T, postgres bool) {
	t.Helper()
	ctx := context.Background()
	var s *Store
	if postgres {
		dsn := os.Getenv("TEST_DATABASE_URL")
		s = newPostgresTestStore(t, dsn)
	} else {
		conn, err := Open(ctx, "file::memory:?cache=shared&_pragma=foreign_keys(1)", 0, 0)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		if err := Migrate(ctx, conn); err != nil {
			t.Fatalf("migrate: %v", err)
		}
		s = &Store{DB: conn}
	}
	uid, err := s.EnsureUserByTelegramID(ctx, 700200, "cascade", "Cascade")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.UpsertWorkItemBinding(ctx, WorkItemBinding{
		UserID: uid, ChatTGID: 700200, RootTGMessageID: 1,
		WorkItemID: "wi_cascade", ExternalKey: "https://github.com/mctlhq/mctl-telegram/issues/1",
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, uid); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	var rowCount int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM work_item_bindings WHERE user_id=$1`, uid).Scan(&rowCount); err != nil {
		t.Fatalf("count after user delete: %v", err)
	}
	if rowCount != 0 {
		t.Fatalf("bindings after user delete = %d, want 0 (ON DELETE CASCADE)", rowCount)
	}
}
