package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// testOutboxBuilder stands in for internal/events: identifiers only.
func testOutboxBuilder(ev IncomingEvent, _ time.Time) (OutboxRow, bool, error) {
	if ev.Kind != EventKindPrivateMessage && ev.Kind != EventKindMessageEdit {
		return OutboxRow{}, false, nil
	}
	return OutboxRow{EventID: ev.EventID, Stream: "mctl:events:telegram",
		Envelope: `{"id":"telegram:` + ev.EventID + `"}`}, true, nil
}

func ingestForOutbox(t *testing.T, s *Store, uid int64, eventID, body string) (bool, error) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "peer", "Peer")
	if err != nil {
		t.Fatalf("ensure conversation: %v", err)
	}
	_, enqueued, err := s.InsertEventEnqueueJobAndTouch(ctx, IncomingEvent{
		EventID: eventID, UserID: uid, Kind: EventKindPrivateMessage,
		ChatTGID: 555, SenderTGID: 555, MessageID: 42, Body: body,
	}, conv.ID)
	return enqueued, err
}

func outboxCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM event_outbox`).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	return n
}

func TestEventOutbox_WrittenWithIngestAndDeduplicated(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t).WithEventOutbox(testOutboxBuilder)
	uid := seedAgentUser(t, s, "owner")

	if ok, err := ingestForOutbox(t, s, uid, "evt:v1:1:555:42", "the secret message text"); err != nil || !ok {
		t.Fatalf("ingest: ok=%v err=%v", ok, err)
	}
	// gotd redelivers after a crash: the duplicate must not add a second row.
	if ok, err := ingestForOutbox(t, s, uid, "evt:v1:1:555:42", "the secret message text"); err != nil || ok {
		t.Fatalf("duplicate ingest: ok=%v err=%v", ok, err)
	}
	rows, err := s.PendingOutbox(ctx, 10)
	if err != nil {
		t.Fatalf("pending: %v", err)
	}
	if len(rows) != 1 || rows[0].EventID != "evt:v1:1:555:42" || rows[0].UserID != uid {
		t.Fatalf("pending = %+v, want the one event", rows)
	}
	if strings.Contains(rows[0].Envelope, "secret") {
		t.Fatalf("outbox envelope carries message text: %s", rows[0].Envelope)
	}
}

func TestEventOutbox_DisabledWritesNothing(t *testing.T) {
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	if ok, err := ingestForOutbox(t, s, uid, "evt:v1:1:555:43", "hi"); err != nil || !ok {
		t.Fatalf("ingest: ok=%v err=%v", ok, err)
	}
	if n := outboxCount(t, s); n != 0 {
		t.Fatalf("outbox rows = %d with the outbox disabled, want 0", n)
	}
}

func TestEventOutbox_BuildFailureRollsBackTheIngest(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("boom")
	s := newTestStoreCrypted(t).WithEventOutbox(func(IncomingEvent, time.Time) (OutboxRow, bool, error) {
		return OutboxRow{}, false, boom
	})
	uid := seedAgentUser(t, s, "owner")
	if _, err := ingestForOutbox(t, s, uid, "evt:v1:1:555:44", "hi"); !errors.Is(err, boom) {
		t.Fatalf("ingest err = %v, want the build failure", err)
	}
	// Event and publication intent commit together or not at all.
	if _, err := s.GetIncomingEvent(ctx, uid, "evt:v1:1:555:44"); !errors.Is(err, ErrIncomingEventNotFound) {
		t.Fatalf("incoming event after rollback: err=%v, want not found", err)
	}
	if n := outboxCount(t, s); n != 0 {
		t.Fatalf("outbox rows = %d after rollback, want 0", n)
	}
}

func TestEventOutbox_PublishLifecycle(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t).WithEventOutbox(testOutboxBuilder)
	exerciseOutboxLifecycle(ctx, t, s, "evt:v1:9:555:")
}

func exerciseOutboxLifecycle(ctx context.Context, t *testing.T, s *Store, prefix string) {
	t.Helper()
	uid := seedAgentUser(t, s, "outbox-owner")
	baseline, err := s.OutboxBacklog(ctx)
	if err != nil {
		t.Fatalf("baseline backlog: %v", err)
	}
	for _, id := range []string{prefix + "1", prefix + "2"} {
		if ok, err := ingestForOutbox(t, s, uid, id, "hi"); err != nil || !ok {
			t.Fatalf("ingest %s: ok=%v err=%v", id, ok, err)
		}
	}
	// A shared database may hold other rows; only this run's rows are asserted.
	mine := func() []OutboxRow {
		all, err := s.PendingOutbox(ctx, 10000)
		if err != nil {
			t.Fatalf("pending: %v", err)
		}
		var out []OutboxRow
		for _, r := range all {
			if strings.HasPrefix(r.EventID, prefix) {
				out = append(out, r)
			}
		}
		return out
	}
	rows := mine()
	if len(rows) != 2 || rows[0].ID > rows[1].ID {
		t.Fatalf("pending = %+v, want two rows oldest first", rows)
	}
	// 803 bytes: the cut at 500 falls inside a two-byte rune, which Postgres
	// would reject as invalid UTF-8 if the truncation split it.
	if err := s.MarkOutboxFailed(ctx, rows[0].ID, strings.Repeat("ж", 401)+"x"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	now := time.Now().UTC()
	if err := s.MarkOutboxPublished(ctx, rows[1].ID, now); err != nil {
		t.Fatalf("mark published: %v", err)
	}
	if n, err := s.OutboxBacklog(ctx); err != nil || n != baseline+1 {
		t.Fatalf("backlog = %d err=%v, want baseline+1 = %d", n, err, baseline+1)
	}
	left := mine()
	if len(left) != 1 || left[0].ID != rows[0].ID || left[0].Attempts != 1 {
		t.Fatalf("pending after publish = %+v, want the failed row with one attempt", left)
	}
	if n, err := s.PurgePublishedOutbox(ctx, now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("purge before publish time removed %d err=%v, want 0", n, err)
	}
	if n, err := s.PurgePublishedOutbox(ctx, now.Add(time.Hour)); err != nil || n < 1 {
		t.Fatalf("purge removed %d err=%v, want at least this run's published row", n, err)
	}
}

func TestEventOutbox_PostgresLifecycle(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	conn, err := Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	// Cleanups run last-in first-out: close is registered first so the row
	// cleanup below still has an open connection. A deferred Close would run
	// before any t.Cleanup and silently skip it, leaving rows that make the
	// next run's ingest a duplicate.
	t.Cleanup(func() { _ = conn.Close() })
	if err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// Unique per run, so leftovers from an earlier run cannot collide either.
	prefix := fmt.Sprintf("evt:v1:9:%d:", time.Now().UnixNano())
	t.Cleanup(func() {
		like := prefix + "%"
		_, _ = conn.ExecContext(ctx, `DELETE FROM event_outbox WHERE event_id LIKE $1`, like)
		_, _ = conn.ExecContext(ctx, `DELETE FROM agent_jobs WHERE event_id LIKE $1`, like)
		_, _ = conn.ExecContext(ctx, `DELETE FROM incoming_events WHERE event_id LIKE $1`, like)
	})
	c, err := crypto.New(makeKey())
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	// Crypt is required: the ingest seals the message body before the insert.
	s := (&Store{DB: conn, Crypt: c}).WithEventOutbox(testOutboxBuilder)
	exerciseOutboxLifecycle(ctx, t, s, prefix)
}
