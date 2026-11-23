package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
)

// Conversation-level outbox rows (#1348) on both dialects, and the
// migration of a pa_outbox created before them.

func TestPAOutboxConversation_SQLite(t *testing.T) {
	runPAOutboxConversationSuite(t, newTestStore(t))
}

func TestPAOutboxConversationPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	runPAOutboxConversationSuite(t, newPostgresTestStore(t, dsn))
}

func convReply(p, update int64, k jobs.OutboxKind, button string) jobs.OutboxItem {
	return jobs.OutboxItem{Principal: p, UpdateID: update, Kind: k, Button: button}
}

func runPAOutboxConversationSuite(t *testing.T, s *Store) {
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("a conversation row is written only with its transaction, once per principal, update and kind", func(t *testing.T) {
		paOutboxReset(t, s)
		u := paJobID(t, 10)
		outboxEnqueue(t, s, now, false, convReply(paAlice, u, jobs.OutboxConsentPrompt, "btn-a"))
		if n := len(outboxRows(t, s, paAlice)); n != 0 {
			t.Fatalf("%d rows survived a rolled-back transaction", n)
		}
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		// A failed assertion must not leave the transaction open: on SQLite
		// (one connection) every later test would wait on it until the
		// package timeout. After Commit this is a no-op (ErrTxDone).
		defer func() { _ = tx.Rollback() }()
		for i, it := range []jobs.OutboxItem{
			convReply(paAlice, u, jobs.OutboxConsentStale, ""),
			convReply(paAlice, u, jobs.OutboxConsentPrompt, "btn-a"),
			// Same principal, update and kind: nothing is written, and
			// the conflict is reported, not swallowed (update id reuse).
			convReply(paAlice, u, jobs.OutboxConsentPrompt, "btn-a2"),
			// The same update id of another principal is another key;
			// the transaction is still usable after the conflict.
			convReply(paBob, u, jobs.OutboxConsentPrompt, "btn-b"),
		} {
			err := s.EnqueuePAOutbox(ctx, tx, it, now)
			if want := i == 2; want != errors.Is(err, jobs.ErrOutboxUpdateReused) || (!want && err != nil) {
				t.Fatalf("enqueue %d = %v", i, err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		rows := outboxRows(t, s, paAlice)
		if len(rows) != 2 || rows[0].Kind != jobs.OutboxConsentStale || rows[1].Kind != jobs.OutboxConsentPrompt {
			t.Fatalf("alice rows = %+v", rows)
		}
		p := rows[1]
		if p.JobID != 0 || p.UpdateID != u || p.Button != "btn-a" || p.Status != jobs.OutboxPending {
			t.Fatalf("prompt row = %+v", p)
		}
		if n := len(outboxRows(t, s, paBob)); n != 1 {
			t.Fatalf("bob rows = %d, want 1", n)
		}
	})

	t.Run("job and conversation rows of a principal go out in order, with their fields", func(t *testing.T) {
		paOutboxReset(t, s)
		j, u := paJobID(t, 11), paJobID(t, 12)
		outboxEnqueue(t, s, now, true, notice(paAlice, j, jobs.OutboxRunFailed))
		outboxEnqueue(t, s, now, true, convReply(paAlice, u, jobs.OutboxConsentPrompt, "btn-c"))
		first := outboxClaim(t, s, now, paAlice)
		if len(first.Items) != 1 || first.Items[0].JobID != j || first.Items[0].UpdateID != 0 {
			t.Fatalf("first claim = %+v", first.Items)
		}
		if err := s.CompletePAOutbox(ctx, first.Items[0], jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}); err != nil {
			t.Fatal(err)
		}
		second := outboxClaim(t, s, now, paAlice)
		if len(second.Items) != 1 {
			t.Fatalf("second claim = %+v", second.Items)
		}
		it := second.Items[0]
		if it.JobID != 0 || it.UpdateID != u || it.Kind != jobs.OutboxConsentPrompt || it.Button != "btn-c" || it.Attempts != 1 {
			t.Fatalf("claimed prompt = %+v", it)
		}
	})

	t.Run("a conversation row past its sending lease is unknown and never claimed again", func(t *testing.T) {
		paOutboxReset(t, s)
		outboxEnqueue(t, s, now, true, convReply(paAlice, paJobID(t, 13), jobs.OutboxForgotten, ""))
		if res := outboxClaim(t, s, now, paAlice); len(res.Items) != 1 {
			t.Fatalf("claim = %+v", res)
		}
		later := now.Add(jobs.OutboxLease + time.Second)
		res := outboxClaim(t, s, later, paAlice)
		if res.Unknown != 1 || len(res.Items) != 0 {
			t.Fatalf("after lease = %+v, want one unknown and nothing claimed", res)
		}
		if res := outboxClaim(t, s, later.Add(time.Hour), paAlice); len(res.Items) != 0 || res.Unknown != 0 {
			t.Fatalf("unknown row claimed again: %+v", res)
		}
	})

	t.Run("forget deletes pending job notices and keeps conversation rows", func(t *testing.T) {
		paOutboxReset(t, s)
		outboxEnqueue(t, s, now, true,
			notice(paAlice, paJobID(t, 14), jobs.OutboxRunFailed),
			convReply(paAlice, paJobID(t, 15), jobs.OutboxConsentPrompt, "btn-d"))
		tx, err := s.DB.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ForgetPAConversations(ctx, tx, paAlice); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		rows := outboxRows(t, s, paAlice)
		if len(rows) != 1 || rows[0].Kind != jobs.OutboxConsentPrompt {
			t.Fatalf("after forget = %+v, want only the prompt", rows)
		}
	})

	t.Run("malformed conversation rows are refused before any write", func(t *testing.T) {
		paOutboxReset(t, s)
		u := paJobID(t, 16)
		long := make([]byte, jobs.MaxOutboxButton+1)
		for i := range long {
			long[i] = 'a'
		}
		for _, it := range []jobs.OutboxItem{
			convReply(paAlice, 0, jobs.OutboxForgotten, ""),                         // no update
			convReply(paAlice, u, jobs.OutboxConsentPrompt, ""),                     // prompt without its button
			convReply(paAlice, u, jobs.OutboxForgotten, "btn"),                      // a button on another kind
			convReply(paAlice, u, jobs.OutboxConsentPrompt, string(long)),           // over callback_data
			{Principal: paAlice, JobID: 5, UpdateID: u, Kind: jobs.OutboxForgotten}, // both keys
			{Principal: paAlice, UpdateID: u, Kind: jobs.OutboxRunFailed},           // job kind without a job
		} {
			tx, err := s.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			err = s.EnqueuePAOutbox(ctx, tx, it, now)
			_ = tx.Rollback()
			if !errors.Is(err, jobs.ErrInvalid) {
				t.Fatalf("enqueue %+v = %v, want ErrInvalid", it, err)
			}
		}
	})
}

// prePR1348OutboxDDL is pa_outbox as released before #1348.
func prePR1348OutboxDDL(pg bool) string {
	intT, idT := "INTEGER", "INTEGER PRIMARY KEY AUTOINCREMENT"
	if pg {
		intT, idT = "BIGINT", "BIGSERIAL PRIMARY KEY"
	}
	return `CREATE TABLE pa_outbox (
			id ` + idT + `,
			principal ` + intT + ` NOT NULL,
			job_id ` + intT + ` NOT NULL,
			kind TEXT NOT NULL,
			conversation_id TEXT NOT NULL DEFAULT '',
			fragment_seq ` + intT + ` NOT NULL DEFAULT 0,
			status TEXT NOT NULL,
			attempts ` + intT + ` NOT NULL DEFAULT 0,
			sent_parts ` + intT + ` NOT NULL DEFAULT 0,
			next_at_ms ` + intT + ` NOT NULL,
			lease_until_ms ` + intT + ` NOT NULL DEFAULT 0,
			created_at_ms ` + intT + ` NOT NULL,
			updated_at_ms ` + intT + ` NOT NULL,
			UNIQUE (job_id, kind)
		)`
}

// TestPAOutboxMigratesPre1348Table: a pa_outbox with job_id NOT NULL takes
// conversation rows after Migrate, its rows survive with their fields, the
// (job, kind) key still holds, and a second Migrate changes nothing.
func TestPAOutboxMigratesPre1348Table(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		ctx := context.Background()
		conn, err := Open(ctx, fmt.Sprintf("file:pa_outbox_mig_%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		checkPre1348Migration(t, conn, false)
	})
	t.Run("postgres", func(t *testing.T) {
		dsn := os.Getenv("TEST_DATABASE_URL")
		if dsn == "" {
			t.Skip("TEST_DATABASE_URL not set")
		}
		checkPre1348Migration(t, emptyPostgresSchema(t, dsn), true)
	})
}

func checkPre1348Migration(t *testing.T, conn *sql.DB, pg bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := conn.ExecContext(ctx, prePR1348OutboxDDL(pg)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO pa_outbox(principal, job_id, kind, conversation_id, fragment_seq, status, attempts, sent_parts,
		                       next_at_ms, created_at_ms, updated_at_ms)
		 VALUES(555, 41, 'reply', 'conv-1', 3, 'pending', 2, 1, 1000, 900, 950)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, conn); err != nil {
			t.Fatalf("migrate %d: %v", i+1, err)
		}
	}
	s := &Store{DB: conn}
	rows, err := s.PAOutboxRows(ctx, 555)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows after migrate = %+v", rows)
	}
	r := rows[0]
	if r.JobID != 41 || r.Kind != jobs.OutboxReply || r.ConversationID != "conv-1" || r.FragmentSeq != 3 ||
		r.Attempts != 2 || r.SentParts != 1 || r.Status != jobs.OutboxPending || r.UpdateID != 0 || r.Button != "" ||
		r.NextAt.UnixMilli() != 1000 {
		t.Fatalf("migrated row = %+v", r)
	}
	now := time.UnixMilli(2000)
	outboxEnqueue(t, s, now, true,
		notice(555, 42, jobs.OutboxRunFailed), notice(555, 42, jobs.OutboxRunFailed),
		convReply(555, 7, jobs.OutboxConsentPrompt, "btn"),
		convReply(555, 7, jobs.OutboxForgotten, ""), convReply(555, 8, jobs.OutboxForgotten, ""))
	// The conversation key holds on the migrated table: a second row for
	// the same principal, update and kind is refused and reported.
	tx, err := s.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	err = s.EnqueuePAOutbox(ctx, tx, convReply(555, 7, jobs.OutboxConsentPrompt, "btn"), now)
	_ = tx.Rollback()
	if !errors.Is(err, jobs.ErrOutboxUpdateReused) {
		t.Fatalf("duplicate conversation row = %v, want ErrOutboxUpdateReused", err)
	}
	rows, err = s.PAOutboxRows(ctx, 555)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("rows = %+v, want the old row, one notice and three conversation rows", rows)
	}
	if rows[1].ID <= rows[0].ID || rows[1].JobID != 42 || rows[2].UpdateID != 7 || rows[2].Button != "btn" {
		t.Fatalf("new rows = %+v", rows[1:])
	}
}

// TestPAOutboxMigratesTableWithoutSentParts: an SQLite pa_outbox from
// before sent_parts existed is rebuilt too; its rows keep their fields and
// take the default for the column they lacked.
func TestPAOutboxMigratesTableWithoutSentParts(t *testing.T) {
	ctx := context.Background()
	conn, err := Open(ctx, fmt.Sprintf("file:pa_outbox_mig_old_%d?mode=memory&cache=shared", time.Now().UnixNano()), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ddl := strings.Replace(prePR1348OutboxDDL(false), "sent_parts INTEGER NOT NULL DEFAULT 0,", "", 1)
	if ddl == prePR1348OutboxDDL(false) {
		t.Fatal("sent_parts not removed from the old DDL")
	}
	if _, err := conn.ExecContext(ctx, ddl); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO pa_outbox(principal, job_id, kind, status, attempts, next_at_ms, created_at_ms, updated_at_ms)
		 VALUES(555, 43, 'run_failed', 'pending', 1, 1000, 900, 950)`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	rows, err := (&Store{DB: conn}).PAOutboxRows(ctx, 555)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].JobID != 43 || rows[0].Kind != jobs.OutboxRunFailed || rows[0].Attempts != 1 || rows[0].SentParts != 0 {
		t.Fatalf("rows = %+v", rows)
	}
}

// emptyPostgresSchema opens TEST_DATABASE_URL in a fresh, unmigrated
// schema, dropped when the test ends.
func emptyPostgresSchema(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	ctx := context.Background()
	admin, err := Open(ctx, dsn, 2, 1)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	schema := fmt.Sprintf("pa_outbox_mig_%d", time.Now().UnixNano())
	if _, err := admin.ExecContext(ctx, `CREATE SCHEMA `+schema); err != nil {
		_ = admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	conn, err := Open(ctx, u.String(), 5, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
