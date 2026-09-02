package db

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fakeOpener drives openWithRetry's injected `open` seam deterministically:
// it fails failCount times (returning a distinctive sentinel-wrapped error
// each time, so a test can tell "the loop's own error" apart from a
// collapsed context.DeadlineExceeded) and then succeeds, unless failCount is
// negative, in which case it always fails.
type fakeOpener struct {
	failCount int // number of failures before success; negative = always fail
	calls     int
}

var errFakeUnreachable = errors.New("fake: connection refused")

func (f *fakeOpener) open(_ context.Context, _ string, _, _ int) (*sql.DB, error) {
	f.calls++
	if f.failCount < 0 || f.calls <= f.failCount {
		return nil, fmt.Errorf("attempt %d: %w", f.calls, errFakeUnreachable)
	}
	// A real (but harmless) *sql.DB the caller can Close(). in-memory SQLite
	// keeps this test independent of the pgx driver / a real Postgres.
	return sql.Open("sqlite", "file::memory:")
}

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

const pgDSN = "postgres://user:pass@localhost:5432/db"

func TestOpenWithRetry_SucceedsAfterFailures(t *testing.T) {
	f := &fakeOpener{failCount: 2}
	dbConn, err := openWithRetry(context.Background(), pgDSN, 0, 0,
		time.Millisecond, time.Second, testLogger(&bytes.Buffer{}), f.open)
	if err != nil {
		t.Fatalf("openWithRetry error: %v", err)
	}
	defer dbConn.Close()
	if f.calls != 3 {
		t.Errorf("calls = %d, want 3 (2 failures + 1 success)", f.calls)
	}
}

func TestOpenWithRetry_GivesUpAtDeadline(t *testing.T) {
	f := &fakeOpener{failCount: -1} // always fails
	start := time.Now()
	timeout := 20 * time.Millisecond
	_, err := openWithRetry(context.Background(), pgDSN, 0, 0,
		2*time.Millisecond, timeout, testLogger(&bytes.Buffer{}), f.open)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("openWithRetry: expected error, got nil")
	}
	if !errors.Is(err, errFakeUnreachable) {
		t.Errorf("error = %v, want it to wrap errFakeUnreachable (the last observed error), not a collapsed context.DeadlineExceeded", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, must not collapse to context.DeadlineExceeded — that discards the real cause", err)
	}
	if !strings.Contains(err.Error(), timeout.String()) {
		t.Errorf("error = %v, want it to name the timeout %s", err, timeout)
	}
	// Generous slack: this must not run substantially past the deadline.
	if elapsed > timeout+200*time.Millisecond {
		t.Errorf("elapsed = %v, want close to timeout %v", elapsed, timeout)
	}
}

func TestOpenWithRetry_FirstAttemptSuccessNeverWaits(t *testing.T) {
	f := &fakeOpener{failCount: 0}
	start := time.Now()
	dbConn, err := openWithRetry(context.Background(), pgDSN, 0, 0,
		time.Hour, time.Hour, testLogger(&bytes.Buffer{}), f.open)
	if err != nil {
		t.Fatalf("openWithRetry error: %v", err)
	}
	defer dbConn.Close()
	if f.calls != 1 {
		t.Errorf("calls = %d, want 1 (first attempt succeeds, no retry)", f.calls)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("elapsed = %v, want near-instant (interval is 1h, so any wait means the fast path wasn't taken)", elapsed)
	}
}

func TestOpenWithRetry_SQLiteSkipsLoop(t *testing.T) {
	f := &fakeOpener{failCount: -1} // always fails
	_, err := openWithRetry(context.Background(), "file::memory:", 0, 0,
		time.Hour, time.Hour, testLogger(&bytes.Buffer{}), f.open)
	if err == nil {
		t.Fatal("openWithRetry: expected error for always-failing SQLite open, got nil")
	}
	if !errors.Is(err, errFakeUnreachable) {
		t.Errorf("error = %v, want it to wrap errFakeUnreachable", err)
	}
	if f.calls != 1 {
		t.Errorf("calls = %d, want exactly 1 — a file: DSN must not enter the retry loop", f.calls)
	}
}

// slowOpener blocks on every attempt until its context is done, standing in
// for a dial into a host that blackholes packets instead of refusing them —
// where a real connect blocks for the OS TCP timeout, on the order of a
// minute.
type slowOpener struct {
	block time.Duration
	calls int
}

func (s *slowOpener) open(ctx context.Context, _ string, _, _ int) (*sql.DB, error) {
	s.calls++
	select {
	case <-time.After(s.block):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return nil, errFakeUnreachable
}

// TestOpenWithRetry_SlowAttemptRespectsDeadline pins the bound to the whole
// call, not just to the waits between attempts. If the attempt runs on the
// parent context instead of the deadline-bounded one, the select cannot fire
// until the attempt returns and a single slow dial overruns the budget —
// measured at 3x before this was fixed.
func TestOpenWithRetry_SlowAttemptRespectsDeadline(t *testing.T) {
	s := &slowOpener{block: 2 * time.Second}
	timeout := 100 * time.Millisecond

	start := time.Now()
	_, err := openWithRetry(context.Background(), pgDSN, 0, 0,
		time.Millisecond, timeout, testLogger(&bytes.Buffer{}), s.open)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("openWithRetry: expected error, got nil")
	}
	if elapsed > timeout+500*time.Millisecond {
		t.Errorf("elapsed = %v, want the attempt itself bounded by timeout %v", elapsed, timeout)
	}
}

// failThenBlockOpener reports a real database error on its first attempt and
// then blocks, so the deadline cuts a later attempt short and that attempt
// reports the expiry rather than anything about the database.
type failThenBlockOpener struct{ calls int }

func (f *failThenBlockOpener) open(ctx context.Context, _ string, _, _ int) (*sql.DB, error) {
	f.calls++
	if f.calls == 1 {
		return nil, fmt.Errorf("attempt %d: %w", f.calls, errFakeUnreachable)
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestOpenWithRetry_DeadlineDoesNotOverwriteLastError guards the rule that
// only an error saying something about the database is kept. Once the
// deadline cuts an attempt short the driver reports the expiry itself, and
// recording that would collapse the give-up error back into
// context.DeadlineExceeded — losing the real cause the operator needs, which
// is the whole reason this loop preserves it.
func TestOpenWithRetry_DeadlineDoesNotOverwriteLastError(t *testing.T) {
	f := &failThenBlockOpener{}
	_, err := openWithRetry(context.Background(), pgDSN, 0, 0,
		time.Millisecond, 150*time.Millisecond, testLogger(&bytes.Buffer{}), f.open)

	if err == nil {
		t.Fatal("openWithRetry: expected error, got nil")
	}
	if !errors.Is(err, errFakeUnreachable) {
		t.Errorf("error = %v, want it to still wrap the database error from the first attempt", err)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("error = %v, must not collapse into context.DeadlineExceeded once a later attempt is cut short by the deadline", err)
	}
}

func TestOpenWithRetry_CtxCancelReturnsPromptly(t *testing.T) {
	f := &fakeOpener{failCount: -1} // always fails
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel shortly after the first failed attempt's wait begins, well
	// before the (deliberately long) timeout would ever fire.
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := openWithRetry(ctx, pgDSN, 0, 0, time.Hour, time.Hour, testLogger(&bytes.Buffer{}), f.open)
	elapsed := time.Since(start)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if elapsed > time.Second {
		t.Errorf("elapsed = %v, want the cancellation to abort the wait promptly (interval/timeout are 1h)", elapsed)
	}
}

func TestOpenWithRetry_LogsAttemptCount(t *testing.T) {
	t.Run("zero_retries", func(t *testing.T) {
		var buf bytes.Buffer
		f := &fakeOpener{failCount: 0}
		dbConn, err := openWithRetry(context.Background(), pgDSN, 0, 0,
			time.Millisecond, time.Second, testLogger(&buf), f.open)
		if err != nil {
			t.Fatalf("openWithRetry error: %v", err)
		}
		defer dbConn.Close()
		if !strings.Contains(buf.String(), `"attempts":0`) {
			t.Errorf("log output = %s, want attempts=0 for an immediate success", buf.String())
		}
	})

	t.Run("seven_retries", func(t *testing.T) {
		var buf bytes.Buffer
		f := &fakeOpener{failCount: 7}
		dbConn, err := openWithRetry(context.Background(), pgDSN, 0, 0,
			time.Millisecond, time.Second, testLogger(&buf), f.open)
		if err != nil {
			t.Fatalf("openWithRetry error: %v", err)
		}
		defer dbConn.Close()
		if !strings.Contains(buf.String(), `"attempts":7`) {
			t.Errorf("log output = %s, want attempts=7 after 7 failed attempts", buf.String())
		}
	})
}

// TestOpenWithRetry_ExportedWrapper is a light smoke test that OpenWithRetry
// wires openWithRetry to the real Open and slog.Default() without error for
// the non-retried (SQLite) path — the retried path is covered above via the
// injectable seam, which real network I/O in a unit test should not exercise.
func TestOpenWithRetry_ExportedWrapper(t *testing.T) {
	dbConn, err := OpenWithRetry(context.Background(), "file::memory:", 0, 0, time.Second, time.Second)
	if err != nil {
		t.Fatalf("OpenWithRetry error: %v", err)
	}
	defer dbConn.Close()
}
