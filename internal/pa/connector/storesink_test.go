// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "pa-audit.db") + "?_pragma=busy_timeout(5000)"
	conn, err := db.Open(ctx, dsn, 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.NewStore(conn, nil)
}

type auditRow struct {
	tool, peer, status, callPath string
	errCol                       *string
}

func readRows(t *testing.T, s *db.Store, userID int64) []auditRow {
	t.Helper()
	rows, err := s.DB.QueryContext(context.Background(),
		`SELECT tool_name, peer_redacted, status, call_path, error FROM audit_logs WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.tool, &r.peer, &r.status, &r.callPath, &r.errCol); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// S1-U1, S1-U2 through the real ADR 0003 chain: a dispatched call writes
// exactly two chained rows holding digests only, and the user's chain still
// verifies.
func TestStoreSink_ChainedDigestRows(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	userID, err := store.EnsureUserByTelegramID(ctx, aliceID, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	const secret = "SECRET-BODY-and-Bearer-token-abc"
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	dispatch := func(context.Context) (Result, error) {
		return Result{Output: []byte(secret)}, nil
	}
	if _, err := x.Execute(ctx, tgSurface(t), readCall(t, `{"q":"`+secret+`"}`), dispatch); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	rows := readRows(t, store, userID)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for i, wantStatus := range []string{"dispatching", "ok"} {
		r := rows[i]
		if r.tool != "pa:tg/get_messages" || r.status != wantStatus || r.callPath != AuditCallPath || r.errCol != nil {
			t.Fatalf("row %d = %+v", i, r)
		}
		if !strings.HasPrefix(r.peer, "pa/v1 call=") || strings.Contains(r.peer, "SECRET") {
			t.Fatalf("row %d record = %q", i, r.peer)
		}
	}
	v, err := store.VerifyAuditChain(ctx, userID)
	if err != nil || !v.OK || v.Verified != 2 {
		t.Fatalf("chain = %+v, %v", v, err)
	}
}

// S1-U3 through the real store: a principal with no users row cannot be
// audited, so the call is refused and never dispatched.
func TestStoreSink_UnresolvablePrincipalRefusesCall(t *testing.T) {
	store := newStore(t)
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	n := 0
	dispatch := func(context.Context) (Result, error) { n++; return Result{}, nil }
	_, err := x.Execute(context.Background(), tgSurface(t), readCall(t, `{}`), dispatch)
	if !errors.Is(err, ErrAuditUnavailable) || n != 0 {
		t.Fatalf("err = %v, dispatches = %d", err, n)
	}
}

// S1-U3 through the real store: a database that rejects the insert refuses
// the call.
func TestStoreSink_InsertFailureRefusesCall(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	if _, err := store.EnsureUserByTelegramID(ctx, aliceID, "alice", "Alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.DB.ExecContext(ctx,
		`CREATE TRIGGER pa_reject BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		t.Fatal(err)
	}
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	n := 0
	dispatch := func(context.Context) (Result, error) { n++; return Result{}, nil }
	_, err := x.Execute(ctx, tgSurface(t), readCall(t, `{}`), dispatch)
	if !errors.Is(err, ErrAuditUnavailable) || n != 0 {
		t.Fatalf("err = %v, dispatches = %d", err, n)
	}
}

// FormatRecord refuses identifiers outside the safe alphabet instead of
// writing them.
func TestFormatRecordRefusesUnsafeIdentifiers(t *testing.T) {
	base := Entry{CallID: "c1", Phase: PhasePreDispatch, Principal: aliceID, Server: "tg", Tool: "get_messages",
		ConnectionID: "conn-a", AuthorityRevision: 1, ArgsSHA256: digest(nil), Taint: TaintClean, Status: StatusDispatching}
	if _, err := FormatRecord(base); err != nil {
		t.Fatalf("base: %v", err)
	}
	for name, mutate := range map[string]func(e *Entry){
		"space in conn":    func(e *Entry) { e.ConnectionID = "conn a" },
		"equals in tool":   func(e *Entry) { e.Tool = "x=y" },
		"newline approver": func(e *Entry) { e.Approver = "a\nb" },
		"empty args":       func(e *Entry) { e.ArgsSHA256 = "" },
		"empty server":     func(e *Entry) { e.Server = "" },
	} {
		e := base
		mutate(&e)
		if _, err := FormatRecord(e); !errors.Is(err, ErrUnrecordable) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
