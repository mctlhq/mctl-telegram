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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
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

// S1-U2 through the real store: a run cancelled while the call is in flight
// still writes both rows. The principal lookup of the result append must not
// run on the cancelled context.
func TestStoreSink_CancelledRunWritesBothRows(t *testing.T) {
	store := newStore(t)
	userID, err := store.EnsureUserByTelegramID(context.Background(), aliceID, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	var alerts int
	x.OnAuditAppendFailure = func(Entry, error) { alerts++ }
	ctx, cancel := context.WithCancel(context.Background())
	dispatch := func(ctx context.Context) (Result, error) {
		cancel()
		return Result{}, ctx.Err()
	}
	if _, err := x.Execute(ctx, tgSurface(t), readCall(t, `{}`), dispatch); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	rows := readRows(t, store, userID)
	if len(rows) != 2 || rows[1].status != string(StatusOutcomeUnknown) || alerts != 0 {
		t.Fatalf("rows = %+v, alerts = %d", rows, alerts)
	}
}

// zeroStore resolves every principal to user id 0, which no users row has.
type zeroStore struct{ logged int }

func (z *zeroStore) UserIDByTelegramID(context.Context, int64) (int64, error) { return 0, nil }
func (z *zeroStore) LogToolCallChecked(context.Context, db.ToolCall) error {
	z.logged++
	return nil
}

// StoreSink refuses a lookup that returns no user instead of writing a row
// with user_id 0.
func TestStoreSink_ZeroUserIDRefused(t *testing.T) {
	z := &zeroStore{}
	e := Entry{CallID: "c1", Phase: PhasePreDispatch, Principal: aliceID, Server: "tg", Tool: "get_messages",
		ConnectionID: "conn-a", AuthorityRevision: 1, ArgsSHA256: digest(nil), Taint: TaintClean, Status: StatusDispatching}
	if err := (StoreSink{Store: z}).Append(context.Background(), e); !errors.Is(err, ErrUnrecordable) || z.logged != 0 {
		t.Fatalf("err = %v, logged = %d", err, z.logged)
	}
}

// PA users row (owner decision 2026-11-19 on #1312): a principal whose only
// contact with MCTL is a PA connection gets its users row from
// EnsurePAUser on its first connection, marked provider "pa", and its calls
// are audited through the same chain as anyone else's. Alice here has no
// tg-mcp login and no telegram_accounts row.
func TestStoreSink_PAOnlyPrincipalIsAudited(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	userID, err := store.EnsurePAUser(ctx, aliceID)
	if err != nil {
		t.Fatalf("EnsurePAUser: %v", err)
	}
	var provider string
	if err := store.DB.QueryRowContext(ctx, `SELECT provider FROM users WHERE id = $1`, userID).Scan(&provider); err != nil {
		t.Fatal(err)
	}
	if provider != db.PAProvider {
		t.Fatalf("provider = %q, want %q", provider, db.PAProvider)
	}
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	n := 0
	dispatch := func(context.Context) (Result, error) { n++; return Result{Output: []byte("ok")}, nil }
	if _, err := x.Execute(ctx, tgSurface(t), readCall(t, `{}`), dispatch); err != nil {
		t.Fatalf("Execute for a PA-only principal: %v", err)
	}
	if n != 1 {
		t.Fatalf("dispatches = %d, want 1", n)
	}
	if rows := readRows(t, store, userID); len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(rows))
	}
	v, err := store.VerifyAuditChain(ctx, userID)
	if err != nil || !v.OK || v.Verified != 2 {
		t.Fatalf("chain = %+v, %v", v, err)
	}
	// A second connection reuses the row.
	again, err := store.EnsurePAUser(ctx, aliceID)
	if err != nil || again != userID {
		t.Fatalf("second EnsurePAUser = %d, %v; want %d", again, err, userID)
	}
}

// aliceSurface observes the committed pin against mctl-alice's tools/list
// snapshot (internal/pa/catalog/testdata).
func aliceSurface(t *testing.T) *catalog.Surface {
	t.Helper()
	page, err := os.ReadFile(filepath.Join("..", "catalog", "testdata", "alice.tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := catalog.LoadPin()
	if err != nil {
		t.Fatal(err)
	}
	s := pin.Observe("alice", [][]byte{page}, nil, t0)
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
	return s
}

// The owner-required case literally: an alice-only principal. Alice's only
// PA connection is to the alice server, she has no tg-mcp login and no
// telegram_accounts row, and her alice_list_devices call is audited through
// the ADR 0003 chain under the users row EnsurePAUser created.
func TestStoreSink_AliceOnlyPrincipalIsAudited(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	userID, err := store.EnsurePAUser(ctx, aliceID)
	if err != nil {
		t.Fatalf("EnsurePAUser: %v", err)
	}
	x := &Executor{Sink: StoreSink{Store: store}, Now: func() time.Time { return t0 }}
	n := 0
	dispatch := func(context.Context) (Result, error) { n++; return Result{Output: []byte("[]")}, nil }
	call := Call{Policy: alicePolicy(t), ConnectionID: "conn-a", Tool: "alice_list_devices", Args: []byte(`{}`), Taint: TaintClean}
	if _, err := x.Execute(ctx, aliceSurface(t), call, dispatch); err != nil {
		t.Fatalf("Execute on the alice surface: %v", err)
	}
	if n != 1 {
		t.Fatalf("dispatches = %d, want 1", n)
	}
	rows := readRows(t, store, userID)
	if len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r.tool != "pa:alice/alice_list_devices" || r.callPath != AuditCallPath {
			t.Fatalf("row %+v", r)
		}
	}
	v, err := store.VerifyAuditChain(ctx, userID)
	if err != nil || !v.OK || v.Verified != 2 {
		t.Fatalf("chain = %+v, %v", v, err)
	}
}
