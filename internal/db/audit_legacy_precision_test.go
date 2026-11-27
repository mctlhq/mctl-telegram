package db

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// seedLegacyAuditRows writes a chain the way it was written before
// created_at was truncated: each row is hashed over stored+hashed[i] and
// stored with the time stored. mutate may change what is stored after the
// hash was computed.
func seedLegacyAuditRows(t *testing.T, s *Store, hashed []time.Duration, mutate func(i int, status *string, at *time.Time)) int64 {
	t.Helper()
	ctx := context.Background()
	// Postgres is reused between runs: a user of its own.
	uid, err := s.EnsureUserByTelegramID(ctx, time.Now().UnixNano(), "alice_tg", "Alice")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	prev := make([]byte, 32)
	base := time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC)
	callPath := sql.NullString{String: "", Valid: true}
	for i, d := range hashed {
		at, status := base.Add(time.Duration(i)*time.Second), "ok"
		entry := hashAuditEntry(prev, uid, "list_dialogs", "", status, "", callPath, at.Add(d), auditEdge{})
		if mutate != nil {
			mutate(i, &status, &at)
		}
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO audit_logs(user_id, tool_name, status, created_at, prev_hash, entry_hash, call_path)
			 VALUES($1,$2,$3,$4,$5,$6,$7)`,
			uid, "list_dialogs", status, at, prev, entry, callPath.String); err != nil {
			t.Fatalf("insert: %v", err)
		}
		prev = entry
	}
	return uid
}

func TestVerifyAuditChain_Postgres_RowsHashedBelowAMicrosecond(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	verify := func(t *testing.T, uid int64) AuditChainVerification {
		t.Helper()
		v, err := s.VerifyAuditChain(context.Background(), uid)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return v
	}
	hashed := []time.Duration{1, 0, 500, 999}

	t.Run("untouched rows verify", func(t *testing.T) {
		v := verify(t, seedLegacyAuditRows(t, s, hashed, nil))
		if !v.OK || v.Verified != int64(len(hashed)) {
			t.Fatalf("chain does not verify: %+v", v)
		}
	})
	for name, mutate := range map[string]func(int, *string, *time.Time){
		"another status": func(i int, status *string, _ *time.Time) {
			if i == 2 {
				*status = "error"
			}
		},
		"a time one microsecond later": func(i int, _ *string, at *time.Time) {
			if i == 2 {
				*at = at.Add(time.Microsecond)
			}
		},
		"a time one microsecond earlier": func(i int, _ *string, at *time.Time) {
			if i == 2 {
				*at = at.Add(-time.Microsecond)
			}
		},
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			v := verify(t, seedLegacyAuditRows(t, s, hashed, mutate))
			if v.OK || v.Verified != 2 || v.FirstBadID == 0 {
				t.Fatalf("a changed row verified: %+v", v)
			}
		})
	}
}

// SQLite keeps the full time, so there a difference below a microsecond is
// a changed row.
func TestVerifyAuditChain_SQLite_TimeIsExact(t *testing.T) {
	s := newTestStoreCrypted(t)
	uid := seedLegacyAuditRows(t, s, []time.Duration{500}, nil)
	v, err := s.VerifyAuditChain(context.Background(), uid)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if v.OK {
		t.Fatalf("a time that differs from the hashed one verified on SQLite: %+v", v)
	}
}
