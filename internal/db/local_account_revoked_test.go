package db

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// seedModedAccount inserts one account row with an explicit mode and returns
// its user id. Distinct from store_test.go seedAccount, which predates mode.
func seedModedAccount(t *testing.T, s *Store, login string, tgID int64, mode string, revoked bool, sendEnabled bool) int64 {
	t.Helper()
	ctx := context.Background()
	uid, err := s.EnsureUser(ctx, login, "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	var revokedAt any
	if revoked {
		revokedAt = time.Now().UTC()
	}
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode, send_enabled, revoked_at)
		 VALUES($1,$2,$3,$4,$5,$6)`,
		uid, tgID, []byte("blob"), mode, sendEnabled, revokedAt,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	return uid
}

// TestRevokedLocalAccountStaysOperable is the sibling of
// TestGetAccountMode_SurvivesRevocationWhenLocal. GetAccountMode was changed
// to ignore revoked_at so a migrated local account keeps reporting 'local'
// after its vestigial hosted session is revoked. The queries that gate what
// the account can actually do have to agree, or the account reports 'local'
// while behaving like a dead one: send silently degrades to dry-run, and the
// operator cannot repair it because every UPDATE matches zero rows -- including
// the flip back to hosted, which is the only lever for cutting off a leaked
// bridge token.
func TestRevokedLocalAccountStaysOperable(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid := seedModedAccount(t, s, "revoked-local", 700000201, ModeLocal, true, true)

	if mode, err := s.GetAccountMode(ctx, uid); err != nil || mode != ModeLocal {
		t.Fatalf("GetAccountMode = %q, %v; want %q (baseline)", mode, err, ModeLocal)
	}

	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if !enabled {
		t.Error("IsSendEnabled = false for a revoked local account; sending would silently degrade to dry-run")
	}

	n, err := s.SetSendEnabled(ctx, uid, false)
	if err != nil {
		t.Fatalf("SetSendEnabled: %v", err)
	}
	if n != 1 {
		t.Errorf("SetSendEnabled affected %d rows, want 1 — the operator must still be able to change it", n)
	}

	n, err = s.SetAccountMode(ctx, uid, ModeHosted)
	if err != nil {
		t.Fatalf("SetAccountMode: %v", err)
	}
	if n != 1 {
		t.Errorf("SetAccountMode affected %d rows, want 1 — the flip back to hosted must stay available", n)
	}
}

// TestRevokedHostedAccountStaysInert is the other side of the same predicate:
// relaxing revoked_at for local rows must not relax it for hosted ones, whose
// revocation genuinely means "there is no session here any more".
func TestRevokedHostedAccountStaysInert(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid := seedModedAccount(t, s, "revoked-hosted", 700000202, ModeHosted, true, true)

	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if enabled {
		t.Error("IsSendEnabled = true for a revoked hosted account; its session is gone")
	}
	if n, err := s.SetSendEnabled(ctx, uid, true); err != nil || n != 0 {
		t.Errorf("SetSendEnabled affected %d rows (err %v), want 0 for a revoked hosted account", n, err)
	}
}

// TestActionableAccountPicksTheSameRowAsGetAccountMode guards the row-selection
// half of the predicate. A user with an old revoked local row and a newer
// active hosted row must be treated as hosted by both GetAccountMode and the
// action queries. Filtering before ordering would pick the older local row here.
func TestActionableAccountPicksTheSameRowAsGetAccountMode(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid := seedModedAccount(t, s, "two-rows", 700000203, ModeLocal, true, true)

	// A newer hosted row, as a fresh SaveSession would create.
	if _, err := s.DB.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode, send_enabled, connected_at)
		 VALUES($1,$2,$3,$4,$5,$6)`,
		uid, 700000203, []byte("blob"), ModeHosted, false, time.Now().UTC().Add(time.Hour),
	); err != nil {
		t.Fatalf("seed newer hosted row: %v", err)
	}

	mode, err := s.GetAccountMode(ctx, uid)
	if err != nil || mode != ModeHosted {
		t.Fatalf("GetAccountMode = %q, %v; want %q", mode, err, ModeHosted)
	}
	enabled, err := s.IsSendEnabled(ctx, uid)
	if err != nil {
		t.Fatalf("IsSendEnabled: %v", err)
	}
	if enabled {
		t.Error("IsSendEnabled read the older local row instead of the newer hosted one GetAccountMode chose")
	}
}

// TestSameSecondRowsResolveByID pins the tiebreaker. connected_at defaults to
// CURRENT_TIMESTAMP, which SQLite resolves to whole seconds, so two rows
// written in the same second compare equal on it. The design relies on "a
// fresh hosted login inserts a newer connected_at and therefore wins", which
// without a tiebreaker is decided arbitrarily — an account could read as local
// immediately after reconnecting to hosted. Both rows here are inserted with
// the column default, exactly as the real login path does.
func TestSameSecondRowsResolveByID(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "same-second", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	for _, mode := range []string{ModeLocal, ModeHosted} {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, mode)
			 VALUES($1,$2,$3,$4)`,
			uid, 700000204, []byte("blob"), mode,
		); err != nil {
			t.Fatalf("seed %s row: %v", mode, err)
		}
	}
	mode, err := s.GetAccountMode(ctx, uid)
	if err != nil {
		t.Fatalf("GetAccountMode: %v", err)
	}
	if mode != ModeHosted {
		t.Errorf("GetAccountMode = %q, want %q — the later-inserted row must win even when connected_at ties", mode, ModeHosted)
	}
}

// TestGetActiveAccountFollowsTheSameRow guards the UI surface. /api/account
// and the manage dashboard read GetActiveAccount; if it disagrees with
// GetAccountMode, a working bridge account is shown as disconnected and the
// page offers a hosted re-login — which inserts a fresh hosted row and takes
// the account out of local mode, destroying the setup it was trying to repair.
func TestGetActiveAccountFollowsTheSameRow(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid := seedModedAccount(t, s, "active-revoked-local", 700000205, ModeLocal, true, true)

	info, err := s.GetActiveAccount(ctx, uid)
	if err != nil {
		t.Fatalf("GetActiveAccount: %v", err)
	}
	if !info.Connected {
		t.Error("GetActiveAccount reports Connected=false for a revoked local account that GetAccountMode calls local")
	}

	// A revoked hosted account must still read as disconnected.
	uid2 := seedModedAccount(t, s, "active-revoked-hosted", 700000206, ModeHosted, true, true)
	info2, err := s.GetActiveAccount(ctx, uid2)
	if err != nil {
		t.Fatalf("GetActiveAccount: %v", err)
	}
	if info2.Connected {
		t.Error("GetActiveAccount reports Connected=true for a revoked hosted account")
	}
}

// TestMigrateLeavesLocalLifecycleColumnsNull pins the invariant
// ProvisionLocalAccount's doc comment states. Migrate runs on every server
// start, and its backfill fills last_used_at/expires_at for rows that have
// none — which is every provisioned local account, by design. The sweepers
// exclude local rows independently, so this is currently invisible; the point
// is that the columns must not acquire a session lifecycle a sessionless
// account does not have, because CheckSessionValid reads them without a mode
// filter.
func TestMigrateLeavesLocalLifecycleColumnsNull(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUser(ctx, "migrate-twice", "", "test")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if err := s.ProvisionLocalAccount(ctx, uid, 700000207, "", ""); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := Migrate(ctx, s.DB, 700000207); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	var lastUsed, expires sql.NullTime
	if err := s.DB.QueryRowContext(ctx,
		`SELECT last_used_at, expires_at FROM telegram_accounts WHERE user_id = $1`, uid,
	).Scan(&lastUsed, &expires); err != nil {
		t.Fatalf("read lifecycle columns: %v", err)
	}
	if lastUsed.Valid || expires.Valid {
		t.Errorf("after a restart the local row has last_used_at=%v expires_at=%v, want both NULL", lastUsed, expires)
	}
}
