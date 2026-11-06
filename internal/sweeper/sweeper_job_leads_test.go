package sweeper

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestJobLeadsSweepOnce_DeletesExpiredAndSealsTheRest(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:sweeper_job_leads?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	c, err := crypto.New(make([]byte, 32))
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := &db.Store{DB: conn, Crypt: c}
	uid, err := store.EnsureUser(ctx, "owner", "", "test")
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	insert := func(age time.Duration) int64 {
		t.Helper()
		var id int64
		if err := conn.QueryRow(
			`INSERT INTO job_leads(user_id, company, updated_at) VALUES($1,'Acme',$2) RETURNING id`,
			uid, time.Now().UTC().Add(-age),
		).Scan(&id); err != nil {
			t.Fatalf("insert: %v", err)
		}
		return id
	}
	expired := insert(91 * 24 * time.Hour)
	kept := insert(24 * time.Hour)

	jobLeadsSweepOnce(ctx, store, 90*24*time.Hour)

	var n int
	if err := conn.QueryRow(`SELECT count(*) FROM job_leads WHERE id = $1`, expired).Scan(&n); err != nil || n != 0 {
		t.Fatalf("expired lead rows = %d, err %v", n, err)
	}
	if err := conn.QueryRow(`SELECT count(*) FROM job_leads WHERE id = $1 AND company IS NULL`, kept).Scan(&n); err != nil || n != 1 {
		t.Fatalf("sealed kept lead rows = %d, err %v", n, err)
	}
	got, err := store.GetJobLead(ctx, uid, kept)
	if err != nil || got.Company != "Acme" {
		t.Fatalf("kept lead = %+v, err %v", got, err)
	}
}
