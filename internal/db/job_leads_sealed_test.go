package db

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// sealedLeadCases run on SQLite and, with TEST_DATABASE_URL, on Postgres.
func sealedLeadCases(t *testing.T, newOwner func(t *testing.T) (*Store, int64)) {
	t.Run("nothing private is readable at rest", func(t *testing.T) {
		s, uid := newOwner(t)
		assertLeadSealedAtRest(t, s, uid)
	})
	t.Run("legacy row reads, then seals without moving updated_at", func(t *testing.T) {
		s, uid := newOwner(t)
		assertLegacyLeadSeals(t, s, uid)
	})
	t.Run("update of a legacy row keeps its fields", func(t *testing.T) {
		s, uid := newOwner(t)
		assertLegacyLeadUpdateMerges(t, s, uid)
	})
	t.Run("a value an older binary wrote wins over the sealed one", func(t *testing.T) {
		s, uid := newOwner(t)
		assertRollbackWriteWins(t, s, uid)
	})
	t.Run("unreadable blob is an error and survives", func(t *testing.T) {
		s, uid := newOwner(t)
		assertUnreadableLeadSurvives(t, s, uid)
	})
	t.Run("concurrent saves both land", func(t *testing.T) {
		s, uid := newOwner(t)
		assertConcurrentLeadSaves(t, s, uid)
	})
	t.Run("sweep deletes only leads past retention", func(t *testing.T) {
		s, uid := newOwner(t)
		assertLeadSweep(t, s, uid)
	})
}

// The fields share one blob, so a save without the row lock would overwrite
// a concurrent one. Only Postgres has real concurrency; SQLite still checks
// that the saves finish with both fields.
func assertConcurrentLeadSaves(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	for round := 0; round < 15; round++ {
		id, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv, Status: "new"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, l := range []JobLead{
			{ID: id, UserID: uid, ConversationID: conv, Company: "Acme"},
			{ID: id, UserID: uid, ConversationID: conv, Role: "Backend"},
		} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, errs[i] = s.UpsertJobLead(ctx, l)
			}()
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				t.Fatalf("save: %v", err)
			}
		}
		got, err := s.GetJobLead(ctx, uid, id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Company != "Acme" || got.Role != "Backend" {
			t.Fatalf("round %d lost a save: %+v", round, got)
		}
	}
}

func TestSweepJobLeads_RemovesJobResultBinding(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	conv := leadConversation(t, s, uid)
	id := insertLegacyLead(t, s, uid, conv, time.Now().UTC().Add(-91*24*time.Hour))
	if _, err := s.DB.Exec(`INSERT INTO agent_job_lead_results(job_id, user_id, lead_id) VALUES(999,$1,$2)`, uid, id); err != nil {
		t.Fatalf("bind: %v", err)
	}
	fresh := insertLegacyLead(t, s, uid, conv, time.Now().UTC())
	if _, err := s.DB.Exec(`INSERT INTO agent_job_lead_results(job_id, user_id, lead_id) VALUES(1000,$1,$2)`, uid, fresh); err != nil {
		t.Fatalf("bind fresh: %v", err)
	}
	if _, err := s.SweepJobLeads(ctx, 90*24*time.Hour); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM agent_job_lead_results WHERE lead_id = $1`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bindings left = %d, err %v", n, err)
	}
	if err := s.DB.QueryRow(`SELECT count(*) FROM agent_job_lead_results WHERE lead_id = $1`, fresh).Scan(&n); err != nil || n != 1 {
		t.Fatalf("fresh lead bindings = %d, err %v", n, err)
	}
}

func TestSealedJobLeads_SQLite(t *testing.T) {
	sealedLeadCases(t, func(t *testing.T) (*Store, int64) {
		s := newTestStoreCrypted(t)
		return s, seedAgentUser(t, s, "owner")
	})
}

func leadConversation(t *testing.T, s *Store, uid int64) int64 {
	t.Helper()
	conv, err := s.EnsureConversation(context.Background(), uid, 777, "rec", "Rec")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	return conv.ID
}

// leadPlainColumnCount counts the columns of a lead that are still in the clear.
func leadPlainColumnCount(t *testing.T, s *Store, id int64) int {
	t.Helper()
	var n int
	if err := s.DB.QueryRow(
		`SELECT count(*) FROM job_leads WHERE id = $1 AND `+jobLeadHasPlaintext, id,
	).Scan(&n); err != nil {
		t.Fatalf("count plaintext: %v", err)
	}
	return n
}

func insertLegacyLead(t *testing.T, s *Store, uid, conv int64, updated time.Time) int64 {
	t.Helper()
	var id int64
	if err := s.DB.QueryRow(
		`INSERT INTO job_leads(user_id, conversation_id, company, role, recruiter_name,
		     recruiter_tg_id, compensation, status, detail, updated_at)
		 VALUES($1,$2,'Acme','Backend','Rita',42,'100k','new','{"remote":true}',$3) RETURNING id`,
		uid, conv, updated,
	).Scan(&id); err != nil {
		t.Fatalf("insert legacy lead: %v", err)
	}
	return id
}

func assertLeadSealedAtRest(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	id, err := s.UpsertJobLead(ctx, JobLead{
		UserID: uid, ConversationID: conv, Company: "Acme", Role: "Backend", RecruiterName: "Rita",
		RecruiterTGID: 42, Compensation: "100k", Detail: `{"remote":true}`,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	check := func(stage string) {
		t.Helper()
		if n := leadPlainColumnCount(t, s, id); n != 0 {
			t.Fatalf("%s: lead has fields in the clear", stage)
		}
		var blob []byte
		if err := s.DB.QueryRow(`SELECT data_encrypted FROM job_leads WHERE id = $1`, id).Scan(&blob); err != nil {
			t.Fatalf("%s: read blob: %v", stage, err)
		}
		for _, secret := range []string{"Acme", "Rita", "100k", "remote"} {
			if bytes.Contains(blob, []byte(secret)) {
				t.Fatalf("%s: blob contains %q in the clear", stage, secret)
			}
		}
		if len(blob) == 0 {
			t.Fatalf("%s: no blob", stage)
		}
	}
	check("create")
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: id, UserID: uid, ConversationID: conv, Compensation: "120k"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	check("update")
	got, err := s.GetJobLead(ctx, uid, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Company != "Acme" || got.Role != "Backend" || got.RecruiterName != "Rita" || got.RecruiterTGID != 42 ||
		got.Compensation != "120k" || got.Detail != `{"remote":true}` {
		t.Fatalf("lead = %+v", got)
	}
}

func assertLegacyLeadSeals(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	updated := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Second)
	id := insertLegacyLead(t, s, uid, conv, updated)
	want := func(stage string) {
		t.Helper()
		got, err := s.GetJobLead(ctx, uid, id)
		if err != nil {
			t.Fatalf("%s: get: %v", stage, err)
		}
		if got.Company != "Acme" || got.Role != "Backend" || got.RecruiterName != "Rita" || got.RecruiterTGID != 42 ||
			got.Compensation != "100k" || got.Detail != `{"remote":true}` {
			t.Fatalf("%s: lead = %+v", stage, got)
		}
		if !got.UpdatedAt.Equal(updated) {
			t.Fatalf("%s: updated_at = %v, want %v", stage, got.UpdatedAt, updated)
		}
	}
	want("legacy")
	sealed, _, err := s.SealPlaintextJobLeads(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if sealed < 1 {
		t.Fatalf("sealed = %d", sealed)
	}
	if n := leadPlainColumnCount(t, s, id); n != 0 {
		t.Fatal("legacy lead still in the clear after the seal pass")
	}
	want("sealed")
	if _, _, err := s.SealPlaintextJobLeads(ctx); err != nil {
		t.Fatalf("second seal: %v", err)
	}
	want("second pass")
}

func assertLegacyLeadUpdateMerges(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	id := insertLegacyLead(t, s, uid, conv, time.Now().UTC())
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: id, UserID: uid, ConversationID: conv, Role: "Staff"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if n := leadPlainColumnCount(t, s, id); n != 0 {
		t.Fatal("update left fields in the clear")
	}
	got, err := s.GetJobLead(ctx, uid, id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Company != "Acme" || got.Role != "Staff" || got.RecruiterTGID != 42 || got.Detail != `{"remote":true}` {
		t.Fatalf("lead = %+v", got)
	}
}

func assertRollbackWriteWins(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	id, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv, Company: "Acme", Role: "Backend"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.DB.Exec(`UPDATE job_leads SET company = 'Newer' WHERE id = $1`, id); err != nil {
		t.Fatalf("older binary write: %v", err)
	}
	check := func(stage string) {
		t.Helper()
		got, err := s.GetJobLead(ctx, uid, id)
		if err != nil {
			t.Fatalf("%s: get: %v", stage, err)
		}
		if got.Company != "Newer" || got.Role != "Backend" {
			t.Fatalf("%s: lead = %+v", stage, got)
		}
	}
	check("before seal")
	if _, _, err := s.SealPlaintextJobLeads(ctx); err != nil {
		t.Fatalf("seal: %v", err)
	}
	if n := leadPlainColumnCount(t, s, id); n != 0 {
		t.Fatal("still in the clear after the seal pass")
	}
	check("after seal")
}

func assertUnreadableLeadSurvives(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	id, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv, Company: "Acme"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	broken := []byte{2, 1, 2, 3}
	if _, err := s.DB.Exec(`UPDATE job_leads SET data_encrypted = $1, role = 'Backend' WHERE id = $2`, broken, id); err != nil {
		t.Fatalf("break blob: %v", err)
	}
	if _, err := s.GetJobLead(ctx, uid, id); err == nil || errors.Is(err, ErrJobLeadNotFound) {
		t.Fatalf("get = %v, want a read failure", err)
	}
	if _, err := s.ListJobLeads(ctx, uid, 10); err == nil {
		t.Fatal("list hid an unreadable lead")
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: id, UserID: uid, ConversationID: conv, Role: "Staff"}); err == nil ||
		errors.Is(err, ErrJobLeadNotFound) {
		t.Fatalf("update = %v, want a read failure", err)
	}
	_, failed, err := s.SealPlaintextJobLeads(ctx)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if failed < 1 {
		t.Fatalf("failed = %d, want the unreadable row counted", failed)
	}
	var blob []byte
	var role string
	if err := s.DB.QueryRow(`SELECT data_encrypted, role FROM job_leads WHERE id = $1`, id).Scan(&blob, &role); err != nil {
		t.Fatalf("read row: %v", err)
	}
	if !bytes.Equal(blob, broken) || role != "Backend" {
		t.Fatalf("row was changed: blob=%v role=%q", blob, role)
	}
	// Other tests in a shared database must not trip over it.
	if _, err := s.DB.Exec(`DELETE FROM job_leads WHERE id = $1`, id); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

func assertLeadSweep(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv := leadConversation(t, s, uid)
	now := time.Now().UTC()
	old := insertLegacyLead(t, s, uid, conv, now.Add(-91*24*time.Hour))
	fresh := insertLegacyLead(t, s, uid, conv, now.Add(-89*24*time.Hour))
	if n, err := s.SweepJobLeads(ctx, 0); err != nil || n != 0 {
		t.Fatalf("retention 0: n=%d err=%v", n, err)
	}
	if _, err := s.GetJobLead(ctx, uid, old); err != nil {
		t.Fatalf("retention 0 removed the lead: %v", err)
	}
	if n, err := s.SweepJobLeads(ctx, 90*24*time.Hour); err != nil || n < 1 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}
	if _, err := s.GetJobLead(ctx, uid, old); !errors.Is(err, ErrJobLeadNotFound) {
		t.Fatalf("old lead: %v", err)
	}
	if _, err := s.GetJobLead(ctx, uid, fresh); err != nil {
		t.Fatalf("fresh lead: %v", err)
	}
}
