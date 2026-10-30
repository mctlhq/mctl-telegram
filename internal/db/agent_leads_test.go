package db

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

// leadCases are the #951 lead semantics: a conversation holds any number of
// leads, a save without an id creates one, and a save with an id updates
// that lead only if it belongs to the same user and conversation. They run
// on SQLite and, with TEST_DATABASE_URL, on Postgres.
func leadCases(t *testing.T, newOwner func(t *testing.T) (*Store, int64)) {
	t.Run("two creates in one conversation keep both", func(t *testing.T) {
		s, uid := newOwner(t)
		assertTwoLeadsInOneConversation(t, s, uid)
	})
	t.Run("update by id merges into that lead only", func(t *testing.T) {
		s, uid := newOwner(t)
		assertUpdateByIDMerges(t, s, uid)
	})
	t.Run("update cannot reach another conversation or user", func(t *testing.T) {
		s, uid := newOwner(t)
		other := seedAgentUser(t, s, fmt.Sprintf("lead_other_%d", time.Now().UnixNano()))
		t.Cleanup(func() { _, _ = s.DB.Exec(`DELETE FROM users WHERE id = $1`, other) })
		assertUpdateIsScoped(t, s, uid, other)
	})
	t.Run("one job saves two leads", func(t *testing.T) {
		s, uid := newOwner(t)
		assertJobSavesTwoLeads(t, s, uid)
	})
}

func TestJobLeads_SQLite(t *testing.T) {
	leadCases(t, func(t *testing.T) (*Store, int64) {
		s := newTestStoreCrypted(t)
		return s, seedAgentUser(t, s, "owner")
	})
}

func TestJobLeads_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	leadCases(t, func(t *testing.T) (*Store, int64) {
		uid := seedAgentUser(t, s, fmt.Sprintf("lead_%d", time.Now().UnixNano()))
		t.Cleanup(func() {
			for _, q := range []string{
				`DELETE FROM agent_job_lead_results WHERE user_id = $1`,
				`DELETE FROM job_leads WHERE user_id = $1`,
				`DELETE FROM agent_job_attempts WHERE job_id IN (SELECT id FROM agent_jobs WHERE user_id = $1)`,
				`DELETE FROM agent_jobs WHERE user_id = $1`,
				`DELETE FROM conversations WHERE user_id = $1`,
				`DELETE FROM users WHERE id = $1`,
			} {
				_, _ = s.DB.Exec(q, uid)
			}
		})
		return s, uid
	})
}

func assertTwoLeadsInOneConversation(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	goLead, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Company: "Halcyon Talent", Role: "Senior Go Engineer"})
	if err != nil {
		t.Fatalf("save go lead: %v", err)
	}
	sreLead, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Company: "Halcyon Talent", Role: "Site Reliability Engineer"})
	if err != nil {
		t.Fatalf("save sre lead: %v", err)
	}
	if goLead == sreLead {
		t.Fatalf("second role overwrote the first: both saves returned lead %d", goLead)
	}
	leads, err := s.ListJobLeadsByConversation(ctx, uid, conv.ID, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(leads) != 2 || leads[0].ID != sreLead || leads[1].ID != goLead {
		t.Fatalf("leads = %+v, want [sre, go] newest first", leads)
	}
	if leads[1].Role != "Senior Go Engineer" {
		t.Fatalf("first lead lost its role: %+v", leads[1])
	}
	newest, err := s.GetJobLeadByConversation(ctx, uid, conv.ID)
	if err != nil || newest.ID != sreLead {
		t.Fatalf("newest lead = %+v err=%v, want %d", newest, err, sreLead)
	}
	all, err := s.ListJobLeads(ctx, uid, 20)
	if err != nil || len(all) != 2 {
		t.Fatalf("account leads = %d err=%v, want 2", len(all), err)
	}
	// Updating the older lead makes it the newest.
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: goLead, UserID: uid, ConversationID: conv.ID, Status: "awaiting_details"}); err != nil {
		t.Fatalf("update go lead: %v", err)
	}
	if newest, _ := s.GetJobLeadByConversation(ctx, uid, conv.ID); newest == nil || newest.ID != goLead {
		t.Fatalf("newest after update = %+v, want %d", newest, goLead)
	}
}

func assertUpdateByIDMerges(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	a, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Role: "Backend Engineer"})
	if err != nil {
		t.Fatalf("save a: %v", err)
	}
	b, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Company: "Corvane", Role: "Data Engineer", Status: "contacted"})
	if err != nil {
		t.Fatalf("save b: %v", err)
	}
	got, err := s.UpsertJobLead(ctx, JobLead{ID: a, UserID: uid, ConversationID: conv.ID, Company: "Nordlicht", Compensation: "to be discussed", Detail: `{"remote":true}`})
	if err != nil || got != a {
		t.Fatalf("update a: id=%d err=%v, want %d", got, err, a)
	}
	leadA, _ := s.GetJobLead(ctx, uid, a)
	if leadA.Role != "Backend Engineer" || leadA.Company != "Nordlicht" || leadA.Compensation != "to be discussed" ||
		leadA.Status != "new" || leadA.Detail != `{"remote":true}` {
		t.Fatalf("merged lead a = %+v", leadA)
	}
	// An empty detail keeps the saved one.
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: a, UserID: uid, ConversationID: conv.ID, Status: "awaiting_details"}); err != nil {
		t.Fatalf("status-only update: %v", err)
	}
	leadA, _ = s.GetJobLead(ctx, uid, a)
	if leadA.Detail != `{"remote":true}` || leadA.Company != "Nordlicht" || leadA.Status != "awaiting_details" {
		t.Fatalf("status-only update erased fields: %+v", leadA)
	}
	leadB, _ := s.GetJobLead(ctx, uid, b)
	if leadB.Company != "Corvane" || leadB.Role != "Data Engineer" || leadB.Status != "contacted" {
		t.Fatalf("update of a touched b: %+v", leadB)
	}
}

func assertUpdateIsScoped(t *testing.T, s *Store, uid, other int64) {
	t.Helper()
	ctx := context.Background()
	convAlice, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("conversation alice: %v", err)
	}
	convBob, err := s.EnsureConversation(ctx, uid, 556, "bob", "Bob")
	if err != nil {
		t.Fatalf("conversation bob: %v", err)
	}
	bobLead, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: convBob.ID, Company: "Tallgrass"})
	if err != nil {
		t.Fatalf("save bob lead: %v", err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: bobLead, UserID: uid, ConversationID: convAlice.ID, Company: "Injected"}); !errors.Is(err, ErrJobLeadNotFound) {
		t.Fatalf("cross-conversation update err=%v, want ErrJobLeadNotFound", err)
	}
	otherConv, err := s.EnsureConversation(ctx, other, 557, "carol", "Carol")
	if err != nil {
		t.Fatalf("conversation carol: %v", err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: bobLead, UserID: other, ConversationID: otherConv.ID, Company: "Injected"}); !errors.Is(err, ErrJobLeadNotFound) {
		t.Fatalf("cross-user update err=%v, want ErrJobLeadNotFound", err)
	}
	for _, id := range []int64{bobLead + 100000, -1} {
		if _, err := s.UpsertJobLead(ctx, JobLead{ID: id, UserID: uid, ConversationID: convBob.ID, Company: "Injected"}); !errors.Is(err, ErrJobLeadNotFound) {
			t.Fatalf("update of lead %d err=%v, want ErrJobLeadNotFound", id, err)
		}
	}
	got, _ := s.GetJobLead(ctx, uid, bobLead)
	if got.Company != "Tallgrass" {
		t.Fatalf("bob's lead was rewritten to %q", got.Company)
	}
	if leads, _ := s.ListJobLeadsByConversation(ctx, uid, convAlice.ID, 10); len(leads) != 0 {
		t.Fatalf("a refused update created leads in alice's conversation: %+v", leads)
	}
}

func assertJobSavesTwoLeads(t *testing.T, s *Store, uid int64) {
	t.Helper()
	ctx := context.Background()
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	jobID := seedJob(t, s, uid, fmt.Sprintf("evt:v1:1:555:two-leads-%d", time.Now().UnixNano()))
	if _, err := s.DB.ExecContext(ctx, `UPDATE agent_jobs SET conversation_id=$1 WHERE id=$2`, conv.ID, jobID); err != nil {
		t.Fatalf("bind job: %v", err)
	}
	claimed, err := s.ClaimAgentJobs(ctx, "worker", uid, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %+v err=%v", claimed, err)
	}
	attempt := claimed[0].Attempts
	first, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: attempt, Role: "Senior Go Engineer"})
	if err != nil {
		t.Fatalf("save first: %v", err)
	}
	second, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: attempt, Role: "Site Reliability Engineer"})
	if err != nil || second == first {
		t.Fatalf("save second: id=%d err=%v (first %d)", second, err, first)
	}
	if got, err := s.UpsertJobLead(ctx, JobLead{ID: first, UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: attempt, Company: "Halcyon Talent"}); err != nil || got != first {
		t.Fatalf("job-bound update of first: id=%d err=%v", got, err)
	}
	if _, err := s.UpsertJobLead(ctx, JobLead{ID: first, UserID: uid, ConversationID: conv.ID, JobID: jobID, Attempt: attempt + 1, Company: "Stale"}); !errors.Is(err, ErrAgentJobNotFound) {
		t.Fatalf("update under a stale attempt err=%v, want ErrAgentJobNotFound", err)
	}
	if err := s.CompleteAgentJobWithResult(ctx, uid, jobID, attempt, JobCompleted, "", 0, first); err != nil {
		t.Fatalf("complete with the last saved lead: %v", err)
	}
	if leads, _ := s.ListJobLeadsByConversation(ctx, uid, conv.ID, 10); len(leads) != 2 {
		t.Fatalf("leads after job = %d, want 2", len(leads))
	}
}

// TestJobLeads_MigrationDropsLegacyUniqueIndex: a database created before
// #951 has the one-lead-per-conversation unique index. Migrating it must
// drop that index, or the second lead of a conversation fails to insert.
func TestJobLeads_MigrationDropsLegacyUniqueIndex(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	if _, err := s.DB.ExecContext(ctx, `CREATE UNIQUE INDEX IF NOT EXISTS idx_job_leads_conversation ON job_leads(conversation_id)`); err != nil {
		t.Fatalf("recreate legacy index: %v", err)
	}
	if err := migrateAgent(ctx, s.DB, false); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	conv, err := s.EnsureConversation(ctx, uid, 555, "alice", "Alice")
	if err != nil {
		t.Fatalf("conversation: %v", err)
	}
	for _, role := range []string{"Senior Go Engineer", "Site Reliability Engineer"} {
		if _, err := s.UpsertJobLead(ctx, JobLead{UserID: uid, ConversationID: conv.ID, Role: role}); err != nil {
			t.Fatalf("save %q after migration: %v", role, err)
		}
	}
}
