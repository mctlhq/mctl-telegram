package db

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

// Durable deny codes (#1271): agent_actions.deny_code and audit_logs.deny_code,
// one same-transaction audit row per action that actually moves to denied.
// Fixtures reuse the supersession fixture's persona, Alice (chat 555).

type denyAuditRow struct {
	tool, status string
	errMsg       sql.NullString
	peer         sql.NullString
	code         sql.NullString
}

func denyAuditRows(t *testing.T, s *Store, uid int64) []denyAuditRow {
	t.Helper()
	rows, err := s.DB.Query(
		`SELECT tool_name, status, error, peer_redacted, deny_code FROM audit_logs
		  WHERE user_id = $1 AND tool_name = $2 ORDER BY id`, uid, AuditToolActionDenied)
	if err != nil {
		t.Fatalf("query denial audit rows: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []denyAuditRow
	for rows.Next() {
		var r denyAuditRow
		if err := rows.Scan(&r.tool, &r.status, &r.errMsg, &r.peer, &r.code); err != nil {
			t.Fatalf("scan denial audit row: %v", err)
		}
		out = append(out, r)
	}
	return out
}

func rawDenyCode(t *testing.T, s *Store, id int64) sql.NullString {
	t.Helper()
	var c sql.NullString
	if err := s.DB.QueryRow(`SELECT deny_code FROM agent_actions WHERE id = $1`, id).Scan(&c); err != nil {
		t.Fatalf("read deny_code of %d: %v", id, err)
	}
	return c
}

func mustVerify(t *testing.T, s *Store, uid int64) {
	t.Helper()
	res, err := s.VerifyAuditChain(context.Background(), uid)
	if err != nil || !res.OK {
		t.Fatalf("audit chain must verify: %+v err=%v", res, err)
	}
}

// approvedActions makes n approved actions, each under its own claimed job.
func approvedActions(t *testing.T, f *supersessionFixture, first int64, n int) []AgentAction {
	t.Helper()
	var out []AgentAction
	for i := 0; i < n; i++ {
		f.ingest(t, first+int64(i), "")
		job := f.claim(t)
		out = append(out, f.action(t, job, PolicyAllow, ActionApproved))
		completeJob(t, f, job)
	}
	return out
}

// completeJob closes the claimed job so the conversation's next message can be
// claimed; the action it produced stays.
func completeJob(t *testing.T, f *supersessionFixture, job AgentJob) {
	t.Helper()
	if err := f.s.CompleteAgentJob(context.Background(), job.ID, job.Attempts, JobCompleted, ""); err != nil {
		t.Fatalf("complete job: %v", err)
	}
}

func failDenialAudits(t *testing.T, s *Store, when string) {
	t.Helper()
	q := `CREATE TRIGGER deny_audit_fail BEFORE INSERT ON audit_logs
	      WHEN NEW.tool_name = 'agent_action_denied' ` + when + `
	      BEGIN SELECT RAISE(ABORT, 'audit write refused'); END`
	if _, err := s.DB.Exec(q); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	t.Cleanup(func() { _, _ = s.DB.Exec(`DROP TRIGGER IF EXISTS deny_audit_fail`) })
}

func TestDenyCode_MigrationIsIdempotentAndLegacyRowsStayNull(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	f := newSupersessionFixture(t, s, uid)

	// A denied row and an audit row written before the columns carry NULL.
	f.ingest(t, 10, "")
	a := f.action(t, f.claim(t), PolicyAllow, ActionApproved)
	if _, err := s.DB.Exec(`UPDATE agent_actions SET status = $1 WHERE id = $2`, ActionDenied, a.ID); err != nil {
		t.Fatal(err)
	}
	// Re-running the migration must not fail, drop or rewrite anything.
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, s.DB); err != nil {
			t.Fatalf("re-migrate %d: %v", i, err)
		}
	}
	for _, table := range []string{"agent_actions", "audit_logs"} {
		var n int
		if err := s.DB.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name = 'deny_code'`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s.deny_code present %d times, err=%v", table, n, err)
		}
	}
	if c := rawDenyCode(t, s, a.ID); c.Valid {
		t.Fatalf("legacy denied row must stay NULL, got %q", c.String)
	}
	got, err := s.GetAgentAction(ctx, uid, a.ID)
	if err != nil || got.Status != ActionDenied || got.DenyCode != "" {
		t.Fatalf("legacy readback: %+v err=%v", got, err)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 0 {
		t.Fatalf("migration must not backfill audit rows: %d", len(rows))
	}
}

func TestDenyCode_PolicyCodeAndUnknownArePersistedAndAudited(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	f := newSupersessionFixture(t, s, uid)
	acts := approvedActions(t, f, 10, 3)

	if ok, err := s.DenyAgentAction(ctx, uid, acts[0].ID, ActionApproved, "autopilot paused for this account", "autopilot_paused"); err != nil || !ok {
		t.Fatalf("DenyAgentAction: ok=%v err=%v", ok, err)
	}
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, acts[1].ID, ActionApproved, ActionDenied); err != nil || !ok {
		t.Fatalf("UpdateAgentActionStatus: ok=%v err=%v", ok, err)
	}
	if ok, err := s.DenyAgentActionWithReason(ctx, uid, acts[2].ID, ActionApproved, ReasonSourceEdited, DenyCodeSourceSuperseded); err != nil || !ok {
		t.Fatalf("DenyAgentActionWithReason: ok=%v err=%v", ok, err)
	}
	want := []string{"autopilot_paused", DenyCodeUnknown, "source_message_superseded"}
	for i, a := range acts {
		got, err := s.GetAgentAction(ctx, uid, a.ID)
		if err != nil || got.Status != ActionDenied || got.DenyCode != want[i] {
			t.Fatalf("action %d readback: status=%q code=%q err=%v, want code %q", i, got.Status, got.DenyCode, err, want[i])
		}
	}
	rows := denyAuditRows(t, s, uid)
	if len(rows) != 3 {
		t.Fatalf("denial audit rows = %d, want 3", len(rows))
	}
	for i, r := range rows {
		if r.status != "denied" || r.code.String != want[i] || r.errMsg.String != auditActionDeniedError {
			t.Fatalf("audit row %d = %+v, want code %q and the constant error", i, r, want[i])
		}
	}
	// policy_reasons prose is untouched by the code.
	if g, _ := s.GetAgentAction(ctx, uid, acts[0].ID); g.PolicyReasons != "autopilot paused for this account" {
		t.Fatalf("reason prose changed: %q", g.PolicyReasons)
	}
	// The status-only denial keeps the reasons the action was proposed with.
	if g, _ := s.GetAgentAction(ctx, uid, acts[1].ID); g.PolicyReasons != "" {
		t.Fatalf("status-only denial rewrote reasons: %q", g.PolicyReasons)
	}
	mustVerify(t, s, uid)
}

func TestDenyCode_EmptyCodeIsStoredAsUnknown(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	a := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 1)[0]
	if ok, err := s.DenyAgentActionCode(ctx, uid, a.ID, ActionApproved, ""); err != nil || !ok {
		t.Fatalf("deny: ok=%v err=%v", ok, err)
	}
	if c := rawDenyCode(t, s, a.ID); c.String != DenyCodeUnknown {
		t.Fatalf("deny_code = %+v, want unknown", c)
	}
}

func TestDenyCode_NonDeniedTransitionsAreNotMislabelled(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	f := newSupersessionFixture(t, s, uid)
	f.ingest(t, 10, "")
	pj := f.claim(t)
	pending := f.action(t, pj, PolicyRequireApproval, ActionPendingApproval)
	completeJob(t, f, pj)
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, pending.ID, ActionPendingApproval, ActionRejected); err != nil || !ok {
		t.Fatalf("reject: ok=%v err=%v", ok, err)
	}
	f.ingest(t, 11, "")
	uj := f.claim(t)
	unknown := f.action(t, uj, PolicyAllow, ActionApproved)
	completeJob(t, f, uj)
	if _, err := s.DB.Exec(`UPDATE agent_actions SET status = $1 WHERE id = $2`, ActionDeliveryUnknown, unknown.ID); err != nil {
		t.Fatal(err)
	}
	// An action inserted proposed/approved with a stray DenyCode keeps NULL.
	f.ingest(t, 12, "")
	job := f.claim(t)
	id, err := s.InsertAgentAction(ctx, AgentAction{
		JobID: job.ID, Attempt: job.Attempts, ConversationID: f.convID, UserID: uid,
		ActionType: ActionTypeReply, Payload: "Hi Alice", PolicyDecision: PolicyAllow,
		Status: ActionApproved, DenyCode: "mode_off",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{pending.ID, unknown.ID, id} {
		if c := rawDenyCode(t, s, id); c.Valid {
			t.Fatalf("non-denied action %d has deny_code %q", id, c.String)
		}
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 0 {
		t.Fatalf("non-denied transitions wrote %d denial audit rows", len(rows))
	}
}

func TestDenyCode_CASLossAndReplayWriteNoSecondAudit(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	a := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 1)[0]

	if ok, err := s.DenyAgentAction(ctx, uid, a.ID, ActionApproved, "r", "mode_off"); err != nil || !ok {
		t.Fatalf("first deny: ok=%v err=%v", ok, err)
	}
	// Same transition again, and a different writer racing for the same row.
	if ok, err := s.DenyAgentAction(ctx, uid, a.ID, ActionApproved, "r", "mode_off"); err != nil || ok {
		t.Fatalf("replay: ok=%v err=%v, want a lost CAS", ok, err)
	}
	if ok, err := s.UpdateAgentActionStatus(ctx, uid, a.ID, ActionApproved, ActionDenied); err != nil || ok {
		t.Fatalf("racing writer: ok=%v err=%v", ok, err)
	}
	if ok, err := s.DenyAgentAction(ctx, uid+99, a.ID, ActionApproved, "r", "mode_off"); err != nil || ok {
		t.Fatalf("other tenant: ok=%v err=%v", ok, err)
	}
	rows := denyAuditRows(t, s, uid)
	if len(rows) != 1 || rows[0].code.String != "mode_off" {
		t.Fatalf("audit rows after replay = %+v, want exactly one mode_off", rows)
	}
	if c := rawDenyCode(t, s, a.ID); c.String != "mode_off" {
		t.Fatalf("replay overwrote the code: %+v", c)
	}
}

func TestDenyCode_InsertAsDeniedAuditsOnceAndReplayDoesNot(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	f := newSupersessionFixture(t, s, uid)
	f.ingest(t, 10, "")
	job := f.claim(t)
	a := AgentAction{
		JobID: job.ID, Attempt: job.Attempts, ConversationID: f.convID, UserID: uid,
		ActionType: ActionTypeReply, Payload: "Hi Alice", PolicyDecision: PolicyDeny,
		PolicyReasons: "autopilot paused for this account", Status: ActionDenied, DenyCode: "autopilot_paused",
	}
	id, err := s.InsertAgentAction(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := s.InsertAgentAction(ctx, a); err != nil || again != id {
		t.Fatalf("replay: id=%d err=%v, want %d", again, err, id)
	}
	completeJob(t, f, job)
	got, err := s.GetAgentAction(ctx, uid, id)
	if err != nil || got.DenyCode != "autopilot_paused" || got.Status != ActionDenied {
		t.Fatalf("readback: %+v err=%v", got, err)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 1 || rows[0].code.String != "autopilot_paused" {
		t.Fatalf("audit rows = %+v, want exactly one", rows)
	}
	// Jobless insert takes the other branch and also audits once.
	jl, err := s.InsertAgentAction(ctx, AgentAction{
		ConversationID: f.convID, UserID: uid, ActionType: ActionTypeOwnerSummary, Payload: "x",
		PolicyDecision: PolicyDeny, Status: ActionDenied, DenyCode: "global_kill",
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := rawDenyCode(t, s, jl); c.String != "global_kill" {
		t.Fatalf("jobless code = %+v", c)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(rows))
	}
	// A denied insert without a code is stored as unknown.
	f.ingest(t, 11, "")
	job2 := f.claim(t)
	id2, err := s.InsertAgentAction(ctx, AgentAction{
		JobID: job2.ID, Attempt: job2.Attempts, ConversationID: f.convID, UserID: uid,
		ActionType: ActionTypeReply, Payload: "x", PolicyDecision: PolicyDeny, Status: ActionDenied,
	})
	if err != nil {
		t.Fatal(err)
	}
	if c := rawDenyCode(t, s, id2); c.String != DenyCodeUnknown {
		t.Fatalf("default code = %+v", c)
	}
	mustVerify(t, s, uid)
}

func TestDenyCode_EveryBulkPathWritesOneAuditRowPerAction(t *testing.T) {
	ctx := context.Background()

	t.Run("conversation sweep", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		acts := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 3)
		n, err := s.DenyPendingActionsForConversation(ctx, uid, acts[0].ConversationID, "owner sent a message directly")
		if err != nil || n != 3 {
			t.Fatalf("denied %d err=%v, want 3", n, err)
		}
		assertBulk(t, s, uid, acts, DenyCodeUnknown)
		// A second sweep moves nothing and adds nothing.
		if n, err := s.DenyPendingActionsForConversation(ctx, uid, acts[0].ConversationID, "again"); err != nil || n != 0 {
			t.Fatalf("replay denied %d err=%v", n, err)
		}
		if rows := denyAuditRows(t, s, uid); len(rows) != 3 {
			t.Fatalf("replay changed audit rows: %d", len(rows))
		}
	})

	t.Run("source message sweep", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		f := newSupersessionFixture(t, s, uid)
		acts := approvedActions(t, f, 10, 3)
		// Only the drafts of message 11 are withdrawn.
		n, err := s.DenyPendingActionsForSourceMessage(ctx, uid, f.convID, 11, ReasonSourceEdited)
		if err != nil || n != 1 {
			t.Fatalf("denied %d err=%v, want 1", n, err)
		}
		assertBulk(t, s, uid, acts[1:2], DenyCodeSourceSuperseded)
		if rows := denyAuditRows(t, s, uid); len(rows) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(rows))
		}
	})

	t.Run("message delete", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		f := newSupersessionFixture(t, s, uid)
		acts := approvedActions(t, f, 10, 2)
		res := f.recordDelete(t, 10)
		if res.DeniedActions != 1 {
			t.Fatalf("DeniedActions = %d, want 1", res.DeniedActions)
		}
		assertBulk(t, s, uid, acts[:1], DenyCodeSourceSuperseded)
		// A redelivered delete changes nothing, including the audit trail.
		if again := f.recordDelete(t, 10); again.DeniedActions != 0 {
			t.Fatalf("redelivery denied %d", again.DeniedActions)
		}
		if rows := denyAuditRows(t, s, uid); len(rows) != 1 {
			t.Fatalf("audit rows = %d, want 1", len(rows))
		}
	})

	t.Run("earlier install sweep", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		acts := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 2)
		if _, err := s.DB.Exec(`INSERT INTO agent_profiles(user_id, install_revision) VALUES($1, 5)`, uid); err != nil {
			t.Fatal(err)
		}
		n, err := s.DenyActionsFromEarlierInstalls(ctx, uid, "the assistant install changed since this work began")
		if err != nil || n != 2 {
			t.Fatalf("denied %d err=%v, want 2", n, err)
		}
		assertBulk(t, s, uid, acts, DenyCodeInstallChanged)
	})

	t.Run("retention sweep", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		acts := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 2)
		old := time.Now().UTC().Add(-48 * time.Hour)
		if _, err := s.DB.Exec(`UPDATE agent_actions SET created_at = $1, updated_at = $1 WHERE user_id = $2`, old, uid); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SweepAgentMessageBodies(ctx, 24*time.Hour); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		assertBulk(t, s, uid, acts, DenyCodeUnknown)
	})
}

// Only rows the sweep actually transitioned (stale revision, proposed or
// approved) get install_changed and an audit row; a current-revision row and a
// replay get neither; an audit failure rolls the whole sweep back.
func TestDenyCode_EarlierInstallSweepCodesOnlyTransitionedRows(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	acts := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 3)
	if _, err := s.DB.Exec(`INSERT INTO agent_profiles(user_id, install_revision) VALUES($1, 5)`, uid); err != nil {
		t.Fatal(err)
	}
	// acts[2] is current: it must not be swept.
	if _, err := s.DB.Exec(`UPDATE agent_actions SET install_revision = 5 WHERE id = $1`, acts[2].ID); err != nil {
		t.Fatal(err)
	}

	failDenialAudits(t, s, "")
	if n, err := s.DenyActionsFromEarlierInstalls(ctx, uid, "install changed"); err == nil || n != 0 {
		t.Fatalf("n=%d err=%v, want rollback on a failed audit", n, err)
	}
	for _, a := range acts {
		if got, _ := s.GetAgentAction(ctx, uid, a.ID); got.Status != ActionApproved || got.DenyCode != "" {
			t.Fatalf("action %d changed despite a failed audit: %+v", a.ID, got)
		}
	}
	if _, err := s.DB.Exec(`DROP TRIGGER deny_audit_fail`); err != nil {
		t.Fatal(err)
	}

	n, err := s.DenyActionsFromEarlierInstalls(ctx, uid, "install changed")
	if err != nil || n != 2 {
		t.Fatalf("denied %d err=%v, want 2", n, err)
	}
	assertBulk(t, s, uid, acts[:2], DenyCodeInstallChanged)
	if got, _ := s.GetAgentAction(ctx, uid, acts[2].ID); got.Status != ActionApproved || got.DenyCode != "" {
		t.Fatalf("current-revision action touched: %+v", got)
	}
	if n, err := s.DenyActionsFromEarlierInstalls(ctx, uid, "install changed"); err != nil || n != 0 {
		t.Fatalf("replay denied %d err=%v, want 0", n, err)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2 (replay adds none)", len(rows))
	}
}

// assertBulk checks that each action is denied with code and has exactly one
// denial audit row naming it, and that the chain verifies.
func assertBulk(t *testing.T, s *Store, uid int64, acts []AgentAction, code string) {
	t.Helper()
	for _, a := range acts {
		got, err := s.GetAgentAction(context.Background(), uid, a.ID)
		if err != nil || got.Status != ActionDenied || got.DenyCode != code {
			t.Fatalf("action %d: status=%q code=%q err=%v, want denied/%q", a.ID, got.Status, got.DenyCode, err, code)
		}
		var n int
		if err := s.DB.QueryRow(
			`SELECT count(*) FROM audit_logs WHERE user_id = $1 AND tool_name = $2 AND peer_redacted = $3 AND deny_code = $4`,
			uid, AuditToolActionDenied, "action:"+strconv.FormatInt(a.ID, 10), code).Scan(&n); err != nil || n != 1 {
			t.Fatalf("action %d has %d audit rows with code %q, err=%v, want 1", a.ID, n, code, err)
		}
	}
	mustVerify(t, s, uid)
}

func TestDenyCode_AuditFailureRollsBackTheStatusChange(t *testing.T) {
	ctx := context.Background()

	t.Run("single deny", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		a := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 1)[0]
		failDenialAudits(t, s, "")
		ok, err := s.DenyAgentAction(ctx, uid, a.ID, ActionApproved, "r", "mode_off")
		if err == nil || ok {
			t.Fatalf("ok=%v err=%v, want a failure and no reported success", ok, err)
		}
		got, _ := s.GetAgentAction(ctx, uid, a.ID)
		if got.Status != ActionApproved || got.DenyCode != "" || got.PolicyReasons != "" {
			t.Fatalf("status change survived a failed audit: %+v", got)
		}
	})

	t.Run("bulk failing on the second audit row", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		acts := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 3)
		failDenialAudits(t, s, "AND (SELECT count(*) FROM audit_logs WHERE tool_name = 'agent_action_denied') >= 1")
		n, err := s.DenyPendingActionsForConversation(ctx, uid, acts[0].ConversationID, "r")
		if err == nil || n != 0 {
			t.Fatalf("n=%d err=%v, want 0 and an error", n, err)
		}
		for _, a := range acts {
			if got, _ := s.GetAgentAction(ctx, uid, a.ID); got.Status != ActionApproved || got.DenyCode != "" {
				t.Fatalf("action %d partially denied: %+v", a.ID, got)
			}
		}
		if rows := denyAuditRows(t, s, uid); len(rows) != 0 {
			t.Fatalf("audit row of the first action survived: %d", len(rows))
		}
	})

	t.Run("message delete", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		f := newSupersessionFixture(t, s, uid)
		acts := approvedActions(t, f, 10, 1)
		failDenialAudits(t, s, "")
		if _, err := s.RecordMessageDelete(ctx, uid, 1, 10); err == nil {
			t.Fatal("delete must fail when its denial audit cannot be written")
		}
		if got, _ := s.GetAgentAction(ctx, uid, acts[0].ID); got.Status != ActionApproved {
			t.Fatalf("status = %q", got.Status)
		}
		// The delete event rolled back too, so a redelivery can apply it.
		if f.deleteEvents(t) != 0 {
			t.Fatal("message_delete event survived the rollback")
		}
	})

	t.Run("insert as denied", func(t *testing.T) {
		s := newTestStoreCrypted(t)
		uid := seedAgentUser(t, s, "owner")
		f := newSupersessionFixture(t, s, uid)
		f.ingest(t, 10, "")
		job := f.claim(t)
		failDenialAudits(t, s, "")
		_, err := s.InsertAgentAction(ctx, AgentAction{
			JobID: job.ID, Attempt: job.Attempts, ConversationID: f.convID, UserID: uid,
			ActionType: ActionTypeReply, Payload: "x", PolicyDecision: PolicyDeny, Status: ActionDenied, DenyCode: "mode_off",
		})
		if err == nil {
			t.Fatal("insert must fail when its denial audit cannot be written")
		}
		var n int
		if err := s.DB.QueryRow(`SELECT count(*) FROM agent_actions WHERE user_id = $1`, uid).Scan(&n); err != nil || n != 0 {
			t.Fatalf("denied action row survived: %d err=%v", n, err)
		}
	})
}

// TestDenyCode_Postgres runs the dialect-sensitive parts (UPDATE ... RETURNING,
// the idempotent ADD COLUMN IF NOT EXISTS, same-transaction audit) against a
// real PostgreSQL. It needs TEST_DATABASE_URL and is skipped without it, so a
// run without one proves nothing about PostgreSQL.
func TestDenyCode_Postgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s := newPostgresTestStore(t, dsn)
	uid := seedAgentUser(t, s, "denycode_"+strconv.FormatInt(time.Now().UnixNano(), 10))
	t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM audit_logs WHERE user_id = $1`,
			`DELETE FROM agent_actions WHERE user_id = $1`,
			`DELETE FROM agent_job_attempts WHERE job_id IN (SELECT id FROM agent_jobs WHERE user_id = $1)`,
			`DELETE FROM agent_jobs WHERE user_id = $1`,
			`DELETE FROM incoming_events WHERE user_id = $1`,
			`DELETE FROM conversations WHERE user_id = $1`,
			`DELETE FROM users WHERE id = $1`,
		} {
			_, _ = s.DB.Exec(q, uid)
		}
	})
	if err := Migrate(ctx, s.DB); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	for _, table := range []string{"agent_actions", "audit_logs"} {
		var n int
		if err := s.DB.QueryRow(`SELECT count(*) FROM information_schema.columns WHERE table_name = $1 AND column_name = 'deny_code'`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("%s.deny_code present %d times, err=%v", table, n, err)
		}
	}
	f := newSupersessionFixture(t, s, uid)
	acts := approvedActions(t, f, 10, 2)
	if ok, err := s.DenyAgentAction(ctx, uid, acts[0].ID, ActionApproved, "r", "mode_off"); err != nil || !ok {
		t.Fatalf("deny: ok=%v err=%v", ok, err)
	}
	if ok, err := s.DenyAgentAction(ctx, uid, acts[0].ID, ActionApproved, "r", "mode_off"); err != nil || ok {
		t.Fatalf("replay: ok=%v err=%v", ok, err)
	}
	n, err := s.DenyPendingActionsForConversation(ctx, uid, f.convID, "owner sent a message directly")
	if err != nil || n != 1 {
		t.Fatalf("bulk denied %d err=%v, want 1", n, err)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 2 || rows[0].code.String != "mode_off" || rows[1].code.String != DenyCodeUnknown {
		t.Fatalf("audit rows = %+v", rows)
	}
	mustVerify(t, s, uid)
}

func TestDenyCode_CancelledContextPersistsNeitherWrite(t *testing.T) {
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	a := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 1)[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := s.DenyAgentAction(ctx, uid, a.ID, ActionApproved, "r", "mode_off")
	if ok || err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("ok=%v err=%v, want context.Canceled", ok, err)
	}
	if got, _ := s.GetAgentAction(context.Background(), uid, a.ID); got.Status != ActionApproved {
		t.Fatalf("cancelled deny changed the action: %+v", got)
	}
	if rows := denyAuditRows(t, s, uid); len(rows) != 0 {
		t.Fatalf("cancelled deny wrote %d audit rows", len(rows))
	}
}

func TestDenyCode_AuditRowKeepsScrubTenantAndCorrelation(t *testing.T) {
	ctx := context.Background()
	s := newTestStoreCrypted(t)
	uid := seedAgentUser(t, s, "owner")
	other := seedAgentUser(t, s, "other")
	a := approvedActions(t, newSupersessionFixture(t, s, uid), 10, 1)[0]
	if ok, err := s.DenyAgentAction(ctx, uid, a.ID, ActionApproved, "r", "mode_off"); err != nil || !ok {
		t.Fatal(err)
	}
	var callPath sql.NullString
	var created time.Time
	if err := s.DB.QueryRow(
		`SELECT call_path, created_at FROM audit_logs WHERE user_id = $1 AND tool_name = $2`,
		uid, AuditToolActionDenied).Scan(&callPath, &created); err != nil {
		t.Fatal(err)
	}
	if !callPath.Valid || callPath.String != "" || created.IsZero() {
		t.Fatalf("call_path=%+v created=%v, want a hosted row with a timestamp", callPath, created)
	}
	if rows := denyAuditRows(t, s, other); len(rows) != 0 {
		t.Fatalf("another tenant sees %d rows", len(rows))
	}
}
