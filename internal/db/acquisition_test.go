package db

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func acqRow(t *testing.T, s *Store, uid int64) (Acquisition, bool) {
	t.Helper()
	var a Acquisition
	err := s.DB.QueryRow(`SELECT state, referrer_host, utm_source, utm_campaign, landing_path, mcp_client
		FROM user_acquisition WHERE user_id=$1`, uid).
		Scan(&a.State, &a.ReferrerHost, &a.UTMSource, &a.UTMCampaign, &a.LandingPath, &a.MCPClient)
	if err != nil {
		return Acquisition{}, false
	}
	return a, true
}

func captureFor(tg int64, a *Acquisition) TelegramIdentityCapture {
	return TelegramIdentityCapture{TelegramID: tg, FirstName: "Alice", Source: "telegram_oidc", Acquisition: a}
}

func TestEnsureUserByTelegramCapture_WritesAcquisitionOnceOnCreate(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	first := &Acquisition{State: AcquisitionAttributed, UTMSource: "x", UTMCampaign: "y", ReferrerHost: "news.example", LandingPath: "/docs", MCPClient: "claude"}
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77001, first))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := acqRow(t, s, uid)
	if !ok || got.State != AcquisitionAttributed || got.UTMSource != "x" || got.UTMCampaign != "y" ||
		got.ReferrerHost != "news.example" || got.LandingPath != "/docs" || got.MCPClient != "claude" {
		t.Fatalf("row = %+v ok=%v", got, ok)
	}
	// Returning user with a different snapshot: the row is untouched.
	uid2, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77001, &Acquisition{State: AcquisitionDirect, UTMSource: "other"}))
	if err != nil || uid2 != uid {
		t.Fatalf("returning: %d %v", uid2, err)
	}
	if again, _ := acqRow(t, s, uid); again != got {
		t.Fatalf("row changed: %+v -> %+v", got, again)
	}
}

func TestEnsureUserByTelegramCapture_NilAcquisitionWritesNothing(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77002, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := acqRow(t, s, uid); ok {
		t.Fatal("nil snapshot must not write a row")
	}
}

func TestEnsureUserByTelegramCapture_AcquisitionFailureKeepsUser(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	reg := metrics.New()
	s.WithMetrics(reg)
	if _, err := s.DB.Exec(`ALTER TABLE user_acquisition RENAME TO user_acquisition_gone`); err != nil {
		t.Fatal(err)
	}
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77003, &Acquisition{State: AcquisitionDirect}))
	if err != nil || uid == 0 {
		t.Fatalf("sign-in must succeed: %d %v", uid, err)
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=$1`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("user row missing: %d %v", n, err)
	}
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM user_acquisition_gone`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no row (and never a direct stand-in) expected: %d %v", n, err)
	}
	if got := testutil.ToFloat64(reg.AcquisitionWriteFailuresTotal); got != 1 {
		t.Fatalf("mctl_acquisition_write_failures_total = %v, want 1", got)
	}
}

func TestHardDeleteAccount_PurgesAcquisition(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77004, &Acquisition{State: AcquisitionUnknown, MCPClient: "local-bridge"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := acqRow(t, s, uid); !ok {
		t.Fatal("setup: row missing")
	}
	if _, err := s.HardDeleteAccount(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, ok := acqRow(t, s, uid); ok {
		t.Fatal("acquisition row survived account deletion")
	}
	var n int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE id=$1`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("users row must survive: %d %v", n, err)
	}
}

// TestAcquisitionLabelsAndReport runs on SQLite and, with
// TEST_DATABASE_URL, on Postgres: the report's per-day expression differs
// per dialect.
func TestAcquisitionLabelsAndReport(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { testAcquisitionLabelsAndReport(t, newTestStore(t)) })
	t.Run("postgres", func(t *testing.T) { testAcquisitionLabelsAndReport(t, newFreshSchemaPostgresStore(t)) })
}

func testAcquisitionLabelsAndReport(t *testing.T, s *Store) {
	ctx := context.Background()
	mk := func(tg int64, a *Acquisition) int64 {
		uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(tg, a))
		if err != nil {
			t.Fatal(err)
		}
		return uid
	}
	alice := mk(77011, &Acquisition{State: AcquisitionAttributed, UTMSource: "blog", ReferrerHost: "x.example"})
	bob := mk(77012, &Acquisition{State: AcquisitionAttributed, ReferrerHost: "dir.example"})
	carol := mk(77013, &Acquisition{State: AcquisitionDirect})
	dana := mk(77014, &Acquisition{State: AcquisitionUnknown})
	notRecorded := mk(77015, nil)
	preCapture := mk(77016, nil)
	// A user created before the epoch reports as pre-capture.
	if _, err := s.DB.Exec(`UPDATE users SET created_at=$1 WHERE id=$2`, time.Now().UTC().Add(-48*time.Hour), preCapture); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`UPDATE acquisition_capture_epoch SET enabled_at=$1`, time.Now().UTC().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	labels, err := s.AcquisitionLabelsFor(ctx, []int64{77011, 77012, 77013, 77014, 77015, 77016})
	if err != nil {
		t.Fatal(err)
	}
	want := map[int64]string{77011: "blog", 77012: "dir.example", 77013: "direct", 77014: "unknown",
		77015: AcquisitionLabelNotRecorded, 77016: AcquisitionLabelPreCapture}
	for id, w := range want {
		if labels[id] != w {
			t.Errorf("label[%d] = %q, want %q", id, labels[id], w)
		}
	}

	// Tool calls: alice on 2 days, bob on 1 day, others none.
	ins := func(uid int64, ts time.Time) {
		if _, err := s.DB.Exec(`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,'list_dialogs','ok',$2)`, uid, ts); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	// Backdate the synthetic registrations so every intended successful
	// call is after signup. Bob's two calls on the same day then exercise
	// UTC-day deduplication rather than silently losing the earlier row.
	for _, uid := range []int64{alice, bob} {
		if _, err := s.DB.Exec(`UPDATE users SET created_at=$1 WHERE id=$2`, now.Add(-72*time.Hour), uid); err != nil {
			t.Fatal(err)
		}
	}
	ins(alice, now)
	ins(alice, now.Add(-30*time.Hour))
	ins(bob, now)
	ins(bob, now.Add(-time.Minute))
	// PA connector rows are calls the assistant made, not the user using
	// the connector: bob's on another day must not make him a 2+ day user,
	// and carol's must not make her an activated one (#1331 follow-up).
	insPA := func(uid int64, ts time.Time) {
		if _, err := s.DB.Exec(`INSERT INTO audit_logs(user_id, tool_name, status, call_path, created_at) VALUES($1,'pa:tg/list_dialogs','ok','pa',$2)`, uid, ts); err != nil {
			t.Fatal(err)
		}
	}
	insPA(bob, now.Add(-50*time.Hour))
	insPA(carol, now)
	_, _ = dana, notRecorded

	rep, err := s.AcquisitionReport(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]AcquisitionBucket{}
	for _, b := range rep {
		got[b.Source] = b
	}
	if b := got["blog"]; b.Signups != 1 || b.ToolCallUsers != 1 || b.Active2PlusDays != 1 {
		t.Errorf("blog bucket %+v", b)
	}
	if b := got["dir.example"]; b.Signups != 1 || b.ToolCallUsers != 1 || b.Active2PlusDays != 0 {
		t.Errorf("dir bucket %+v", b)
	}
	if b := got["direct"]; b.Signups != 1 || b.ToolCallUsers != 0 || b.Active2PlusDays != 0 {
		t.Errorf("direct bucket %+v", b)
	}
}

// A returning user never gains a row, even when their creation wrote none
// (nil snapshot then, a real snapshot now). ON CONFLICT DO NOTHING cannot
// catch this case because there is no row to conflict with; only the
// RowsAffected()==1 guard does, which is what this test pins.
func TestEnsureUserByTelegramCapture_ReturningUserWithoutRowGetsNone(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77005, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := acqRow(t, s, uid); ok {
		t.Fatal("nil snapshot must not write a row")
	}
	again, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77005, &Acquisition{State: AcquisitionDirect, MCPClient: "claude"}))
	if err != nil {
		t.Fatal(err)
	}
	if again != uid {
		t.Fatalf("second sign-in resolved to a different user: %d vs %d", again, uid)
	}
	if _, ok := acqRow(t, s, uid); ok {
		t.Fatal("a returning user must not gain an acquisition row")
	}
}

func TestRecordHeardFrom_FirstAnswerStaysAndLeadsTheLabel(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77021,
		&Acquisition{State: AcquisitionAttributed, UTMSource: "blog"}))
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC().Add(-time.Hour)
	if ask, err := s.HeardFromUnanswered(ctx, uid, since); err != nil || !ask {
		t.Fatalf("new account: ask=%v err=%v, want true", ask, err)
	}
	if err := s.RecordHeardFrom(ctx, uid, "search"); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordHeardFrom(ctx, uid, "telegram"); err != nil {
		t.Fatal(err)
	}
	if ask, err := s.HeardFromUnanswered(ctx, uid, since); err != nil || ask {
		t.Fatalf("answered account: ask=%v err=%v, want false", ask, err)
	}
	labels, err := s.AcquisitionLabelsFor(ctx, []int64{77021})
	if err != nil {
		t.Fatal(err)
	}
	if labels[77021] != "search" {
		t.Fatalf("label = %q, want the first answer", labels[77021])
	}
}

func TestHeardFromUnanswered_NotAskedOutsideTheWindowOrWithoutARecord(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	old, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77022, &Acquisition{State: AcquisitionUnknown}))
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now().UTC().Add(time.Hour)
	if ask, err := s.HeardFromUnanswered(ctx, old, since); err != nil || ask {
		t.Fatalf("record older than the window: ask=%v err=%v", ask, err)
	}
	none, err := s.EnsureUserByTelegramCapture(ctx, captureFor(77023, nil))
	if err != nil {
		t.Fatal(err)
	}
	if ask, err := s.HeardFromUnanswered(ctx, none, time.Now().UTC().Add(-time.Hour)); err != nil || ask {
		t.Fatalf("no record: ask=%v err=%v", ask, err)
	}
}

func TestHeardFromUnanswered_FailedReadIsAnErrorNotFalse(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if _, err := s.DB.Exec(`ALTER TABLE user_acquisition RENAME TO user_acquisition_gone`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.HeardFromUnanswered(ctx, 1, time.Now()); err == nil {
		t.Fatal("a failed read must return an error")
	}
	if err := s.RecordHeardFrom(ctx, 1, "search"); err == nil {
		t.Fatal("a failed write must return an error")
	}
}

// TestAcquisitionReport_QualifyingEvents exercises the acquisition funnel's
// activity predicate on SQLite and Postgres. A successful signup and its
// connect:* audit steps are NOT MCP product use; neither are failed calls,
// Local Bridge housekeeping, web forms or Personal Assistant connector rows.
//
// Mutation check: replacing publicToolFilter with "tool_name NOT LIKE 'pa:%'"
// must fail this test; removing the signup timestamp fence must fail too.
func TestAcquisitionReport_QualifyingEvents(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) { testAcquisitionReportQualifyingEvents(t, newTestStore(t)) })
	t.Run("postgres", func(t *testing.T) { testAcquisitionReportQualifyingEvents(t, newFreshSchemaPostgresStore(t)) })
}

func testAcquisitionReportQualifyingEvents(t *testing.T, s *Store) {
	ctx := context.Background()
	// Noon UTC gives stable distinct-day expectations on both SQL dialects.
	now := time.Now().UTC().Truncate(24*time.Hour).Add(12 * time.Hour)
	started := now.Add(-72 * time.Hour)
	create := func(tg int64, source string) int64 {
		t.Helper()
		uid, err := s.EnsureUserByTelegramCapture(ctx, captureFor(tg, &Acquisition{
			State: AcquisitionAttributed, UTMSource: source,
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB.ExecContext(ctx,
			`UPDATE users SET created_at=$1 WHERE id=$2`, started, uid); err != nil {
			t.Fatal(err)
		}
		return uid
	}
	insert := func(uid int64, tool, status string, at time.Time) {
		t.Helper()
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO audit_logs(user_id, tool_name, status, created_at) VALUES($1,$2,$3,$4)`,
			uid, tool, status, at); err != nil {
			t.Fatal(err)
		}
	}
	// Reuse synthetic numeric IDs from other isolated acquisition tests.
	connect := create(77001, "only-connect")
	insert(connect, "connect:oidc_callback", "ok", now.Add(-26*time.Hour))
	insert(connect, "connect:success", "ok", now.Add(-2*time.Hour))
	failed := create(77002, "only-failed")
	insert(failed, "get_messages", "error", now.Add(-26*time.Hour))
	insert(failed, "search_messages", "refused", now.Add(-2*time.Hour))
	bridge := create(77003, "only-bridge")
	insert(bridge, "local_bridge_device_refresh", "ok", now.Add(-26*time.Hour))
	insert(bridge, "local_bridge_device_refresh", "ok", now.Add(-2*time.Hour))
	web := create(77004, "only-web")
	insert(web, "POST /telegram/connect/manage/notifications", "ok", now.Add(-26*time.Hour))
	insert(web, "POST /telegram/connect/manage/notifications", "ok", now.Add(-2*time.Hour))
	pa := create(77005, "only-pa")
	insert(pa, "pa:tg/list_dialogs", "ok", now.Add(-26*time.Hour))
	insert(pa, "pa:tg/list_dialogs", "ok", now.Add(-2*time.Hour))
	preSignup := create(77011, "only-before-signup")
	insert(preSignup, "list_dialogs", "ok", started.Add(-time.Hour))
	twoDays := create(77012, "valid-two-days")
	insert(twoDays, "list_dialogs", "ok", now.Add(-26*time.Hour))
	insert(twoDays, "get_messages", "ok", now.Add(-2*time.Hour))
	oneDay := create(77013, "valid-one-day")
	insert(oneDay, "get_messages", "ok", now.Add(-2*time.Hour))
	insert(oneDay, "search_messages", "error", now.Add(-26*time.Hour))
	sameDay := create(77014, "valid-same-day")
	insert(sameDay, "list_dialogs", "ok", now.Add(-2*time.Hour))
	insert(sameDay, "get_messages", "ok", now.Add(-time.Hour))

	report, err := s.AcquisitionReport(ctx, now.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]AcquisitionBucket, len(report))
	for _, b := range report {
		got[b.Source] = b
	}
	for _, source := range []string{
		"only-connect", "only-failed", "only-bridge", "only-web",
		"only-pa", "only-before-signup",
	} {
		b, found := got[source]
		if !found || b.Signups != 1 || b.ToolCallUsers != 0 || b.Active2PlusDays != 0 {
			t.Errorf("%s = %+v (found=%v); want signups=1, calls=0, 2plus=0", source, b, found)
		}
	}
	for _, tc := range []struct {
		source string
		twoPlus int64
	}{
		{source: "valid-two-days", twoPlus: 1},
		{source: "valid-one-day", twoPlus: 0},
		{source: "valid-same-day", twoPlus: 0},
	} {
		b, found := got[tc.source]
		if !found || b.Signups != 1 || b.ToolCallUsers != 1 || b.Active2PlusDays != tc.twoPlus {
			t.Errorf("%s = %+v (found=%v); want signup=1, tool_user=1, 2plus=%d",
				tc.source, b, found, tc.twoPlus)
		}
	}
}

