package db

import (
	"context"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/metrics"
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

func TestAcquisitionLabelsAndReport(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
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
	erin := mk(77015, nil) // not recorded
	old := mk(77016, nil)
	// A user created before the epoch reports as pre-capture.
	if _, err := s.DB.Exec(`UPDATE users SET created_at=$1 WHERE id=$2`, time.Now().UTC().Add(-48*time.Hour), old); err != nil {
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
	ins(alice, now)
	ins(alice, now.Add(-30*time.Hour))
	ins(bob, now)
	ins(bob, now.Add(-time.Minute))
	_, _, _ = carol, dana, erin

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
	if b := got["direct"]; b.Signups != 1 || b.ToolCallUsers != 0 {
		t.Errorf("direct bucket %+v", b)
	}
}
