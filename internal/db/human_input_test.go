package db

import (
	"context"
	"errors"
	"os"
	"sort"
	"testing"
	"time"
)

func TestHumanInputStoreSQLite(t *testing.T) {
	assertHumanInputStore(t, newTestStoreCrypted(t))
}

// TestHumanInputStorePostgres carries "Postgres" in its top-level name so the
// CI step that asserts Postgres-backed tests really ran (-run 'Postgres')
// selects it.
func TestHumanInputStorePostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	s := newPostgresTestStore(t, dsn)
	// The Postgres database outlives a test run, so clean both before (a
	// previous failed run may have left rows) and after.
	clean := func() {
		_, _ = s.DB.Exec(`DELETE FROM human_input_deliveries`)
		_, _ = s.DB.Exec(`DELETE FROM human_input_actors`)
		_, _ = s.DB.Exec(`DELETE FROM owner_notifications WHERE kind = $1`, NotificationHumanInput)
	}
	clean()
	t.Cleanup(clean)
	assertHumanInputStore(t, s)
}

func assertHumanInputStore(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	uid, err := s.EnsureUserByTelegramID(ctx, 700200, "alice", "Alice")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	base := HumanInputDelivery{
		UserID: uid, RequestID: "hi_1", RequestHash: "h1", RequestVersion: 1,
		WorkItemID: "wi_1", Kind: "single_choice", AnswerCode: "K7QM3R",
		OptionDigests: []string{"0123456789abcdef", "fedcba9876543210"}, MaxLength: 0,
	}

	// Idempotent insert: the second call is a no-op and queues no second
	// notification.
	ins, err := s.UpsertHumanInputDeliveryTx(ctx, base, "body one")
	if err != nil || !ins {
		t.Fatalf("first upsert inserted=%v err=%v", ins, err)
	}
	ins, err = s.UpsertHumanInputDeliveryTx(ctx, base, "body one")
	if err != nil || ins {
		t.Fatalf("second upsert inserted=%v err=%v", ins, err)
	}
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_notifications WHERE user_id=$1 AND kind=$2`, uid, NotificationHumanInput).Scan(&n); err != nil || n != 1 {
		t.Fatalf("notifications = %d err=%v, want 1", n, err)
	}

	// A different request reusing the code is a conflict, nothing written.
	clash := base
	clash.RequestID, clash.RequestHash = "hi_2", "h2"
	if _, err := s.UpsertHumanInputDeliveryTx(ctx, clash, "x"); !errors.Is(err, ErrHumanInputCodeConflict) {
		t.Fatalf("clash err = %v, want ErrHumanInputCodeConflict", err)
	}
	if err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM owner_notifications WHERE user_id=$1`, uid).Scan(&n); err != nil || n != 1 {
		t.Fatalf("notifications after clash = %d", n)
	}

	got, err := s.GetHumanInputDeliveryByCode(ctx, uid, "K7QM3R")
	if err != nil {
		t.Fatalf("get by code: %v", err)
	}
	if got.RequestID != "hi_1" || got.State != HumanInputQueued || len(got.OptionDigests) != 2 || got.NotificationID == 0 {
		t.Fatalf("delivery = %+v", got)
	}
	if _, err := s.GetHumanInputDeliveryByCode(ctx, uid+999, "K7QM3R"); !errors.Is(err, ErrHumanInputDeliveryNotFound) {
		t.Fatalf("other user's lookup err = %v", err)
	}

	// queued -> sent via the notification id.
	if _, found, err := s.SetHumanInputDeliveryMessageID(ctx, got.NotificationID, 4242); err != nil || !found {
		t.Fatalf("set message id found=%v err=%v", found, err)
	}
	if _, found, _ := s.SetHumanInputDeliveryMessageID(ctx, got.NotificationID, 4243); found {
		t.Fatal("a sent row must not be re-marked")
	}
	got, _ = s.GetHumanInputDeliveryByCode(ctx, uid, "K7QM3R")
	if got.State != HumanInputSent || got.TGMessageID != 4242 || got.DeliveredAt.IsZero() {
		t.Fatalf("after send = %+v", got)
	}

	// New hash for the same request supersedes the old row.
	v2 := base
	v2.RequestHash, v2.AnswerCode = "h1b", "ZZ2222"
	if ins, err := s.UpsertHumanInputDeliveryTx(ctx, v2, "body two"); err != nil || !ins {
		t.Fatalf("v2 upsert inserted=%v err=%v", ins, err)
	}
	if c, err := s.SupersedeHumanInputDeliveries(ctx, uid, "hi_1", "h1b"); err != nil || c != 1 {
		t.Fatalf("supersede = %d err=%v", c, err)
	}
	old, _ := s.GetHumanInputDeliveryByCode(ctx, uid, "K7QM3R")
	if old.State != HumanInputSuperseded || !old.Terminal() {
		t.Fatalf("old = %+v", old)
	}

	// Marking a still-queued row terminal retires its pending notification.
	open, err := s.ListOpenHumanInputDeliveries(ctx, uid)
	if err != nil || len(open) != 1 || open[0].AnswerCode != "ZZ2222" {
		t.Fatalf("open = %+v err=%v", open, err)
	}

	// submitted (a 202 pending_delivery answer) is an open state: listed as
	// open, supersedable, and it does not retire anything.
	v3 := base
	v3.RequestID, v3.RequestHash, v3.AnswerCode = "hi_3", "h3", "SB3333"
	if ins, err := s.UpsertHumanInputDeliveryTx(ctx, v3, "body three"); err != nil || !ins {
		t.Fatalf("v3 upsert inserted=%v err=%v", ins, err)
	}
	sub, _ := s.GetHumanInputDeliveryByCode(ctx, uid, "SB3333")
	if ch, err := s.MarkHumanInputDelivery(ctx, uid, sub.ID, HumanInputSubmitted, "pending_delivery"); err != nil || !ch {
		t.Fatalf("mark submitted changed=%v err=%v", ch, err)
	}
	if ch, _ := s.MarkHumanInputDelivery(ctx, uid, sub.ID, HumanInputSubmitted, "pending_delivery"); ch {
		t.Fatal("re-marking the same state must report no change")
	}
	sub, _ = s.GetHumanInputDeliveryByCode(ctx, uid, "SB3333")
	if sub.State != HumanInputSubmitted || sub.Terminal() || sub.RespondedAt.IsZero() {
		t.Fatalf("submitted = %+v", sub)
	}
	var subStatus string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM owner_notifications WHERE id=$1`, sub.NotificationID).Scan(&subStatus); err != nil || subStatus != NotificationPending {
		t.Fatalf("submitted notification status = %q err=%v, want pending", subStatus, err)
	}
	if open, _ := s.ListOpenHumanInputDeliveries(ctx, uid); len(open) != 2 {
		t.Fatalf("open with submitted = %d, want 2", len(open))
	}
	if ch, err := s.MarkHumanInputDelivery(ctx, uid, sub.ID, HumanInputAnswered, "resolved"); err != nil || !ch {
		t.Fatalf("submitted -> answered changed=%v err=%v", ch, err)
	}
	if ch, err := s.MarkHumanInputDelivery(ctx, uid, open[0].ID, HumanInputInactive, "gone"); err != nil || !ch {
		t.Fatalf("mark changed=%v err=%v", ch, err)
	}
	if ch, _ := s.MarkHumanInputDelivery(ctx, uid, open[0].ID, HumanInputAnswered, "late"); ch {
		t.Fatal("terminal row must not be rewritten")
	}
	var status string
	if err := s.DB.QueryRowContext(ctx, `SELECT status FROM owner_notifications WHERE id=$1`, open[0].NotificationID).Scan(&status); err != nil || status != NotificationFailed {
		t.Fatalf("queued notification status = %q err=%v, want failed", status, err)
	}

	// Actors: enroll, dormant backoff doubles and caps, re-enroll clears it.
	if err := s.UpsertHumanInputActor(ctx, uid, 700200); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	act, _ := s.ListPollableHumanInputActors(ctx, now)
	if len(act) != 1 {
		t.Fatalf("pollable = %+v", act)
	}
	for i := 0; i < 3; i++ {
		if err := s.MarkHumanInputActorDormant(ctx, uid, "link_not_found", time.Minute, 4*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if act, _ := s.ListPollableHumanInputActors(ctx, now); len(act) != 0 {
		t.Fatalf("dormant actor still pollable: %+v", act)
	}
	later, _ := s.ListPollableHumanInputActors(ctx, now.Add(5*time.Minute))
	if len(later) != 1 || later[0].FailCount != 3 {
		t.Fatalf("after backoff = %+v", later)
	}
	var dormant time.Time
	if err := s.DB.QueryRowContext(ctx, `SELECT dormant_until FROM human_input_actors WHERE user_id=$1`, uid).Scan(&dormant); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(dormant); d > 4*time.Minute+5*time.Second || d < 3*time.Minute {
		t.Fatalf("third backoff = %s, want ~4m (capped)", d)
	}
	if err := s.UpsertHumanInputActor(ctx, uid, 700200); err != nil {
		t.Fatal(err)
	}
	if act, _ := s.ListPollableHumanInputActors(ctx, now); len(act) != 1 || act[0].FailCount != 0 {
		t.Fatalf("re-enrolled = %+v", act)
	}

	// Backfill from bindings.
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM human_input_actors`); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertWorkItemBinding(ctx, WorkItemBinding{
		UserID: uid, ChatTGID: 700200, RootTGMessageID: 9, WorkItemID: "wi_1",
		ExternalKey: "https://github.com/mctlhq/mctl-telegram/issues/571",
	}); err != nil {
		t.Fatal(err)
	}
	if c, err := s.BackfillHumanInputActorsFromBindings(ctx); err != nil || c != 1 {
		t.Fatalf("backfill = %d err=%v", c, err)
	}
	if c, _ := s.BackfillHumanInputActorsFromBindings(ctx); c != 0 {
		t.Fatalf("second backfill inserted %d", c)
	}
	if key, ok, err := s.WorkItemExternalKey(ctx, uid, "wi_1"); err != nil || !ok || key == "" {
		t.Fatalf("external key = %q ok=%v err=%v", key, ok, err)
	}
}

// TestHumanInputSchemaHasNoContentColumn is T15: human_input_deliveries holds
// only ids, hash, code, kind, state, outcome, option digests (in
// option_ids_json, never option text) and bookkeeping.
func TestHumanInputSchemaHasNoContentColumn(t *testing.T) {
	s := newTestStore(t)
	rows, err := s.DB.Query(`SELECT name FROM pragma_table_info('human_input_deliveries')`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		got = append(got, name)
	}
	want := []string{"id", "user_id", "request_id", "request_hash", "request_version", "work_item_id", "kind",
		"answer_code", "option_ids_json", "max_length", "notification_id", "tg_message_id", "state",
		"last_outcome", "delivered_at", "responded_at", "created_at", "updated_at"}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("columns = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("columns = %v, want %v", got, want)
		}
	}
}
