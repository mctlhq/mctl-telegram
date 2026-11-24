package pa

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// TestS2A10_CardOffersOnlyApproveAndCancel enumerates everything a card is
// made of: its buttons, the keyboard built from them, the keyboards of
// every other outbox kind, the card's server texts and what a press can
// reach in the ledger. A card has Approve and Cancel and no third thing:
// no button, text or callback grants a standing permission (threat model
// T7). Standing permissions are granted only on a /permissions screen
// (P2-S10): the card shares no button, label or callback action with one,
// and TestS2A10_PermissionScreensRouteToTheirOwnCallbacks enumerates the
// screens the same way.
func TestS2A10_CardOffersOnlyApproveAndCancel(t *testing.T) {
	want := []CardButton{
		{Label: safetext.LabelApprove, Action: ActionApprovalApprove},
		{Label: safetext.LabelCancel, Action: ActionApprovalCancel},
	}
	if got := ApprovalCardButtons(); !slices.Equal(got, want) {
		t.Fatalf("card buttons %+v, want exactly Approve and Cancel", got)
	}

	// Nothing of a /permissions screen is on a card, and no card action
	// is one the /permissions handler takes.
	for _, b := range ApprovalCardButtons() {
		if permissions.IsAction(b.Action) {
			t.Errorf("card action %q is a /permissions action", b.Action)
		}
		for _, pb := range PermissionScreenButtons() {
			if b.Label == pb.Label {
				t.Errorf("card button %q is also a /permissions button", b.Label.String())
			}
		}
	}

	kb, ok := approvalCardKeyboard(ApprovalCard{Approve: "cb-approve", Cancel: "cb-cancel"})
	if !ok || len(kb) != 1 || !slices.Equal(kb[0], []output.Button{
		{Label: safetext.LabelApprove, Data: "cb-approve"}, {Label: safetext.LabelCancel, Data: "cb-cancel"},
	}) {
		t.Fatalf("card keyboard %+v (ok %v), want one row of Approve and Cancel", kb, ok)
	}
	for name, c := range map[string]ApprovalCard{
		"no approve id": {Cancel: "cb-cancel"},
		"no cancel id":  {Approve: "cb-approve"},
		"one id twice":  {Approve: "cb", Cancel: "cb"},
		"a long id":     {Approve: strings.Repeat("a", jobs.MaxOutboxButton+1), Cancel: "cb-cancel"},
	} {
		if kb, ok := approvalCardKeyboard(c); ok || kb != nil {
			t.Errorf("%s: a keyboard was built", name)
		}
	}

	// Every kind the bot can send: the card is the only one built from the
	// card registry, and the only other keyboards are the consent prompt's
	// single button.
	cards := 0
	for _, k := range jobs.OutboxKinds() {
		if k.CardLevel() {
			cards++
			if k != jobs.OutboxApprovalCard {
				t.Errorf("unexpected card-level kind %q", k)
			}
			continue
		}
		it := jobs.OutboxItem{Kind: k}
		if k.CarriesButton() {
			it.Button = "cb"
		}
		kb, ok := outboxKeyboard(it)
		if !ok {
			t.Errorf("kind %q builds no keyboard decision", k)
		}
		if kb == nil {
			continue
		}
		if !k.CarriesButton() || len(kb) != 1 || len(kb[0]) != 1 ||
			(kb[0][0].Label != safetext.LabelConsentAccept && kb[0][0].Label != safetext.LabelConsentAcceptRU) {
			t.Errorf("kind %q is sent with the keyboard %+v", k, kb)
		}
	}
	if cards != 1 {
		t.Fatalf("%d card-level kinds, want 1", cards)
	}

	// No text of a card, and no label on it, offers to skip the next card.
	texts := append(safetext.CardTemplates(), safetext.DisclosureCardTemplates()...)
	for _, b := range ApprovalCardButtons() {
		texts = append(texts, b.Label)
	}
	for _, tp := range texts {
		for _, l := range []safetext.Lang{safetext.LangEN, safetext.LangRU} {
			s := strings.ToLower(tp.In(l))
			for _, word := range []string{"always", "remember", "don't ask", "do not ask", "every time", "всегда", "запомн", "не спрашива", "каждый раз"} {
				if strings.Contains(s, word) {
					t.Errorf("card text %q offers a standing permission (%q)", tp.In(l), word)
				}
			}
		}
	}

	// A press reaches the ledger through these calls only: it can approve
	// or cancel one approval and nothing else.
	typ := reflect.TypeOf((*ApprovalCallbacks)(nil)).Elem()
	var methods []string
	for i := range typ.NumMethod() {
		methods = append(methods, typ.Method(i).Name)
	}
	if !slices.Equal(methods, []string{"ApprovePAApproval", "CancelPAApproval", "LookupPAApprovalByCallback"}) {
		t.Fatalf("a card's press can call %v", methods)
	}
}

// fakeCards is a CardRenderer with a fixed answer.
type fakeCards struct {
	card ApprovalCard
	err  error
}

func (f *fakeCards) RenderApprovalCard(context.Context, int64, string) (ApprovalCard, error) {
	return f.card, f.err
}

func mustCard(t *testing.T) safetext.Text {
	t.Helper()
	c, err := safetext.Card("send_message (tg)", `{"to":"Carol"}`, false)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestOutboxApprovalCard_Outcomes: what the deliverer does with a card row
// for each answer of the renderer. Only a card that was built, belongs to
// the row and still has time left is sent; an unreadable approval leaves
// the row due (I9), and it is never taken for an approval that ended.
func TestOutboxApprovalCard_Outcomes(t *testing.T) {
	text := mustCard(t)
	h := newRunLoopHarness(t)
	live := h.now.Add(5 * time.Minute)
	cases := []struct {
		name   string
		cards  CardRenderer
		status jobs.OutboxStatus
		sent   int
	}{
		{"no renderer", nil, jobs.OutboxFailed, 0},
		{"approval ended", &fakeCards{err: ErrCardGone}, jobs.OutboxDropped, 0},
		{"approval unreadable", &fakeCards{err: errors.Join(ErrCardUnreadable, errors.New("injected"))}, jobs.OutboxPending, 0},
		{"cannot be built", &fakeCards{err: errors.New("injected")}, jobs.OutboxFailed, 0},
		{"another card", &fakeCards{card: ApprovalCard{Text: text, Approve: "cb-other", Cancel: "cb-cancel", ExpiresAt: live}}, jobs.OutboxFailed, 0},
		{"no cancel id", &fakeCards{card: ApprovalCard{Text: text, Approve: "cb", ExpiresAt: live}}, jobs.OutboxFailed, 0},
		{"about to expire", &fakeCards{card: ApprovalCard{Text: text, Approve: "cb", Cancel: "cb-cancel", ExpiresAt: h.now.Add(30 * time.Second)}}, jobs.OutboxDropped, 0},
		{"live", &fakeCards{card: ApprovalCard{Text: text, Approve: "cb", Cancel: "cb-cancel", ExpiresAt: live}}, jobs.OutboxSent, 1},
	}
	store := h.convoHarness.store
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.DB.Exec(`DELETE FROM pa_outbox WHERE principal = $1`, aliceID); err != nil {
				t.Fatal(err)
			}
			before := len(h.sender.messagesTo(aliceID))
			tx, err := store.DB.BeginTx(context.Background(), &sql.TxOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.EnqueuePAOutbox(context.Background(), tx, jobs.OutboxItem{
				Principal: aliceID, Kind: jobs.OutboxApprovalCard, Button: "cb",
			}, h.now); err != nil {
				_ = tx.Rollback()
				t.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			h.loop.cards = tc.cards
			h.loop.DeliverAfter(context.Background(), aliceID)
			h.loop.WaitDeliveries()
			var status string
			if err := store.DB.QueryRow(`SELECT status FROM pa_outbox WHERE principal = $1`, aliceID).Scan(&status); err != nil {
				t.Fatal(err)
			}
			if status != string(tc.status) {
				t.Errorf("row is %q, want %q", status, tc.status)
			}
			msgs := h.sender.messagesTo(aliceID)[before:]
			if len(msgs) != tc.sent {
				t.Fatalf("%d messages sent, want %d", len(msgs), tc.sent)
			}
			if tc.sent == 1 && (len(msgs[0].kb) != 1 || len(msgs[0].kb[0]) != 2 || msgs[0].text != text.String()) {
				t.Errorf("sent %+v", msgs[0])
			}
		})
	}
}

// TestPostCommitApproval: the approved id is handed over only through the
// update's own post-commit slot.
func TestPostCommitApproval(t *testing.T) {
	if err := setPostCommitApproval(context.Background(), "apr"); !errors.Is(err, ErrNoPostCommit) {
		t.Fatalf("without a slot: %v", err)
	}
	ctx := WithPostCommit(context.Background())
	if id, ok := PostCommitApproval(ctx); ok || id != "" {
		t.Fatalf("an empty slot holds %q", id)
	}
	if err := setPostCommitApproval(ctx, "apr"); err != nil {
		t.Fatal(err)
	}
	if id, ok := PostCommitApproval(ctx); !ok || id != "apr" {
		t.Fatalf("slot holds %q, %v", id, ok)
	}
	if _, ok := PostCommitApproval(WithPostCommit(context.Background())); ok {
		t.Fatal("another update's slot holds the approval")
	}
}
