package pa_test

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/pa/permissions"
)

// S2-C9 end to end (#1320 slice P2-S12): the card, the webhook's button
// handler and the write executor over a store in which a connection or a
// principal was ended.

// seedPermission grants Alice a standing permission on her tg connection.
func (e *cardEnv) seedPermission(id string) {
	e.t.Helper()
	p := permissions.Permission{
		Principal: alice, ID: id, ConnectionID: e.connA.ID, AuthorityRevision: e.connA.AuthorityRevision,
		Server: "tg", Tool: writeTool, DeviceIDs: []string{"dev-1"}, Ceiling: 5, ExpiresAt: e.h.Now().Add(24 * time.Hour),
	}
	e.inTx(func(tx *sql.Tx) error { return e.store.InsertPAPermission(context.Background(), tx, p, e.h.Now()) })
}

func (e *cardEnv) permissionsInForce() []string {
	return e.strings(`SELECT id FROM pa_permissions WHERE principal = $1 AND revoked_at_ms = 0 ORDER BY id`, alice)
}

// TestS2C9_CancelledCardAnswersCancelled: Alice has a card waiting, an
// approval she approved that was not sent yet, and a standing permission.
// Then her connection is disconnected, or an admin disables her. Both
// approvals are cancelled rows with their arguments erased and no
// callbacks; the permission is revoked; one notice says so; a tap on
// either button of the card is answered "cancelled", and handing the
// approved one to the executor sends nothing.
func TestS2C9_CancelledCardAnswersCancelled(t *testing.T) {
	ctx := context.Background()
	ends := map[string]struct {
		end func(e *cardEnv)
		// tap is the answer to a tap on the cancelled card.
		tap pa.Reply
	}{
		"disconnect": {func(e *cardEnv) {
			if _, err := e.mgr.Disconnect(ctx, alice, e.connA.ID); err != nil {
				e.t.Fatal(err)
			}
		}, pa.ReplyApprovalCancelled},
		// A disabled principal's updates are refused before any handler:
		// the tap is answered by that refusal, once per rate window.
		"admin disable": {func(e *cardEnv) {
			if err := e.store.SetPAPrincipalDisabled(ctx, alice, bob, "test", e.h.Now()); err != nil {
				e.t.Fatal(err)
			}
		}, pa.ReplyPrincipalDisabled},
	}
	for name, c := range ends {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newCardEnv(t, s)
				card := e.emit(writeArgs)
				appr := e.writeEnv.approved(`{"chat":"@bob","text":"second"}`)
				e.seedPermission("prm_c9")

				c.end(e)

				for _, id := range []string{card.id, appr.ID} {
					if got := e.approvalState(id); got != "cancelled/erased" {
						t.Errorf("approval %s is %s, want cancelled/erased", id, got)
					}
				}
				if got := e.cardCallbacks(alice); len(got) != 0 {
					t.Errorf("callbacks left: %v", got)
				}
				if got := e.permissionsInForce(); len(got) != 0 {
					t.Errorf("permissions still in force: %v", got)
				}
				if got := e.notices(); !slices.Equal(got, []string{"actions_cancelled"}) {
					t.Errorf("notices %v, want one actions_cancelled", got)
				}
				for _, data := range []string{card.approve, card.cancel} {
					if got := e.press(alice, data); got != c.tap && got != "" {
						t.Errorf("tap on the cancelled card: %q, want %q", got, c.tap)
					}
				}
				if got := e.lastReply(alice); got != c.tap {
					t.Errorf("the taps were answered %q, want %q", got, c.tap)
				}
				// The executor, handed the approved one anyway.
				out := e.dispatch(appr.ID)
				if out.Status != connector.StatusRefused || out.Reason != connector.ReasonApprovalEnded {
					t.Errorf("outcome %+v, want refused approval_ended", out)
				}
				e.noCalls()
				if got := e.dispatches(); len(got) != 0 {
					t.Errorf("dispatch records %v", got)
				}
				// The notice reaches Alice's chat once, as its template.
				// (The revocation stamps the row with the wall clock and the
				// harness delivers on its own: make the row due on both.)
				if _, err := s.DB.Exec(`UPDATE pa_outbox SET next_at_ms = 0 WHERE principal = $1 AND kind = 'actions_cancelled'`, alice); err != nil {
					t.Fatal(err)
				}
				e.h.Loop().DeliverAfter(ctx, alice)
				told := 0
				for _, m := range e.h.MessagesTo(alice) {
					if m.Text == safetext.TextActionsCancelled.In(safetext.LangEN) {
						told++
					}
				}
				if told != 1 {
					t.Errorf("the notice was sent %d times: %+v", told, e.h.MessagesTo(alice))
				}
				// Still cancelled, and still one notice: the executor adds
				// none for an approval somebody else ended.
				if got := e.approvalState(appr.ID); got != "cancelled/erased" {
					t.Errorf("after the dispatch the approval is %s", got)
				}
				if got := e.notices(); !slices.Equal(got, []string{"actions_cancelled"}) {
					t.Errorf("notices after the dispatch %v", got)
				}
			})
		})
	}
}

// TestS2C9_ForgetAndWithdrawCancel: /forget and /consent withdraw, as the
// webhook handles them, delete the waiting approvals (their arguments go
// with the conversation), revoke the permission and queue the one notice.
// A tap on the card afterwards reaches no server and approves nothing.
func TestS2C9_ForgetAndWithdrawCancel(t *testing.T) {
	for _, cmd := range []string{"/forget", "/consent withdraw"} {
		t.Run(cmd, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, s *db.Store) {
				e := newCardEnv(t, s)
				card := e.emit(writeArgs)
				appr := e.writeEnv.approved(`{"chat":"@bob","text":"second"}`)
				e.seedPermission("prm_c9")

				e.h.Text(alice, cmd)

				if rows := e.approvals(alice); len(rows) != 0 {
					t.Errorf("approval rows left: %+v", rows)
				}
				if got := e.cardCallbacks(alice); len(got) != 0 {
					t.Errorf("callbacks left: %v", got)
				}
				if got := e.permissionsInForce(); len(got) != 0 {
					t.Errorf("permissions still in force: %v", got)
				}
				if got := e.notices(); !slices.Equal(got, []string{"actions_cancelled"}) {
					t.Errorf("notices %v, want one actions_cancelled", got)
				}
				for _, data := range []string{card.approve, card.cancel} {
					e.press(alice, data)
				}
				out, err := e.x.DispatchApproved(context.Background(), alice, appr.ID)
				if err == nil && out.Status != connector.StatusRefused {
					t.Errorf("outcome %+v for an approval that was deleted", out)
				}
				e.noCalls()
				if rows := e.approvals(alice); len(rows) != 0 {
					t.Errorf("approval rows after the taps: %+v", rows)
				}
			})
		})
	}
}

// TestActionsCancelledNotice_SaysNothingWasSent: the notice is queued only
// for approvals that were never dispatched, so both languages say nothing
// was sent, and neither promises a retry or carries a placeholder.
func TestActionsCancelledNotice_SaysNothingWasSent(t *testing.T) {
	en, ru := safetext.TextActionsCancelled.In(safetext.LangEN), safetext.TextActionsCancelled.In(safetext.LangRU)
	if !strings.Contains(en, "cancelled") || !strings.Contains(en, "Nothing was sent") {
		t.Errorf("EN %q", en)
	}
	if !strings.Contains(ru, "отменены") || !strings.Contains(ru, "ничего не отправлено") {
		t.Errorf("RU %q", ru)
	}
	if strings.ContainsAny(en+ru, "%{}") {
		t.Errorf("placeholder in %q / %q", en, ru)
	}
}
