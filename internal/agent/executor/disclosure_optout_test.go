package executor

import (
	"context"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

func approveAndCaptureText(t *testing.T, optOut bool, draft string) string {
	t.Helper()
	exec, sender, store, uid, conv := newTestExecutor(t)
	ctx := context.Background()
	if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
		UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "— ИИ-ассистент",
		DisclosureDisabled: optOut,
	}); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	_, code := seedPendingApproval(t, store, uid, conv.ID, draft)
	if err := exec.Approve(ctx, uid, code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if len(sender.calls) != 1 {
		t.Fatalf("send calls = %d, want 1", len(sender.calls))
	}
	return sender.calls[0].text
}

// The owner's opt-out means no signature at all: nothing is appended even
// though a disclosure text is still stored.
func TestExecutor_DisclosureOptOutAppendsNothing(t *testing.T) {
	if got := approveAndCaptureText(t, true, "Подскажите пару слотов."); got != "Подскажите пару слотов." {
		t.Fatalf("sent %q, want the draft unchanged", got)
	}
	if got := approveAndCaptureText(t, false, "Подскажите пару слотов."); got != "Подскажите пару слотов.\n— ИИ-ассистент" {
		t.Fatalf("without opt-out sent %q, want the disclosure appended", got)
	}
}

// Replies sent before the opt-out end with the line, and the model imitates
// them; with the opt-out that imitated copy must not go out either.
func TestExecutor_DisclosureOptOutStripsImitatedLine(t *testing.T) {
	if got := approveAndCaptureText(t, true, "Подскажите пару слотов.\n— ИИ-ассистент\n"); got != "Подскажите пару слотов." {
		t.Fatalf("sent %q, want the imitated disclosure stripped", got)
	}
	// Mid-text mentions are not the signature and stay.
	const mid = "Внизу было — ИИ-ассистент, теперь нет. Подскажите слоты."
	if got := approveAndCaptureText(t, true, mid); got != mid {
		t.Fatalf("sent %q, want mid-text mention kept", got)
	}
}

// A draft that is only the imitated line strips to nothing. Telegram rejects
// an empty message, so the action is denied before anything is sent instead
// of failing MESSAGE_EMPTY on every retry.
func TestExecutor_DisclosureOptOutDeniesDraftThatIsOnlyTheLine(t *testing.T) {
	for _, draft := range []string{"— ИИ-ассистент", "\n— ИИ-ассистент\n"} {
		exec, sender, store, uid, conv := newTestExecutor(t)
		ctx := context.Background()
		if err := store.UpsertAgentProfile(ctx, db.AgentProfile{
			UserID: uid, Mode: db.AgentModeGuarded, DisclosureText: "— ИИ-ассистент",
			DisclosureDisabled: true,
		}); err != nil {
			t.Fatalf("seed profile: %v", err)
		}
		actionID, code := seedPendingApproval(t, store, uid, conv.ID, draft)
		if err := exec.Approve(ctx, uid, code); err == nil {
			t.Fatalf("draft %q: approve succeeded, want an error", draft)
		}
		if len(sender.calls) != 0 {
			t.Fatalf("draft %q: sent %d messages, want none", draft, len(sender.calls))
		}
		got, err := store.GetAgentAction(ctx, uid, actionID)
		if err != nil {
			t.Fatalf("load action: %v", err)
		}
		if got.Status != db.ActionDenied {
			t.Fatalf("draft %q: status = %q, want denied", draft, got.Status)
		}
	}
}
