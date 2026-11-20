package pa

// callbacks.go answers a pressed button (answerCallbackQuery) once its
// update committed, so the Telegram client stops the spinner on it. The
// reply to the press is an outbox row like any other; the answer only
// acknowledges the press and carries no text.
//
// It is best effort and never part of the update: it runs after the
// commit, on a context of its own, and its failure is logged and counted,
// never retried and never turned into a failed update. Answering inline,
// in the webhook's HTTP response, was not chosen: that response cannot
// report whether Telegram accepted the method, and it would put a Bot API
// method outside output.Sender (TestS1O1_SenderIsTheOnlyBotAPICallSite).

import (
	"context"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
)

// CallbackCounter counts callback answers (*metrics.Registry implements
// it).
type CallbackCounter interface {
	CountPACallbackAnswer(outcome string)
}

// Callback answer outcome labels.
const (
	CallbackAnswerAnswered = "answered"
	// CallbackAnswerFailed: the answer was refused, or its outcome is not
	// known. The press was handled either way; only the spinner runs on
	// until the client gives up on it.
	CallbackAnswerFailed = "failed"
)

// callbackAnswerTimeout bounds one answer. Telegram stops accepting an
// answer to a query after a short while, so waiting longer buys nothing.
const callbackAnswerTimeout = 10 * time.Second

// AnswerCallbackAfter answers u's callback query in the background, once
// u's transaction committed. It does nothing for a message update. Like
// deliverAfter it runs detached from the request (WithoutCancel) and is
// tracked by WaitDeliveries, so a graceful shutdown waits for it.
func (l *RunLoop) AnswerCallbackAfter(ctx context.Context, u VerifiedUpdate) {
	if u.Kind() != KindCallbackQuery || u.CallbackID() == "" {
		return
	}
	id, updateID := u.CallbackID(), u.UpdateID()
	l.pending.Add(1)
	go func() {
		defer l.pending.Done()
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), callbackAnswerTimeout)
		defer cancel()
		// No notice: the press is answered by its own outbox row.
		if err := l.sender.AnswerCallback(actx, id, safetext.Template{}); err != nil {
			slog.Warn("pa callback not answered", "update_id", updateID, "err", err)
			l.countCallback(CallbackAnswerFailed)
			return
		}
		l.countCallback(CallbackAnswerAnswered)
	}()
}

func (l *RunLoop) countCallback(outcome string) {
	if l.cbCount != nil {
		l.cbCount.CountPACallbackAnswer(outcome)
	}
}
