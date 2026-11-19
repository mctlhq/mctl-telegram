package pa

// outbox.go delivers the PA outbox (issue #1313 slice d2; the rules are in
// internal/pa/jobs/outbox.go). Every message still goes through
// output.Render or output.ServerText and output.Sender only: a notice row
// maps to a registry template, and a reply row is rendered from its stored,
// external-marked assistant fragment with the allow-list of the
// principal's own text in that conversation (T14).

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/jobs"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

// OutboxCounter counts outbox outcomes (*metrics.Registry implements it).
type OutboxCounter interface {
	CountPAOutbox(outcome string)
}

// Outbox outcome labels.
const (
	OutboxOutcomeSent    = "sent"
	OutboxOutcomeRetry   = "retry"
	OutboxOutcomeFailed  = "failed"
	OutboxOutcomeDropped = "dropped"
	OutboxOutcomeUnknown = "unknown"
	// OutboxOutcomeStale: the send finished after the row's lease, which
	// had already marked it unknown.
	OutboxOutcomeStale = "stale"
	// OutboxOutcomeClaimError: the outbox could not be read. Nothing was
	// sent, and the rows stay due.
	OutboxOutcomeClaimError = "claim_error"
)

// outboxTemplates maps every notice kind to its server text.
var outboxTemplates = map[jobs.OutboxKind]output.Template{
	jobs.OutboxReplyTooLong:   output.TextReplyTooLong,
	jobs.OutboxBudgetHold:     output.TextBudgetHold,
	jobs.OutboxRunFailed:      output.TextRunFailed,
	jobs.OutboxRequestDropped: output.TextRequestDropped,
}

// outboxSendTimeout bounds one send of one row (up to output.MaxParts
// messages); it is well inside jobs.OutboxLease, so a send that returns
// is completed before its lease could mark it unknown.
const outboxSendTimeout = 45 * time.Second

// delivery is the outcome of one claimed row.
type delivery struct {
	item   jobs.OutboxItem
	status jobs.OutboxStatus
}

// deliver sends the due outbox rows of principal (0: every principal) and
// records each outcome. It never returns an error: a row that was not sent
// stays due, and the background pass (RunOutbox) retries it.
func (l *RunLoop) deliver(ctx context.Context, principal int64) []delivery {
	res, err := l.store.ClaimPAOutbox(ctx, jobs.OutboxClaimRequest{
		Now: l.now(), Lease: jobs.OutboxLease, Principal: principal, Limit: jobs.OutboxBatch,
	})
	if err != nil {
		slog.Warn("pa outbox not readable", "err", err)
		l.count(OutboxOutcomeClaimError)
		return nil
	}
	for range res.Unknown {
		l.count(OutboxOutcomeUnknown)
	}
	if res.Unknown > 0 {
		slog.Warn("pa outbox rows outlived their send lease; not sent again", "rows", res.Unknown)
	}
	out := make([]delivery, 0, len(res.Items))
	for _, it := range res.Items {
		c := l.sendItem(ctx, it)
		// The outcome is recorded even when the caller's request is gone:
		// a sent row left in sending would become unknown.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		err := l.store.CompletePAOutbox(cctx, it, c)
		cancel()
		outcome := outboxOutcome(c.Status)
		switch {
		case errors.Is(err, jobs.ErrOutboxStale):
			outcome = OutboxOutcomeStale
		case err != nil:
			// The row stays sending and becomes unknown after its lease:
			// it is not sent twice.
			slog.Warn("pa outbox outcome not recorded", "job_id", it.JobID, "kind", string(it.Kind), "err", err)
		}
		l.count(outcome)
		if c.Status != jobs.OutboxSent {
			slog.Warn("pa outbox row not sent", "job_id", it.JobID, "kind", string(it.Kind),
				"attempt", it.Attempts, "outcome", outcome)
		}
		out = append(out, delivery{item: it, status: c.Status})
	}
	return out
}

func outboxOutcome(s jobs.OutboxStatus) string {
	switch s {
	case jobs.OutboxSent:
		return OutboxOutcomeSent
	case jobs.OutboxPending:
		return OutboxOutcomeRetry
	case jobs.OutboxDropped:
		return OutboxOutcomeDropped
	default:
		return OutboxOutcomeFailed
	}
}

func (l *RunLoop) count(outcome string) {
	if l.metrics != nil {
		l.metrics.CountPAOutbox(outcome)
	}
}

// sendItem builds and sends one claimed row and says what to record.
func (l *RunLoop) sendItem(ctx context.Context, it jobs.OutboxItem) jobs.OutboxCompletion {
	now := l.now()
	var text output.Text
	switch {
	case it.Kind == jobs.OutboxReply:
		t, err := l.renderReply(ctx, it)
		switch {
		case err == nil:
			text = t
		case errors.Is(err, convo.ErrNotFound):
			// Closed (/new), forgotten (/forget), withdrawn or expired
			// before delivery: the answer goes with its conversation.
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxDropped}
		case errors.Is(err, convo.ErrStoreFault):
			return l.retry(it, now, 0)
		default:
			// A fragment that does not open will not open later (T5).
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}
		}
	default:
		tpl, ok := outboxTemplates[it.Kind]
		if !ok {
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}
		}
		text = output.ServerText(tpl)
	}
	sctx, cancel := context.WithTimeout(ctx, outboxSendTimeout)
	defer cancel()
	err := l.sender.Send(sctx, it.Principal, text, nil)
	if err == nil {
		return jobs.OutboxCompletion{Now: l.now(), Status: jobs.OutboxSent}
	}
	if permanentSendError(err) {
		return jobs.OutboxCompletion{Now: l.now(), Status: jobs.OutboxFailed}
	}
	var api *output.APIError
	wait := time.Duration(0)
	if errors.As(err, &api) && api.RetryAfter > 0 {
		wait = time.Duration(api.RetryAfter) * time.Second
	}
	return l.retry(it, l.now(), wait)
}

// retry schedules the row again, or fails it once it used its attempts.
func (l *RunLoop) retry(it jobs.OutboxItem, now time.Time, wait time.Duration) jobs.OutboxCompletion {
	if it.Attempts >= jobs.OutboxMaxAttempts {
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}
	}
	wait = max(wait, jobs.OutboxBackoff(it.Attempts))
	return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxPending, RetryAt: now.Add(wait)}
}

// permanentSendError reports a send that would fail the same way again: a
// message Sender refuses to build, or a Bot API 4xx other than a flood wait
// (blocked by the user, chat not found).
func permanentSendError(err error) bool {
	for _, e := range []error{output.ErrEmptyText, output.ErrInvalidChat, output.ErrInvalidKeyboard,
		output.ErrPartTooLong, output.ErrTooLong} {
		if errors.Is(err, e) {
			return true
		}
	}
	var api *output.APIError
	return errors.As(err, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 429
}

// renderReply renders the stored answer of a reply row: the fragment it
// names, which must be an external-marked assistant fragment, with the
// principal's own text in that conversation as the allow-list. An answer
// that no longer fits is replaced by the server text, never truncated.
func (l *RunLoop) renderReply(ctx context.Context, it jobs.OutboxItem) (output.Text, error) {
	rows, err := l.store.LoadPAFragments(ctx, it.Principal, it.ConversationID, l.now())
	if err != nil {
		return output.Text{}, err
	}
	var typed []string
	answer, found := "", false
	for _, row := range rows {
		f, err := l.sealer.Open(it.Principal, row)
		if err != nil {
			return output.Text{}, err
		}
		text, prov := f.Text()
		if prov == convo.ProvenanceUser {
			typed = append(typed, text)
		}
		if row.Seq == it.FragmentSeq {
			if f.Kind() != convo.KindAssistant || prov != convo.ProvenanceExternal {
				return output.Text{}, convo.ErrUnreadable
			}
			answer, found = text, true
		}
	}
	if !found {
		return output.Text{}, convo.ErrNotFound
	}
	t, err := output.Render(answer, output.AllowFromUserText(typed...))
	if errors.Is(err, output.ErrTooLong) {
		return output.ServerText(output.TextReplyTooLong), nil
	}
	return t, err
}

// OutboxInterval is how often RunOutbox retries due rows.
const OutboxInterval = 15 * time.Second

// RunOutbox delivers due outbox rows of every principal until ctx ends.
// The request paths deliver their own rows at once; this pass retries the
// ones whose send failed and marks rows that outlived their lease unknown.
func (l *RunLoop) RunOutbox(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = OutboxInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			for len(l.deliver(ctx, 0)) == jobs.OutboxBatch && ctx.Err() == nil {
			}
		}
	}
}
