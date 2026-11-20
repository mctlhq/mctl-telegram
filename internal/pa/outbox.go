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
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
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
	OutboxOutcomeSent  = "sent"
	OutboxOutcomeRetry = "retry"
	// OutboxOutcomeFailed: out of attempts, a row that cannot be built, or
	// a Bot API 4xx that is not the principal's doing (a request we built
	// wrong, a bad or revoked bot token). An operational fault: it pages.
	OutboxOutcomeFailed = "failed"
	// OutboxOutcomeRefused: the principal blocked the bot or the chat is
	// gone (a 403, or a 400 "chat not found"). A principal's choice, not an
	// operational fault, so it is counted apart from failed.
	OutboxOutcomeRefused = "refused"
	OutboxOutcomeDropped = "dropped"
	// OutboxOutcomeUnknown: the send may have reached Telegram and its
	// answer was not read, or the row outlived its lease. Not sent again.
	OutboxOutcomeUnknown = "unknown"
	// OutboxOutcomeStale: the send finished after the row's lease, which
	// had already marked it unknown.
	OutboxOutcomeStale = "stale"
	// OutboxOutcomeClaimError: the outbox could not be read. Nothing was
	// sent, and the rows stay due.
	OutboxOutcomeClaimError = "claim_error"
	// OutboxOutcomeButtonExpired: a consent prompt held back (flood waits,
	// an outage) until its button would no longer resolve when pressed.
	// It is dropped unsent; the principal's next message gets a fresh one.
	OutboxOutcomeButtonExpired = "button_expired"
	// OutboxOutcomeUpdateReused: a conversation-level reply was not queued
	// because a row for the same principal, update id and kind already
	// exists. The update dedup should have refused such an update first,
	// so this means Telegram reused an update id (it may after a week
	// without updates) or a handler queued one kind twice. Counted at
	// enqueue, not delivery; the reply is not sent.
	OutboxOutcomeUpdateReused = "update_reused"
)

// outboxButtonMinLife is how long a consent prompt's button must still
// resolve when the prompt is sent. A prompt whose button expires sooner
// would be pressed into "no longer valid", so it is dropped instead.
const outboxButtonMinLife = 5 * time.Minute

// outboxTemplates maps every notice kind, job-level and conversation-level
// (#1348), to its server text.
var outboxTemplates = map[jobs.OutboxKind]output.Template{
	jobs.OutboxReplyTooLong:   output.TextReplyTooLong,
	jobs.OutboxBudgetHold:     output.TextBudgetHold,
	jobs.OutboxRunFailed:      output.TextRunFailed,
	jobs.OutboxRequestDropped: output.TextRequestDropped,

	jobs.OutboxConsentPrompt:    output.TextConsentPrompt,
	jobs.OutboxConsentAccepted:  output.TextConsentAccepted,
	jobs.OutboxConsentWithdrawn: output.TextConsentWithdrawn,
	jobs.OutboxConsentStale:     output.TextConsentStale,
	jobs.OutboxNewConversation:  output.TextNewConversation,
	jobs.OutboxForgotten:        output.TextForgotten,
	jobs.OutboxUnknownButton:    output.TextUnknownButton,
	jobs.OutboxRateLimited:      output.TextRateLimited,
	jobs.OutboxMessageTooLong:   output.TextMessageTooLong,
}

// outboxKeyboard is the keyboard a row is sent with: the consent prompt's
// single button, carrying the opaque callback id stored with the row, and
// none for every other kind. A prompt row without its id cannot be sent.
func outboxKeyboard(it jobs.OutboxItem) (output.Keyboard, bool) {
	if it.Kind != jobs.OutboxConsentPrompt {
		return nil, it.Button == ""
	}
	if it.Button == "" {
		return nil, false
	}
	return output.Keyboard{{{Label: output.LabelConsentAccept, Data: it.Button}}}, true
}

const (
	// outboxSendTimeout bounds building and sending one claimed row (up to
	// output.MaxParts messages). A row is claimed right before its own
	// send, so with outboxRecordTimeout for its bookkeeping it ends well
	// inside jobs.OutboxLease: a send that returns is completed before its
	// lease could mark it unknown.
	outboxSendTimeout = 45 * time.Second
	// outboxRecordTimeout bounds one bookkeeping write of a row.
	outboxRecordTimeout = 10 * time.Second
	// outboxRequestDeadline bounds the delivery a request path starts after
	// its response: it stops claiming further rows past it. The send of a
	// claimed row runs to its own timeout.
	outboxRequestDeadline = time.Minute
)

// delivery is the outcome of one claimed row.
type delivery struct {
	item    jobs.OutboxItem
	status  jobs.OutboxStatus
	outcome string
}

// deliver sends the due outbox rows of principal (0: every principal), at
// most jobs.OutboxBatch of them, and records each outcome. Each row is
// claimed right before its own send, so its lease covers that send only.
// ctx decides whether another row is claimed; a claimed row is built,
// sent and completed on a context detached from it (WithoutCancel plus its
// own timeouts), so a caller that goes away never cuts a send off midway.
// deliver never returns an error: a row that was not sent stays due, and
// the background pass (RunOutbox) retries it.
func (l *RunLoop) deliver(ctx context.Context, principal int64) []delivery {
	var out []delivery
	for len(out) < jobs.OutboxBatch && ctx.Err() == nil {
		res, err := l.store.ClaimPAOutbox(ctx, jobs.OutboxClaimRequest{
			Now: l.now(), Lease: jobs.OutboxLease, Principal: principal, Limit: 1,
		})
		if err != nil {
			slog.Warn("pa outbox not readable", "err", err)
			l.count(OutboxOutcomeClaimError)
			return out
		}
		for range res.Unknown {
			l.count(OutboxOutcomeUnknown)
		}
		if res.Unknown > 0 {
			slog.Warn("pa outbox rows outlived their send lease; not sent again", "rows", res.Unknown)
		}
		if len(res.Items) == 0 {
			return out
		}
		for _, it := range res.Items {
			out = append(out, l.deliverItem(context.WithoutCancel(ctx), it))
		}
	}
	return out
}

// deliverItem sends one claimed row and records its outcome.
func (l *RunLoop) deliverItem(ctx context.Context, it jobs.OutboxItem) delivery {
	sctx, cancel := context.WithTimeout(ctx, outboxSendTimeout)
	c, outcome := l.sendItem(sctx, it)
	cancel()
	// The outcome is recorded on its own deadline: a sent row left in
	// sending would become unknown.
	cctx, cancel := context.WithTimeout(ctx, outboxRecordTimeout)
	err := l.store.CompletePAOutbox(cctx, it, c)
	cancel()
	switch {
	case errors.Is(err, jobs.ErrOutboxStale):
		outcome = OutboxOutcomeStale
	case err != nil:
		// The row stays sending and becomes unknown after its lease: it is
		// not sent twice.
		slog.Warn("pa outbox outcome not recorded", "job_id", it.JobID, "update_id", it.UpdateID, "kind", string(it.Kind), "err", err)
	}
	l.count(outcome)
	if c.Status != jobs.OutboxSent {
		slog.Warn("pa outbox row not sent", "job_id", it.JobID, "update_id", it.UpdateID, "kind", string(it.Kind),
			"attempt", it.Attempts, "outcome", outcome)
	}
	return delivery{item: it, status: c.Status, outcome: outcome}
}

func (l *RunLoop) count(outcome string) {
	if l.metrics != nil {
		l.metrics.CountPAOutbox(outcome)
	}
}

// sendItem builds and sends one claimed row and says what to record.
func (l *RunLoop) sendItem(ctx context.Context, it jobs.OutboxItem) (jobs.OutboxCompletion, string) {
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
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxDropped}, OutboxOutcomeDropped
		case errors.Is(err, convo.ErrStoreFault):
			// Could not read the answer: that says nothing about it, and
			// nothing was sent. It is due again.
			return l.retry(it, now, 0)
		default:
			// A fragment that does not open will not open later (T5).
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
		}
	default:
		tpl, ok := outboxTemplates[it.Kind]
		if !ok {
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
		}
		text = output.ServerText(tpl)
	}
	kb, ok := outboxKeyboard(it)
	if !ok {
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
	}
	if it.SentParts >= text.Parts() {
		// Every part was delivered on an earlier attempt and only the
		// completion was lost.
		return jobs.OutboxCompletion{Now: l.now(), Status: jobs.OutboxSent}, OutboxOutcomeSent
	}
	// Only a prompt that still has parts to send is checked: one delivered
	// in full on an earlier attempt was sent, whatever its button became
	// since (a press consumes it).
	if it.Kind == jobs.OutboxConsentPrompt {
		live, err := l.buttonLive(ctx, it, now)
		if err != nil {
			// Could not read the button: nothing is known about it and
			// nothing was sent. It is due again.
			slog.Warn("pa outbox prompt button not readable", "update_id", it.UpdateID, "err", err)
			return l.retry(it, now, 0)
		}
		if !live {
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxDropped}, OutboxOutcomeButtonExpired
		}
	}
	err := l.sender.SendFrom(ctx, it.Principal, text, kb, it.SentParts, func(parts int) error {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outboxRecordTimeout)
		defer cancel()
		if err := l.store.RecordPAOutboxParts(rctx, it, parts, l.now()); err != nil {
			// A delivered part that is not recorded would be sent again
			// by a retry: the row cannot be retried.
			return fmt.Errorf("%w: part %d delivered, not recorded: %w", output.ErrOutcomeUnknown, parts, err)
		}
		return nil
	})
	return l.sendOutcome(it, err)
}

// buttonLive reports whether a consent prompt's button still resolves for
// at least outboxButtonMinLife. A button whose id is gone (consumed,
// purged, never issued) is not live; a failed read is an error, never
// either answer.
func (l *RunLoop) buttonLive(ctx context.Context, it jobs.OutboxItem, now time.Time) (bool, error) {
	expires, err := l.store.PACallbackExpiry(ctx, it.Principal, it.Button)
	switch {
	case errors.Is(err, convo.ErrNotFound):
		return false, nil
	case err != nil:
		return false, err
	}
	return expires.After(now.Add(outboxButtonMinLife)), nil
}

// sendOutcome classifies a send. Only a failure known to have left the
// message undelivered is retried: one before the request was written, or
// an explicit Bot API 429 or 5xx. Any other 4xx is final: refused when it
// is the principal's choice (refusedByPrincipal), failed otherwise. Every
// other failure may have delivered the message, so the row becomes
// unknown and is never sent again (send-once).
func (l *RunLoop) sendOutcome(it jobs.OutboxItem, err error) (jobs.OutboxCompletion, string) {
	now := l.now()
	var api *output.APIError
	switch {
	case err == nil:
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxSent}, OutboxOutcomeSent
	case errors.Is(err, output.ErrOutcomeUnknown):
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxUnknown}, OutboxOutcomeUnknown
	case refusedByPrincipal(err):
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeRefused
	case permanentSendError(err):
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
	case errors.As(err, &api):
		if api.Status != http.StatusTooManyRequests && (api.Status < 500 || api.Status > 599) {
			return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxUnknown}, OutboxOutcomeUnknown
		}
		return l.retry(it, now, time.Duration(api.RetryAfter)*time.Second)
	case isLocalSendError(err):
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
	default:
		// Failed before the request was written (dial, TLS, egress
		// refusal, a context that ended first): nothing reached Telegram.
		return l.retry(it, now, 0)
	}
}

// retry schedules the row again, or fails it once it used its attempts.
func (l *RunLoop) retry(it jobs.OutboxItem, now time.Time, wait time.Duration) (jobs.OutboxCompletion, string) {
	if it.Attempts >= jobs.OutboxMaxAttempts {
		return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxFailed}, OutboxOutcomeFailed
	}
	wait = max(wait, jobs.OutboxBackoff(it.Attempts))
	return jobs.OutboxCompletion{Now: now, Status: jobs.OutboxPending, RetryAt: now.Add(wait)}, OutboxOutcomeRetry
}

// permanentSendError reports a Bot API 4xx other than a flood wait:
// sending again would be refused the same way.
func permanentSendError(err error) bool {
	var api *output.APIError
	return errors.As(err, &api) && api.Status >= 400 && api.Status < 500 && api.Status != http.StatusTooManyRequests
}

// principalForbidden are the 403 descriptions that mean the principal
// blocked the bot, left, or never started it. Other 403s ("bots can't send
// messages to bots", none at all) point at a chat id or token of ours.
var principalForbidden = []string{
	"bot was blocked by the user",
	"user is deactivated",
	"bot was kicked",
	"bot can't initiate conversation",
}

// refusedByPrincipal reports the 4xx answers that mean the principal
// blocked the bot or the chat is gone: a 403 with one of the
// principalForbidden descriptions, or a 400 whose description says the
// chat was not found. Every other 4xx (a malformed request, a bad or
// revoked token's 401 or 404, an unexplained 403) is ours to fix and must
// not hide here.
func refusedByPrincipal(err error) bool {
	var api *output.APIError
	if !errors.As(err, &api) {
		return false
	}
	desc := strings.ToLower(api.Description)
	switch api.Status {
	case http.StatusForbidden:
		for _, d := range principalForbidden {
			if strings.Contains(desc, d) {
				return true
			}
		}
	case http.StatusBadRequest:
		return strings.Contains(desc, "chat not found")
	}
	return false
}

// isLocalSendError reports a message Sender refused to build, before any
// request: it would be refused the same way again.
func isLocalSendError(err error) bool {
	for _, e := range []error{output.ErrEmptyText, output.ErrInvalidChat, output.ErrInvalidKeyboard,
		output.ErrPartTooLong, output.ErrTooLong, output.ErrInvalidConfig} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
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
		// The allow-list is what the principal typed before the answer,
		// as when the reply was accepted: the rendering, and so the parts
		// a retry resumes after, do not change with later messages.
		if prov == convo.ProvenanceUser && row.Seq < it.FragmentSeq {
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
// The request paths start delivering their own rows after their response;
// this pass retries the ones whose send failed and marks rows that
// outlived their lease unknown.
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
			l.outboxPass(ctx)
		}
	}
}

// outboxPass delivers due rows of every principal. A full batch may have
// left due rows behind, so it keeps going until a batch comes back short.
func (l *RunLoop) outboxPass(ctx context.Context) {
	for len(l.deliver(ctx, 0)) == jobs.OutboxBatch && ctx.Err() == nil {
	}
}

// deliverAfter delivers the principals' due rows in the background, on a
// context detached from the request (WithoutCancel) with its own deadline,
// so a request path never waits on Telegram and a worker that hangs up
// never cuts a send off. Rows it does not reach stay due for RunOutbox.
func (l *RunLoop) deliverAfter(ctx context.Context, principals ...int64) {
	if len(principals) == 0 {
		return
	}
	ps := slices.Clone(principals)
	slices.Sort(ps)
	ps = slices.Compact(ps)
	l.pending.Add(1)
	go func() {
		defer l.pending.Done()
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outboxRequestDeadline)
		defer cancel()
		for _, p := range ps {
			l.deliver(dctx, p)
		}
	}()
}

// DeliverAfter starts delivering principal's due rows after a request
// path committed them: the webhook calls it once an update's transaction
// committed, so a consent prompt or a command's answer goes out at once
// instead of on the next RunOutbox pass (#1348).
func (l *RunLoop) DeliverAfter(ctx context.Context, principal int64) {
	if principal > 0 {
		l.deliverAfter(ctx, principal)
	}
}

// WaitDeliveries waits for the deliveries the request paths started, for
// a graceful shutdown and for tests.
func (l *RunLoop) WaitDeliveries() { l.pending.Wait() }
