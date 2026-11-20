package metrics

// Personal Assistant bot metrics (issue #1313 slice d2): webhook ingress,
// the outbox, and the getWebhookInfo monitor (threat model T4).

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PAWebhookProblems is pa.WebhookProblems(): the closed problem label set
// (TestPAWebhookProblemLabels in internal/pa keeps them equal).
var PAWebhookProblems = []string{"url_changed", "allowed_updates_changed", "delivery_error", "secret_rejected"}

// PAOutboxOutcomes is the closed outcome label set of mctl_pa_outbox_total
// (the pa.OutboxOutcome* constants).
var PAOutboxOutcomes = []string{
	"sent", "retry", "failed", "refused", "dropped", "unknown", "stale", "claim_error",
	"button_expired", "update_reused",
}

// PACallbackAnswerOutcomes is the closed outcome label set of
// mctl_pa_callback_answers_total (the pa.CallbackAnswer* constants).
var PACallbackAnswerOutcomes = []string{"answered", "failed"}

// PAUpdateOutcomes is the closed outcome label set of
// mctl_pa_updates_total (the pa.Outcome* constants of the webhook).
var PAUpdateOutcomes = []string{
	"accepted", "duplicate", "malformed", "unsupported_kind", "business", "not_private",
	"chat_from_mismatch", "sender_chat", "via_bot", "no_sender", "bot_sender",
	"inline_callback", "callback_no_data", "game_callback",
	"bad_secret", "bad_method", "too_large", "read_error", "dedup_error", "handler_error", "gave_up",
}

type paCollectors struct {
	updates *prometheus.CounterVec
	outbox  *prometheus.CounterVec
	answers *prometheus.CounterVec
	checks  *prometheus.CounterVec
	// problemChecks counts readable checks per problem found. The problem
	// gauge holds the last check's value until the next one, so its
	// samples count scrapes, not checks; alerts that need "seen at two
	// checks" count increments of this instead.
	problemChecks *prometheus.CounterVec
	// up, ok and lastOK have no labels but are vectors so that they do
	// not exist at all until the monitor starts: with PA_ENABLED off there
	// is no webhook to watch, and a 0 would read as "unreadable".
	up      *prometheus.GaugeVec
	ok      *prometheus.GaugeVec
	lastOK  *prometheus.GaugeVec
	problem *prometheus.GaugeVec
	pending *prometheus.GaugeVec
	lastErr *prometheus.GaugeVec
}

func newPACollectors() *paCollectors {
	c := &paCollectors{
		updates: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_updates_total",
			Help: "PA webhook deliveries by outcome. bad_secret counts requests without the PA_WEBHOOK_SECRET token.",
		}, []string{"outcome"}),
		outbox: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_outbox_total",
			Help: "PA outbox rows by delivery outcome. unknown: a row outlived its send lease and is not resent; claim_error: the outbox could not be read; button_expired: a consent prompt not sent because its button no longer resolves; update_reused: a reply not queued because a row for the same update id and kind exists.",
		}, []string{"outcome"}),
		answers: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_callback_answers_total",
			Help: "PA answerCallbackQuery calls after a button press committed, by outcome: answered or failed (best effort, never retried).",
		}, []string{"outcome"}),
		checks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_webhook_info_checks_total",
			Help: "getWebhookInfo checks by result: ok, problem or unreadable.",
		}, []string{"result"}),
		problemChecks: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "mctl_pa_webhook_problem_checks_total",
			Help: "Readable getWebhookInfo checks that found the problem. Exists from the monitor start.",
		}, []string{"problem"}),
		up: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_info_up",
			Help: "1 when the last getWebhookInfo read succeeded, 0 when it failed (state unknown, never healthy). Absent while the monitor is not running.",
		}, nil),
		ok: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_info_ok",
			Help: "1 when the last check read the webhook and found no problem; 0 on a problem or an unreadable check.",
		}, nil),
		lastOK: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_info_last_success_timestamp_seconds",
			Help: "Unix time of the last readable getWebhookInfo check; 0 from the monitor start until the first one.",
		}, nil),
		problem: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_problem",
			Help: "1 when the last readable check found the problem, else 0. Absent while the webhook is unreadable.",
		}, []string{"problem"}),
		pending: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_pending_updates",
			Help: "getWebhookInfo pending_update_count. Absent while the webhook is unreadable.",
		}, nil),
		lastErr: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "mctl_pa_webhook_info_last_error_timestamp_seconds",
			Help: "getWebhookInfo last_error_date (0: none). Absent while the webhook is unreadable.",
		}, nil),
	}
	for _, o := range PAUpdateOutcomes {
		c.updates.WithLabelValues(o).Add(0)
	}
	for _, o := range PAOutboxOutcomes {
		c.outbox.WithLabelValues(o).Add(0)
	}
	for _, o := range PACallbackAnswerOutcomes {
		c.answers.WithLabelValues(o).Add(0)
	}
	for _, r := range []string{"ok", "problem", "unreadable"} {
		c.checks.WithLabelValues(r).Add(0)
	}
	return c
}

func (c *paCollectors) collectors() []prometheus.Collector {
	return []prometheus.Collector{c.updates, c.outbox, c.answers, c.checks, c.problemChecks, c.up, c.ok, c.lastOK, c.problem, c.pending, c.lastErr}
}

// CountPAUpdate counts one webhook delivery. Satisfies pa.Counter.
func (r *Registry) CountPAUpdate(outcome string) {
	r.pa.updates.WithLabelValues(outcome).Inc()
}

// CountPAOutbox counts one outbox outcome. Satisfies pa.OutboxCounter.
func (r *Registry) CountPAOutbox(outcome string) {
	r.pa.outbox.WithLabelValues(outcome).Inc()
}

// CountPACallbackAnswer counts one callback answer. Satisfies
// pa.CallbackCounter.
func (r *Registry) CountPACallbackAnswer(outcome string) {
	r.pa.answers.WithLabelValues(outcome).Inc()
}

// ObservePAWebhookInfo exports one getWebhookInfo check. Satisfies
// pa.WebhookGauges. An unreadable check withdraws the per-state series
// rather than leaving the last values (or zeros) to read as current.
func (r *Registry) ObservePAWebhookInfo(readable bool, problems []string, pendingUpdates int, lastErrorUnix int64, at time.Time) {
	c := r.pa
	if !readable {
		c.checks.WithLabelValues("unreadable").Inc()
		c.up.WithLabelValues().Set(0)
		c.ok.WithLabelValues().Set(0)
		c.problem.Reset()
		c.pending.Reset()
		c.lastErr.Reset()
		return
	}
	c.up.WithLabelValues().Set(1)
	c.lastOK.WithLabelValues().Set(float64(at.Unix()))
	c.pending.WithLabelValues().Set(float64(pendingUpdates))
	c.lastErr.WithLabelValues().Set(float64(lastErrorUnix))
	found := map[string]bool{}
	for _, p := range problems {
		found[p] = true
	}
	for _, p := range PAWebhookProblems {
		v := 0.0
		if found[p] {
			v = 1
			c.problemChecks.WithLabelValues(p).Inc()
		}
		c.problem.WithLabelValues(p).Set(v)
	}
	if len(problems) > 0 {
		c.checks.WithLabelValues("problem").Inc()
		c.ok.WithLabelValues().Set(0)
		return
	}
	c.checks.WithLabelValues("ok").Inc()
	c.ok.WithLabelValues().Set(1)
}

// StartPAWebhookMonitor marks the monitor as running: the last-success
// timestamp exists (at 0) from now on, so a monitor that never reads the
// webhook is visibly stale instead of absent.
func (r *Registry) StartPAWebhookMonitor() {
	r.pa.lastOK.WithLabelValues().Set(0)
	r.pa.up.WithLabelValues().Set(0)
	r.pa.ok.WithLabelValues().Set(0)
	for _, p := range PAWebhookProblems {
		r.pa.problemChecks.WithLabelValues(p).Add(0)
	}
}
