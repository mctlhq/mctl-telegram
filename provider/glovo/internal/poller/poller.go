// Package poller is the claim loop and the per-command state machine. It is
// the provider's only driver: it claims commands from the mctl-api bridge, asks
// for a single-use write permit before each mutation, runs the effect through
// the executor, and posts exactly one encoded result per command, retrying the
// same bytes. mctl-api alone decides scope, tenant, owner and approval.
package poller

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/executor"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/fairness"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/health"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/obs"
	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/protocol/v1alpha1"
)

// Config holds the loop's timings. Zero fields take the production defaults.
type Config struct {
	WorkerIdentity   string
	ClaimMax         int
	PollInterval     time.Duration
	ClaimBackoffCap  time.Duration
	LeaseTTL         time.Duration // mctl-api DefaultLeaseTTL
	LeaseMargin      time.Duration
	ResultBackoffMin time.Duration
	ResultBackoffMax time.Duration
	StopTimeout      time.Duration
	MaxInflight      int
}

func (c *Config) defaults() {
	if c.WorkerIdentity == "" {
		c.WorkerIdentity = "provider:glovo"
	}
	if c.ClaimMax == 0 {
		c.ClaimMax = 4
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.ClaimBackoffCap == 0 {
		c.ClaimBackoffCap = 60 * time.Second
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = 60 * time.Second
	}
	if c.LeaseMargin == 0 {
		c.LeaseMargin = 5 * time.Second
	}
	if c.ResultBackoffMin == 0 {
		c.ResultBackoffMin = 250 * time.Millisecond
	}
	if c.ResultBackoffMax == 0 {
		c.ResultBackoffMax = 8 * time.Second
	}
	if c.StopTimeout == 0 {
		c.StopTimeout = 25 * time.Second
	}
	if c.MaxInflight == 0 {
		c.MaxInflight = 2 * c.ClaimMax
	}
}

// Poller wires the pieces together.
type Poller struct {
	Client  *bridgeclient.Client
	Exec    *executor.Executor
	Limiter *fairness.Limiter
	Health  *health.State
	Metrics *obs.Metrics
	Log     *slog.Logger
	Cfg     Config
	Now     func() time.Time

	once sync.Once
}

func (p *Poller) init() { p.once.Do(p.Cfg.defaults) }

func (p *Poller) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Poller) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.New(slog.DiscardHandler)
}

func codeOf(err error) string {
	var ae *bridgeclient.APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

func retryAfter(err error) time.Duration {
	var ae *bridgeclient.APIError
	if errors.As(err, &ae) {
		return ae.RetryAfter
	}
	return 0
}

// sleep waits d or until ctx ends; it reports whether the full wait elapsed.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// jitter only lengthens a wait, so "at least Retry-After" always holds.
func jitter(d time.Duration) time.Duration {
	return time.Duration(float64(d) * (1 + 0.2*rand.Float64()))
}

// Run claims and handles commands until ctx ends, then waits for in-flight
// commands for at most StopTimeout. It returns nil on a clean stop.
func (p *Poller) Run(ctx context.Context) error {
	p.init()
	workCtx, cancelWork := context.WithCancel(context.Background())
	defer cancelWork()
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.Cfg.MaxInflight)
	failures := 0
	for ctx.Err() == nil {
		wait := p.Cfg.PollInterval
		if free := cap(sem) - len(sem); free > 0 {
			resp, err := p.Client.Claim(ctx, min(p.Cfg.ClaimMax, free))
			if err != nil {
				if ctx.Err() != nil {
					break
				}
				failures++
				wait = p.claimError(err, failures)
			} else {
				failures = 0
				if p.Health != nil {
					p.Health.ClaimSucceeded()
				}
				claimedAt := p.now()
				for _, raw := range resp.Commands {
					sem <- struct{}{}
					wg.Add(1)
					go func(raw json.RawMessage) {
						defer func() { <-sem; wg.Done() }()
						p.Handle(workCtx, claimedAt, resp.SchemaVersion, raw)
					}(raw)
				}
			}
		}
		sleep(ctx, jitter(wait))
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(p.Cfg.StopTimeout):
		cancelWork()
		<-done
	}
	return nil
}

// claimError records the failure and returns how long to wait.
func (p *Poller) claimError(err error, failures int) time.Duration {
	label := "transport"
	wait := p.Cfg.PollInterval
	for i := 0; i < failures && wait < p.Cfg.ClaimBackoffCap; i++ {
		wait *= 2
	}
	wait = min(wait, p.Cfg.ClaimBackoffCap)
	sit, notReady := executor.ClassifyClaim(err)
	switch {
	case errors.Is(err, bridgeclient.ErrMalformed):
		label = "malformed"
	case sit == executor.SitClaim429:
		label = "rate_limited"
		wait = max(wait, retryAfter(err))
	case notReady:
		label = "refused"
		wait = p.Cfg.ClaimBackoffCap
		if p.Health != nil {
			p.Health.ClaimFailed()
		}
	case codeOf(err) != "" || errors.As(err, new(*bridgeclient.APIError)):
		label = "unmapped"
	}
	if p.Metrics != nil {
		p.Metrics.ClaimErrors.WithLabelValues(label).Inc()
	}
	p.log().Warn("claim failed", "code", label)
	return wait
}

func (p *Poller) drop(reason string, id v1alpha1.Envelope) {
	if p.Metrics != nil {
		p.Metrics.Dropped.WithLabelValues(reason).Inc()
	}
	p.log().Warn("command dropped", "command_id", id.CommandID, "code", reason)
}

// Handle runs the state machine for one claimed command.
func (p *Poller) Handle(ctx context.Context, claimedAt time.Time, claimVersion string, raw json.RawMessage) {
	p.init()
	cmd, env, err := v1alpha1.ParseCommand(raw)
	fallback := claimedAt.Add(p.Cfg.LeaseTTL)
	if err != nil {
		if env.Complete() {
			p.submitSituation(ctx, fallback, "invalid", env, executor.SitSchemaInvalid, "schema_invalid")
			return
		}
		reason := "schema_invalid"
		if env.CommandID != "" && env.LeaseToken == "" {
			reason = "no_lease_token"
		}
		p.drop(reason, env)
		return
	}
	id := executor.ID(cmd)
	if cmd.LeaseToken == "" {
		p.drop("no_lease_token", id)
		return
	}
	expiresAt, perr := time.Parse(time.RFC3339Nano, cmd.ExpiresAt)
	if perr != nil {
		p.drop("schema_invalid", id)
		return
	}
	if claimVersion == v1alpha1.ClaimVersion && cmd.SchemaVersion == v1alpha1.VersionV2 {
		p.submitSituation(ctx, expiresAt, cmd.Kind, id, executor.SitSchemaInvalid, "schema_invalid")
		return
	}
	if cmd.Audience != p.Cfg.WorkerIdentity {
		p.submitSituation(ctx, expiresAt, cmd.Kind, id, executor.SitSchemaInvalid, "audience_mismatch")
		return
	}
	submit := func(s executor.Situation) { p.submitSituation(ctx, expiresAt, cmd.Kind, id, s, "") }

	// Pre-flight.
	if cmd.CancelRequested {
		submit(executor.SitCancelRequested)
		return
	}
	if !p.now().Before(expiresAt) {
		p.drop("expired", id)
		return
	}
	if p.Exec.Unavailable() {
		submit(executor.SitUnavailable)
		return
	}
	if p.Limiter != nil {
		if !p.Limiter.TryAcquire(cmd.TenantRef) {
			submit(executor.SitUnavailable)
			return
		}
		defer p.Limiter.Release(cmd.TenantRef)
	}
	leaseDeadline := claimedAt.Add(p.Cfg.LeaseTTL - p.Cfg.LeaseMargin)
	if expiresAt.Before(leaseDeadline) {
		leaseDeadline = expiresAt
	}
	leaseCtx, cancel := context.WithDeadline(ctx, leaseDeadline)
	defer cancel()

	if !cmd.Mutating() {
		submit(p.Exec.RunRead(leaseCtx, cmd))
		return
	}
	if p.Exec.HasPriorEffect(cmd) {
		submit(executor.SitAppliedPriorLease)
		return
	}
	if !p.now().Before(leaseDeadline) {
		p.drop("lease_deadline", id)
		return
	}
	_, err = p.Client.WritePermit(leaseCtx, cmd.CommandID, cmd.LeaseToken)
	if err != nil {
		sit := executor.ClassifyPermit(err)
		p.permitMetric(string(sit))
		switch sit {
		case executor.SitStop, executor.SitNotFound, executor.SitUnauthorized, executor.SitUnmapped:
			p.stop(sit, id, "permit", err)
		default:
			submit(sit)
		}
		return
	}
	p.permitMetric("granted")
	sit := p.Exec.RunWrite(leaseCtx, cmd)
	switch sit {
	case executor.SitAmbiguousWrite:
		obs.Audit(p.log(), obs.EventMutationUnknown, cmd.ExecutionID, cmd.OrderRef, "ambiguous_write")
	case executor.SitApplied:
		obs.Audit(p.log(), obs.EventMutationApplied, cmd.ExecutionID, cmd.OrderRef, "applied")
	}
	submit(sit)
}

func (p *Poller) permitMetric(result string) {
	if p.Metrics != nil {
		p.Metrics.Permits.WithLabelValues(result).Inc()
	}
}

// stop ends a command with no result of ours.
func (p *Poller) stop(sit executor.Situation, id v1alpha1.Envelope, route string, err error) {
	if p.Metrics != nil {
		switch sit {
		case executor.SitUnmapped:
			p.Metrics.Unmapped.WithLabelValues(route).Inc()
		case executor.SitNotFound:
			p.Metrics.Dropped.WithLabelValues("not_found").Inc()
		case executor.SitUnauthorized:
			p.Metrics.Dropped.WithLabelValues("unauthorized").Inc()
		default:
			p.Metrics.Dropped.WithLabelValues("lease_lost").Inc()
		}
	}
	if sit == executor.SitUnauthorized && p.Health != nil {
		p.Health.ClaimFailed()
	}
	obs.Audit(p.log(), obs.EventCommandStopped, id.ExecutionID, "", string(sit))
	p.log().Warn("command stopped", "command_id", id.CommandID, "route", route, "code", codeOf(err))
}

// submitSituation builds, encodes once and sends the result of a situation.
func (p *Poller) submitSituation(ctx context.Context, expiresAt time.Time, kind string, id v1alpha1.Envelope, sit executor.Situation, detail string) {
	res, err := p.Exec.Build(sit, id, detail)
	if err == nil {
		var body []byte
		if body, err = v1alpha1.EncodeResult(res); err == nil {
			if p.Metrics != nil {
				p.Metrics.Commands.WithLabelValues(kind, res.Outcome, res.ProviderEffect).Inc()
			}
			p.send(ctx, expiresAt, id, body)
			return
		}
	}
	p.drop("result_encode_failed", id)
}

// send posts the same bytes until a final answer or expires_at.
func (p *Poller) send(ctx context.Context, expiresAt time.Time, id v1alpha1.Envelope, body []byte) {
	rctx, cancel := context.WithDeadline(ctx, expiresAt)
	defer cancel()
	results := func(s string) {
		if p.Metrics != nil {
			p.Metrics.Results.WithLabelValues(s).Inc()
		}
	}
	backoff := p.Cfg.ResultBackoffMin
	for {
		ack, err := p.Client.SubmitResult(rctx, id.CommandID, body)
		if err == nil {
			if ack.Replayed {
				results("replayed")
			} else {
				results("ok")
			}
			return
		}
		sit := executor.ClassifyResult(err)
		switch sit {
		case executor.SitResultAlreadyDone:
			results("already_completed")
			return
		case executor.SitResultConflict:
			if p.Metrics != nil {
				p.Metrics.ResultConflicts.Inc()
			}
			p.log().Error("result refused", "command_id", id.CommandID, "code", codeOf(err))
			return
		case executor.SitResultBug:
			results("rejected")
			p.log().Error("result refused", "command_id", id.CommandID, "code", codeOf(err))
			return
		case executor.SitStop, executor.SitNotFound, executor.SitUnauthorized, executor.SitUnmapped:
			p.stop(sit, id, "result", err)
			return
		}
		// SitResultRetry: resend the same bytes.
		if rctx.Err() != nil {
			results("gave_up")
			p.log().Warn("result retries ended", "command_id", id.CommandID)
			return
		}
		wait := max(backoff, retryAfter(err))
		if !sleep(rctx, jitter(wait)) {
			results("gave_up")
			return
		}
		backoff = min(backoff*2, p.Cfg.ResultBackoffMax)
	}
}
