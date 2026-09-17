package events

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

// AuditStream receives one entry per stage of an event's life, keyed by
// event_id and correlation_id, across every producer and consumer.
const AuditStream = "mctl:events:audit"

const (
	streamMaxLen        = 10000
	auditMaxLen         = 10000
	batchSize           = 100
	safetyInterval      = 30 * time.Second
	maxBackoff          = time.Minute
	publishedRetention  = 7 * 24 * time.Hour
	leaseTTL            = time.Minute
	leaseReleaseTimeout = 5 * time.Second
	leaseRetry          = time.Second
	leaseRenewEvery     = leaseTTL / 3
	auditTimeout        = time.Second
	storeTimeout        = 10 * time.Second
)

// ErrLeaseHeld means another replica is draining the shared outbox; this one
// retries shortly instead of publishing the same rows concurrently.
var ErrLeaseHeld = errors.New("event outbox relay lease held by another replica")

// Store is the slice of *db.Store the relay needs.
type Store interface {
	PendingOutbox(ctx context.Context, limit int) ([]db.OutboxRow, error)
	MarkOutboxPublished(ctx context.Context, id int64, at time.Time) error
	MarkOutboxFailed(ctx context.Context, id int64, reason string) error
	PurgePublishedOutbox(ctx context.Context, before time.Time) (int64, error)
	OutboxBacklog(ctx context.Context) (int64, error)
	AcquireOutboxLease(ctx context.Context, holder string, now time.Time, ttl time.Duration) (bool, error)
	ReleaseOutboxLease(ctx context.Context, holder string) error
}

// Publisher is the transport the relay writes to.
type Publisher interface {
	XAdd(ctx context.Context, stream string, maxLen int, fields ...string) (string, error)
	Close()
}

// Relay publishes committed outbox rows to Valkey. It is woken by Notify right
// after an ingest commits and, as a safety net, every 30s -- that timer only
// drains this service's own table after a Valkey outage, it is not how events
// are discovered.
type Relay struct {
	store Store
	pub   Publisher
	now   func() time.Time
	wake  chan struct{}
	mu    sync.Mutex // one drain at a time in this process
	// holder names this process in the database lease that makes one replica
	// at a time own the outbox, so replicas never publish the same rows and
	// rows keep their order.
	holder string
	// storeTimeout bounds each database call, so a stalled connection makes
	// the pass fail and back off instead of hanging with the lease held.
	storeTimeout time.Duration

	published prometheus.Counter
	failures  prometheus.Counter
	backlog   prometheus.Gauge
}

// NewRelay builds a relay reporting into m (nil uses unregistered collectors,
// for tests).
func NewRelay(store Store, pub Publisher, m *metrics.Registry) *Relay {
	if m == nil {
		m = metrics.New()
	}
	return &Relay{
		store:        store,
		pub:          pub,
		now:          time.Now,
		wake:         make(chan struct{}, 1),
		holder:       relayHolder(),
		storeTimeout: storeTimeout,
		published:    m.EventsPublishedTotal,
		failures:     m.EventsPublishFailuresTotal,
		backlog:      m.EventsOutboxBacklog,
	}
}

func relayHolder() string {
	host, _ := os.Hostname()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return host + "/" + strconv.Itoa(os.Getpid()) + "/" + hex.EncodeToString(b)
}

// storeCtx bounds one database call.
func (r *Relay) storeCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.storeTimeout)
}

// Notify asks the relay to drain now. Never blocks.
func (r *Relay) Notify() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run drains until ctx is done.
func (r *Relay) Run(ctx context.Context) {
	defer r.pub.Close()
	backoff := time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()
	lastPurge := time.Time{}
	var retryAt time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
			// A new row does not cut a failure backoff short: under a
			// sustained outage every ingest would otherwise trigger a retry.
			// The armed timer still fires at retryAt.
			if r.now().Before(retryAt) {
				continue
			}
		case <-timer.C:
		}
		err := r.Drain(ctx)
		bctx, bcancel := r.storeCtx(ctx)
		if n, berr := r.store.OutboxBacklog(bctx); berr == nil {
			r.backlog.Set(float64(n))
		}
		bcancel()
		wait := safetyInterval
		retryAt = time.Time{}
		switch {
		case errors.Is(err, ErrLeaseHeld):
			wait = leaseRetry
			// Coalesce new-row notifications until the retry, too: otherwise
			// every ingest contends for the lease again right away.
			retryAt = r.now().Add(leaseRetry)
		case err != nil:
			slog.Warn("event relay drain failed", "err", err, "retry_in", backoff)
			wait = backoff
			retryAt = r.now().Add(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		default:
			backoff = time.Second
		}
		if now := r.now(); now.Sub(lastPurge) > time.Hour {
			pctx, pcancel := r.storeCtx(ctx)
			n, perr := r.store.PurgePublishedOutbox(pctx, now.Add(-publishedRetention))
			pcancel()
			if perr == nil {
				lastPurge = now
				if n > 0 {
					slog.Info("event outbox purged", "rows", n)
				}
			}
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)
	}
}

// Drain publishes every pending row in order and stops at the first transport
// failure, so a Valkey outage costs one failed attempt per pass, not one per row.
func (r *Relay) Drain(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	defer func() {
		// Hand the outbox over as soon as this pass ends, so another replica's
		// fresh rows do not wait for the lease to expire.
		// Detached from shutdown so the hand-over still happens, but bounded:
		// an unreachable database must not keep Run from closing the publisher.
		releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), leaseReleaseTimeout)
		defer cancel()
		if err := r.store.ReleaseOutboxLease(releaseCtx, r.holder); err != nil {
			slog.Warn("event outbox lease not released", "err", err)
		}
	}()
	// The lease is renewed while rows are published, not only per batch: slow
	// Valkey calls can make one batch outlast leaseTTL, and a replica that lost
	// ownership must stop before another one publishes the same rows.
	var renewedAt time.Time
	renew := func(force bool) error {
		now := r.now()
		if !force && now.Sub(renewedAt) < leaseRenewEvery {
			return nil
		}
		lctx, lcancel := r.storeCtx(ctx)
		owned, err := r.store.AcquireOutboxLease(lctx, r.holder, now, leaseTTL)
		lcancel()
		if err != nil {
			return err
		}
		if !owned {
			return ErrLeaseHeld
		}
		renewedAt = now
		return nil
	}
	// Audit is best effort and must not hold delivery back: each write is
	// bounded, and after one failure the rest of this pass skips the trail
	// instead of paying the timeout again for every row.
	auditOK := true
	for {
		if err := renew(true); err != nil {
			return err
		}
		qctx, qcancel := r.storeCtx(ctx)
		rows, err := r.store.PendingOutbox(qctx, batchSize)
		qcancel()
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		for _, row := range rows {
			if err := renew(false); err != nil {
				return err
			}
			if _, err := r.pub.XAdd(ctx, row.Stream, streamMaxLen, "envelope", row.Envelope); err != nil {
				r.failures.Inc()
				if merr := r.markFailed(ctx, row.ID, err.Error()); merr != nil {
					slog.Warn("event outbox failure not recorded", "err", merr)
				}
				return err
			}
			published := r.now()
			// Audit the append itself, before the database mark: a publish
			// whose mark fails still happened and must be on the trail.
			r.published.Inc()
			if auditOK {
				auditOK = r.audit(ctx, row, published)
			} else {
				slog.Warn("event audit skipped after an earlier failure in this pass")
			}
			mctx, mcancel := r.storeCtx(ctx)
			err := r.store.MarkOutboxPublished(mctx, row.ID, published)
			mcancel()
			if err != nil {
				// Published but not marked: the next pass publishes it again,
				// and the consumer deduplicates by envelope id. Count this XADD
				// as an attempt so the republish is audited with its real number.
				if merr := r.markFailed(ctx, row.ID, "published but not marked: "+err.Error()); merr != nil {
					slog.Warn("event outbox attempt not recorded", "err", merr)
				}
				return err
			}
		}
		if len(rows) < batchSize {
			return nil
		}
	}
}

func (r *Relay) markFailed(ctx context.Context, id int64, reason string) error {
	fctx, cancel := r.storeCtx(ctx)
	defer cancel()
	return r.store.MarkOutboxFailed(fctx, id, reason)
}

func (r *Relay) audit(ctx context.Context, row db.OutboxRow, at time.Time) bool {
	id := "telegram:" + row.EventID
	auditCtx, cancel := context.WithTimeout(ctx, auditTimeout)
	defer cancel()
	_, err := r.pub.XAdd(auditCtx, AuditStream, auditMaxLen,
		"stage", "published",
		"component", Source,
		"event_id", id,
		"correlation_id", id,
		"stream", row.Stream,
		"attempt", strconv.Itoa(row.Attempts+1),
		"latency_ms", strconv.FormatInt(at.Sub(row.CreatedAt).Milliseconds(), 10),
	)
	if err != nil {
		// Best effort: the audit trail must never hold delivery back.
		slog.Warn("event audit write failed", "err", err)
		return false
	}
	return true
}

// OutboxBuilder adapts BuildEnvelope to db.OutboxBuilder for stream.
func OutboxBuilder(stream string) db.OutboxBuilder {
	return func(ev db.IncomingEvent, occurredAt time.Time) (db.OutboxRow, bool, error) {
		if !Publishable(ev.Kind) {
			return db.OutboxRow{}, false, nil
		}
		env, err := BuildEnvelope(ev, occurredAt)
		if err != nil {
			return db.OutboxRow{}, false, err
		}
		body, err := env.Marshal()
		if err != nil {
			return db.OutboxRow{}, false, err
		}
		return db.OutboxRow{EventID: ev.EventID, Stream: stream, Envelope: body}, true, nil
	}
}
