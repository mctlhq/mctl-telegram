package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
)

// The production store satisfies the run loop's store; asserted here, where
// the two meet, so a missing method fails the build rather than startup.
var _ pa.RunLoopStore = (*db.Store)(nil)

// paMetrics is what the PA runtime counts to (*metrics.Registry).
type paMetrics interface {
	pa.Counter
	pa.OutboxCounter
	pa.CallbackCounter
}

// paLoop is the part of *pa.RunLoop the server's lifecycle drives.
type paLoop interface {
	RunOutbox(ctx context.Context, interval time.Duration)
	WaitDeliveries()
}

// newPASender builds the PA bot's sender. A variable only so the wiring
// tests can record what the wired runtime sends instead of calling the Bot
// API; nothing else assigns it.
var newPASender = func(token string) (pa.BotSender, error) {
	return output.NewSender(output.Config{Token: token})
}

// paRuntime is the Personal Assistant's server half (#1313, wired by
// #1343): the webhook with the Conversations handler, the run-loop routes
// (claim, turn, reply), the outbox retry loop and its shutdown drain.
//
// It deliberately has no tools: Tools is pa.NoTools, and neither the
// connector dispatcher (RouteTool), the connection manager, the KEK nor
// account linking is built here. Those land together in the tools slice
// (#1314), which must also start Dispatcher.Run. A nil *paRuntime is the
// PA switched off, and every method on it does nothing.
type paRuntime struct {
	loop    paLoop
	webhook http.Handler
	mount   func(chi.Router)
	wg      sync.WaitGroup
}

// buildPA builds the PA runtime when, and only when, cfg.PAEnabled is true;
// with it off it constructs nothing and returns nil, nil. config.Load has
// already refused an enabled configuration without the bot token, webhook
// secret, webhook URL, ENCRYPTION_KEY or OAuth signing key; buildPA checks
// what it uses again, so a hand-built Config cannot start a half-configured
// PA. Any error refuses startup.
func buildPA(cfg *config.Config, store *db.Store, rc *localjwt.RevocationCache, m paMetrics) (*paRuntime, error) {
	if !cfg.PAEnabled {
		return nil, nil
	}
	if store == nil || rc == nil {
		return nil, errors.New("pa: store and worker-token revocation cache are required")
	}
	secret := []byte(cfg.OAUTHJWTSecret)
	if len(secret) == 0 || !cfg.OAUTHJWTSecretDedicated {
		return nil, errors.New("pa: a dedicated OAUTH_JWT_SIGNING_KEY in AUTH_MODE=local-jwt is required")
	}
	issuer := strings.TrimRight(cfg.PublicBaseURL, "/")
	sealer, err := convo.NewSealer(cfg.EncryptionKey)
	if err != nil {
		return nil, errors.New("pa: ENCRYPTION_KEY does not key the conversation sealer")
	}
	minter, err := localjwt.NewIssuer(secret, issuer)
	if err != nil {
		return nil, err
	}
	pool, err := localjwt.NewPoolProvider(localjwt.PoolProviderConfig{Secret: secret, ExpectedIssuer: issuer, RevocationCache: rc})
	if err != nil {
		return nil, err
	}
	verifier, err := localjwt.NewPAJobVerifier(secret, issuer, rc)
	if err != nil {
		return nil, err
	}
	sender, err := newPASender(cfg.PABotToken)
	if err != nil {
		return nil, err
	}
	// m is optional (tests pass nil); a nil m leaves both counters nil
	// interfaces rather than wrapping it. main always passes a registry.
	var counter pa.Counter
	var outboxCounter pa.OutboxCounter
	var callbackCounter pa.CallbackCounter
	if m != nil {
		counter, outboxCounter, callbackCounter = m, m, m
	}
	// The preview allowlist (PA_ALLOWED_PRINCIPALS): checked at ingress and
	// at every run step. Empty allows nobody, and says so at startup.
	allowed := pa.NewAllowlist(cfg.PAAllowedPrincipals)
	if allowed.Len() == 0 {
		slog.Warn("pa allowlist is empty: every principal is refused", "env", config.PAAllowedPrincipalsEnv)
	}
	loop, err := pa.NewRunLoop(pa.RunLoopConfig{
		Store: store, Sealer: sealer, Pool: pool, Minter: minter, Verifier: verifier, Sender: sender,
		Tools:  pa.NoTools,
		Limits: cfg.PALimits(), Budget: cfg.PABudget(),
		Metrics: outboxCounter, CallbackMetrics: callbackCounter,
		Allowed: allowed,
	})
	if err != nil {
		return nil, err
	}
	// The conversation's own answers (the consent prompt and its button,
	// /new, /forget, /consent) are conversation-level outbox rows (#1348),
	// written in the update's transaction and delivered after its commit.
	conv, err := pa.NewConversations(pa.ConversationsConfig{
		Store: store, Sealer: sealer, TTL: cfg.PAConversationTTL, Runs: loop, Limiter: loop,
		Replies: &pa.OutboxReplies{Store: store, Metrics: outboxCounter},
		Allowed: allowed,
	})
	if err != nil {
		return nil, err
	}
	hook, err := pa.NewWebhookHandler(pa.WebhookConfig{
		Secret: cfg.PAWebhookSecret, Dedup: store, Handler: conv, Failures: store,
		// Counts every delivery outcome, bad_secret included: a secret
		// mismatch with Telegram shows here as well as in getWebhookInfo.
		Counter: counter,
		// Deliver the rows the update queued once it committed; rows this
		// does not reach stay due for RunOutbox. A pressed button is
		// answered too, best effort, so the client stops its spinner.
		AfterCommit: func(ctx context.Context, u pa.VerifiedUpdate) {
			loop.DeliverAfter(ctx, u.Principal().TelegramID())
			loop.AnswerCallbackAfter(ctx, u)
		},
	})
	if err != nil {
		return nil, err
	}
	return &paRuntime{loop: loop, webhook: hook, mount: func(r chi.Router) { loop.Mount(r) }}, nil
}

// Mount registers the webhook and the run-loop routes.
func (r *paRuntime) Mount(mux chi.Router) {
	if r == nil {
		slog.Info("pa bot disabled", "reason", "PA_ENABLED not true")
		return
	}
	// Handle, not Method(POST): the handler checks the secret before the
	// method, so a GET without the secret is a 401 like any other request
	// and the router does not reveal the endpoint with a 405.
	mux.Handle(pa.WebhookPath, r.webhook)
	if r.mount != nil {
		r.mount(mux)
	}
	slog.Info("pa bot enabled", "webhook", pa.WebhookPath, "tools", "none")
}

// Start runs the outbox retry loop until ctx ends.
func (r *paRuntime) Start(ctx context.Context) {
	if r == nil {
		return
	}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.loop.RunOutbox(ctx, pa.OutboxInterval)
	}()
}

// Shutdown waits for the outbox loop (its context must already be done)
// and then for the deliveries request paths started, until deadline. It is
// called after the HTTP server has stopped serving and before the store
// closes, so a delivery is not cut off mid-write. If the server's own
// shutdown timed out, a handler still running may start a delivery this
// wait does not see; like a delivery still running at the deadline, it is
// abandoned, and its row outlives its lease and becomes unknown, never
// resent.
func (r *paRuntime) Shutdown(deadline time.Time) {
	if r == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		r.loop.WaitDeliveries()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
		slog.Warn("pa shutdown: deliveries still running at the deadline")
	}
}

// gracefulShutdown stops the HTTP server first, then drains the PA and the
// broadcast worker, all before main returns and the deferred database
// close runs. Split out of main so a test can check the order.
func gracefulShutdown(ctx context.Context, srv interface{ Shutdown(context.Context) error }, paRT *paRuntime, deadline time.Time) {
	if err := srv.Shutdown(ctx); err != nil {
		slog.Warn("http shutdown incomplete; requests may still be running", "err", err)
	}
	paRT.Shutdown(deadline)
	waitBroadcastWorker(deadline)
}
