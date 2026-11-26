package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/auth/localjwt"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/db"
	mcpapp "github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/pa"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/pa/connector"
	"github.com/mctlhq/mctl-telegram/internal/pa/convo"
	"github.com/mctlhq/mctl-telegram/internal/pa/linking"
	"github.com/mctlhq/mctl-telegram/internal/pa/output"
	"github.com/mctlhq/mctl-telegram/internal/pa/output/safetext"
	"github.com/mctlhq/mctl-telegram/internal/sweeper"
	"github.com/mctlhq/mctl-telegram/internal/web"
)

// The production store satisfies the run loop's store; asserted here, where
// the two meet, so a missing method fails the build rather than startup.
var _ pa.RunLoopStore = (*db.Store)(nil)

// paMetrics is what the PA runtime counts to (*metrics.Registry).
type paMetrics interface {
	pa.Counter
	pa.OutboxCounter
	pa.CallbackCounter
	pa.PhaseObserver
	connector.Metrics
}

// paLoop is the part of *pa.RunLoop the server's lifecycle drives.
type paLoop interface {
	RunOutbox(ctx context.Context, interval time.Duration)
	WaitDeliveries()
}

// paBotSender is the PA bot's sender as the run loop and the linking flow
// use it (*output.Sender).
type paBotSender interface {
	pa.BotSender
	pa.TypingSender
	pa.PermissionSender
	pa.DraftSender
	linking.BotSender
}

var _ paBotSender = (*output.Sender)(nil)

// newPASender builds the PA bot's sender. webAppURL is the linking Mini App
// URL, or "" when no linking flow runs (no web_app button can be sent). A
// variable only so the wiring tests can record what the wired runtime
// sends instead of calling the Bot API; nothing else assigns it.
var newPASender = func(token, webAppURL string, langs *output.Languages) (paBotSender, error) {
	return output.NewSender(output.Config{Token: token, WebAppURL: webAppURL, Languages: langs})
}

// paMenuSetter is the part of *output.Sender that sets the bot's command
// menu. The wiring tests' recorder does not implement it, so Start sets no
// menu there.
type paMenuSetter interface {
	SetCommands(ctx context.Context, cmds []output.Command) error
}

// paMenu is the command menu for the commands this server answers: the
// linking commands only when a linking flow runs.
func paMenu(linking bool) []output.Command {
	cmds := []output.Command{
		{Name: "new", Description: safetext.CmdNew},
		{Name: "forget", Description: safetext.CmdForget},
		{Name: "consent", Description: safetext.CmdConsent},
	}
	if linking {
		cmds = append(cmds,
			output.Command{Name: "connect", Description: safetext.CmdConnect},
			output.Command{Name: "connections", Description: safetext.CmdConnections},
			output.Command{Name: "disconnect", Description: safetext.CmdDisconnect},
		)
	}
	return cmds
}

// runPADispatcher runs the dispatcher's pin refresh loop. A variable only
// so the wiring tests can see that Start runs it, with which dispatcher and
// interval, without waiting a PinRefreshInterval; nothing else assigns it.
var runPADispatcher = func(ctx context.Context, d *connector.Dispatcher, every time.Duration) {
	d.Run(ctx, every)
}

// paRuntime is the Personal Assistant's server half (#1313, wired by
// #1343): the webhook with the Conversations handler, the run-loop routes
// (claim, turn, reply), the outbox retry loop and its shutdown drain.
//
// With a PA server enabled (#1318 slice C2) it also runs the tools
// runtime (pa_tools.go): the account-linking routes and bot commands, the
// connector dispatcher (RouteTool) with its pin refresh loop, and the tool
// resolver at claim. With every server off, tools is nil and none of that
// exists: no linking or tool route, and runs bind no tool. A nil
// *paRuntime is the PA switched off, and every method on it does nothing.
type paRuntime struct {
	loop    paLoop
	webhook http.Handler
	mount   func(chi.Router)
	tools   *paTools
	// writes is the write path (pa_writes.go): nil unless
	// PA_WRITES_ENABLED read true at startup.
	writes     *paWrites
	dispatcher *connector.Dispatcher
	// staleWrites resolves approved-call dispatch records nobody finished
	// (slice P2-S3). Set with the dispatcher.
	staleWrites *connector.StaleWriteSweeper
	// menu sets menuCommands as the bot's command menu at Start; nil when
	// the sender cannot (the wiring tests' recorder).
	menu         paMenuSetter
	menuCommands []output.Command
	wg           sync.WaitGroup
}

// paMenuTimeout bounds the one setMyCommands round at Start.
const paMenuTimeout = 30 * time.Second

// buildPA builds the PA runtime when, and only when, cfg.PAEnabled is true;
// with it off it constructs nothing and returns nil, nil. config.Load has
// already refused an enabled configuration without the bot token, webhook
// secret, webhook URL, ENCRYPTION_KEY or OAuth signing key; buildPA checks
// what it uses again, so a hand-built Config cannot start a half-configured
// PA. Any error refuses startup. ctx is main's: a SIGTERM during startup
// cancels the tools runtime's metadata fetch.
func buildPA(ctx context.Context, cfg *config.Config, store *db.Store, rc *localjwt.RevocationCache, m paMetrics) (*paRuntime, error) {
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
	tools, err := config.LoadPATools(cfg, os.Getenv)
	if err != nil {
		return nil, err
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
	var appURL string
	if tools.AnyEnabled() {
		appURL = tools.AppURL
	}
	// The language of each principal's client, from their latest update:
	// the sender answers in it (output.Languages).
	langs := output.NewLanguages()
	sender, err := newPASender(cfg.PABotToken, appURL, langs)
	if err != nil {
		return nil, err
	}
	pt, err := buildPATools(ctx, cfg, tools, store, sender)
	if err != nil {
		return nil, err
	}
	// The preview allowlist (PA_ALLOWED_PRINCIPALS): checked at ingress and
	// at every run step. Empty allows nobody, and says so at startup.
	allowed := pa.NewAllowlist(cfg.PAAllowedPrincipals)
	if allowed.Len() == 0 {
		slog.Warn("pa allowlist is empty: every principal is refused", "env", config.PAAllowedPrincipalsEnv)
	}
	// m is optional (tests pass nil); a nil m must stay a nil interface.
	var dm connector.Metrics
	if m != nil {
		dm = m
	}
	// The write path, or nil: everything below that names pw is the whole
	// of its wiring, and with pw nil each of those is what it was before.
	pw, err := buildPAWrites(cfg, pt, store, sender, allowed, dm)
	if err != nil {
		return nil, err
	}
	resolver := pa.ToolResolver(pa.NoTools)
	if pt != nil {
		pt.writes = pw
		resolver = pt.toolResolver(store)
	}
	// m is optional (tests pass nil); a nil m leaves both counters nil
	// interfaces rather than wrapping it. main always passes a registry.
	var counter pa.Counter
	var outboxCounter pa.OutboxCounter
	var callbackCounter pa.CallbackCounter
	var phases pa.PhaseObserver
	if m != nil {
		counter, outboxCounter, callbackCounter, phases = m, m, m, m
	}
	loopCfg := pa.RunLoopConfig{
		Store: store, Sealer: sealer, Pool: pool, Minter: minter, Verifier: verifier, Sender: sender,
		Tools:  resolver,
		Limits: cfg.PALimits(), Budget: cfg.PABudget(),
		Metrics: outboxCounter, CallbackMetrics: callbackCounter,
		Allowed: allowed, Typing: sender, Drafts: sender, Getenv: os.Getenv, Phases: phases,
	}
	if pf, ok := sender.(pa.PhotoFetcher); ok {
		loopCfg.Photos = pf
	}
	convCfg := pa.ConversationsConfig{
		Store: store, Sealer: sealer, TTL: cfg.PAConversationTTL,
		Replies: &pa.OutboxReplies{Store: store, Metrics: outboxCounter},
		// The linking commands and buttons run after the commit, through
		// pt.commands below; without a tools runtime they are answered
		// "not available" in the transaction.
		Linking: pt != nil,
		Allowed: allowed,
	}
	var cards *connector.Cards
	if pw != nil {
		// PA_WRITES_ENABLED, read where the dispatcher reads it: while it
		// is on, /consent shows the consent to actions (#1320 P2-S14c).
		// Only with a built write path: a service started with writes off
		// has none until it restarts, so it never asks for a consent to
		// actions it cannot carry out, whatever the flag reads later.
		// Turning the flag off is read at once.
		convCfg.Writes = paWritesSwitch(pt.flags)
		// A typed nil must not reach these interfaces: they are set only
		// here, from a built write path.
		cards = pw.cards
		loopCfg.Cards, loopCfg.ApproveTools, loopCfg.ActionsHint = pw.cards, pw.approveTools, pw.hint
		convCfg.Approvals, convCfg.Permissions = pw.approvals, pw.permissions
	}
	loop, err := pa.NewRunLoop(loopCfg)
	if err != nil {
		return nil, err
	}
	pw.bind(loop.DeliverAfter)
	// The conversation's own answers (the consent prompt and its button,
	// /new, /forget, /consent) are conversation-level outbox rows (#1348),
	// written in the update's transaction and delivered after its commit.
	convCfg.Runs, convCfg.Limiter = loop, loop
	conv, err := pa.NewConversations(convCfg)
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
		// A linking command or button recorded in the transaction runs
		// now, never inside it (internal/pa/postcommit.go).
		AfterCommit: func(ctx context.Context, u pa.VerifiedUpdate) {
			langs.Set(u.Principal().TelegramID(), u.LanguageCode())
			loop.TypingAfter(ctx, u.Principal().TelegramID())
			loop.DeliverAfter(ctx, u.Principal().TelegramID())
			loop.AnswerCallbackAfter(ctx, u)
			if pt != nil {
				pt.commands.AfterCommit(ctx, u)
			}
			// An approved call is dispatched and an admitted /permissions
			// command run, now, after the commit; nothing without a write
			// path.
			pw.afterCommit(ctx, u)
		},
	})
	if err != nil {
		return nil, err
	}
	rt := &paRuntime{loop: loop, webhook: hook, mount: func(r chi.Router) { loop.Mount(r) }, tools: pt, writes: pw}
	if ms, ok := sender.(paMenuSetter); ok {
		rt.menu, rt.menuCommands = ms, paMenu(pt != nil)
	}
	if pt != nil {
		// Cards is nil without a write path: the tool route then has no
		// card path and serves pinned reads only.
		rt.dispatcher, err = connector.NewDispatcher(connector.DispatcherConfig{
			Jobs: loop, Connections: pt.manager, Pin: pt.pin, Endpoints: pt.endpoints,
			Executor: pt.executor, Flags: pt.flags, Metrics: dm, Cards: cards,
		})
		if err != nil {
			return nil, err
		}
		// The approval ledger's dispatch records have no other owner once
		// their executor is gone (threat model T2, S2-C12): this resolves
		// them to outcome_unknown with the notice and the audit entry. It
		// dispatches nothing, and finds nothing while no write path is
		// built.
		rt.staleWrites = &connector.StaleWriteSweeper{Store: store, Executor: pt.executor}
	}
	return rt, nil
}

// Links is the linking flow's sweep for startPAState, or nil (an untyped
// nil interface) when no linking flow runs.
func (r *paRuntime) Links() sweeper.PALinkExpirer {
	if r == nil || r.tools == nil {
		return nil
	}
	return r.tools.links
}

// Connections is the connection manager, or nil when no tools runtime
// runs. The account-delete handlers revoke a deleted principal's
// connections through it (slice A2).
func (r *paRuntime) Connections() *connection.Manager {
	if r == nil || r.tools == nil {
		return nil
	}
	return r.tools.manager
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
	if r.tools == nil {
		slog.Info("pa bot enabled", "webhook", pa.WebhookPath, "tools", "none")
		return
	}
	r.tools.links.Mount(mux)
	r.dispatcher.Mount(mux)
	servers := make([]string, 0, len(r.tools.servers))
	for _, s := range r.tools.servers {
		servers = append(servers, string(s))
	}
	// Enabled servers only: each call still needs PA_EXTERNAL_TOOLS_ENABLED
	// and its server flag at dispatch time (connector.EnvFlags).
	slog.Info("pa bot enabled", "webhook", pa.WebhookPath, "tools", "linking and dispatch",
		"servers", strings.Join(servers, ","), "route", connector.RouteTool, "writes", r.writes != nil)
}

// wirePARevokers gives the account-deletion surfaces (the web account page
// and the MCP delete tool) the connection manager, so deleting an account
// first revokes the provider tokens the PA holds for it (#1389). Only a
// runtime with tools has a manager; otherwise both fields stay a nil
// interface, never a typed-nil *connection.Manager, which would pass their
// nil checks. Called before the server serves.
func wirePARevokers(rt *paRuntime, account *web.AccountHandlers, srv *mcpapp.Server) {
	m := rt.Connections()
	if m == nil {
		return
	}
	account.PARevoker = m
	srv.PARevoker = m
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
	if r.menu != nil {
		// Best effort: without it the bot works, only the menu is stale.
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			mctx, cancel := context.WithTimeout(ctx, paMenuTimeout)
			defer cancel()
			if err := r.menu.SetCommands(mctx, r.menuCommands); err != nil {
				slog.Warn("pa bot: command menu not set", "err", err)
			}
		}()
	}
	if r.dispatcher != nil {
		// Whoever serves RouteTool must also run this: it ages tools/list
		// observations out of the pin gauges.
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			runPADispatcher(ctx, r.dispatcher, connector.PinRefreshInterval)
		}()
	}
	if r.staleWrites != nil {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.staleWrites.Run(ctx, connector.StaleWriteSweepInterval)
		}()
	}
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
		// The write path first: a dispatch it started ends by starting a
		// delivery, and the deliveries are waited for after it.
		r.writes.wait()
		r.loop.WaitDeliveries()
		if r.tools != nil {
			r.tools.commands.Wait()
		}
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
