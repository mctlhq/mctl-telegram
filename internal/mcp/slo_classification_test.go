package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// mctl-telegram#974: a call by a user with no connected Telegram account, and
// any call by the monitoring canary, must leave the user-facing SLIs. These
// tests drive a real tool (list_dialogs) through the tools/call middleware
// and a real ClientPool, so they fail if either layer reverts: the
// pre-#974 behaviour recorded status="error" / result="error" with
// reason=telegram_error and no traffic label.

const sloCanaryTGID int64 = 500100101

func sloTestServer(t *testing.T, canary canaryguard.Set) (*Server, *metrics.Registry, *db.Store) {
	t.Helper()
	store := newToolsTestStore(t)
	reg := metrics.New()
	pool := telegram.NewClientPool(1, "hash", time.Minute, store)
	pool.WithMetrics(reg)
	srv := &Server{Store: store, Pool: pool, Metrics: reg}
	srv.WithCanaryGuard(canary)
	return srv, reg, store
}

func sloIdentity(t *testing.T, store *db.Store, tgID int64) *auth.Identity {
	t.Helper()
	uid, err := store.EnsureUser(context.Background(), fmt.Sprintf("slo-user-%d", tgID), "", "test")
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	return &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: []string{"telegram:dialogs:read"}}
}

func toolCount(reg *metrics.Registry, tool, status, traffic string) float64 {
	return testutil.ToFloat64(reg.ToolInvocationsTotal.WithLabelValues(tool, status, traffic))
}

func borrowCount(reg *metrics.Registry, result, traffic string) float64 {
	return testutil.ToFloat64(reg.SessionsBorrowTotal.WithLabelValues(result, traffic))
}

// A user who never connected (or disconnected) gets the friendly error, the
// audit row keeps status=error, but both SLI series record no_session and
// nothing in ok|error.
func TestSLO_NoActiveSessionLeavesBothSLIs(t *testing.T) {
	srv, reg, store := sloTestServer(t, canaryTestSet(t))
	mcpSrv := srv.newMCPServer()
	id := sloIdentity(t, store, 700000001)
	ctx := auth.With(context.Background(), id)

	res := callTool(t, ctx, mcpSrv, "list_dialogs", map[string]any{})
	if !res.IsError {
		t.Fatalf("list_dialogs with no session succeeded: %+v", res)
	}

	if got := toolCount(reg, "list_dialogs", statusNoSession, metrics.TrafficUser); got != 1 {
		t.Errorf("tool{no_session,user} = %v, want 1", got)
	}
	for _, st := range []string{"ok", "error", statusCallerError} {
		if got := toolCount(reg, "list_dialogs", st, metrics.TrafficUser); got != 0 {
			t.Errorf("tool{%s,user} = %v, want 0 (no_session must not enter the SLI)", st, got)
		}
	}
	if got := borrowCount(reg, "no_session", metrics.TrafficUser); got != 1 {
		t.Errorf("borrow{no_session,user} = %v, want 1", got)
	}
	for _, r := range []string{"ok", "error"} {
		if got := borrowCount(reg, r, metrics.TrafficUser); got != 0 {
			t.Errorf("borrow{%s,user} = %v, want 0", r, got)
		}
	}
	// Audit trail is unchanged in status, and the reason no longer claims a
	// Telegram failure: Telegram was never called.
	tool, status, _ := latestAudit(t, store, id.UserID)
	if tool != "list_dialogs" || status != "error" {
		t.Errorf("audit = (%q, %q), want (list_dialogs, error)", tool, status)
	}
	if reason := latestAuditReason(t, store, id.UserID); reason != ReasonNoSession {
		t.Errorf("audit reason = %q, want %q", reason, ReasonNoSession)
	}
}

// The canary's calls carry traffic=canary on both series, whatever their
// outcome, so the SLI rules can drop them with traffic!="canary".
func TestSLO_CanaryCallsAreLabelledCanary(t *testing.T) {
	srv, reg, store := sloTestServer(t, canaryTestSet(t))
	mcpSrv := srv.newMCPServer()
	id := sloIdentity(t, store, sloCanaryTGID)
	ctx := auth.With(context.Background(), id)

	_ = callTool(t, ctx, mcpSrv, "list_dialogs", map[string]any{})

	if got := toolCount(reg, "list_dialogs", statusNoSession, metrics.TrafficCanary); got != 1 {
		t.Errorf("tool{no_session,canary} = %v, want 1", got)
	}
	if got := borrowCount(reg, "no_session", metrics.TrafficCanary); got != 1 {
		t.Errorf("borrow{no_session,canary} = %v, want 1", got)
	}
	for _, st := range []string{"ok", "error", statusNoSession} {
		if got := toolCount(reg, "list_dialogs", st, metrics.TrafficUser); got != 0 {
			t.Errorf("tool{%s,user} = %v, want 0 (a canary call must not count as user traffic)", st, got)
		}
	}
	for _, r := range []string{"ok", "error", "no_session"} {
		if got := borrowCount(reg, r, metrics.TrafficUser); got != 0 {
			t.Errorf("borrow{%s,user} = %v, want 0", r, got)
		}
	}
}

// With CANARY_TELEGRAM_IDS empty nothing is canary: the label can only ever
// be set by server config.
func TestSLO_NoCanaryConfigMeansUserTraffic(t *testing.T) {
	srv, reg, store := sloTestServer(t, nil)
	mcpSrv := srv.newMCPServer()
	id := sloIdentity(t, store, sloCanaryTGID)
	ctx := auth.With(context.Background(), id)

	_ = callTool(t, ctx, mcpSrv, "list_dialogs", map[string]any{})

	if got := toolCount(reg, "list_dialogs", statusNoSession, metrics.TrafficUser); got != 1 {
		t.Errorf("tool{no_session,user} = %v, want 1", got)
	}
	if got := toolCount(reg, "list_dialogs", statusNoSession, metrics.TrafficCanary); got != 0 {
		t.Errorf("tool{no_session,canary} = %v, want 0", got)
	}
}

// A real failure is still an error: only db.ErrNoActiveSession moves to
// no_session, so a store failure on the same path must stay in the SLI.
func TestSLO_RealErrorStillCounts(t *testing.T) {
	store := newToolsTestStore(t)
	reg := metrics.New()
	srv := &Server{Store: store, Metrics: reg}
	id := &auth.Identity{UserID: 1, TelegramID: 700000002}

	for _, err := range []error{
		errors.New("check session: connection refused"),
		fmt.Errorf("telegram client failed: %w", errors.New("dial tcp: i/o timeout")),
	} {
		srv.audit(context.Background(), id, "list_dialogs", "", err, time.Now())
	}
	srv.audit(context.Background(), id, "list_dialogs", "", fmt.Errorf("telegram client failed: %w", db.ErrNoActiveSession), time.Now())

	if got := toolCount(reg, "list_dialogs", "error", metrics.TrafficUser); got != 2 {
		t.Errorf("tool{error,user} = %v, want 2", got)
	}
	if got := toolCount(reg, "list_dialogs", statusNoSession, metrics.TrafficUser); got != 1 {
		t.Errorf("tool{no_session,user} = %v, want 1 (a wrapped ErrNoActiveSession is still no_session)", got)
	}
}

func TestBorrowErrResult_NoSessionReason(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{db.ErrNoActiveSession, ReasonNoSession},
		{fmt.Errorf("telegram client failed: %w", db.ErrNoActiveSession), ReasonNoSession},
		{db.ErrSessionExpired, ReasonTelegramError},
		{db.ErrSessionRevoked, ReasonTelegramError},
		{telegram.ErrPoolFull, ReasonTelegramError},
	}
	for _, tc := range cases {
		rec := &callRecorder{}
		ctx := withRecorder(context.Background(), rec)
		_ = borrowErrResult(ctx, "list_dialogs", tc.err)
		if got := rec.snapshotHint(); got != tc.want {
			t.Errorf("borrowErrResult(%v) hint = %q, want %q", tc.err, got, tc.want)
		}
	}
}
