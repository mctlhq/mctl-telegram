package mcp

import (
	"context"
	"strings"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/canaryguard"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// Synthetic ids: Alice is the monitoring canary, Bob an ordinary account and
// Dana the admin who targets either of them (issue #961).
const (
	canaryAliceTGID int64 = 500100101
	canaryBobTGID   int64 = 500100202
	canaryDanaTGID  int64 = 500100303
)

func canaryTestSet(t *testing.T) canaryguard.Set {
	t.Helper()
	set, err := canaryguard.Parse("500100101")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return set
}

// canaryCase is one session-ending tool. self tools act on the caller's own
// account; the others are admin tools that take telegram_id.
type canaryCase struct {
	tool    string
	self    bool
	args    map[string]any
	handler func(*Server) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error)
	// ended reports whether the target account lost what the tool takes away.
	ended func(t *testing.T, store *db.Store, uid, tgID int64) bool
}

func canaryCases() []canaryCase {
	sessionEnded := func(t *testing.T, store *db.Store, uid, _ int64) bool {
		return activeAccountCount(t, store, uid) == 0
	}
	return []canaryCase{
		{
			tool: "disconnect_telegram_account", self: true,
			handler: func(s *Server) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
				_, h := s.toolDisconnectAccount()
				return h
			},
			ended: sessionEnded,
		},
		{
			tool: "delete_telegram_account", self: true,
			handler: func(s *Server) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
				_, h := s.toolDeleteAccount()
				return h
			},
			ended: func(t *testing.T, store *db.Store, uid, _ int64) bool {
				return totalAccountCount(t, store, uid) == 0
			},
		},
		{
			tool: "revoke_telegram_session",
			handler: func(s *Server) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
				_, h := s.toolRevokeSession()
				return h
			},
			ended: sessionEnded,
		},
		{
			tool: "set_telegram_access",
			args: map[string]any{"tier": db.TierNone},
			handler: func(s *Server) func(context.Context, mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
				_, h := s.toolSetAccess()
				return h
			},
			ended: func(t *testing.T, store *db.Store, _, tgID int64) bool {
				tier, err := store.GetAccessTier(context.Background(), tgID)
				if err != nil {
					t.Fatalf("GetAccessTier: %v", err)
				}
				return tier == db.TierNone
			},
		},
	}
}

// runCanaryCase seeds the target account with a session and the client tier,
// calls the tool against it and returns the result, the target's uid and the
// uid the audit row is written under. pool=false leaves Server.Pool nil, so a
// refusal that is not short-circuited before the pool panics.
func runCanaryCase(t *testing.T, c canaryCase, targetTGID int64, confirm, pool bool) (res *mcplib.CallToolResult, store *db.Store, targetUID, callerUID int64) {
	t.Helper()
	ctx := context.Background()
	store = newToolsTestStore(t)
	targetUID = seedAccountWithSession(t, store, targetTGID, false)
	if err := store.SetAccessTier(ctx, targetTGID, db.TierClient); err != nil {
		t.Fatalf("SetAccessTier: %v", err)
	}
	srv := &Server{Store: store}
	srv.WithCanaryGuard(canaryTestSet(t))
	if pool {
		srv.Pool = telegram.NewClientPool(0, "", 0, store)
	}
	args := map[string]any{}
	for k, v := range c.args {
		args[k] = v
	}
	var id *auth.Identity
	if c.self {
		id = &auth.Identity{UserID: targetUID, TelegramID: targetTGID, Scopes: []string{"account:manage"}}
	} else {
		adminUID, err := store.EnsureUserByTelegramID(ctx, canaryDanaTGID, "dana", "Dana")
		if err != nil {
			t.Fatalf("EnsureUserByTelegramID: %v", err)
		}
		id = &auth.Identity{UserID: adminUID, TelegramID: canaryDanaTGID, Scopes: []string{"admin:users"}}
		args["telegram_id"] = float64(targetTGID)
	}
	if confirm {
		args["confirm_canary"] = true
	}
	res, err := c.handler(srv)(auth.With(ctx, id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: c.tool, Arguments: args}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return res, store, targetUID, id.UserID
}

func TestCanaryGuard_RefusesUnconfirmed(t *testing.T) {
	for _, c := range canaryCases() {
		t.Run(c.tool, func(t *testing.T) {
			res, store, targetUID, callerUID := runCanaryCase(t, c, canaryAliceTGID, false, false)
			if !res.IsError {
				t.Fatal("an unconfirmed call on the canary account must be refused")
			}
			if got := contentText(res); !strings.Contains(got, "monitoring canary") || !strings.Contains(got, "confirm_canary") {
				t.Fatalf("refusal must name the canary and the confirmation, got %q", got)
			}
			if c.ended(t, store, targetUID, canaryAliceTGID) {
				t.Fatal("a refused call must leave the canary account intact")
			}
			tool, status, msg := latestAudit(t, store, callerUID)
			if tool != c.tool || status != "error" || !strings.Contains(msg, "monitoring canary") {
				t.Fatalf("refusal not audited: tool=%q status=%q msg=%q", tool, status, msg)
			}
			if r := latestAuditReason(t, store, callerUID); r != ReasonRefused {
				t.Fatalf("refusal reason = %q, want %q", r, ReasonRefused)
			}
		})
	}
}

func TestCanaryGuard_ConfirmedOverrideIsAudited(t *testing.T) {
	for _, c := range canaryCases() {
		t.Run(c.tool, func(t *testing.T) {
			res, store, targetUID, callerUID := runCanaryCase(t, c, canaryAliceTGID, true, true)
			if res.IsError {
				t.Fatalf("a confirmed call must proceed, got %s", contentText(res))
			}
			if !c.ended(t, store, targetUID, canaryAliceTGID) {
				t.Fatal("a confirmed call must end the canary account's session")
			}
			tool, status, _ := latestAudit(t, store, callerUID)
			if tool != c.tool+canaryguard.OverrideSuffix || status != "ok" {
				t.Fatalf("override not audited: tool=%q status=%q", tool, status)
			}
		})
	}
}

func TestCanaryGuard_OtherAccountsAreNotGated(t *testing.T) {
	for _, c := range canaryCases() {
		t.Run(c.tool, func(t *testing.T) {
			res, store, targetUID, callerUID := runCanaryCase(t, c, canaryBobTGID, false, true)
			if res.IsError {
				t.Fatalf("an ordinary account must not need confirm_canary, got %s", contentText(res))
			}
			if !c.ended(t, store, targetUID, canaryBobTGID) {
				t.Fatal("the call must end the ordinary account's session")
			}
			if tool, _, _ := latestAudit(t, store, callerUID); tool != c.tool {
				t.Fatalf("audited tool = %q, want %q", tool, c.tool)
			}
		})
	}
}

// Granting the canary access cannot break it, so set_telegram_access with
// tier "client" is not gated.
func TestCanaryGuard_GrantingAccessIsNotGated(t *testing.T) {
	ctx := context.Background()
	store := newToolsTestStore(t)
	seedAccountWithSession(t, store, canaryAliceTGID, false)
	adminUID, err := store.EnsureUserByTelegramID(ctx, canaryDanaTGID, "dana", "Dana")
	if err != nil {
		t.Fatalf("EnsureUserByTelegramID: %v", err)
	}
	srv := (&Server{Store: store}).WithCanaryGuard(canaryTestSet(t))
	id := &auth.Identity{UserID: adminUID, TelegramID: canaryDanaTGID, Scopes: []string{"admin:users"}}
	_, h := srv.toolSetAccess()
	res, err := h(auth.With(ctx, id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{
		Name:      "set_telegram_access",
		Arguments: map[string]any{"telegram_id": float64(canaryAliceTGID), "tier": db.TierClient},
	}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if res.IsError {
		t.Fatalf("granting the canary access must not be gated, got %s", contentText(res))
	}
	if tier, _ := store.GetAccessTier(ctx, canaryAliceTGID); tier != db.TierClient {
		t.Fatalf("tier = %q, want %q", tier, db.TierClient)
	}
}
