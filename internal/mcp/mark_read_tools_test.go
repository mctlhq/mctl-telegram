package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/audit"
	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type readFake struct {
	calls int
	peer  string
	maxID int
}

func (f *readFake) mark(_ context.Context, _ int64, peer string, maxID int) error {
	f.calls++
	f.peer, f.maxID = peer, maxID
	return nil
}

func markReadServer(t *testing.T, sendEnabled bool) (*Server, *readFake, *auth.Identity) {
	t.Helper()
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424251, sendEnabled)
	fake := &readFake{}
	s := &Server{Store: store, AllowSend: true, Limiter: audit.NewRateLimiter(1000), readMark: fake.mark}
	id := &auth.Identity{UserID: uid, Subject: "tg:424251", Scopes: []string{"telegram:messages:send"}}
	return s, fake, id
}

func callMarkRead(t *testing.T, s *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, h := s.toolMarkRead()
	res, err := h(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "mark_read", Arguments: args}})
	if err != nil {
		t.Fatalf("mark_read: unexpected Go error: %v", err)
	}
	return res
}

func TestMarkRead_MarksUpToMaxID(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	res := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41)})
	if res.IsError || fake.calls != 1 || fake.peer != "user:7120" || fake.maxID != 41 {
		t.Fatalf("isError=%v call=%+v %s", res.IsError, fake, contentText(res))
	}
	rows, err := s.Store.ListAuditFor(context.Background(), id.UserID, 10, time.Time{})
	if err != nil || len(rows) == 0 || rows[0].ToolName != "mark_read" || rows[0].Status != "ok" {
		t.Fatalf("audit = %+v, %v; want a mark_read ok row", rows, err)
	}
}

// The owner decision on #1175: a read receipt is visible to the other side,
// so mark_read needs the full send gate, send_enabled included, and a
// closed gate is an error, never a preview.
func TestMarkRead_NeedsTheFullSendGate(t *testing.T) {
	t.Run("send_enabled", func(t *testing.T) {
		s, fake, id := markReadServer(t, false)
		res := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41)})
		if !res.IsError || !strings.HasPrefix(contentText(res), "mark_read blocked: "+reasonSendDisabled) || fake.calls != 0 {
			t.Fatalf("isError=%v calls=%d %s", res.IsError, fake.calls, contentText(res))
		}
	})
	t.Run("kill switch", func(t *testing.T) {
		s, fake, id := markReadServer(t, true)
		s.AllowSend = false
		if res := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(41)}); !res.IsError || fake.calls != 0 {
			t.Fatalf("isError=%v calls=%d", res.IsError, fake.calls)
		}
	})
}

// mark_read spends its own per-chat budget: a spent send budget does not
// stop it, a spent read budget does.
func TestMarkRead_OwnPerPeerBudget(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	key := telegram.PeerLimitKey("user:7120")
	if !s.Limiter.AllowPeerN(id, key, audit.PeerSendCap, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("could not drain the send budget")
	}
	if res := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(1)}); res.IsError {
		t.Fatalf("a spent send budget refused mark_read: %s", contentText(res))
	}
	if !s.Limiter.AllowPeerN(id, readLimiterPrefix+key, audit.PeerSendCap-1, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("could not drain the read budget")
	}
	calls := fake.calls
	res := callMarkRead(t, s, id, map[string]any{"peer": "user:7120", "max_id": float64(2)})
	if !res.IsError || !strings.Contains(contentText(res), "mark_read rate limit reached") || fake.calls != calls {
		t.Fatalf("spent read budget: isError=%v %s", res.IsError, contentText(res))
	}
}

func TestMarkRead_NeedsPositiveMaxID(t *testing.T) {
	s, fake, id := markReadServer(t, true)
	for _, args := range []map[string]any{
		{"peer": "user:7120"},
		{"peer": "user:7120", "max_id": float64(0)},
		{"peer": "user:7120", "max_id": float64(-3)},
		{"peer": "user:7120", "max_id": float64(1<<32 + 41)},
		{"peer": "user:7120", "max_id": float64(1 << 31)},
		{"peer": "user:7120", "max_id": 41.5},
		{"peer": "user:7120", "max_id": "41"},
		{"max_id": float64(3)},
	} {
		if res := callMarkRead(t, s, id, args); !res.IsError {
			t.Errorf("%v: accepted", args)
		}
	}
	if fake.calls != 0 {
		t.Fatal("Telegram was called for an invalid argument")
	}
}
