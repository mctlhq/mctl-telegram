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

// draftFake records what save_draft asked Telegram for.
type draftFake struct {
	calls     int
	peer      string
	text      string
	overwrite bool
	result    telegram.DraftResult
	err       error
}

func (f *draftFake) save(_ context.Context, _ int64, peer, text string, overwrite bool) (telegram.DraftResult, error) {
	f.calls++
	f.peer, f.text, f.overwrite = peer, text, overwrite
	return f.result, f.err
}

// draftServer is a server whose account has never opted into real sends:
// send_enabled=false, the state save_draft must work in (#1175).
func draftServer(t *testing.T) (*Server, *draftFake, *auth.Identity) {
	t.Helper()
	store := newToolsTestStore(t)
	uid := seedAccountWithSession(t, store, 424250, false)
	fake := &draftFake{result: telegram.DraftResult{Ref: "user:7120"}}
	s := &Server{Store: store, AllowSend: true, Limiter: audit.NewRateLimiter(1000), draftSave: fake.save}
	id := &auth.Identity{UserID: uid, Subject: "tg:424250", Scopes: []string{"telegram:messages:send"}}
	return s, fake, id
}

func callSaveDraft(t *testing.T, s *Server, id *auth.Identity, args map[string]any) *mcplib.CallToolResult {
	t.Helper()
	_, h := s.toolSaveDraft()
	res, err := h(auth.With(context.Background(), id), mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "save_draft", Arguments: args}})
	if err != nil {
		t.Fatalf("save_draft: unexpected Go error: %v", err)
	}
	return res
}

// The owner decision on #1175: a draft delivers nothing, so it does not
// need send_enabled.
func TestSaveDraft_WorksWithoutSendEnabled(t *testing.T) {
	s, fake, id := draftServer(t)
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
	if res.IsError {
		t.Fatalf("save_draft on a read-only account was refused: %s", contentText(res))
	}
	if fake.calls != 1 || fake.peer != "user:7120" || fake.text != "Hi Bob" || fake.overwrite {
		t.Fatalf("Telegram call = %+v", fake)
	}
	if !strings.Contains(contentText(res), `"saved": true`) {
		t.Errorf("result does not say saved: %s", contentText(res))
	}
	rows, err := s.Store.ListAuditFor(context.Background(), id.UserID, 10, time.Time{})
	if err != nil || len(rows) == 0 || rows[0].ToolName != "save_draft" || rows[0].Status != "ok" {
		t.Fatalf("audit = %+v, %v; want a save_draft ok row", rows, err)
	}
}

// Every other condition of the gate still applies.
func TestSaveDraft_GateStillApplies(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(s *Server, id *auth.Identity)
		want   string
	}{
		{"kill switch", func(s *Server, _ *auth.Identity) { s.AllowSend = false }, "ALLOW_SEND=false"},
		{"scope", func(_ *Server, id *auth.Identity) { id.Scopes = []string{"telegram:messages:read"} }, "identity missing telegram:messages:send scope"},
		{"reviewer", func(s *Server, id *auth.Identity) {
			id.TelegramID = reviewerTestTGID
			s.DemoReviewerTGID = reviewerTestTGID
		}, reasonReviewerWriteRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, fake, id := draftServer(t)
			c.mutate(s, id)
			res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
			if !res.IsError || !strings.Contains(contentText(res), c.want) {
				t.Fatalf("got isError=%v %q, want an error naming %q", res.IsError, contentText(res), c.want)
			}
			if fake.calls != 0 {
				t.Fatal("Telegram was called despite the gate")
			}
		})
	}
}

// A draft the user typed is refused, nothing is written, and the refusal
// tells the model how to proceed; overwrite is passed through only when
// asked for.
func TestSaveDraft_ExistingDraftIsRefused(t *testing.T) {
	s, fake, id := draftServer(t)
	fake.err = &telegram.DraftConflict{ExistingUnits: 17}
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob"})
	if !res.IsError || !strings.Contains(contentText(res), "17 UTF-16 units") || !strings.Contains(contentText(res), "overwrite=true") {
		t.Fatalf("conflict result = %q", contentText(res))
	}
	if got := classifyToolResultReason(res); got != ReasonRefused {
		t.Errorf("reason = %q, want %q", got, ReasonRefused)
	}
	rows, _ := s.Store.ListAuditFor(context.Background(), id.UserID, 10, time.Time{})
	if len(rows) == 0 || rows[0].ToolName != "save_draft:draft_exists" || rows[0].Status != "error" {
		t.Fatalf("audit = %+v, want a save_draft:draft_exists error row", rows)
	}

	fake.err = nil
	fake.result.ReplacedExisting = true
	res = callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "Hi Bob", "overwrite": true})
	if res.IsError || !fake.overwrite || !strings.Contains(contentText(res), `"replaced_existing": true`) {
		t.Fatalf("overwrite=true: isError=%v overwrite=%v %s", res.IsError, fake.overwrite, contentText(res))
	}
}

// Drafts spend their own budget: a spent send budget does not stop them,
// and a spent draft budget does.
func TestSaveDraft_OwnPerPeerBudget(t *testing.T) {
	s, fake, id := draftServer(t)
	key := telegram.PeerLimitKey("user:7120")
	if !s.Limiter.AllowPeerN(id, key, audit.PeerSendCap, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("could not drain the send budget")
	}
	if res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "a"}); res.IsError {
		t.Fatalf("a spent send budget refused a draft: %s", contentText(res))
	}
	if !s.Limiter.AllowPeerN(id, draftLimiterPrefix+key, audit.PeerSendCap-1, audit.PeerSendCap, audit.PeerWindow) {
		t.Fatal("could not drain the draft budget")
	}
	calls := fake.calls
	res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "b"})
	if !res.IsError || !strings.Contains(contentText(res), "draft rate limit reached") || fake.calls != calls {
		t.Fatalf("spent draft budget: isError=%v calls=%d->%d %s", res.IsError, calls, fake.calls, contentText(res))
	}
}

func TestSaveDraft_ArgumentChecks(t *testing.T) {
	s, fake, id := draftServer(t)
	for _, args := range []map[string]any{
		{"text": "hi"},
		{"peer": "user:7120", "text": strings.Repeat("a", maxReplyText+1)},
	} {
		if res := callSaveDraft(t, s, id, args); !res.IsError {
			t.Errorf("%v: accepted", args)
		}
	}
	if fake.calls != 0 {
		t.Fatal("Telegram was called for an invalid argument")
	}
	// A blank text clears the draft rather than saving whitespace.
	fake.result.Cleared = true
	if res := callSaveDraft(t, s, id, map[string]any{"peer": "user:7120", "text": "  "}); res.IsError || fake.text != "" {
		t.Fatalf("blank text: isError=%v text=%q %s", res.IsError, fake.text, contentText(res))
	}
}
