package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

const (
	bcIssuer   = "https://tg.mctl.ai"
	bcConnect  = "mctl_self_connect"
	bcOperator = int64(777000111)
	bcClient   = int64(777000222)
)

type bcEnv struct {
	t       *testing.T
	store   *db.Store
	svc     *broadcast.Service
	srv     *BroadcastServer
	opUID   int64
	policy  broadcast.Policy
	clients []int64
}

func newBroadcastEnv(t *testing.T) *bcEnv {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := db.NewStore(conn, nil)
	e := &bcEnv{t: t, store: store, policy: broadcast.Policy{AdminTelegramIDs: map[int64]bool{bcOperator: true}}}
	e.opUID = e.user(bcOperator, "")
	e.clients = append(e.clients, e.user(bcClient, db.TierClient))
	e.svc = broadcast.NewService(store, broadcast.Config{
		Operators: map[int64]bool{bcOperator: true},
		Policy:    e.policy,
	}, nil)
	e.srv = NewBroadcastServer(store, e.svc, bcIssuer, bcConnect)
	return e
}

func (e *bcEnv) user(tg int64, tier string) int64 {
	e.t.Helper()
	ctx := context.Background()
	uid, err := e.store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{
		TelegramID: tg, Username: "u", FirstName: "U", Source: "telegram_oidc", CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		e.t.Fatalf("capture: %v", err)
	}
	if tier != "" {
		if err := e.store.SetAccessTier(ctx, tg, tier); err != nil {
			e.t.Fatalf("tier: %v", err)
		}
	}
	return uid
}

// prepared stands in for prepare_broadcast over MCP: the service call the
// tool makes, with an MCP-client surface.
func (e *bcEnv) prepared(text string) *broadcast.Preview {
	e.t.Helper()
	p, err := e.svc.Prepare(context.Background(), broadcast.Actor{UserID: e.opUID, TelegramID: bcOperator, Surface: "mcp:tgmcp_claude"},
		broadcast.PrepareRequest{Selector: broadcast.Selector{Category: "maintenance"}, Text: text})
	if err != nil {
		e.t.Fatalf("prepare: %v", err)
	}
	return p
}

// connectIdentity is what the browser's mctl_connect_token cookie
// authenticates as after the Telegram login.
func (e *bcEnv) connectIdentity() *auth.Identity {
	return &auth.Identity{UserID: e.opUID, TelegramID: bcOperator, ClientID: bcConnect, Scopes: []string{"admin:broadcast"}}
}

func (e *bcEnv) approve(id *auth.Identity, p *broadcast.Preview, origin string, mutate ...func(url.Values)) *httptest.ResponseRecorder {
	e.t.Helper()
	form := url.Values{"campaign_id": {p.CampaignID}, "content_hash": {p.ContentHash}, "selector_hash": {p.SelectorHash}}
	for _, m := range mutate {
		m(form)
	}
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/broadcasts/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if id != nil {
		req = req.WithContext(auth.With(req.Context(), id))
	}
	w := httptest.NewRecorder()
	e.srv.HandleApprove(w, req)
	return w
}

func (e *bcEnv) state(id string) string {
	e.t.Helper()
	c, err := e.store.GetBroadcastCampaign(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return c.State
}

func TestBroadcastPage_ConnectOperatorApproves(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Maintenance tonight.")

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
	req = req.WithContext(auth.With(req.Context(), e.connectIdentity()))
	w := httptest.NewRecorder()
	e.srv.HandleList(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Maintenance tonight.") || !strings.Contains(w.Body.String(), p.ContentHash) {
		t.Fatalf("page = %d, text/hash not rendered:\n%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "<script") {
		t.Fatal("the approval page must not carry script")
	}

	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d %s", w.Code, w.Body.String())
	}
	if got := e.state(p.CampaignID); got != db.CampaignApproved {
		t.Fatalf("state = %s", got)
	}
}

// TestBroadcastPage_MCPCredentialCannotApprove is the confirmation
// boundary of issue-439: an assistant holding an MCP token -- even an admin
// operator's, with admin:broadcast, presented as the connect cookie -- cannot
// approve the campaign it prepared.
func TestBroadcastPage_MCPCredentialCannotApprove(t *testing.T) {
	cases := []struct {
		name   string
		id     func(e *bcEnv) *auth.Identity
		origin string
	}{
		{"mcp client token", func(e *bcEnv) *auth.Identity {
			id := e.connectIdentity()
			id.ClientID = "tgmcp_0123456789abcdef"
			return id
		}, bcIssuer},
		{"token without client_id (worker/bridge/pre-claim)", func(e *bcEnv) *auth.Identity {
			id := e.connectIdentity()
			id.ClientID = ""
			return id
		}, bcIssuer},
		{"no admin:broadcast scope", func(e *bcEnv) *auth.Identity {
			id := e.connectIdentity()
			id.Scopes = []string{"admin:users", "account:manage"}
			return id
		}, bcIssuer},
		{"scope but not an operator", func(e *bcEnv) *auth.Identity {
			id := e.connectIdentity()
			id.TelegramID = bcClient
			return id
		}, bcIssuer},
		{"cross-origin post", func(e *bcEnv) *auth.Identity { return e.connectIdentity() }, "https://evil.example"},
		{"origin-less post", func(e *bcEnv) *auth.Identity { return e.connectIdentity() }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newBroadcastEnv(t)
			p := e.prepared("Hello.")
			if w := e.approve(tc.id(e), p, tc.origin); w.Code != http.StatusForbidden {
				t.Fatalf("approve = %d, want 403", w.Code)
			}
			if got := e.state(p.CampaignID); got != db.CampaignPrepared {
				t.Fatalf("state = %s after a refused approval", got)
			}
			var n int
			if err := e.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs WHERE tool_name = 'broadcast_approve_web' AND status = 'error'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("refusal audit rows = %d %v", n, err)
			}
		})
	}
	t.Run("anonymous", func(t *testing.T) {
		e := newBroadcastEnv(t)
		p := e.prepared("Hello.")
		if w := e.approve(nil, p, bcIssuer); w.Code != http.StatusUnauthorized {
			t.Fatalf("approve = %d, want 401", w.Code)
		}
	})
}

func TestBroadcastPage_ApprovalBoundToRenderedHashes(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Hello.")
	w := e.approve(e.connectIdentity(), p, bcIssuer, func(f url.Values) { f.Set("content_hash", broadcast.Hash("Other text.")) })
	if w.Code != http.StatusConflict || e.state(p.CampaignID) != db.CampaignPrepared {
		t.Fatalf("drifted approval = %d, state %s", w.Code, e.state(p.CampaignID))
	}
	// Single use: a second approval of an approved campaign is refused.
	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d", w.Code)
	}
	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code != http.StatusConflict {
		t.Fatalf("replayed approve = %d, want 409", w.Code)
	}
}

type recordingSender struct {
	mu   sync.Mutex
	sent map[int64]string
}

func (r *recordingSender) SendMessage(_ context.Context, chatID int64, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent[chatID] = text
	return nil
}

// TestBroadcast_EndToEnd walks the whole path: prepared by an assistant,
// nothing sent; approved by the operator on the page; delivered by the
// worker exactly to the eligible client, with the approved text.
func TestBroadcast_EndToEnd(t *testing.T) {
	e := newBroadcastEnv(t)
	sender := &recordingSender{sent: map[int64]string{}}
	worker := broadcast.NewWorker(e.store, sender, broadcast.WorkerConfig{Policy: e.policy, RatePerSecond: 1000}, nil)
	p := e.prepared("Maintenance tonight.")

	if err := worker.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 0 {
		t.Fatal("a prepared (unapproved) campaign was delivered")
	}
	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d", w.Code)
	}
	if err := worker.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.sent) != 1 || sender.sent[bcClient] != "Maintenance tonight." {
		t.Fatalf("sent = %v", sender.sent)
	}
	if got := e.state(p.CampaignID); got != db.CampaignCompleted {
		t.Fatalf("state = %s", got)
	}
}
