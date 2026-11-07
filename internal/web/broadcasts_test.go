package web

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/productupdate"
	"github.com/mctlhq/mctl-telegram/internal/ui"
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
	conn    *sql.DB
	svc     *broadcast.Service
	srv     *BroadcastServer
	opUID   int64
	policy  broadcast.Policy
	clients []int64
}

func newBroadcastEnv(t *testing.T, mutate ...func(*DigestSource)) *bcEnv {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+strings.ReplaceAll(t.Name(), "/", "_")+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := db.NewStore(conn, nil)
	e := &bcEnv{t: t, store: store, conn: conn, policy: broadcast.Policy{AdminTelegramIDs: map[int64]bool{bcOperator: true}}}
	e.opUID = e.user(bcOperator, "")
	e.clients = append(e.clients, e.user(bcClient, db.TierClient))
	e.svc = broadcast.NewService(store, broadcast.Config{
		Operators: map[int64]bool{bcOperator: true},
		Policy:    e.policy,
	}, nil)
	var digests DigestSource
	for _, m := range mutate {
		m(&digests)
	}
	e.srv = NewBroadcastServer(store, e.svc, bcIssuer, bcConnect, digests)
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

func (e *bcEnv) prepareDigest(id *auth.Identity, origin string, form url.Values) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/broadcasts/prepare-digest", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if id != nil {
		req = req.WithContext(auth.With(req.Context(), id))
	}
	w := httptest.NewRecorder()
	e.srv.HandlePrepareDigest(w, req)
	return w
}

// maintenanceDigestEntry is a valid approved product-update feed entry in
// the "maintenance" category (opt-out, so the existing bcClient fixture is
// already an eligible recipient) -- a links-only notice, since maintenance
// needs no tool-diff evidence.
func maintenanceDigestEntry(id string) productupdate.Entry {
	return productupdate.Entry{
		Schema: productupdate.EntrySchema, ID: id, Kind: productupdate.KindMaintenance,
		Title: "Scheduled maintenance", Summary: "The service will be briefly unavailable tonight.",
		Locale: "en", Delivery: productupdate.DeliveryNextDigest,
		Evidence:   productupdate.Evidence{Links: []string{"https://example.com/maint"}},
		Status:     productupdate.StatusApproved,
		Provenance: productupdate.Provenance{Author: "alice", ReviewedBy: "alice"},
		CreatedAt:  "2026-09-24", ReviewedAt: "2026-09-24",
	}
}

// securityDigestEntry is the same shape in the "security" category, so a
// test can prepare a digest campaign in parallel with a manual maintenance
// one without tripping the one-campaign-per-category guard.
func securityDigestEntry(id string) productupdate.Entry {
	e := maintenanceDigestEntry(id)
	e.Kind = productupdate.KindSecurity
	e.Evidence.Links = []string{"https://example.com/sec"}
	return e
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
	// The operator sees through which MCP client the campaign was prepared.
	if !strings.Contains(w.Body.String(), "mcp:tgmcp_claude") {
		t.Fatal("the page does not show the preparing surface")
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
	// A refused page VIEW is logged, not audited: any signed-in user can
	// load the URL, and each reload would otherwise add a row.
	t.Run("page view refusal is not audited", func(t *testing.T) {
		e := newBroadcastEnv(t)
		id := e.connectIdentity()
		id.ClientID = "tgmcp_0123456789abcdef"
		req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
		req = req.WithContext(auth.With(req.Context(), id))
		w := httptest.NewRecorder()
		e.srv.HandleList(w, req)
		var n int
		if err := e.store.DB.QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&n); w.Code != http.StatusForbidden || err != nil || n != 0 {
			t.Fatalf("refused GET = %d, audit rows %d %v", w.Code, n, err)
		}
	})
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

func (r *recordingSender) SendHTMLMessage(ctx context.Context, chatID int64, text string) error {
	return r.SendMessage(ctx, chatID, text)
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

func TestBroadcastPage_OperatorCancels(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Hello.")
	form := url.Values{"campaign_id": {p.CampaignID}}
	post := func(id *auth.Identity) int {
		req := httptest.NewRequest(http.MethodPost, "/telegram/connect/broadcasts/cancel", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", bcIssuer)
		req = req.WithContext(auth.With(req.Context(), id))
		w := httptest.NewRecorder()
		e.srv.HandleCancel(w, req)
		return w.Code
	}
	mcp := e.connectIdentity()
	mcp.ClientID = "tgmcp_0123456789abcdef"
	if code := post(mcp); code != http.StatusForbidden || e.state(p.CampaignID) != db.CampaignPrepared {
		t.Fatalf("mcp-token cancel = %d, state %s", code, e.state(p.CampaignID))
	}
	if code := post(e.connectIdentity()); code != http.StatusSeeOther || e.state(p.CampaignID) != db.CampaignCancelled {
		t.Fatalf("cancel = %d, state %s", code, e.state(p.CampaignID))
	}
}

// A live campaign's Stop button must stay on the page however many newer
// campaigns have finished since.
func TestBroadcastPage_LiveCampaignNeverPushedOffByFinishedOnes(t *testing.T) {
	e := newBroadcastEnv(t)
	live := e.prepared("Live one.")
	if w := e.approve(e.connectIdentity(), live, bcIssuer); w.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d", w.Code)
	}
	op := broadcast.Actor{UserID: e.opUID, TelegramID: bcOperator, Surface: "web"}
	for i := 0; i < 25; i++ {
		p := e.prepared("Finished one.")
		if err := e.svc.Cancel(context.Background(), op, p.CampaignID); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
	req = req.WithContext(auth.With(req.Context(), e.connectIdentity()))
	w := httptest.NewRecorder()
	e.srv.HandleList(w, req)
	if !strings.Contains(w.Body.String(), live.CampaignID) {
		t.Fatal("the approved campaign (and its Cancel button) fell off the page")
	}
}

// TestBroadcastPage_PrepareFromDigest_EndToEnd is T5 (amended): the flow is
// exercised end to end through HandlePrepareDigest on a seeded feed. It
// freezes, persists, prepares one campaign with source_ref, and sends
// nothing.
func TestBroadcastPage_PrepareFromDigest_EndToEnd(t *testing.T) {
	entry := maintenanceDigestEntry("maint-note")
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })

	form := url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}}
	w := e.prepareDigest(e.connectIdentity(), bcIssuer, form)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("prepare-digest = %d %s", w.Code, w.Body.String())
	}

	ctx := context.Background()
	list, err := e.store.ListBroadcastCampaigns(ctx, 10, db.CampaignPrepared)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("prepared campaigns = %d, want 1", len(list))
	}
	c := list[0]
	if c.SourceRef == nil || c.SourceRef.DigestID != "maint-2026-w39" || c.SourceRef.DigestVersion != 1 {
		t.Fatalf("source_ref = %+v", c.SourceRef)
	}
	if !strings.Contains(c.Content, entry.Title) || !strings.Contains(c.Content, entry.Summary) {
		t.Fatalf("content does not carry the reviewed entry text: %q", c.Content)
	}
	stored, err := e.store.GetProductUpdateDigest(ctx, "maint-2026-w39", 1)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ContentHash != c.SourceRef.ContentHash {
		t.Fatalf("stored digest content hash %q != campaign source_ref hash %q", stored.ContentHash, c.SourceRef.ContentHash)
	}
	// Nothing sent: still prepared, awaiting the separate approval action.
	if c.State != db.CampaignPrepared {
		t.Fatalf("state = %s, want prepared", c.State)
	}
}

// TestBroadcastPage_PrepareFromDigest_Refusals is T6 (amended): the page
// action refuses each of the following as approve/cancel do -- a missing
// admin:broadcast scope, a non-operator, a cross-origin POST, a text field,
// a category with no entries of its own, and a second non-terminal campaign
// in the same category.
func TestBroadcastPage_PrepareFromDigest_Refusals(t *testing.T) {
	entry := maintenanceDigestEntry("maint-note")
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	env := func(t *testing.T) *bcEnv {
		return newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })
	}
	baseForm := func() url.Values {
		return url.Values{"category": {"maintenance"}, "digest_id": {"maint-2026-w39"}, "version": {"1"}}
	}

	t.Run("missing admin:broadcast scope", func(t *testing.T) {
		e := env(t)
		id := e.connectIdentity()
		id.Scopes = nil
		if w := e.prepareDigest(id, bcIssuer, baseForm()); w.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", w.Code)
		}
	})
	t.Run("non-operator", func(t *testing.T) {
		e := env(t)
		id := e.connectIdentity()
		id.TelegramID = bcClient
		if w := e.prepareDigest(id, bcIssuer, baseForm()); w.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", w.Code)
		}
	})
	t.Run("cross-origin POST", func(t *testing.T) {
		e := env(t)
		if w := e.prepareDigest(e.connectIdentity(), "https://evil.example", baseForm()); w.Code != http.StatusForbidden {
			t.Fatalf("code = %d, want 403", w.Code)
		}
	})
	t.Run("text field is refused", func(t *testing.T) {
		e := env(t)
		f := baseForm()
		f.Set("text", "hand-written body")
		w := e.prepareDigest(e.connectIdentity(), bcIssuer, f)
		if w.Code != http.StatusConflict {
			t.Fatalf("code = %d %s, want 409", w.Code, w.Body.String())
		}
	})
	// A category that disagrees with the feed's entries cannot freeze them:
	// DigestCandidates offers only entries of the requested category, so the
	// reachable refusal is "has no entries" (a digest's category is its
	// request's by construction; there is no separate mismatch to hit).
	t.Run("a category with no entries of its own freezes nothing", func(t *testing.T) {
		e := env(t)
		f := baseForm()
		f.Set("category", "security") // the seeded entry is "maintenance"
		w := e.prepareDigest(e.connectIdentity(), bcIssuer, f)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "has no entries") {
			t.Fatalf("code = %d %s, want 409 \"has no entries\"", w.Code, w.Body.String())
		}
		assertDigestNotStored(t, e, "maint-2026-w39", 1, entry.ID)
	})
	t.Run("a second non-terminal campaign in the same category is refused", func(t *testing.T) {
		e := env(t)
		if w := e.prepareDigest(e.connectIdentity(), bcIssuer, baseForm()); w.Code != http.StatusSeeOther {
			t.Fatalf("first prepare = %d %s", w.Code, w.Body.String())
		}
		f := baseForm()
		f.Set("digest_id", "maint-2026-w40")
		w := e.prepareDigest(e.connectIdentity(), bcIssuer, f)
		if w.Code != http.StatusConflict {
			t.Fatalf("second prepare = %d %s, want 409", w.Code, w.Body.String())
		}
		list, err := e.store.ListBroadcastCampaigns(context.Background(), 10, db.CampaignPrepared)
		if err != nil {
			t.Fatal(err)
		}
		if len(list) != 1 {
			t.Fatalf("prepared campaigns = %d, want 1 (the second must not have been created)", len(list))
		}
	})
}

// TestBroadcastPage_ListShowsSourceRefForDigestCampaignOnly is T10: the
// broadcast page shows the digest id, version and content hash for a sourced
// campaign and nothing extra for a manual one.
func TestBroadcastPage_ListShowsSourceRefForDigestCampaignOnly(t *testing.T) {
	entry := securityDigestEntry("sec-note") // a different category than e.prepared's "maintenance"
	feed := productupdate.Feed{Entries: []productupdate.Entry{entry}}
	e := newBroadcastEnv(t, func(d *DigestSource) { *d = DigestSource{Feed: feed, LatestRelease: "0.70.0"} })

	manual := e.prepared("Manual campaign text.")
	form := url.Values{"category": {"security"}, "digest_id": {"sec-2026-w39"}, "version": {"1"}}
	if w := e.prepareDigest(e.connectIdentity(), bcIssuer, form); w.Code != http.StatusSeeOther {
		t.Fatalf("prepare-digest = %d %s", w.Code, w.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
	req = req.WithContext(auth.With(req.Context(), e.connectIdentity()))
	w := httptest.NewRecorder()
	e.srv.HandleList(w, req)
	body := w.Body.String()
	if !strings.Contains(body, "sec-2026-w39 v1 sha256:") {
		t.Fatalf("page does not show the source digest for the sourced campaign:\n%s", body)
	}
	// The manual campaign's block must carry no "Source digest" line. Count
	// occurrences: exactly one (the digest campaign's), not two.
	if n := strings.Count(body, "Source digest"); n != 1 {
		t.Fatalf(`"Source digest" appears %d times, want 1 (manual campaign %s must not show one)`, n, manual.CampaignID)
	}
}

func (e *bcEnv) listBody() string {
	req := httptest.NewRequest(http.MethodGet, "/telegram/connect/broadcasts", nil)
	req = req.WithContext(auth.With(req.Context(), e.connectIdentity()))
	w := httptest.NewRecorder()
	e.srv.HandleList(w, req)
	return w.Body.String()
}

// The pending block leads with a plain-language audience and result, and the
// raw selector, preview counts and both hashes stay inspectable inside a
// collapsed details block. The hashes the Approve form carries are unchanged.
func TestBroadcastPage_PlainLanguageWithTechnicalDetails(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Plain language check.")
	body := e.listBody()

	for _, want := range []string{
		"<strong>Audience:</strong> Maintenance notices for clients.",
		"<strong>Result:</strong>",
		"<details><summary>Technical details</summary>",
		"Content hash <code>" + p.ContentHash,
		"Selector hash <code>" + p.SelectorHash,
		`name="content_hash" value="` + p.ContentHash + `"`,
		`name="selector_hash" value="` + p.SelectorHash + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
	// Raw JSON is not the headline: it appears only after the details opener.
	if i, j := strings.Index(body, `{&#34;category&#34;`), strings.Index(body, "<summary>Technical details"); i < 0 || j < 0 || i < j {
		t.Errorf("raw selector JSON must sit inside the technical details block (json at %d, details at %d)", i, j)
	}
}

// An unreadable stored selector or preview is reported as unreadable, never
// as an empty audience or zero recipients.
func TestBroadcastPage_UnreadableStoredJSONIsNotShownAsZero(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Corrupt row check.")
	if _, err := e.conn.ExecContext(context.Background(),
		`UPDATE broadcast_campaigns SET selector_json = 'not json', preview_counts = 'not json' WHERE id = ?`, p.CampaignID); err != nil {
		t.Fatalf("corrupt row: %v", err)
	}
	body := e.listBody()
	if !strings.Contains(body, "Could not read the stored audience") || !strings.Contains(body, "Could not read the stored preview counts") {
		t.Fatalf("unreadable JSON must be reported as unreadable:\n%s", body)
	}
	if strings.Contains(body, "Nobody will receive it") || strings.Contains(body, "None skipped") {
		t.Fatalf("unreadable counts must not read as zero:\n%s", body)
	}
}

func TestBroadcastPage_DigestFormExplainsItself(t *testing.T) {
	body := newBroadcastEnv(t).listBody()
	for _, want := range []string{
		`class="bcform"`, "Empty means clients only.", "Only people seen in the last N days.",
		"Nothing is sent until you approve it there.",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

// Every custom property the broadcast page's own CSS reads must be defined by
// the shared UI stylesheet (or carry a fallback): an undefined var() voids the
// whole declaration and the control silently renders unstyled.
func TestBroadcastExtraCSS_UsesOnlyDefinedTokens(t *testing.T) {
	defined := ui.TokensCSS + ui.ComponentsCSS + ui.AuthCSS + manageExtraCSS
	re := regexp.MustCompile(`var\((--[a-z0-9-]+)(,[^)]*)?\)`)
	for _, m := range re.FindAllStringSubmatch(broadcastExtraCSS, -1) {
		if m[2] != "" {
			continue // has a fallback
		}
		if !strings.Contains(defined, m[1]+":") {
			t.Errorf("broadcastExtraCSS uses %s, which no shared stylesheet defines", m[1])
		}
	}
}

// preparedHTML stands in for prepare_broadcast with format=html.
func (e *bcEnv) preparedHTML(text string) *broadcast.Preview {
	e.t.Helper()
	p, err := e.svc.Prepare(context.Background(), broadcast.Actor{UserID: e.opUID, TelegramID: bcOperator, Surface: "mcp:tgmcp_claude"},
		broadcast.PrepareRequest{Selector: broadcast.Selector{Category: "maintenance"}, Text: text, Format: broadcast.FormatHTML})
	if err != nil {
		e.t.Fatalf("prepare html: %v", err)
	}
	return p
}

// An html campaign is shown the way recipients will see it, with every link
// target listed so the anchor text cannot hide where it goes, and the exact
// source kept under a details block.
func TestBroadcastPage_HTMLCampaignShowsRenderedMessageAndLinks(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.preparedHTML(`<b>Release</b> notes: <a href="https://example.com/notes?a=1&amp;b=2">read more</a>`)
	body := e.listBody()
	for _, want := range []string{
		`Format <strong>html</strong>`,
		`<div class="rendered"><b>Release</b> notes: <a href="https://example.com/notes?a=1&amp;b=2" rel="noopener noreferrer nofollow">read more</a></div>`,
		`<li><code>https://example.com/notes?a=1&amp;b=2</code></li>`,
		`<details><summary>Source HTML</summary>`,
		`name="content_hash" value="` + p.ContentHash + `"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
}

// Plain campaigns keep their old rendering: text in a pre block, no format
// banner, and markup-looking text is escaped, not rendered.
func TestBroadcastPage_PlainCampaignNeverRendersMarkup(t *testing.T) {
	e := newBroadcastEnv(t)
	e.prepared(`<b>not bold</b> <script>alert(1)</script>`)
	body := e.listBody()
	if strings.Contains(body, "<script>alert(1)</script>") || strings.Contains(body, `class="rendered"`) {
		t.Fatalf("plain text was rendered as markup:\n%s", body)
	}
	if !strings.Contains(body, "&lt;b&gt;not bold&lt;/b&gt;") {
		t.Fatalf("plain text not shown escaped:\n%s", body)
	}
}

// A row altered in the database to hold markup the validator would refuse is
// never rendered: the page says it cannot be parsed and shows the source
// escaped. The stored string never reaches the page as HTML.
func TestBroadcastPage_TamperedHTMLRowIsNotRendered(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.preparedHTML(`<b>fine</b>`)
	if _, err := e.conn.ExecContext(context.Background(),
		`UPDATE broadcast_campaigns SET content = ? WHERE id = ?`, `<script>alert(1)</script><b>x</b>`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	body := e.listBody()
	if strings.Contains(body, "<script>") {
		t.Fatalf("tampered content reached the page as markup:\n%s", body)
	}
	if !strings.Contains(body, "could not be parsed; do not approve") || strings.Contains(body, `class="rendered"`) {
		t.Fatalf("tampered row must be reported, not rendered:\n%s", body)
	}
}

func TestBroadcastPage_UnknownFormatIsNotShownAsPlain(t *testing.T) {
	e := newBroadcastEnv(t)
	p := e.prepared("Hello.")
	if _, err := e.conn.ExecContext(context.Background(),
		`UPDATE broadcast_campaigns SET content_format = 'markdownv2' WHERE id = ?`, p.CampaignID); err != nil {
		t.Fatal(err)
	}
	body := e.listBody()
	if !strings.Contains(body, "message format could not be read; do not approve") {
		t.Fatalf("unknown format must be reported:\n%s", body)
	}
	// The text may appear, but only inside the "Stored text" details block
	// that follows the warning -- never as the message itself.
	warn, stored, text := strings.Index(body, "do not approve"), strings.Index(body, "<summary>Stored text</summary>"), strings.Index(body, "<pre>Hello.</pre>")
	if warn < 0 || stored < warn || text < stored {
		t.Fatalf("a row with an unreadable format was shown as plain text (warn=%d stored=%d text=%d):\n%s", warn, stored, text, body)
	}
	// And the approval itself is refused, so the page warning is not the only guard.
	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code == http.StatusSeeOther {
		t.Fatal("approved a campaign whose format cannot be read")
	}
}

// End to end: prepared as html, approved on the page, delivered through the
// html send path with the exact approved text.
func TestBroadcast_HTMLEndToEnd(t *testing.T) {
	e := newBroadcastEnv(t)
	body := `<b>Heads up</b>: <a href="https://example.com/x">details</a>`
	p := e.preparedHTML(body)
	if w := e.approve(e.connectIdentity(), p, bcIssuer); w.Code != http.StatusSeeOther {
		t.Fatalf("approve = %d %s", w.Code, w.Body.String())
	}
	sender := &htmlRecordingSender{sent: map[int64]string{}}
	worker := broadcast.NewWorker(e.store, sender, broadcast.WorkerConfig{
		Policy: e.policy, RatePerSecond: 1000, BatchSize: 50, MaxAttempts: 3,
		BaseBackoff: time.Minute, MaxBackoff: 10 * time.Minute, Lease: 2 * time.Minute,
	}, time.Now)
	if err := worker.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if sender.sent[bcClient] != body || !sender.html {
		t.Fatalf("sent = %v html=%v, want the approved text via the html path", sender.sent, sender.html)
	}
}

type htmlRecordingSender struct {
	mu   sync.Mutex
	sent map[int64]string
	html bool
}

func (r *htmlRecordingSender) SendMessage(_ context.Context, chatID int64, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent[chatID] = text
	return nil
}

func (r *htmlRecordingSender) SendHTMLMessage(_ context.Context, chatID int64, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent[chatID] = text
	r.html = true
	return nil
}
