package web

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// recordingPool is an AccountCloser that records RemoveAtomic calls and
// runs fn, as the real pool does under its mutex.
type recordingPool struct {
	mu      sync.Mutex
	removes []int64
}

func (p *recordingPool) Close(int64) bool { return false }

func (p *recordingPool) RemoveAtomic(userID int64, fn func() error) error {
	p.mu.Lock()
	p.removes = append(p.removes, userID)
	p.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// webPARevoker is a db.PATokenRevoker: it fails with err, or revokes every
// connection of the principal locally, standing in for
// (*connection.Manager).RevokeHeldTokens.
type webPARevoker struct {
	s     *db.Store
	err   error
	calls []int64
}

func (f *webPARevoker) RevokeHeldTokens(ctx context.Context, principal int64) error {
	f.calls = append(f.calls, principal)
	if f.err != nil {
		return f.err
	}
	list, err := f.s.ListPAConnections(ctx, principal)
	if err != nil {
		return err
	}
	for _, c := range list {
		if _, _, _, err := f.s.RevokePAConnection(ctx, principal, c.ID, "account_deleted"); err != nil {
			return err
		}
	}
	return nil
}

func withPARevoke(pool AccountCloser, r db.PATokenRevoker) func(*AccountHandlers) {
	return func(h *AccountHandlers) {
		h.Pool = pool
		h.PARevoker = r
	}
}

// TestAccountDelete_PARevokeFailsReturns409WithoutEviction: with a PA
// revoker wired, a revocation that fails refuses the delete with 409 and
// the user message, deletes nothing, and never reaches RemoveAtomic, so the
// account's live Telegram client stays in the pool (#1318, #1338).
func TestAccountDelete_PARevokeFailsReturns409WithoutEviction(t *testing.T) {
	pool := &recordingPool{}
	rev := &webPARevoker{err: errors.New("provider unreachable")}
	f := newAccountManageFixture(t, 7700201, withPARevoke(pool, rev))
	rev.s = f.store
	seedTokenHoldingPAConnection(t, f.store, f.tgID)

	rec := f.call(http.MethodDelete, "/", f.accessToken("dcr-client", "telegram:messages:read", "account:manage"), "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Disconnect or revoke your linked services first") {
		t.Fatalf("body = %s, want the user message", rec.Body.String())
	}
	if !slices.Equal(rev.calls, []int64{f.tgID}) {
		t.Fatalf("revoker calls = %v, want [%d]", rev.calls, f.tgID)
	}
	if len(pool.removes) != 0 {
		t.Fatalf("RemoveAtomic calls = %v after a refused revocation, want none (the live client must stay)", pool.removes)
	}
	if n := f.accountRows(); n != 1 {
		t.Fatalf("account rows = %d after a refused delete, want 1", n)
	}
	if len(f.evictor.users) != 0 {
		t.Fatalf("evicted %v after a refused delete, want none", f.evictor.users)
	}
	if tool, status, _ := f.latestAudit(); tool != "DELETE /api/account" || status != "error" {
		t.Fatalf("audit = %s/%s, want the refused delete recorded as an error", tool, status)
	}
}

// TestAccountDelete_PARevokeSucceedsDeletes: a revoker that revokes the
// token-holding connection lets the delete through: revoke first, then one
// RemoveAtomic, and the account and its PA connection are gone.
func TestAccountDelete_PARevokeSucceedsDeletes(t *testing.T) {
	pool := &recordingPool{}
	rev := &webPARevoker{}
	f := newAccountManageFixture(t, 7700202, withPARevoke(pool, rev))
	rev.s = f.store
	seedTokenHoldingPAConnection(t, f.store, f.tgID)

	rec := f.call(http.MethodDelete, "/", f.accessToken("dcr-client", "telegram:messages:read", "account:manage"), "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if !slices.Equal(rev.calls, []int64{f.tgID}) {
		t.Fatalf("revoker calls = %v, want [%d]", rev.calls, f.tgID)
	}
	if !slices.Equal(pool.removes, []int64{f.uid}) {
		t.Fatalf("RemoveAtomic calls = %v, want one for the user", pool.removes)
	}
	if n := f.accountRows(); n != 0 {
		t.Fatalf("account rows = %d after the delete, want 0", n)
	}
	var conns int
	if err := f.store.DB.QueryRow(`SELECT count(*) FROM pa_connections WHERE principal = $1`, f.tgID).Scan(&conns); err != nil {
		t.Fatalf("count connections: %v", err)
	}
	if conns != 0 {
		t.Fatalf("%d PA connections after the delete, want 0", conns)
	}
}
