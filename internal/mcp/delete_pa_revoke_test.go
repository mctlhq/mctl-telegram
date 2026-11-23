package mcp

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/pa/connection"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// recordingRemover stands in for the pool in delete_telegram_account: it
// records RemoveAtomic calls and runs fn, as the pool does under its mutex.
type recordingRemover struct {
	mu      sync.Mutex
	removes []int64
}

func (r *recordingRemover) RemoveAtomic(userID int64, fn func() error) error {
	r.mu.Lock()
	r.removes = append(r.removes, userID)
	r.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// mcpPARevoker is a db.PATokenRevoker: it fails with err, or revokes every
// connection of the principal locally, standing in for
// (*connection.Manager).RevokeHeldTokens.
type mcpPARevoker struct {
	s     *db.Store
	err   error
	calls []int64
}

func (f *mcpPARevoker) RevokeHeldTokens(ctx context.Context, principal int64) error {
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

// seedMCPTokenHoldingPAConnection gives principal a PA connection that
// holds provider tokens (pending_confirm).
func seedMCPTokenHoldingPAConnection(t *testing.T, store *db.Store, principal int64, id string) {
	t.Helper()
	ctx := context.Background()
	a, err := store.AdmitPAConnection(ctx, principal)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	if err := store.CreatePAConnection(ctx, connection.Connection{
		ID: id, Principal: principal, Server: connection.ServerTG, State: connection.StatePendingLink, AuthorityRevision: 1,
	}, connection.Sealed{KEKID: "test", WrappedDEK: []byte("wrapped")}, a); err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, tr := range []connection.Transition{
		{From: connection.StatePendingLink, To: connection.StatePendingOAuth, ExpectRevision: 1},
		{From: connection.StatePendingOAuth, To: connection.StatePendingReturn, ExpectRevision: 2, SealedCode: []byte("code")},
		{From: connection.StatePendingReturn, To: connection.StatePendingConfirm, ExpectRevision: 3,
			AccountID: "acct", GrantedScope: "telegram:dialogs:read", SealedTokens: []byte("tokens")},
	} {
		if _, err := store.TransitionPAConnection(ctx, principal, id, tr); err != nil {
			t.Fatalf("%s -> %s: %v", tr.From, tr.To, err)
		}
	}
}

func deleteWithPARevoker(t *testing.T, tgID int64, rev *mcpPARevoker) (*db.Store, int64, *recordingRemover, *mcplib.CallToolResult) {
	t.Helper()
	ctx := context.Background()
	store := newToolsTestStore(t)
	rev.s = store
	uid := seedAccountWithSession(t, store, tgID, false)
	seedMCPTokenHoldingPAConnection(t, store, tgID, "pac_mcp_revoke")
	remover := &recordingRemover{}
	srv := &Server{Store: store, Pool: telegram.NewClientPool(0, "", 0, store), DemoReviewerTGID: guardReviewerTGID,
		PARevoker: rev, accountRemover: remover}
	ctx = auth.With(ctx, &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: []string{"telegram:messages:read", "account:manage"}})
	_, handler := srv.toolDeleteAccount()
	res, err := handler(ctx, mcplib.CallToolRequest{Params: mcplib.CallToolParams{Name: "delete_telegram_account"}})
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	return store, uid, remover, res
}

// TestDeleteTelegramAccount_PARevokeFails: with a PA revoker wired, a
// revocation that fails returns the user message as a tool error, deletes
// nothing and never reaches RemoveAtomic, so the live client is not evicted
// (#1318, #1338).
func TestDeleteTelegramAccount_PARevokeFails(t *testing.T) {
	const tgID int64 = 500100201
	rev := &mcpPARevoker{err: errors.New("provider unreachable")}
	store, uid, remover, res := deleteWithPARevoker(t, tgID, rev)
	if !res.IsError || contentText(res) != db.PAConnectionsNeedRevocationMessage {
		t.Fatalf("result %q (error=%v), want the user message", contentText(res), res.IsError)
	}
	if !slices.Equal(rev.calls, []int64{tgID}) {
		t.Fatalf("revoker calls = %v, want [%d]", rev.calls, tgID)
	}
	if len(remover.removes) != 0 {
		t.Fatalf("RemoveAtomic calls = %v after a refused revocation, want none", remover.removes)
	}
	if n := totalAccountCount(t, store, uid); n == 0 {
		t.Fatal("the account was deleted despite the refusal")
	}
	if tool, status, _ := latestAudit(t, store, uid); tool != "delete_telegram_account" || status != "error" {
		t.Fatalf("audit = %s/%s, want the refused delete recorded as an error", tool, status)
	}
}

// TestDeleteTelegramAccount_PARevokeSucceeds: a revoker that revokes the
// token-holding connection lets the delete through, revoke first and then
// one RemoveAtomic.
func TestDeleteTelegramAccount_PARevokeSucceeds(t *testing.T) {
	const tgID int64 = 500100202
	rev := &mcpPARevoker{}
	store, uid, remover, res := deleteWithPARevoker(t, tgID, rev)
	if res.IsError {
		t.Fatalf("delete failed: %s", contentText(res))
	}
	if !slices.Equal(rev.calls, []int64{tgID}) {
		t.Fatalf("revoker calls = %v, want [%d]", rev.calls, tgID)
	}
	if !slices.Equal(remover.removes, []int64{uid}) {
		t.Fatalf("RemoveAtomic calls = %v, want one for the user", remover.removes)
	}
	if n := totalAccountCount(t, store, uid); n != 0 {
		t.Fatalf("%d account rows after the delete, want 0", n)
	}
}
