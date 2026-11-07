package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func newHiddenWiringStore(t *testing.T) *db.Store {
	t.Helper()
	ctx := context.Background()
	name := strings.ReplaceAll(t.Name(), "/", "_") + "_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	conn, err := db.Open(ctx, "file:"+name+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.MigrateCached(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return db.NewStore(conn, crypt)
}

// TestPoolSender_HiddenChatRefusedBeforeAnyRPC: an assistant reply to a chat
// the owner hid (#1152) is a definitive refusal, so the executor denies it,
// and an unreadable hidden list sends nothing. The pool is nil: reaching it
// would panic, which proves no RPC was attempted.
func TestPoolSender_HiddenChatRefusedBeforeAnyRPC(t *testing.T) {
	ctx := context.Background()
	store := newHiddenWiringStore(t)
	uid, err := store.EnsureUserByTelegramID(ctx, 77201, "alice", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.HideDialog(ctx, uid, "user:7002", "Bob"); err != nil {
		t.Fatal(err)
	}
	s := &poolSender{store: store}
	_, err = s.SendWithRandomID(ctx, uid, 7002, 22, 1, "hi")
	var refused *executor.SendRefusedError
	if !errors.As(err, &refused) || refused.Class != HiddenChatRefusalClass {
		t.Fatalf("send to hidden chat = %v, want SendRefusedError %s", err, HiddenChatRefusalClass)
	}

	if _, err := store.DB.ExecContext(ctx, `DROP TABLE hidden_dialogs`); err != nil {
		t.Fatal(err)
	}
	_, err = s.SendWithRandomID(ctx, uid, 7003, 33, 2, "hi")
	if err == nil || errors.As(err, &refused) {
		t.Fatalf("unreadable hidden list = %v, want a plain error", err)
	}
}
