package main

import (
	"context"
	"errors"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
)

func TestAgentSendGate_EnforcesGlobalScopeAndAccountGates(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	crypt, err := crypto.New(nil)
	if err != nil {
		t.Fatalf("crypto: %v", err)
	}
	store := db.NewStore(conn, crypt)
	const tgID int64 = 424242
	uid, err := store.EnsureUserByTelegramID(ctx, tgID, "", "")
	if err != nil {
		t.Fatalf("ensure user: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO telegram_accounts(user_id, telegram_user_id, session_encrypted, send_enabled)
		 VALUES($1,$2,$3,$4)`,
		uid, tgID, []byte{0}, false,
	); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	gate := &agentSendGate{
		store:             store,
		allowSend:         true,
		clientTelegramIDs: map[int64]bool{tgID: true},
	}
	if err := gate.Allow(ctx, uid, 99); !errors.Is(err, errAgentSendGateDenied) {
		t.Fatalf("send_enabled=false err=%v, want gate denial", err)
	}
	if _, err := conn.ExecContext(ctx,
		`UPDATE telegram_accounts SET send_enabled = $1 WHERE user_id = $2`,
		true, uid,
	); err != nil {
		t.Fatalf("enable send: %v", err)
	}
	if err := gate.Allow(ctx, uid, 99); err != nil {
		t.Fatalf("fully-open gate denied: %v", err)
	}

	gate.allowSend = false
	if err := gate.Allow(ctx, uid, 99); !errors.Is(err, errAgentSendGateDenied) {
		t.Fatalf("ALLOW_SEND=false err=%v, want gate denial", err)
	}
	gate.allowSend = true
	if err := store.SetAccessTier(ctx, tgID, db.TierNone); err != nil {
		t.Fatalf("set tier none: %v", err)
	}
	if err := gate.Allow(ctx, uid, 99); !errors.Is(err, errAgentSendGateDenied) {
		t.Fatalf("scope-revoked err=%v, want gate denial", err)
	}
	if err := store.SetAccessTier(ctx, tgID, db.TierClient); err != nil {
		t.Fatalf("set tier client: %v", err)
	}
	gate.clientTelegramIDs = nil
	if err := gate.Allow(ctx, uid, 99); err != nil {
		t.Fatalf("DB client tier denied: %v", err)
	}
	gate.demoReviewerTGID = tgID
	if err := gate.Allow(ctx, uid, 99); !errors.Is(err, errAgentSendGateDenied) {
		t.Fatalf("demo reviewer err=%v, want gate denial", err)
	}
}
