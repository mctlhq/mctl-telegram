// Command login walks the operator through Telegram MTProto authentication
// and persists the encrypted session into the DB used by `mctl-telegram serve`.
//
// Usage:
//
//	TG_API_ID=...   TG_API_HASH=... \
//	OPERATOR_GITHUB_LOGIN=mashkovd \
//	DATABASE_URL='file:./mctl-telegram.db?_pragma=journal_mode(WAL)' \
//	ENCRYPTION_KEY=$(openssl rand -hex 32) \
//	go run ./cmd/login --phone +14155551234
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"

	"github.com/mctlhq/mctl-telegram/internal/auth/localdev"
	"github.com/mctlhq/mctl-telegram/internal/config"
	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
	"golang.org/x/term"
)

func main() {
	phone := flag.String("phone", "", "Phone number in international format (e.g. +14155551234)")
	flag.Parse()

	if *phone == "" {
		fmt.Fprintln(os.Stderr, "--phone required")
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		die(err)
	}
	if cfg.TGAPIID == 0 || cfg.TGAPIHash == "" {
		die(errors.New("TG_API_ID and TG_API_HASH must be set (register at https://my.telegram.org)"))
	}

	ctx := context.Background()

	rawDB, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		die(fmt.Errorf("db open: %w", err))
	}
	defer rawDB.Close()
	if err := db.Migrate(ctx, rawDB); err != nil {
		die(fmt.Errorf("db migrate: %w", err))
	}
	cryp, err := crypto.New(cfg.EncryptionKey)
	if err != nil {
		die(fmt.Errorf("crypto: %w", err))
	}
	store := db.NewStore(rawDB, cryp)

	provider := localdev.New(store, cfg.OperatorLogin)
	uid, err := provider.EnsureSeedUser(ctx)
	if err != nil {
		die(fmt.Errorf("ensure user: %w", err))
	}
	slog.Info("login starting", "user_id", uid, "github_login", cfg.OperatorLogin, "phone", *phone)

	stdin := bufio.NewReader(os.Stdin)
	askCode := func(ctx context.Context) (string, error) {
		fmt.Print("Enter the Telegram code: ")
		line, err := stdin.ReadString('\n')
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(line), nil
	}
	askPassword := func(ctx context.Context) (string, error) {
		fmt.Print("Enter 2FA cloud password: ")
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(pw)), nil
	}

	tgID, displayName, username, err := telegram.Login(
		ctx, cfg.TGAPIID, cfg.TGAPIHash, store, uid, *phone, askCode, askPassword,
	)
	if err != nil {
		die(fmt.Errorf("login: %w", err))
	}

	if err := store.SaveSession(ctx, uid, mustLoadFreshSession(ctx, store, uid), tgID, displayName, username); err != nil {
		// SaveSession revokes prior + reinserts with the just-stored bytes — for
		// idempotence on partial-failure recovery flows. Errors here mean the DB
		// is unhappy; surface and exit non-zero so the operator retries.
		die(fmt.Errorf("save metadata: %w", err))
	}

	fmt.Printf("\nLogin OK — Telegram user %d (%s @%s) bound to operator %q.\n",
		tgID, displayName, username, cfg.OperatorLogin)
}

func mustLoadFreshSession(ctx context.Context, store *db.Store, uid int64) []byte {
	pt, err := store.LoadSession(ctx, uid)
	if err != nil {
		die(fmt.Errorf("reload session after login: %w", err))
	}
	if pt == nil {
		die(errors.New("session bytes missing after login"))
	}
	return pt
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
