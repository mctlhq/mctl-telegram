// Command ci-anchor signs the dedicated CI account in once and writes the
// session the live integration tests run as (issue #854,
// internal/telegram/live_integration_test.go). The workflow reads it from the
// TG_LIVE_SESSION secret, so the tests never log in themselves.
//
// It works in two steps, so no interactive terminal is needed:
//
//	TG_LIVE_API_ID=... TG_LIVE_API_HASH=... \
//	  go run ./cmd/ci-anchor send -state DIR -phone +15550100000
//	TG_LIVE_API_ID=... TG_LIVE_API_HASH=... \
//	  go run ./cmd/ci-anchor resend -state DIR   # optional: next delivery method, e.g. SMS
//	TG_LIVE_API_ID=... TG_LIVE_API_HASH=... \
//	  go run ./cmd/ci-anchor confirm -state DIR -code 12345
//
// If the account has a cloud password, put it in TG_LIVE_PASSWORD for
// confirm; it is not a flag, so it stays out of shell history and ps.
//
// It talks to the production DCs: Telegram's test DCs no longer provision
// accounts. Use it only for the one service account CI runs as, never for a
// personal account, and it refuses to create an account that does not exist.
// Signing in adds a "MCTL CI" device to that account's active sessions;
// terminating it there invalidates the secret, and then this is run again.
//
// DIR keeps the auth key and the pending code hash between the steps and,
// after confirm, holds DIR/session.json, the value for the TG_LIVE_SESSION
// secret. Keep DIR outside the repository; it holds credentials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
)

// pending is what send leaves for confirm.
type pending struct {
	Phone         string `json:"phone"`
	PhoneCodeHash string `json:"phone_code_hash"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	state := fs.String("state", "", "directory for the auth key, pending code hash and resulting session (required)")
	phone := fs.String("phone", "", "phone number in international format (send)")
	code := fs.String("code", "", "login code Telegram sent (confirm)")
	_ = fs.Parse(args)
	if *state == "" {
		usage()
	}
	if err := os.MkdirAll(*state, 0o700); err != nil {
		die(err)
	}

	apiID, err := strconv.Atoi(os.Getenv("TG_LIVE_API_ID"))
	apiHash := os.Getenv("TG_LIVE_API_HASH")
	if err != nil || apiHash == "" {
		die(errors.New("TG_LIVE_API_ID and TG_LIVE_API_HASH must be set"))
	}
	client := telegram.NewClient(apiID, apiHash, telegram.Options{
		SessionStorage: &session.FileStorage{Path: filepath.Join(*state, "session.json")},
		Device: telegram.DeviceConfig{
			DeviceModel:    "MCTL CI",
			SystemVersion:  "Linux",
			AppVersion:     "1.0",
			SystemLangCode: "en",
			LangCode:       "en",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pendingPath := filepath.Join(*state, "pending.json")

	switch cmd {
	case "send":
		if *phone == "" {
			usage()
		}
		err = client.Run(ctx, func(ctx context.Context) error {
			sent, err := client.Auth().SendCode(ctx, *phone, auth.SendCodeOptions{})
			if err != nil {
				return fmt.Errorf("send code: %w", err)
			}
			sc, ok := sent.(*tg.AuthSentCode)
			if !ok {
				return fmt.Errorf("unexpected answer %T", sent)
			}
			b, _ := json.Marshal(pending{Phone: *phone, PhoneCodeHash: sc.PhoneCodeHash})
			if err := os.WriteFile(pendingPath, b, 0o600); err != nil {
				return err
			}
			fmt.Printf("code sent, delivery: %T", sc.Type)
			if l, ok := sc.Type.(interface{ GetLength() int }); ok {
				fmt.Printf(", %d digits", l.GetLength())
			}
			fmt.Println()
			return nil
		})
	case "resend":
		b, rerr := os.ReadFile(pendingPath)
		if rerr != nil {
			die(fmt.Errorf("run send first: %w", rerr))
		}
		var p pending
		if err := json.Unmarshal(b, &p); err != nil {
			die(err)
		}
		err = client.Run(ctx, func(ctx context.Context) error {
			sent, err := client.API().AuthResendCode(ctx, &tg.AuthResendCodeRequest{
				PhoneNumber:   p.Phone,
				PhoneCodeHash: p.PhoneCodeHash,
			})
			if err != nil {
				return fmt.Errorf("resend code: %w", err)
			}
			sc, ok := sent.(*tg.AuthSentCode)
			if !ok {
				return fmt.Errorf("unexpected answer %T", sent)
			}
			p.PhoneCodeHash = sc.PhoneCodeHash
			b, _ := json.Marshal(p)
			if err := os.WriteFile(pendingPath, b, 0o600); err != nil {
				return err
			}
			fmt.Printf("code resent, delivery: %T\n", sc.Type)
			return nil
		})
	case "confirm":
		if *code == "" {
			usage()
		}
		b, rerr := os.ReadFile(pendingPath)
		if rerr != nil {
			die(fmt.Errorf("run send first: %w", rerr))
		}
		var p pending
		if err := json.Unmarshal(b, &p); err != nil {
			die(err)
		}
		err = client.Run(ctx, func(ctx context.Context) error {
			a := client.Auth()
			_, err := a.SignIn(ctx, p.Phone, *code, p.PhoneCodeHash)
			var signUp *auth.SignUpRequired
			switch {
			case errors.As(err, &signUp):
				return errors.New("number is not registered; refusing to create an account")
			case errors.Is(err, auth.ErrPasswordAuthNeeded):
				password := os.Getenv("TG_LIVE_PASSWORD")
				if password == "" {
					return errors.New("this account has a cloud password; set TG_LIVE_PASSWORD")
				}
				_, err = a.Password(ctx, password)
			}
			if err != nil {
				return fmt.Errorf("sign in: %w", err)
			}
			self, err := client.Self(ctx)
			if err != nil {
				return fmt.Errorf("self: %w", err)
			}
			fmt.Printf("signed in: user id %d\n", self.ID)
			return os.Remove(pendingPath)
		})
		if err == nil {
			fmt.Printf("session: %s\n", filepath.Join(*state, "session.json"))
		}
	default:
		usage()
	}
	if err != nil {
		die(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ci-anchor send -state DIR -phone NUMBER | resend -state DIR | confirm -state DIR -code CODE")
	os.Exit(2)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "ci-anchor:", err)
	os.Exit(1)
}
