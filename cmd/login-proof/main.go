// Command login-proof is the low-frequency live proof of the Telegram login
// path (issue #1057). It runs the product telegram.LoginQR or telegram.Login
// against Telegram's production datacenters, stores the session through the
// normal store path, makes one read-only MCP call with it, logs the new
// authorization out, and prints exactly one evidence line:
//
//	login-proof mode=qr outcome=pass reached=cleanup commit=<sha> at=<utc>
//
// The line holds no phone number, Telegram id, username, name, session, code,
// password or token, and the command exits 0 only for outcome=pass. Anything
// that was not observed is fail, and flood_wait, refused and unknown are never
// converted to a pass.
//
// IMPORTANT: use only the dedicated login-proof service account. Never a
// personal, operator or canary account (the TG_LIVE_SESSION account is the
// canary's). The proof must never run on a schedule: the only automatic
// entry point is the dispatch-only live-telegram-login workflow.
//
// Modes:
//
//	login-proof qr
//	    Unattended, used by CI. An already-authorized anchor session of the
//	    same account (TG_PROOF_ANCHOR_SESSION, made with cmd/ci-anchor)
//	    accepts the exported login token.
//	login-proof phone [-expect ok|wrong-password|expired-code]
//	    Attended, on an operator machine with a terminal. The login code is
//	    typed at a no-echo prompt. Nothing is written to disk.
//
// All credentials come from the environment, never from flags:
// TG_PROOF_API_ID, TG_PROOF_API_HASH, TG_PROOF_EXPECT_TG_ID, and per mode
// TG_PROOF_ANCHOR_SESSION (qr), TG_PROOF_PHONE (phone), TG_PROOF_PASSWORD
// (optional, the 2FA password). COMMIT is printed in the evidence line.
// See docs/runbooks/live-login-proof.md.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gotd/td/session"
	gotdtelegram "github.com/gotd/td/telegram"
	"golang.org/x/term"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	mcrypto "github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/loginproof"
	"github.com/mctlhq/mctl-telegram/internal/mcp"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

const wrongPassword = "login-proof-known-wrong-password"

// options is the parsed command line. It carries a mode and an expectation,
// nothing secret.
type options struct {
	mode loginproof.Mode
}

// newFlagSet builds the flag set of a subcommand. None of them accepts a phone
// number, a code, a password or a session: those come from the environment or
// a no-echo prompt.
func newFlagSet(sub string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if sub != "phone" {
		return fs, nil
	}
	return fs, fs.String("expect", "ok", "ok, wrong-password or expired-code")
}

func parseArgs(args []string) (options, error) {
	if len(args) == 0 {
		return options{}, errors.New("usage: login-proof qr | phone [-expect ok|wrong-password|expired-code]")
	}
	fs, expect := newFlagSet(args[0])
	switch args[0] {
	case "qr", "phone":
	default:
		return options{}, fmt.Errorf("unknown mode %q", args[0])
	}
	if err := fs.Parse(args[1:]); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		return options{}, errors.New("unexpected arguments")
	}
	if args[0] == "qr" {
		return options{mode: loginproof.ModeQR}, nil
	}
	switch *expect {
	case "ok":
		return options{mode: loginproof.ModePhone}, nil
	case "wrong-password":
		return options{mode: loginproof.ModePhoneWrongPassword}, nil
	case "expired-code":
		return options{mode: loginproof.ModePhoneExpiredCode}, nil
	}
	return options{}, fmt.Errorf("unknown -expect %q", *expect)
}

type env struct {
	apiID    int
	apiHash  string
	wantTGID int64
	anchor   string
	phone    string
	password string
}

func readEnv(mode loginproof.Mode) (env, error) {
	var e env
	var err error
	if e.apiID, err = strconv.Atoi(os.Getenv("TG_PROOF_API_ID")); err != nil || e.apiID == 0 {
		return e, errors.New("TG_PROOF_API_ID must be set")
	}
	if e.apiHash = os.Getenv("TG_PROOF_API_HASH"); e.apiHash == "" {
		return e, errors.New("TG_PROOF_API_HASH must be set")
	}
	if e.wantTGID, err = strconv.ParseInt(os.Getenv("TG_PROOF_EXPECT_TG_ID"), 10, 64); err != nil || e.wantTGID <= 0 {
		return e, errors.New("TG_PROOF_EXPECT_TG_ID must be set to the service account's Telegram id")
	}
	e.password = os.Getenv("TG_PROOF_PASSWORD")
	switch mode {
	case loginproof.ModeQR:
		if e.anchor = os.Getenv("TG_PROOF_ANCHOR_SESSION"); e.anchor == "" {
			return e, errors.New("TG_PROOF_ANCHOR_SESSION must be set")
		}
	default:
		if e.phone = os.Getenv("TG_PROOF_PHONE"); e.phone == "" {
			return e, errors.New("TG_PROOF_PHONE must be set")
		}
	}
	return e, nil
}

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	// The repository and its Actions logs are public; the pool and gotd log
	// user and peer ids, so their output is dropped.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	opts, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login-proof:", err)
		return 2
	}
	outcome, reached := execute(opts)
	ev := loginproof.NewEvidence(opts.mode, outcome, reached, os.Getenv("COMMIT"), time.Now())
	fmt.Println(ev.Line())
	if outcome != loginproof.OutcomePass {
		return 1
	}
	return 0
}

func execute(opts options) (string, loginproof.Step) {
	e, err := readEnv(opts.mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login-proof:", err)
		return loginproof.OutcomeRefused, "none"
	}
	if opts.mode != loginproof.ModeQR {
		if !term.IsTerminal(int(syscall.Stdin)) {
			fmt.Fprintln(os.Stderr, "login-proof: phone mode needs an interactive terminal")
			return loginproof.OutcomeRefused, "none"
		}
		unlock, err := lockLocal()
		if err != nil {
			fmt.Fprintln(os.Stderr, "login-proof:", err)
			return loginproof.OutcomeRefused, "none"
		}
		defer unlock()
	}

	timeout := 5 * time.Minute
	if opts.mode != loginproof.ModeQR {
		timeout = 20 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	store, uid, err := newStore(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login-proof:", err)
		return loginproof.OutcomeFail, "none"
	}
	pool := telegram.NewClientPool(e.apiID, e.apiHash, time.Minute, store)
	var poolOnce sync.Once
	shutdown := func() { poolOnce.Do(pool.Shutdown) }
	defer shutdown()
	srv := mcp.New(store, pool, false)

	cfg := telegram.LoginConfig{WantTelegramID: e.wantTGID, QRWait: 60 * time.Second}
	var tgID int64
	steps := loginproof.Steps{
		LoadSession: func(ctx context.Context) ([]byte, error) { return store.LoadSession(ctx, uid) },
		SaveSession: func(ctx context.Context, data []byte) error {
			return store.SaveSession(ctx, uid, data, tgID, "", "")
		},
		CallTool: func(ctx context.Context) error {
			id := &auth.Identity{UserID: uid, TelegramID: tgID, Scopes: []string{"telegram:dialogs:read"}}
			res, err := srv.CallToolInProcess(ctx, id, "list_dialogs", map[string]any{"limit": 1})
			if err != nil {
				return err
			}
			if res == nil || res.IsError {
				return errors.New("list_dialogs returned an error result")
			}
			return nil
		},
		LogOut: func(ctx context.Context, data []byte) error {
			shutdown() // the pool holds the same auth key
			lctx, lcancel := telegram.DetachedLogOutContext(ctx)
			defer lcancel()
			return telegram.LogOutSession(lctx, e.apiID, e.apiHash, data, cfg)
		},
	}
	checkID := func(id int64) error {
		tgID = id
		if id != e.wantTGID {
			return loginproof.ErrIdentityMismatch
		}
		return nil
	}

	if opts.mode == loginproof.ModeQR {
		return runQR(ctx, opts.mode, e, store, uid, cfg, steps, checkID)
	}
	steps.Login = func(ctx context.Context) error {
		id, _, _, err := telegram.Login(ctx, e.apiID, e.apiHash, store, uid, e.phone,
			promptCode, passwordFunc(opts.mode, e.password), cfg)
		if err != nil {
			return err
		}
		return checkID(id)
	}
	return loginproof.Run(ctx, opts.mode, steps)
}

func runQR(ctx context.Context, mode loginproof.Mode, e env, store *db.Store, uid int64,
	cfg telegram.LoginConfig, steps loginproof.Steps, checkID func(int64) error) (string, loginproof.Step) {

	mem := &session.StorageMemory{}
	if err := mem.StoreSession(ctx, []byte(e.anchor)); err != nil {
		return loginproof.OutcomeFail, "none"
	}
	anchor := gotdtelegram.NewClient(e.apiID, e.apiHash, gotdtelegram.Options{
		SessionStorage: mem,
		Device: gotdtelegram.DeviceConfig{
			DeviceModel:    "MCTL Login Proof Anchor",
			SystemVersion:  "Linux",
			AppVersion:     "1.0",
			SystemLangCode: "en",
		},
	})

	var (
		outcome = loginproof.OutcomeUnknown
		reached = loginproof.Step("none")
	)
	runErr := anchor.Run(ctx, func(ctx context.Context) error {
		var (
			once       sync.Once
			acceptErr  error
			hash       int64
			acceptedMu sync.Mutex
			accepted   bool
		)
		show := func(ctx context.Context, url, _ string) error {
			once.Do(func() {
				token, err := tokenFromURL(url)
				if err != nil {
					acceptErr = err
					return
				}
				authz, err := anchor.API().AuthAcceptLoginToken(ctx, token)
				if err != nil {
					acceptErr = fmt.Errorf("anchor accept: %w", err)
					return
				}
				acceptedMu.Lock()
				hash, accepted = authz.Hash, true
				acceptedMu.Unlock()
			})
			return acceptErr
		}
		var password func(context.Context) (string, error)
		if e.password != "" {
			password = func(context.Context) (string, error) { return e.password, nil }
		}
		steps.Login = func(ctx context.Context) error {
			id, _, _, err := telegram.LoginQR(ctx, e.apiID, e.apiHash, store, uid, show, password, cfg)
			if err != nil {
				return err
			}
			return checkID(id)
		}
		steps.Scanned = func() bool {
			acceptedMu.Lock()
			defer acceptedMu.Unlock()
			return accepted
		}
		steps.Fallback = func(ctx context.Context) error {
			acceptedMu.Lock()
			h, ok := hash, accepted
			acceptedMu.Unlock()
			if !ok {
				return errors.New("no authorization hash")
			}
			_, err := anchor.API().AccountResetAuthorization(ctx, h)
			return err
		}
		steps.StillAuthorized = func(ctx context.Context) (bool, error) {
			acceptedMu.Lock()
			h := hash
			acceptedMu.Unlock()
			list, err := anchor.API().AccountGetAuthorizations(ctx)
			if err != nil {
				return true, err
			}
			for _, a := range list.Authorizations {
				if a.Hash == h {
					return true, nil
				}
			}
			return false, nil
		}
		outcome, reached = loginproof.Run(ctx, mode, steps)
		return nil
	})
	if runErr != nil && outcome == loginproof.OutcomeUnknown {
		// The anchor client itself failed before the proof ran.
		return loginproof.Classify(runErr), "none"
	}
	return outcome, reached
}

// tokenFromURL extracts the login token from tg://login?token=<base64url>.
func tokenFromURL(url string) ([]byte, error) {
	const key = "token="
	i := strings.Index(url, key)
	if i < 0 {
		return nil, errors.New("no token in the login URL")
	}
	tok, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(url[i+len(key):], "="))
	if err != nil || len(tok) == 0 {
		return nil, errors.New("malformed login token")
	}
	return tok, nil
}

func newStore(ctx context.Context) (*db.Store, int64, error) {
	conn, err := db.Open(ctx, "file::memory:?cache=shared", 0, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open store: %w", err)
	}
	if err := db.MigrateCached(ctx, conn); err != nil {
		return nil, 0, fmt.Errorf("migrate store: %w", err)
	}
	crypt, err := mcrypto.New(nil)
	if err != nil {
		return nil, 0, err
	}
	store := &db.Store{DB: conn, Crypt: crypt}
	if err := store.EnsureDCMode(ctx, db.DCModeProduction); err != nil {
		return nil, 0, fmt.Errorf("dc mode: %w", err)
	}
	uid, err := store.EnsureUser(ctx, "login-proof", "", "local-dev")
	if err != nil {
		return nil, 0, fmt.Errorf("ensure user: %w", err)
	}
	return store, uid, nil
}

func promptCode(ctx context.Context) (string, error) {
	fmt.Fprint(os.Stderr, "Login code (hidden): ")
	b, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return telegram.LoginCodeDigits(string(b)), nil
}

func passwordFunc(mode loginproof.Mode, fromEnv string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		if mode == loginproof.ModePhoneWrongPassword {
			return wrongPassword, nil
		}
		if fromEnv != "" {
			return fromEnv, nil
		}
		fmt.Fprint(os.Stderr, "2FA password (hidden): ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
}

// lockLocal stops two local phone proofs from running at once on the same
// account. The file holds only the pid.
func lockLocal() (func(), error) {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = os.TempDir()
	}
	path := filepath.Join(dir, "login-proof.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("another login-proof run holds %s (remove it if that run is gone)", path)
	}
	_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	_ = f.Close()
	return func() { _ = os.Remove(path) }, nil
}
