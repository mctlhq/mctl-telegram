// Command mctl-telegram-local is the Local Bridge daemon (M4).
//
// In Local Bridge mode the MTProto session lives on the user's machine;
// tg.mctl.ai is reduced to a relay that forwards MCP tool calls to this
// daemon and shuttles responses back. The server never sees the user's
// session bytes.
//
// Subcommands:
//
//	init     — Create ~/.config/mctl-telegram-local/config.json.
//	activate — Self-service device activation via Telegram OIDC (no operator step).
//	login    — Interactive Telegram phone/code/2FA login.
//	connect  — Exchange an MCP JWT for a short-lived bridge token.
//	daemon   — Long-running websocket loop (reconnects automatically).
//	version  — Print the binary version.
//	help     — Print this usage message.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/db"
	tg "github.com/mctlhq/mctl-telegram/internal/telegram"
	"golang.org/x/term"
)

// version is stamped at build time with -ldflags "-X main.version=<tag>". The
// fallback matters: a binary built with a plain `go build` says so, instead of
// claiming a release number it does not correspond to. The published builds
// carry the release tag, so a bug report names a build that can be found.
var version = "dev"

const usage = `mctl-telegram-local — Local Bridge daemon for mctl-telegram

Usage:
  mctl-telegram-local <subcommand> [args]

Subcommands:
  init                       Initialise config (TG api_id, api_hash, passphrase).
  activate --telegram-id <id> Self-service device activation (no operator step required).
  login --phone <num>        Interactive Telegram login.
  connect --token <t>        Exchange an MCP JWT for a bridge token and save it.
  daemon                     Start the long-running websocket relay daemon.
  version                    Print the binary version.
  help                       Show this message.
`

func main() {
	// Before anything creates a file: the config, the bridge token and the
	// session database are all owner-only, and the umask is what guarantees
	// that at creation rather than a moment later.
	restrictUmask()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	case "init":
		runInit()
	case "activate":
		runActivate(os.Args[2:])
	case "login":
		runLogin(os.Args[2:])
	case "connect":
		runConnect(os.Args[2:])
	case "daemon":
		runDaemonCmd()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// ---- init ----------------------------------------------------------------

func runInit() {
	stdin := bufio.NewReader(os.Stdin)

	apiID := promptInt(stdin, "TG_API_ID (from https://my.telegram.org/apps): ")
	apiHash := promptStr(stdin, "TG_API_HASH: ")

	fmt.Print("Passphrase (encrypts local session DB): ")
	pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die(fmt.Errorf("read passphrase: %w", err))
	}

	fmt.Print("Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die(fmt.Errorf("read passphrase confirm: %w", err))
	}

	if !bytes.Equal(pass1, pass2) {
		die(errors.New("passphrases do not match"))
	}
	if len(pass1) == 0 {
		die(errors.New("passphrase must not be empty"))
	}

	saltB64, err := generateSalt()
	if err != nil {
		die(err)
	}

	initKey, err := deriveKey(pass1, saltB64)
	if err != nil {
		die(fmt.Errorf("derive key: %w", err))
	}

	cfg := &localConfig{
		APIID:    apiID,
		APIHash:  apiHash,
		Server:   "",
		KeySalt:  saltB64,
		KeyCheck: deriveKeyCheck(initKey),
	}
	if err := saveConfig(cfg); err != nil {
		die(err)
	}

	dir, _ := configDirPath()
	fmt.Printf("Initialized. Config saved to %s\n", filepath.Join(dir, configFileName))
	fmt.Println("Run `mctl-telegram-local login --phone +1...` next.")
}

// ---- login ---------------------------------------------------------------

func runLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	phone := fs.String("phone", "", "Phone number in international format (e.g. +14155551234)")
	if err := fs.Parse(args); err != nil {
		die(err)
	}
	if *phone == "" {
		fmt.Fprintln(os.Stderr, "--phone required")
		os.Exit(2)
	}

	cfg, err := loadConfig()
	if err != nil {
		die(err)
	}

	key := promptPassphrase("Passphrase: ")
	keyHex := encryptionKeyHex(mustDeriveVerifiedKey(key, cfg))

	ctx := context.Background()
	store, closeDB, uid := openLocalStore(ctx, keyHex)
	defer closeDB()

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
		pw, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(pw)), nil
	}

	tgID, displayName, username, err := tg.Login(
		ctx, cfg.APIID, cfg.APIHash, store, uid, *phone, askCode, askPassword,
	)
	if err != nil {
		die(fmt.Errorf("login: %w", err))
	}

	// SaveSession finalises the account row with TG metadata.
	pt, err := store.LoadSession(ctx, uid)
	if err != nil || pt == nil {
		if err == nil {
			err = errors.New("session bytes missing after login")
		}
		die(fmt.Errorf("reload session: %w", err))
	}
	if err := store.SaveSession(ctx, uid, pt, tgID, displayName, username); err != nil {
		die(fmt.Errorf("save session metadata: %w", err))
	}

	fmt.Printf("\nLogin OK — Telegram user %d (%s @%s).\n", tgID, displayName, username)
}

// ---- connect -------------------------------------------------------------

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	mcpToken := fs.String("token", "", "MCP JWT from your mctl-telegram connector settings")
	server := fs.String("server", "", "Override the server URL (default: from config.json)")
	if err := fs.Parse(args); err != nil {
		die(err)
	}

	if *mcpToken == "" {
		fmt.Fprintln(os.Stderr, "Get your MCP token from your mctl-telegram connector settings, then run:")
		fmt.Fprintln(os.Stderr, "  mctl-telegram-local connect --token <token>")
		os.Exit(2)
	}

	cfg, err := loadConfig()
	if err != nil {
		die(err)
	}

	srv := cfg.Server
	if *server != "" {
		srv = *server
		cfg.Server = srv
		// Don't persist yet — save only after the token exchange succeeds.
	}

	tokenURL := strings.TrimRight(srv, "/") + "/api/bridge/token"

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, tokenURL, nil)
	if err != nil {
		die(fmt.Errorf("build request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+*mcpToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		die(fmt.Errorf("POST %s: %w", tokenURL, err))
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		die(fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}

	var tok struct {
		BridgeToken string `json:"bridge_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		die(fmt.Errorf("parse response: %w", err))
	}
	if tok.BridgeToken == "" {
		die(errors.New("server returned empty bridge_token"))
	}

	bt := &bridgeTokenFile{
		MCPToken:    *mcpToken,
		BridgeToken: tok.BridgeToken,
		ExpiresAt:   tok.ExpiresAt,
	}
	if err := saveBridgeToken(bt); err != nil {
		die(err)
	}

	// Persist server override now that the exchange succeeded.
	if *server != "" {
		if err := saveConfig(cfg); err != nil {
			die(fmt.Errorf("persist server override: %w", err))
		}
	}

	fmt.Printf("Connected. Bridge token saved (expires %s).\n", tok.ExpiresAt)
	fmt.Println("Run `mctl-telegram-local daemon` to start.")
}

// ---- daemon --------------------------------------------------------------

func runDaemonCmd() {
	cfg, err := loadConfig()
	if err != nil {
		die(err)
	}

	bt, err := loadBridgeToken()
	if err != nil {
		die(err)
	}

	// A stale bridge token is not a reason to refuse to start. The connect
	// loop already mints a fresh one from the stored MCP token when the
	// current one is close to expiring (see runDaemon), and the bridge token
	// lives an hour while the MCP token lives months — so any restart more
	// than an hour after the last `connect` used to fail for a condition the
	// process could resolve by itself. That is precisely the restart a
	// service manager performs after a reboot.
	//
	// Refresh here instead, and only give up when the refresh itself fails,
	// which is the case a human genuinely has to act on.
	if expiry, expiryErr := bridgeTokenExpiry(bt); expiryErr == nil && time.Until(expiry) <= tokenRefreshAdv {
		slog.Info("bridge token expired or expiring; refreshing before start",
			"expires_at", expiry.Format(time.RFC3339))
		refreshed, refreshErr := refreshBridgeToken(context.Background(), cfg, bt)
		if refreshErr != nil {
			die(fmt.Errorf("bridge token expired (at %s) and could not be refreshed: %w\n"+
				"Run `mctl-telegram-local connect --token <new-token>` with a current MCP token",
				expiry.Format(time.RFC3339), refreshErr))
		}
		bt = refreshed
		slog.Info("bridge token refreshed", "expires_at", bt.ExpiresAt)
	}

	key := promptPassphrase("Passphrase: ")
	keyHex := encryptionKeyHex(mustDeriveVerifiedKey(key, cfg))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	store, closeDB, uid := openLocalStore(ctx, keyHex)
	defer closeDB()

	pool := tg.NewClientPool(cfg.APIID, cfg.APIHash, 10*time.Minute, store)
	defer pool.Shutdown()

	// Graceful shutdown on SIGINT/SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	slog.Info("daemon starting", "server", cfg.Server, "expires_at", bt.ExpiresAt, "user_id", uid)
	if err := runDaemon(ctx, cfg, pool, uid); err != nil && !errors.Is(err, context.Canceled) {
		die(err)
	}
	slog.Info("daemon stopped")
}

// ---- helpers -------------------------------------------------------------

// openLocalStore opens (or creates) the local SQLite DB at the standard path,
// migrates the schema, and returns a *db.Store, a close function, and the
// single local user ID (always 1 after seed).
func openLocalStore(ctx context.Context, keyHex string) (*db.Store, func(), int64) {
	dbPath, err := dbFilePath()
	if err != nil {
		die(err)
	}

	dsn := sqliteDSN(dbPath) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	rawDB, err := db.Open(ctx, dsn, 0, 0)
	if err != nil {
		die(fmt.Errorf("open local db: %w", err))
	}
	if err := db.Migrate(ctx, rawDB); err != nil {
		_ = rawDB.Close()
		die(fmt.Errorf("migrate local db: %w", err))
	}
	if err := restrictDBPerms(dbPath); err != nil {
		_ = rawDB.Close()
		die(err)
	}

	var keyBytes []byte
	if keyHex != "" {
		keyBytes, err = hexDecodeLocal(keyHex)
		if err != nil {
			_ = rawDB.Close()
			die(fmt.Errorf("decode key: %w", err))
		}
	}
	cryp, err := crypto.New(keyBytes)
	if err != nil {
		_ = rawDB.Close()
		die(fmt.Errorf("crypto init: %w", err))
	}

	store := db.NewStore(rawDB, cryp)

	// Seed the single local user row.
	uid, err := store.EnsureUser(ctx, "local", "", "local-bridge")
	if err != nil {
		_ = rawDB.Close()
		die(fmt.Errorf("seed user: %w", err))
	}

	return store, func() { _ = rawDB.Close() }, uid
}

// Environment variables that supply the passphrase without a terminal.
//
// The daemon is meant to run unattended on an always-on machine, and
// term.ReadPassword needs a TTY that launchd and systemd do not provide, so
// without one of these the daemon simply cannot be started by a service
// manager.
//
// The file form is the one to recommend. A launchd plist lives in
// ~/Library/LaunchAgents and is world-readable, and a systemd unit's
// Environment= lines are readable via `systemctl show`, so putting the
// passphrase directly in the service definition publishes it to every local
// account. A path to a 0600 file does not.
const (
	passphraseEnv     = "MCTL_LOCAL_PASSPHRASE"
	passphraseFileEnv = "MCTL_LOCAL_PASSPHRASE_FILE"
)

// passphraseFromEnv returns the passphrase supplied out of band and whether
// one was supplied at all. The file form wins when both are set.
//
// getenv and readFile are parameters so the whole decision — including its
// failure paths — is testable without touching process state or the
// filesystem. promptPassphrase supplies the real ones.
func passphraseFromEnv(getenv func(string) string, readFile func(string) ([]byte, error)) ([]byte, bool, error) {
	if path := getenv(passphraseFileEnv); path != "" {
		data, err := readFile(path)
		if err != nil {
			return nil, true, fmt.Errorf("read %s: %w", passphraseFileEnv, err)
		}
		// A passphrase written with a text editor or with `echo` picks up a
		// trailing newline that is not part of it. Trimming here avoids a
		// key-check failure whose message would blame the passphrase rather
		// than the newline.
		pw := bytes.TrimRight(data, "\r\n")
		if len(pw) == 0 {
			return nil, true, fmt.Errorf("%s (%s) contains no passphrase", passphraseFileEnv, path)
		}
		return pw, true, nil
	}
	if pw := getenv(passphraseEnv); pw != "" {
		return []byte(pw), true, nil
	}
	return nil, false, nil
}

// restrictDBPerms narrows the local database to owner-only.
//
// Every file this command writes itself is created 0600, but the database is
// created by the SQLite driver under the process umask — 0644 on a default
// macOS or Linux account. The rows inside are sealed with the Argon2id key, so
// a readable file is not an immediate compromise; it does hand any other local
// account the ciphertext to attack the passphrase offline at its leisure,
// which is a different and much weaker guarantee than the one the 0600 on
// config.json implies.
//
// The -wal and -shm sidecars carry the same page contents and are recreated by
// the driver whenever the database is opened, so narrowing them once at
// creation would not hold; this runs on every open. They may legitimately not
// exist yet, and that is not an error.
func restrictDBPerms(dbPath string) error {
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(p, 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("restrict permissions on %s: %w", p, err)
		}
	}
	return nil
}

// promptPassphrase reads a passphrase without echo from the terminal, unless
// one was supplied through the environment.
func promptPassphrase(prompt string) []byte {
	pw, supplied, err := passphraseFromEnv(os.Getenv, os.ReadFile)
	if err != nil {
		die(err)
	}
	if supplied {
		return pw
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		die(fmt.Errorf("no terminal to read the passphrase from; set %s (path to a 0600 file, preferred) or %s",
			passphraseFileEnv, passphraseEnv))
	}
	fmt.Print(prompt)
	typed, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		die(fmt.Errorf("read passphrase: %w", err))
	}
	if len(typed) == 0 {
		die(errors.New("passphrase must not be empty"))
	}
	return typed
}

// mustDeriveKey wraps deriveKey and dies on error.
func mustDeriveKey(passphrase []byte, saltB64 string) []byte {
	key, err := deriveKey(passphrase, saltB64)
	if err != nil {
		die(err)
	}
	return key
}

// mustDeriveVerifiedKey derives the key and checks it against cfg.KeyCheck.
// If the check fails the passphrase is wrong; die early rather than letting
// an AES-GCM error surface later with no clear explanation.
func mustDeriveVerifiedKey(passphrase []byte, cfg *localConfig) []byte {
	key := mustDeriveKey(passphrase, cfg.KeySalt)
	if cfg.KeyCheck != "" && deriveKeyCheck(key) != cfg.KeyCheck {
		die(errors.New("wrong passphrase"))
	}
	return key
}

// promptStr reads a trimmed string from stdin with the given prompt.
func promptStr(r *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		die(fmt.Errorf("read input: %w", err))
	}
	return strings.TrimSpace(line)
}

// promptInt reads an integer from stdin.
func promptInt(r *bufio.Reader, prompt string) int {
	for {
		s := promptStr(r, prompt)
		n, err := strconv.Atoi(s)
		if err == nil && n > 0 {
			return n
		}
		fmt.Fprintln(os.Stderr, "Please enter a positive integer.")
	}
}

// hexDecodeLocal decodes a 64-char hex string to 32 bytes (mirrors
// internal/config.hexDecode, duplicated to keep cmd/local self-contained).
func hexDecodeLocal(s string) ([]byte, error) {
	if len(s) != 64 {
		return nil, fmt.Errorf("key hex must be 64 chars, got %d", len(s))
	}
	out := make([]byte, 32)
	for i := range out {
		hi, err := hexNib(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexNib(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexNib(b byte) (byte, error) {
	switch {
	case b >= '0' && b <= '9':
		return b - '0', nil
	case b >= 'a' && b <= 'f':
		return b - 'a' + 10, nil
	case b >= 'A' && b <= 'F':
		return b - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char %q", b)
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
