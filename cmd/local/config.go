package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// writeFileAtomic writes data to path via a temp-file + fsync + rename so a
// crash mid-write never leaves a partially-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // no-op if rename succeeded
	}()
	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	return nil
}

// localConfig is the persisted JSON at ~/.config/mctl-telegram-local/config.json.
type localConfig struct {
	APIID    int    `json:"api_id"`
	APIHash  string `json:"api_hash"`
	Server   string `json:"server"`
	KeySalt  string `json:"key_salt"`  // base64-encoded 16-byte Argon2id salt
	KeyCheck string `json:"key_check"` // HMAC-SHA256(key, "mctl-telegram-local-check")[:16], base64
}

// bridgeTokenFile is the persisted JSON at ~/.config/mctl-telegram-local/bridge_token.json.
type bridgeTokenFile struct {
	MCPToken    string `json:"mcp_token"`
	BridgeToken string `json:"bridge_token"`
	ExpiresAt   string `json:"expires_at"`
}

// deviceKeyFile is the persisted JSON at
// ~/.config/mctl-telegram-local/device_key.json. DeviceRegistrationKey is an
// opaque idempotency key (see internal/db/local_bridge_devices.go /
// RegisterDevice) -- never a device id, which is server-generated and
// returned only by a successful activation.
type deviceKeyFile struct {
	DeviceRegistrationKey string `json:"device_registration_key"`
}

const (
	configDir       = ".config/mctl-telegram-local"
	configFileName  = "config.json"
	bridgeTokenName = "bridge_token.json"
	deviceKeyName   = "device_key.json"
	dbFileName      = "state.db"
)

func configDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	return filepath.Join(home, configDir), nil
}

func configFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, configFileName), nil
}

func bridgeTokenFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, bridgeTokenName), nil
}

func deviceKeyFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, deviceKeyName), nil
}

// loadOrCreateDeviceKey returns the persisted device_registration_key,
// generating and saving a fresh one on first use. Reused on every subsequent
// `activate` run so a retry (network failure, closed browser tab, or a
// completely separate later run) resolves to the SAME local_bridge_devices
// row instead of registering a duplicate device -- see RegisterDevice's
// (user_id, idempotency_key) contract (issue #481).
func loadOrCreateDeviceKey() (string, error) {
	p, err := deviceKeyFilePath()
	if err != nil {
		return "", err
	}
	if data, err := os.ReadFile(p); err == nil {
		var dk deviceKeyFile
		if jerr := json.Unmarshal(data, &dk); jerr == nil && dk.DeviceRegistrationKey != "" {
			return dk.DeviceRegistrationKey, nil
		}
		// Fall through and regenerate if the file is present but unreadable
		// or empty -- better than refusing to activate at all.
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read device key: %w", err)
	}

	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("generate device key: %w", err)
	}
	key := base64.RawURLEncoding.EncodeToString(keyBytes)

	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(deviceKeyFile{DeviceRegistrationKey: key}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal device key: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, deviceKeyName), data, 0o600); err != nil {
		return "", fmt.Errorf("write device key: %w", err)
	}
	return key, nil
}

func dbFilePath() (string, error) {
	dir, err := configDirPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, dbFileName), nil
}

func loadConfig() (*localConfig, error) {
	p, err := configFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config not found — run `mctl-telegram-local init` first")
		}
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg localConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.APIID == 0 || cfg.APIHash == "" {
		return nil, fmt.Errorf("config is incomplete — re-run `mctl-telegram-local init`")
	}
	return &cfg, nil
}

func saveConfig(cfg *localConfig) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, configFileName), data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func loadBridgeToken() (*bridgeTokenFile, error) {
	p, err := bridgeTokenFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("bridge token not found — run `mctl-telegram-local connect --token <mcp-token>` first")
		}
		return nil, fmt.Errorf("read bridge token: %w", err)
	}
	var bt bridgeTokenFile
	if err := json.Unmarshal(data, &bt); err != nil {
		return nil, fmt.Errorf("parse bridge token: %w", err)
	}
	if bt.BridgeToken == "" {
		return nil, fmt.Errorf("bridge token file is invalid — re-run `mctl-telegram-local connect`")
	}
	return &bt, nil
}

func saveBridgeToken(bt *bridgeTokenFile) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(bt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal bridge token: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, bridgeTokenName), data, 0o600); err != nil {
		return fmt.Errorf("write bridge token: %w", err)
	}
	return nil
}

// deriveKey derives a 32-byte AES key from a passphrase and base64-encoded salt
// using Argon2id. The salt is 16 bytes. Argon2id parameters match the init command.
func deriveKey(passphrase []byte, saltB64 string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	if len(salt) != 16 {
		return nil, fmt.Errorf("salt must be 16 bytes, got %d", len(salt))
	}
	key := argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32)
	return key, nil
}

// deriveKeyCheck computes a 16-byte HMAC verifier from the derived key.
// Stored in config so a wrong passphrase is detected early rather than
// surfacing as a cryptic AES-GCM decryption error.
func deriveKeyCheck(key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("mctl-telegram-local-check"))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16])
}

// generateSalt generates a fresh random 16-byte salt and returns its base64 encoding.
func generateSalt() (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// bridgeTokenExpiry parses the ExpiresAt field from a bridgeTokenFile.
func bridgeTokenExpiry(bt *bridgeTokenFile) (time.Time, error) {
	if bt.ExpiresAt == "" {
		return time.Time{}, fmt.Errorf("bridge token has no expiry — re-run connect")
	}
	t, err := time.Parse(time.RFC3339, bt.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expires_at %q: %w", bt.ExpiresAt, err)
	}
	return t, nil
}

// encryptionKeyHex converts a 32-byte key to the 64-char hex string that
// internal/config.Load() expects from ENCRYPTION_KEY.
func encryptionKeyHex(key []byte) string {
	const hextable = "0123456789abcdef"
	out := make([]byte, len(key)*2)
	for i, b := range key {
		out[i*2] = hextable[b>>4]
		out[i*2+1] = hextable[b&0xf]
	}
	return string(out)
}

// sqliteDSN turns a filesystem path into the "file:" URI that the SQLite
// driver expects.
//
// The path cannot simply be concatenated after "file:". On Windows it looks
// like `C:\Users\me\.config\mctl-telegram-local\state.db`: the backslashes are
// not URI path separators and the drive colon is read as the start of a URI
// authority, so the driver is handed a path that does not exist and the daemon
// fails at its very first step. The same concatenation is also wrong on any
// platform once the path contains a character that means something in a URI —
// a space, a '#' or a '?' in a user's home directory is enough.
//
// Building the URI properly fixes both: separators are normalised to forward
// slashes, a drive-letter path gets the leading slash that makes
// `file:///C:/Users/...` a valid absolute file URI, and url.URL escapes the
// rest.
func sqliteDSN(path string) string {
	p := filepath.ToSlash(path)
	// filepath.ToSlash only rewrites the separator of the platform it runs on,
	// so on a POSIX build it leaves a Windows path untouched. Recognising the
	// drive-letter prefix lets the conversion — and its test — be the same
	// everywhere. A POSIX absolute path starts with "/" and never matches, so
	// a backslash that is genuinely part of a Unix filename survives.
	if hasWindowsDriveLetter(p) {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	// `C:/Users/...` must become `/C:/Users/...`, otherwise "C:" parses as a
	// scheme-relative authority rather than as part of the path.
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	return u.String()
}

// hasWindowsDriveLetter reports whether p begins with a drive specifier such
// as "C:", "C:/" or `C:\`.
//
// The drive letter must be followed by a separator or by nothing at all. A
// colon is a legal character in a POSIX filename, so a relative path like
// "a:b/foo" would otherwise be mistaken for a drive path and have a leading
// slash prepended — quietly turning a relative path into an absolute one.
// Today the only caller passes an absolute path derived from
// os.UserHomeDir(), so that case is unreachable; requiring the separator
// keeps it unreachable if the helper is ever reused.
func hasWindowsDriveLetter(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
		return false
	}
	return len(p) == 2 || p[2] == '/' || p[2] == '\\'
}
