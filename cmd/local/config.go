package main

import (
	"bytes"
	"crypto/ed25519"
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

// deviceRecord is the persisted JSON at
// ~/.config/mctl-telegram-local/device_key.json (same path as the pre-#484
// opaque-key-only file, for a smooth upgrade -- only the Go shape and the
// concept it represents changed, from "device key" to "device identity").
//
// It holds EVERYTHING about this device's Local Bridge identity and,
// once issued, its credential, in ONE record written atomically via
// writeFileAtomic. See design.md's "One file, deliberately": splitting the
// key material and the credential issued against it across two files is
// what let them be written apart and end up naming different devices.
type deviceRecord struct {
	// DeviceRegistrationKey is RegisterDevice's idempotency key (see
	// internal/db/local_bridge_devices.go) -- never a device id, which is
	// server-generated and returned only by a successful activation.
	DeviceRegistrationKey string `json:"device_registration_key"`

	// PrivateKey is the Ed25519 SEED (ed25519.SeedSize == 32 bytes), base64
	// standard encoded -- NEVER the 64-byte ed25519.PrivateKey. See
	// deviceIdentityUsable for the exact validation this relies on.
	PrivateKey string `json:"private_key,omitempty"`
	// PublicKey is the Ed25519 public key (ed25519.PublicKeySize == 32
	// bytes), base64 standard encoded.
	PublicKey string `json:"public_key,omitempty"`

	// The following four fields are populated once the post-activation
	// credential bootstrap (or a later daemon refresh) succeeds. Empty
	// until then -- an "identity-only" record (design.md's "interrupted
	// activation" case).
	DeviceID    string `json:"device_id,omitempty"`
	WorkerToken string `json:"worker_token,omitempty"`
	ExpiresAt   string `json:"expires_at,omitempty"`
	Jti         string `json:"jti,omitempty"`
}

const (
	configDir       = ".config/mctl-telegram-local"
	configFileName  = "config.json"
	bridgeTokenName = "bridge_token.json"
	deviceKeyName   = "device_key.json"
	deviceLockName  = "device.lock"
	dbFileName      = "state.db"
)

// deviceLockTimeout/deviceLockRetryInterval govern withDeviceRecordLock: wait
// up to deviceLockTimeout, polling every deviceLockRetryInterval, before
// reporting contention. Both holders (activate and a daemon refresh) only
// ever hold the lock around a local file read-modify-write, so a short
// timeout is enough to let a routine race resolve itself; see
// withDeviceRecordLock's doc comment for why this waits rather than failing
// fast.
const (
	deviceLockTimeout       = 5 * time.Second
	deviceLockRetryInterval = 100 * time.Millisecond
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

// generateDeviceRegistrationKey generates a fresh opaque 32-byte
// idempotency key for RegisterDevice, matching the encoding the pre-#484
// code used for its one and only key.
func generateDeviceRegistrationKey() (string, error) {
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", fmt.Errorf("generate device registration key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(keyBytes), nil
}

// deviceLockFilePath returns the lockfile path used by withDeviceRecordLock.
func deviceLockFilePath(configDir string) string {
	return filepath.Join(configDir, deviceLockName)
}

// withDeviceRecordLock acquires an exclusive lock on the device record --
// an advisory flock (LockFileEx on Windows) on a lockfile in configDir, no
// external dependency needed. The lock lives on the open handle rather than
// on the file's existence, so the kernel releases it when the holder dies
// however it dies; a leftover lockfile is inert -- runs fn, and releases the lock. Used by BOTH activate's record
// read-modify-writes and the daemon's credential-merge writes (design.md,
// "activate serialises its record writes").
//
// Acquisition WAITS, retrying every deviceLockRetryInterval until timeout
// elapses, rather than failing fast: both holders only ever hold the lock
// around a local file read-modify-write, so a routine daemon refresh racing
// an activate run should simply wait a moment and succeed, not error out for
// a reason the user cannot act on. Only report contention once the timeout
// is exhausted.
//
// Critically, this must be called ONLY around the local file
// read-modify-write -- NEVER across activate's unbounded browser-wait/poll
// loop or any network round trip beyond what a single merge needs. That wait
// ends when a human finishes signing in, or never, and holding a
// cross-process lock across it would starve a running daemon's refresh until
// its credential expired and its connection dropped.
func withDeviceRecordLock(configDir string, timeout time.Duration, fn func() error) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	lockPath := deviceLockFilePath(configDir)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open device lock file: %w", err)
	}
	defer f.Close()

	deadline := time.Now().Add(timeout)
	for {
		got, err := lockFileExclusive(f)
		if err != nil {
			return fmt.Errorf("lock device record: %w", err)
		}
		if got {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("another activation or daemon refresh is already running (device lock held past %v) -- try again shortly", timeout)
		}
		time.Sleep(deviceLockRetryInterval)
	}
	// The lockfile itself is left in place deliberately: the lock lives on the
	// open handle, not on the file's existence, so a leftover file is inert and
	// removing it would only race a process that is holding it.
	defer unlockFile(f)
	return fn()
}

// readDeviceRecord reads the on-disk device record, returning an empty
// (zero-value) record if the file does not exist or does not parse as JSON
// -- callers that need to distinguish absent from corrupt for branching
// purposes use loadDeviceRecordIfPresent instead. Unlocked -- callers that
// mutate the result and write it back must wrap the whole
// read-modify-write in withDeviceRecordLock.
func readDeviceRecord() (*deviceRecord, error) {
	p, err := deviceKeyFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &deviceRecord{}, nil
		}
		return nil, fmt.Errorf("read device record: %w", err)
	}
	var rec deviceRecord
	if jerr := json.Unmarshal(data, &rec); jerr != nil {
		// Treated the same as an absent record: repaired in place rather
		// than refusing to activate at all.
		return &deviceRecord{}, nil
	}
	return &rec, nil
}

// loadDeviceRecordIfPresent reads the device record WITHOUT generating or
// repairing anything, distinguishing "no file at all" (nil, nil -- legacy or
// fresh install) from "file present but unparseable" (nil, err). The daemon
// uses this rather than loadOrCreateDeviceIdentity because it must never
// generate or rotate key material itself (design.md: "on unusable key
// material it stops with a message naming activate").
func loadDeviceRecordIfPresent() (*deviceRecord, error) {
	p, err := deviceKeyFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read device record: %w", err)
	}
	var rec deviceRecord
	if jerr := json.Unmarshal(data, &rec); jerr != nil {
		return nil, fmt.Errorf("parse device record: %w", jerr)
	}
	return &rec, nil
}

// writeDeviceRecord marshals and atomically persists rec at 0600. Unlocked
// -- callers that need read-modify-write atomicity wrap this (and the
// preceding read) in withDeviceRecordLock.
func writeDeviceRecord(rec *deviceRecord) error {
	dir, err := configDirPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device record: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, deviceKeyName), data, 0o600); err != nil {
		return fmt.Errorf("write device record: %w", err)
	}
	return nil
}

// deviceIdentityUsable reports whether privB64/pubB64 decode to a valid,
// matching Ed25519 keypair -- see design.md's "Usable means" for the exact
// checks and why each matters:
//
//   - both fields present (a pre-#484 record has neither)
//   - valid base64
//   - private decodes to EXACTLY ed25519.SeedSize (32) bytes -- NOT
//     ed25519.PrivateKeySize (64), which would reject the very seed this
//     design stores
//   - public decodes to EXACTLY ed25519.PublicKeySize (32) bytes
//   - the two halves are actually a pair: deriving the public key from the
//     seed must equal the stored public key byte-for-byte
//
// Anything else is treated as unusable and MUST be regenerated rather than
// passed to ed25519.Sign/Verify, which panic on a malformed key instead of
// returning an error.
func deviceIdentityUsable(privB64, pubB64 string) (priv ed25519.PrivateKey, pub ed25519.PublicKey, ok bool) {
	if privB64 == "" || pubB64 == "" {
		return nil, nil, false
	}
	seed, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, false
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, nil, false
	}
	derivedPriv := ed25519.NewKeyFromSeed(seed)
	derivedPub, ok := derivedPriv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derivedPub, pubBytes) {
		return nil, nil, false
	}
	return derivedPriv, derivedPub, true
}

// deviceCredentialUsable reports whether rec carries a complete,
// well-formed device credential: device_id, worker_token, expires_at and
// jti all present, and worker_token has the three-segment shape of a JWT.
// This is a local shape check only, not an authentication decision -- the
// server is the only party that verifies the token.
func deviceCredentialUsable(rec *deviceRecord) bool {
	if rec == nil {
		return false
	}
	if rec.DeviceID == "" || rec.WorkerToken == "" || rec.ExpiresAt == "" || rec.Jti == "" {
		return false
	}
	return strings.Count(rec.WorkerToken, ".") == 2
}

// deviceCredentialExpiry parses rec.ExpiresAt as RFC3339.
func deviceCredentialExpiry(rec *deviceRecord) (time.Time, error) {
	if rec == nil || rec.ExpiresAt == "" {
		return time.Time{}, fmt.Errorf("device credential has no expiry")
	}
	t, err := time.Parse(time.RFC3339, rec.ExpiresAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse expires_at %q: %w", rec.ExpiresAt, err)
	}
	return t, nil
}

// loadOrCreateDeviceIdentity loads the persisted device record, repairing or
// generating its Ed25519 key material as needed, and returns the
// (possibly rewritten) record along with the parsed private/public key.
// Every caller that needs to sign a PoP challenge goes through this rather
// than reading the file directly, so the "usable or regenerate" rule in
// design.md lives in exactly one place. Only `activate` calls this -- the
// daemon must never generate or rotate key material itself, so it uses
// loadDeviceRecordIfPresent instead.
//
// The read-modify-write is performed under the device lock so a concurrent
// daemon merge cannot land a credential on a record this call is about to
// replace.
func loadOrCreateDeviceIdentity() (*deviceRecord, ed25519.PrivateKey, ed25519.PublicKey, error) {
	dir, err := configDirPath()
	if err != nil {
		return nil, nil, nil, err
	}
	var (
		rec  *deviceRecord
		priv ed25519.PrivateKey
		pub  ed25519.PublicKey
	)
	err = withDeviceRecordLock(dir, deviceLockTimeout, func() error {
		var rerr error
		rec, rerr = readDeviceRecord()
		if rerr != nil {
			return rerr
		}

		if p, u, ok := deviceIdentityUsable(rec.PrivateKey, rec.PublicKey); ok {
			priv, pub = p, u
			// Existing key material is usable -- nothing to repair or
			// rewrite. A missing device_registration_key here would mean a
			// hand-edited file; complete it without rotating (there is no
			// prior registration to orphan).
			if rec.DeviceRegistrationKey == "" {
				regKey, rkErr := generateDeviceRegistrationKey()
				if rkErr != nil {
					return rkErr
				}
				rec.DeviceRegistrationKey = regKey
				return writeDeviceRecord(rec)
			}
			return nil
		}

		// Key material is unusable: absent, undecodable, wrong length, or a
		// non-matching pair. The pre-#484 (#482-era) case -- a record that
		// never had Ed25519 fields at all -- is the exception to rotation:
		// completing it in place binds device_registration_key to a public
		// key for the FIRST time, so there is no existing row holding a
		// DIFFERENT pubkey for the same key to collide with. See design.md's
		// "The #482 case is the exception".
		firstTime := rec.PrivateKey == "" && rec.PublicKey == ""

		newPub, newPriv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return fmt.Errorf("generate device keypair: %w", genErr)
		}
		priv, pub = newPriv, newPub
		rec.PrivateKey = base64.StdEncoding.EncodeToString(newPriv.Seed())
		rec.PublicKey = base64.StdEncoding.EncodeToString(newPub)

		if !firstTime {
			// Key material is being REPLACED, not supplied for the first
			// time -- rotate the registration key (it is RegisterDevice's
			// idempotency key, bound to the OLD public key) and drop any
			// credential issued against the identity being discarded; see
			// design.md's "Regenerating the keypair MUST also rotate
			// device_registration_key".
			regKey, rkErr := generateDeviceRegistrationKey()
			if rkErr != nil {
				return rkErr
			}
			rec.DeviceRegistrationKey = regKey
			rec.DeviceID = ""
			rec.WorkerToken = ""
			rec.ExpiresAt = ""
			rec.Jti = ""
		} else if rec.DeviceRegistrationKey == "" {
			regKey, rkErr := generateDeviceRegistrationKey()
			if rkErr != nil {
				return rkErr
			}
			rec.DeviceRegistrationKey = regKey
		}
		return writeDeviceRecord(rec)
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return rec, priv, pub, nil
}

// mergeDeviceCredential re-reads the on-disk record under the device lock,
// re-validates that its public key still matches signingPub -- the key
// whose private half signed the PoP operation that produced this credential
// -- and, if so, merges {deviceID, workerToken, expiresAt, jti} into it and
// writes it back atomically. See design.md's "Every writer re-validates the
// identity before merging".
//
// The write is abandoned (merged=false, err=nil) when:
//   - the on-disk public key no longer matches signingPub: a concurrent
//     activate run replaced the identity, and this credential belongs to a
//     device the current identity is no longer registered as; or
//   - the on-disk record already carries a usable credential for the SAME
//     device_id that expires LATER than the one being written (avoids a
//     stale write clobbering a newer one).
//
// Every other case -- including a stored credential naming a DIFFERENT
// device, or one that is not usable at all -- is replaced unconditionally,
// regardless of its recorded expiry: stale data must never veto a write
// that supersedes it.
func mergeDeviceCredential(signingPub ed25519.PublicKey, deviceID, workerToken, expiresAt, jti string) (merged bool, err error) {
	dir, err := configDirPath()
	if err != nil {
		return false, err
	}
	lockErr := withDeviceRecordLock(dir, deviceLockTimeout, func() error {
		rec, rerr := readDeviceRecord()
		if rerr != nil {
			return rerr
		}
		_, curPub, ok := deviceIdentityUsable(rec.PrivateKey, rec.PublicKey)
		if !ok || !bytes.Equal(curPub, signingPub) {
			// Identity moved out from under us (or was never usable to begin
			// with) -- abandon the write rather than land a credential next
			// to key material it was never issued for.
			return nil
		}
		if rec.DeviceID == deviceID && deviceCredentialUsable(rec) {
			curExpiry, cerr := deviceCredentialExpiry(rec)
			newExpiry, nerr := time.Parse(time.RFC3339, expiresAt)
			if cerr == nil && nerr == nil && curExpiry.After(newExpiry) {
				// On-disk credential for the same device already expires
				// later than the one we're about to write -- don't clobber
				// a newer credential with a stale one.
				return nil
			}
		}
		rec.DeviceID = deviceID
		rec.WorkerToken = workerToken
		rec.ExpiresAt = expiresAt
		rec.Jti = jti
		merged = true
		return writeDeviceRecord(rec)
	})
	if lockErr != nil {
		return false, lockErr
	}
	return merged, nil
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
