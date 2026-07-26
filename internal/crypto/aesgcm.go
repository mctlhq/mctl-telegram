package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Blob version bytes. The first byte of every stored session blob identifies
// how the rest is structured so old rows keep decoding after we change the
// scheme. Callers do not need these constants in their normal paths — Open
// dispatches on them internally — but they are exported so store-level
// migration helpers can distinguish v1 (master key) from v2 (per-user key)
// when deciding whether to re-seal.
const (
	VersionPlaintext byte = 0x00 // local-dev only, no encryption
	VersionMaster    byte = 0x01 // legacy: AES-GCM with the global master key
	VersionPerUser   byte = 0x02 // current: AES-GCM with HKDF-derived per-user key
)

// hkdfInfo is the application-specific context label mixed into key
// derivation. Changing it would invalidate every existing v2 blob, so it is
// intentionally hard-coded.
const hkdfInfo = "mctl-telegram-session-v2"

// AESGCM wraps a 32-byte AES-256-GCM master key. The master key itself is
// only used for v1 (legacy) blobs; v2 blobs use a per-user subkey derived
// from the master via HKDF-SHA256. A zero-length Key disables encryption
// entirely (sentinel for local-dev only) — callers must check Enabled()
// before using in production paths.
type AESGCM struct {
	Key []byte
}

func New(key []byte) (*AESGCM, error) {
	if len(key) != 0 && len(key) != 32 {
		return nil, fmt.Errorf("AES-256-GCM key must be 32 bytes, got %d", len(key))
	}
	return &AESGCM{Key: key}, nil
}

func (a *AESGCM) Enabled() bool { return len(a.Key) == 32 }

// Seal encrypts plaintext with the master key and tags the output with
// VersionMaster (0x01). Deprecated for new writes — prefer SealForUser so
// every row gets its own subkey. Retained because the login CLI and unit
// tests still produce legacy blobs that the store layer migrates on read.
func (a *AESGCM) Seal(plaintext []byte) ([]byte, error) {
	if !a.Enabled() {
		return append([]byte{VersionPlaintext}, plaintext...), nil
	}
	ct, err := aesGCMSeal(a.Key, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(ct))
	out = append(out, VersionMaster)
	out = append(out, ct...)
	return out, nil
}

func (a *AESGCM) Open(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty blob")
	}
	switch blob[0] {
	case VersionPlaintext:
		return blob[1:], nil
	case VersionMaster:
		if !a.Enabled() {
			return nil, errors.New("blob is encrypted but no key configured")
		}
		return aesGCMOpen(a.Key, blob[1:])
	case VersionPerUser:
		return nil, errors.New("blob is v2 (per-user); call OpenForUser with the user id")
	default:
		return nil, fmt.Errorf("unknown blob version 0x%02x", blob[0])
	}
}

// BlobVersion returns the leading version byte of the blob, or 0xFF on empty
// input. Useful for store-layer lazy migration: callers can check whether a
// row is still v1 after a successful Open and queue a re-seal.
func (a *AESGCM) BlobVersion(blob []byte) byte {
	if len(blob) == 0 {
		return 0xFF
	}
	return blob[0]
}

// SealForUser encrypts plaintext with a per-user key derived from the master
// key via HKDF-SHA256. The output blob is tagged with VersionPerUser (0x02)
// and is independent of the master key for cryptanalysis purposes — a
// compromise of one user's derived key does not let an attacker read any
// other user's blob, and a compromise of the master only matters if the
// attacker also knows the user_id of every row (trivial via SQL access, but
// it forces the attacker to derive each subkey separately instead of using
// one global key).
//
// When the master key is not configured (local-dev mode) this falls back to
// the legacy plaintext form so the dev loop still works.
func (a *AESGCM) SealForUser(plaintext []byte, userID int64) ([]byte, error) {
	if !a.Enabled() {
		return append([]byte{VersionPlaintext}, plaintext...), nil
	}
	subkey, err := deriveUserKey(a.Key, userID)
	if err != nil {
		return nil, err
	}
	ct, err := aesGCMSeal(subkey, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+len(ct))
	out = append(out, VersionPerUser)
	out = append(out, ct...)
	return out, nil
}

// OpenForUser decrypts a session blob and is the canonical entry point used
// by store-layer code. It accepts every legitimate version:
//
//   - VersionPlaintext (0x00) — returns the trailing bytes unchanged.
//   - VersionMaster    (0x01) — decrypts with the master key. Caller should
//     re-seal the result with SealForUser to migrate
//     the row.
//   - VersionPerUser   (0x02) — decrypts with the HKDF-derived subkey for
//     userID. The userID MUST match the row's
//     user_id; otherwise the GCM tag check fails
//     with an error.
//
// Unknown versions are reported with a descriptive error so a future v3
// upgrade can be diagnosed clearly.
func (a *AESGCM) OpenForUser(blob []byte, userID int64) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty blob")
	}
	switch blob[0] {
	case VersionPlaintext:
		return blob[1:], nil
	case VersionMaster:
		if !a.Enabled() {
			return nil, errors.New("blob is encrypted but no key configured")
		}
		return aesGCMOpen(a.Key, blob[1:])
	case VersionPerUser:
		if !a.Enabled() {
			return nil, errors.New("blob is encrypted but no key configured")
		}
		subkey, err := deriveUserKey(a.Key, userID)
		if err != nil {
			return nil, err
		}
		return aesGCMOpen(subkey, blob[1:])
	default:
		return nil, fmt.Errorf("unknown blob version 0x%02x", blob[0])
	}
}

// BlindIndexForUser returns a deterministic tenant-scoped HMAC suitable for
// indexed equality lookup of a short secret. Unlike an unkeyed hash, a DB-only
// compromise cannot offline-enumerate a low-entropy value such as a six-digit
// approval code. purpose is part of the HKDF context so an index key cannot be
// reused across application domains.
func (a *AESGCM) BlindIndexForUser(purpose string, value []byte, userID int64) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("blind-index purpose required")
	}
	var key []byte
	if a.Enabled() {
		var err error
		key, err = deriveKey(a.Key, userID, "mctl-telegram-blind-index-v1:"+purpose)
		if err != nil {
			return nil, err
		}
	} else {
		// Local development intentionally supports a missing encryption key.
		// Keep lookup deterministic there without pretending it protects the
		// local plaintext database.
		sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", purpose, userID)))
		key = sum[:]
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(value)
	return mac.Sum(nil), nil
}

// deriveUserKey runs HKDF-SHA256(master, salt=user_id_be64, info=hkdfInfo)
// to obtain a 32-byte AES-256 subkey. Different user IDs produce
// cryptographically independent keys.
func deriveUserKey(master []byte, userID int64) ([]byte, error) {
	return deriveKey(master, userID, hkdfInfo)
}

func deriveKey(master []byte, userID int64, info string) ([]byte, error) {
	salt := make([]byte, 8)
	binary.BigEndian.PutUint64(salt, uint64(userID))
	r := hkdf.New(sha256.New, master, salt, []byte(info))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return out, nil
}

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func aesGCMOpen(key, body []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(body) < ns {
		return nil, errors.New("blob too short")
	}
	return gcm.Open(nil, body[:ns], body[ns:], nil)
}
