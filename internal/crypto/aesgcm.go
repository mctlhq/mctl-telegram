package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

// AESGCM wraps a 32-byte AES-256-GCM key for sealing/opening session blobs.
// Zero-value Key disables encryption (sentinel for local-dev only) — callers
// must check Enabled() before using in production paths.
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

// Seal encrypts plaintext and returns nonce|ciphertext|tag. When Key is empty,
// plaintext is returned unchanged with a leading 0x00 byte (sentinel "plaintext").
func (a *AESGCM) Seal(plaintext []byte) ([]byte, error) {
	if !a.Enabled() {
		return append([]byte{0x00}, plaintext...), nil
	}
	block, err := aes.NewCipher(a.Key)
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
	out := make([]byte, 0, 1+len(nonce)+len(ct))
	out = append(out, 0x01)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

func (a *AESGCM) Open(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, errors.New("empty blob")
	}
	switch blob[0] {
	case 0x00:
		return blob[1:], nil
	case 0x01:
		if !a.Enabled() {
			return nil, errors.New("blob is encrypted but no key configured")
		}
		block, err := aes.NewCipher(a.Key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		ns := gcm.NonceSize()
		if len(blob) < 1+ns {
			return nil, errors.New("blob too short")
		}
		nonce := blob[1 : 1+ns]
		ct := blob[1+ns:]
		return gcm.Open(nil, nonce, ct, nil)
	default:
		return nil, fmt.Errorf("unknown blob version 0x%02x", blob[0])
	}
}
