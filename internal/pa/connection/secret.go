package connection

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
)

// Secret holds a token or an authorization code in memory. Every way of
// printing it -- fmt verbs, slog, JSON -- yields "[redacted]", so a Secret
// passed to a logger by mistake leaks nothing (threat model T3, S1-K1). Only
// Reveal returns the value, and only the executor's outbound call and the
// DEK seal should call it.
type Secret struct{ v string }

// NewSecret wraps v.
func NewSecret(v string) Secret { return Secret{v: v} }

// Reveal returns the plaintext.
func (s Secret) Reveal() string { return s.v }

// Empty reports whether no value is held.
func (s Secret) Empty() bool { return s.v == "" }

const redacted = "[redacted]"

func (Secret) String() string               { return redacted }
func (Secret) GoString() string             { return redacted }
func (Secret) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
func (Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(redacted)) }
func (s *Secret) UnmarshalJSON(_ []byte) error {
	return errors.New("pa connection: a Secret is never decoded from JSON")
}
func (s *Secret) UnmarshalText(_ []byte) error {
	return errors.New("pa connection: a Secret is never decoded from text")
}

const dekSize = 32

// newDEK returns a fresh random per-connection data-encryption key.
func newDEK() ([]byte, error) {
	k := make([]byte, dekSize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("pa connection: dek: %w", err)
	}
	return k, nil
}

// Seal purposes. The purpose is part of the associated data, so a sealed
// authorization code can never be opened as a token set or the reverse.
const (
	purposeCode   = "code"
	purposeTokens = "tokens"
)

// aad binds a sealed blob to its connection and principal, so a blob copied
// into another row (by someone with database write access) does not open
// there even though both rows' DEKs are wrapped by the same KEK.
func aad(principal int64, id, purpose string) []byte {
	return []byte("pa-connection/v1|" + strconv.FormatInt(principal, 10) + "|" + id + "|" + purpose)
}

func sealWithDEK(dek, plaintext, ad []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, errors.New("pa connection: bad dek length")
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("pa connection: seal: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("pa connection: seal: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pa connection: seal nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, ad), nil
}

func openWithDEK(dek, blob, ad []byte) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, fmt.Errorf("%w: bad dek length", ErrUnreadable)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrUnreadable, err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: open: %v", ErrUnreadable, err)
	}
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, fmt.Errorf("%w: sealed blob too short", ErrUnreadable)
	}
	pt, err := gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], ad)
	if err != nil {
		return nil, fmt.Errorf("%w: sealed blob does not open", ErrUnreadable)
	}
	return pt, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
