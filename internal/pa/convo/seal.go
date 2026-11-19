package convo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
)

// KeyInfo is the HKDF info label of the per-principal fragment key (PR #1329
// decision for slice b). Changing it makes every stored fragment unreadable,
// which is acceptable only because conversation state lives at most one TTL.
const KeyInfo = "mctl-pa-conversation/v1"

// sealVersion is the first byte of every sealed fragment.
const sealVersion byte = 0x01

// aadLabel prefixes the additional data so a fragment blob cannot be
// confused with any other AES-GCM blob sealed under a related key.
const aadLabel = "mctl-pa-fragment/v1"

// ErrSealerKey is returned by NewSealer for anything but a 32-byte key.
var ErrSealerKey = errors.New("pa convo: sealer needs a 32-byte master key")

// Sealer encrypts fragment text with a key derived per principal from the
// service master key (HKDF-SHA256, salt = principal, info = KeyInfo). The
// additional data binds the principal, conversation, sequence number, kind
// and provenance mark: a blob moved to another row, or a mark flipped from
// external to user in the database, fails to open.
type Sealer struct{ master []byte }

// NewSealer builds a Sealer. There is no plaintext fallback: without a key,
// conversation state cannot be stored at all.
func NewSealer(master []byte) (*Sealer, error) {
	if len(master) != 32 {
		return nil, ErrSealerKey
	}
	return &Sealer{master: append([]byte(nil), master...)}, nil
}

func (s *Sealer) aead(principal int64) (cipher.AEAD, error) {
	if principal <= 0 {
		return nil, fmt.Errorf("%w: no principal", ErrInvalid)
	}
	key, err := crypto.DeriveSubkey(s.master, principal, KeyInfo)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func fragmentAAD(principal int64, conversationID string, seq int64, kind Kind, prov Provenance) []byte {
	b := make([]byte, 0, len(aadLabel)+len(conversationID)+len(kind)+len(prov)+40)
	b = append(b, aadLabel...)
	b = binary.BigEndian.AppendUint64(b, uint64(principal))
	b = binary.BigEndian.AppendUint64(b, uint64(seq))
	for _, part := range []string{conversationID, string(kind), string(prov)} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return b
}

// MaxFragmentBytes bounds the text of one sealed fragment. Telegram caps a
// message at 4096 UTF-16 code units (at most 12 KiB of UTF-8) and a caption
// at 1024, so no genuine update comes near it; the bound keeps the sealed
// buffer's size computation from overflowing on an absurd input.
const MaxFragmentBytes = 64 << 10

// Seal returns the stored form of f at (principal, conversationID, seq).
func (s *Sealer) Seal(principal int64, conversationID string, seq int64, f Fragment) (SealedFragment, error) {
	if conversationID == "" || seq <= 0 || !f.kind.Valid() || !f.prov.Known() {
		return SealedFragment{}, fmt.Errorf("%w: fragment", ErrInvalid)
	}
	if len(f.text) > MaxFragmentBytes {
		return SealedFragment{}, fmt.Errorf("%w: fragment of %d bytes", ErrInvalid, len(f.text))
	}
	gcm, err := s.aead(principal)
	if err != nil {
		return SealedFragment{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return SealedFragment{}, err
	}
	out := make([]byte, 0, 1+len(nonce)+len(f.text)+gcm.Overhead())
	out = append(out, sealVersion)
	out = append(out, nonce...)
	out = gcm.Seal(out, nonce, []byte(f.text), fragmentAAD(principal, conversationID, seq, f.kind, f.prov))
	return SealedFragment{
		ConversationID: conversationID,
		Seq:            seq,
		Principal:      principal,
		Kind:           f.kind,
		Provenance:     f.prov,
		Sealed:         out,
	}, nil
}

// Open decodes a stored fragment for principal. The text comes back only
// inside a Fragment, together with the mark the row carried. A row without
// a known mark is ErrUnmarked and is never decoded; a row that does not open
// under the principal's key and its own (conversation, seq, kind, mark) is
// ErrUnreadable.
func (s *Sealer) Open(principal int64, sf SealedFragment) (Fragment, error) {
	if !sf.Provenance.Known() {
		return Fragment{}, ErrUnmarked
	}
	if sf.Principal != principal || !sf.Kind.Valid() {
		return Fragment{}, fmt.Errorf("%w: fragment row", ErrUnreadable)
	}
	gcm, err := s.aead(principal)
	if err != nil {
		return Fragment{}, err
	}
	ns := gcm.NonceSize()
	if len(sf.Sealed) < 1+ns || sf.Sealed[0] != sealVersion {
		return Fragment{}, fmt.Errorf("%w: fragment blob", ErrUnreadable)
	}
	nonce, body := sf.Sealed[1:1+ns], sf.Sealed[1+ns:]
	pt, err := gcm.Open(nil, nonce, body, fragmentAAD(principal, sf.ConversationID, sf.Seq, sf.Kind, sf.Provenance))
	if err != nil {
		return Fragment{}, fmt.Errorf("%w: fragment does not open", ErrUnreadable)
	}
	return Fragment{kind: sf.Kind, prov: sf.Provenance, text: string(pt)}, nil
}
