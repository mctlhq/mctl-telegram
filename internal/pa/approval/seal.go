// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package approval

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/mctlhq/mctl-telegram/internal/crypto"
	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// KeyInfo is the HKDF info label of the per-principal key that seals an
// approval's arguments. It differs from the conversation label, so a
// fragment blob and an argument blob never open under each other's key.
const KeyInfo = "mctl-pa-approval-args/v1"

const (
	sealVersion byte = 0x01
	// sealVersionDetail is a blob that holds the arguments and, after
	// them, the card detail SealWithDetail was given.
	sealVersionDetail byte = 0x02
	aadLabel               = "mctl-pa-approval-args/v1"
)

// MaxDetailBytes bounds the card detail sealed next to the arguments.
const MaxDetailBytes = 8 << 10

// MaxArgsBytes bounds the canonical arguments of one approval. A card is
// refused over 4 KiB (T10), so nothing genuine comes near it.
const MaxArgsBytes = 64 << 10

// ErrSealerKey is returned by NewSealer for anything but a 32-byte key.
var ErrSealerKey = errors.New("pa approval: sealer needs a 32-byte master key")

// Sealer encrypts an approval's canonical arguments with a key derived
// per principal from the service master key (HKDF-SHA256, salt =
// principal, info = KeyInfo), as conversation fragments are. The
// additional data binds the principal, the approval id and the argument
// hash: a blob moved to another approval, or kept under a changed
// args_sha, does not open.
type Sealer struct{ master []byte }

// NewSealer builds a Sealer. There is no plaintext fallback.
func NewSealer(master []byte) (*Sealer, error) {
	if len(master) != 32 {
		return nil, ErrSealerKey
	}
	return &Sealer{master: append([]byte(nil), master...)}, nil
}

func (s *Sealer) aead(principal int64) (cipher.AEAD, error) {
	if s == nil || principal <= 0 {
		return nil, fmt.Errorf("%w: no sealer or principal", ErrInvalid)
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

func argsAAD(principal int64, approvalID, argsSHA string) []byte {
	b := make([]byte, 0, len(aadLabel)+len(approvalID)+len(argsSHA)+16)
	b = append(b, aadLabel...)
	b = binary.BigEndian.AppendUint64(b, uint64(principal))
	for _, part := range []string{approvalID, argsSHA} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return b
}

func argsSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Seal returns a with canonicalArgs sealed into it. The bytes must already
// be canonical (catalog.CanonicalArgs returns them unchanged) and hash to
// a.ArgsSHA: the row then holds exactly the bytes the card showed and the
// hash bound.
func (s *Sealer) Seal(a Approval, canonicalArgs []byte) (Approval, error) {
	return s.seal(a, canonicalArgs, nil)
}

// SealWithDetail is Seal with detail sealed into the same blob: what the
// approval's card shows besides the arguments and what was read from the
// server when the card was made (the target device of a disclosure, #1322
// slice P2-S6). It is never sent anywhere: Open returns the arguments
// only. It is in the blob, not in a column of its own, so that it leaves
// the row with the arguments, in the same statement. detail must not be
// empty.
func (s *Sealer) SealWithDetail(a Approval, canonicalArgs, detail []byte) (Approval, error) {
	if len(detail) == 0 || len(detail) > MaxDetailBytes {
		return Approval{}, fmt.Errorf("%w: seal card detail", ErrInvalid)
	}
	return s.seal(a, canonicalArgs, detail)
}

func (s *Sealer) seal(a Approval, canonicalArgs, detail []byte) (Approval, error) {
	if a.ID == "" || len(canonicalArgs) == 0 || len(canonicalArgs) > MaxArgsBytes {
		return Approval{}, fmt.Errorf("%w: seal arguments", ErrInvalid)
	}
	c, err := catalog.CanonicalArgs(canonicalArgs)
	if err != nil {
		return Approval{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !bytes.Equal(c, canonicalArgs) {
		return Approval{}, fmt.Errorf("%w: arguments are not in canonical form", ErrInvalid)
	}
	if argsSHA256(canonicalArgs) != a.ArgsSHA {
		return Approval{}, fmt.Errorf("%w: arguments do not hash to the bound args_sha", ErrInvalid)
	}
	gcm, err := s.aead(a.Principal)
	if err != nil {
		return Approval{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Approval{}, err
	}
	version, plain := sealVersion, canonicalArgs
	if detail != nil {
		// The arguments' length, the arguments, then the detail.
		version = sealVersionDetail
		plain = binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(canonicalArgs)+len(detail)), uint32(len(canonicalArgs)))
		plain = append(append(plain, canonicalArgs...), detail...)
	}
	out := make([]byte, 0, 1+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, version)
	out = append(out, nonce...)
	a.SealedArgs = gcm.Seal(out, nonce, plain, sealAAD(version, a.Principal, a.ID, a.ArgsSHA))
	return a, nil
}

// sealAAD is the additional data of a blob of version. A version 1 blob
// keeps the data it always had; a later version adds its own byte, so a
// blob does not open as another version's.
func sealAAD(version byte, principal int64, approvalID, argsSHA string) []byte {
	aad := argsAAD(principal, approvalID, argsSHA)
	if version != sealVersion {
		aad = append(aad, version)
	}
	return aad
}

// Open returns the canonical arguments of a consumed approval, the exact
// bytes Seal was given. A blob that does not open under the principal's
// key, the approval id and the bound hash is ErrUnreadable. Seal refused
// content that does not hash to ArgsSHA, and the hash is in the additional
// data, so what opens here is what that hash names.
func (s *Sealer) Open(a Approval) ([]byte, error) {
	args, _, err := s.OpenWithDetail(a)
	return args, err
}

// OpenWithDetail is Open that also returns the detail SealWithDetail was
// given, nil for an approval sealed without one.
func (s *Sealer) OpenWithDetail(a Approval) (args, detail []byte, err error) {
	gcm, err := s.aead(a.Principal)
	if err != nil {
		return nil, nil, err
	}
	ns := gcm.NonceSize()
	if a.ID == "" || len(a.SealedArgs) < 1+ns {
		return nil, nil, fmt.Errorf("%w: sealed arguments", ErrUnreadable)
	}
	version := a.SealedArgs[0]
	if version != sealVersion && version != sealVersionDetail {
		return nil, nil, fmt.Errorf("%w: sealed arguments", ErrUnreadable)
	}
	nonce, body := a.SealedArgs[1:1+ns], a.SealedArgs[1+ns:]
	pt, err := gcm.Open(nil, nonce, body, sealAAD(version, a.Principal, a.ID, a.ArgsSHA))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: sealed arguments do not open", ErrUnreadable)
	}
	if version == sealVersion {
		return pt, nil, nil
	}
	if len(pt) < 4 {
		return nil, nil, fmt.Errorf("%w: sealed arguments", ErrUnreadable)
	}
	n := int(binary.BigEndian.Uint32(pt))
	if n <= 0 || n >= len(pt)-4 {
		// No arguments, or no detail after them.
		return nil, nil, fmt.Errorf("%w: sealed arguments", ErrUnreadable)
	}
	return pt[4 : 4+n], pt[4+n:], nil
}
