// Package answercode generates the short, hand-typeable codes the owner types
// into Saved Messages: agent-action approval codes (/mctl approve <code>) and
// human-input answer codes (/mctl input <code> <value>). The two live in
// separate tables and separate command namespaces; only the generator is
// shared.
package answercode

import (
	"crypto/rand"
	"strings"
)

// Length is the number of characters in a generated code.
const Length = 6

// alphabet excludes visually ambiguous characters (0/O, 1/I/L) since the
// owner types the code by hand in Saved Messages.
const alphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// rejectionCeiling is the largest multiple of len(alphabet) that fits in a
// byte (31*8=248). Random bytes >= this are rejected and re-drawn so every
// alphabet character has exactly equal probability — a plain `% len(alphabet)`
// would give the first 256%31=8 characters slightly higher odds.
const rejectionCeiling = 256 - (256 % len(alphabet))

// New returns a random 6-character code via rejection sampling (uniform over
// the alphabet, no modulo bias). At ~5 bits/char over 6 chars (~30 bits) a
// collision against a user's handful of concurrently-live codes is
// astronomically unlikely; callers retry on the rare insert conflict anyway.
func New() (string, error) {
	var sb strings.Builder
	sb.Grow(Length)
	buf := make([]byte, 1)
	for sb.Len() < Length {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= rejectionCeiling {
			continue
		}
		sb.WriteByte(alphabet[int(buf[0])%len(alphabet)])
	}
	return sb.String(), nil
}
