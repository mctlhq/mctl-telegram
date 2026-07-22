package agentapi

import (
	"crypto/rand"
	"strings"
)

// approvalCodeAlphabet excludes visually ambiguous characters (0/O, 1/I/L)
// since the owner types this code by hand in Saved Messages
// (/mctl approve <code>).
const approvalCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// approvalCodeRejectionCeiling is the largest multiple of len(alphabet) that
// fits in a byte (31*8=248). Random bytes >= this are rejected and re-drawn
// so every alphabet character has exactly equal probability — a plain `%
// len(alphabet)` would give the first 256%31=8 characters slightly higher
// odds than the rest.
const approvalCodeRejectionCeiling = 256 - (256 % len(approvalCodeAlphabet))

// newApprovalCode returns a random 6-character code via rejection sampling
// (uniform over the alphabet, no modulo bias). At ~5 bits/char over 6 chars
// (~30 bits, ~1e9 combinations) a collision against a user's handful of
// concurrently-live (non-terminal) actions is astronomically unlikely; the
// caller retries on the rare insert conflict anyway (see actions.go).
func newApprovalCode() (string, error) {
	var sb strings.Builder
	sb.Grow(6)
	buf := make([]byte, 1)
	for sb.Len() < 6 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if int(buf[0]) >= approvalCodeRejectionCeiling {
			continue
		}
		sb.WriteByte(approvalCodeAlphabet[int(buf[0])%len(approvalCodeAlphabet)])
	}
	return sb.String(), nil
}
