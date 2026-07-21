package agentapi

import (
	"crypto/rand"
	"strings"
)

// approvalCodeAlphabet excludes visually ambiguous characters (0/O, 1/I/L)
// since the owner types this code by hand in Saved Messages
// (/mctl approve <code>).
const approvalCodeAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// newApprovalCode returns a random 6-character code. At ~5 bits/char over 6
// chars (~30 bits, ~1e9 combinations) a collision against a user's handful of
// concurrently-live (non-terminal) actions is astronomically unlikely; the
// caller retries on the rare insert conflict anyway (see actions.go).
func newApprovalCode() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	var sb strings.Builder
	sb.Grow(6)
	for _, v := range b {
		sb.WriteByte(approvalCodeAlphabet[int(v)%len(approvalCodeAlphabet)])
	}
	return sb.String(), nil
}
