package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// refreshTokenSuccessorDomain domain-separates rotation-successor derivation
// from every other use of the signing secret (JWT signing) in this service,
// and from mctl-api's own derivation — even though the two services can
// share the same underlying secret bytes in shared-hmac deployments.
const refreshTokenSuccessorDomain = "mctl-telegram-refresh-token-v1" //nolint:gosec // domain-separation label, not a credential

// deriveSuccessorRefreshToken deterministically computes the next refresh
// token in a rotation chain from its predecessor and the server's signing
// secret: same (secret, predecessor) always yields the same successor. This
// lets a client that never received a rotation response (e.g. a dropped
// connection) retry with the predecessor within the grace window and recover
// the exact successor a prior call already committed, instead of hard-failing.
// The server never persists the raw successor, only its SHA-256 hash, so
// this does not introduce recoverable token storage.
func deriveSuccessorRefreshToken(secret []byte, predecessor string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(refreshTokenSuccessorDomain))
	mac.Write([]byte{0})
	mac.Write([]byte(predecessor))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
