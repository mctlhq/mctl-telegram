package localjwt

// pajob.go is the Personal Assistant job credential (issue #1313 slice d1,
// threat model T4). The claim route mints one per claimed attempt; the turn
// and reply routes, and the tool executor (#1315), accept only it. It
// carries the principal, the job and attempt, the digest of the execution
// context and the signed tool set. The job row stays the authority: every
// route re-reads it and refuses a token whose attempt or digest no longer
// matches, so the token can only narrow what the row allows.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// PAJobAudience is the aud of a Personal Assistant job credential.
const PAJobAudience = "pa-job"

// PAJobSubjectPrefix prefixes the principal in a pa-job token's subject.
const PAJobSubjectPrefix = "pa:"

// MaxPAJobTTL bounds a pa-job token's lifetime. The lease of a claimed job
// is shorter; this is the hard ceiling MintPAJob refuses to exceed.
const MaxPAJobTTL = 15 * time.Minute

// PAJob is what a verified pa-job token asserts. It is input to the job
// row lookup, never authority on its own.
type PAJob struct {
	Principal     int64
	JobID         int64
	Attempt       int
	ContextDigest string
	Tools         []string
	Jti           string
	ExpiresAt     time.Time
}

// hasPAJobClaims reports whether c is, or claims to be, a pa-job token: the
// audience or either PA claim. Provider refuses all of them.
func hasPAJobClaims(c *Claims) bool {
	return slices.Contains(c.Audience, PAJobAudience) || c.PAPrincipal != 0 || c.ContextDigest != ""
}

func validDigest(d string) bool {
	if len(d) != 64 {
		return false
	}
	_, err := hex.DecodeString(d)
	return err == nil && strings.ToLower(d) == d
}

// checkPAJobShape refuses anything but the exact shape MintPAJob produces.
func checkPAJobShape(c *Claims) (PAJob, error) {
	switch {
	case len(c.Audience) != 1 || c.Audience[0] != PAJobAudience:
		return PAJob{}, errors.New("pa-job token must carry exactly the pa-job audience")
	case c.PAPrincipal <= 0:
		return PAJob{}, errors.New("pa-job token requires a principal")
	case c.TelegramID != c.PAPrincipal:
		return PAJob{}, errors.New("pa-job token telegram id must equal its principal")
	case c.Subject != PAJobSubjectPrefix+strconv.FormatInt(c.PAPrincipal, 10):
		return PAJob{}, errors.New("pa-job token subject does not name its principal")
	case c.JobID <= 0 || c.JobAttempt <= 0:
		return PAJob{}, errors.New("pa-job token requires a job and attempt")
	case !validDigest(c.ContextDigest):
		return PAJob{}, errors.New("pa-job token requires a context digest")
	case c.Jti == "":
		return PAJob{}, errors.New("pa-job token requires a jti")
	case c.ConversationID != 0 || c.DeviceID != "" || c.ClientID != "" || c.Profile != "" ||
		c.TelegramUsername != "" || len(c.Groups) > 0 || len(c.Scopes) > 0:
		return PAJob{}, errors.New("pa-job token must not carry account, device, client or conversation claims")
	}
	tools := slices.Clone(c.JobTools)
	if tools == nil {
		tools = []string{}
	}
	return PAJob{
		Principal:     c.PAPrincipal,
		JobID:         c.JobID,
		Attempt:       c.JobAttempt,
		ContextDigest: c.ContextDigest,
		Tools:         tools,
		Jti:           c.Jti,
		ExpiresAt:     time.Unix(c.ExpiresAt, 0).UTC(),
	}, nil
}

// MintPAJob mints a pa-job token for j. parentJti and parentOrigIAT come
// from the pool credential that claimed the job, so revoking the pool's jti
// revokes every job token minted under it, as for agent-job tokens.
func (i *Issuer) MintPAJob(j PAJob, parentJti string, parentOrigIAT int64, ttl time.Duration) (string, error) {
	if ttl <= 0 || ttl > MaxPAJobTTL {
		return "", fmt.Errorf("localjwt: pa-job ttl must be in (0, %s]", MaxPAJobTTL)
	}
	if parentJti == "" {
		return "", errors.New("localjwt: pa-job token requires the parent jti")
	}
	c := Claims{
		Subject:          PAJobSubjectPrefix + strconv.FormatInt(j.Principal, 10),
		TelegramID:       j.Principal,
		PAPrincipal:      j.Principal,
		JobID:            j.JobID,
		JobAttempt:       j.Attempt,
		ContextDigest:    j.ContextDigest,
		JobTools:         slices.Clone(j.Tools),
		Jti:              parentJti,
		OriginalIssuedAt: parentOrigIAT,
		Audience:         []string{PAJobAudience},
	}
	// Refuse to mint what the verifier would refuse.
	if _, err := checkPAJobShape(&c); err != nil {
		return "", fmt.Errorf("localjwt: %w", err)
	}
	return i.Mint(c, ttl)
}

// PAJobVerifier authenticates pa-job tokens. Like PoolProvider it is its
// own type: it resolves no user row and its shape rules must not drift with
// Provider's.
type PAJobVerifier struct {
	secret          []byte
	issuer          string
	revocationCache *RevocationCache
}

// NewPAJobVerifier refuses a verifier without a revocation path.
func NewPAJobVerifier(secret []byte, issuer string, rc *RevocationCache) (*PAJobVerifier, error) {
	if len(secret) == 0 || issuer == "" {
		return nil, errors.New("localjwt: pa-job verifier needs a secret and an issuer")
	}
	if rc == nil {
		return nil, errors.New("localjwt: pa-job verifier requires a revocation cache")
	}
	return &PAJobVerifier{secret: secret, issuer: issuer, revocationCache: rc}, nil
}

// ErrNoPAJobToken is returned when the request carries no bearer token.
var ErrNoPAJobToken = errors.New("localjwt: no pa-job token")

// VerifyRequest reads the bearer token of r (no cookie fallback) and
// verifies it. Any failure is an error; there is no anonymous result.
func (v *PAJobVerifier) VerifyRequest(r *http.Request) (PAJob, error) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return PAJob{}, ErrNoPAJobToken
	}
	tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	if tok == "" {
		return PAJob{}, ErrNoPAJobToken
	}
	return v.Verify(r.Context(), tok)
}

// PAJobRefusal classifies a refused pa-job token for the PA audit record
// (#1315). It is a fixed label, never error text.
type PAJobRefusal string

const (
	// PAJobRefusedExpired: a pa-job token of ours that is past its expiry.
	PAJobRefusedExpired PAJobRefusal = "token_expired"
	// PAJobRefusedRevoked: a pa-job token of ours whose pool credential or
	// principal was revoked, or whose revocation state could not be read.
	PAJobRefusedRevoked PAJobRefusal = "token_revoked"
	// PAJobRefusedInvalid: any other refusal.
	PAJobRefusedInvalid PAJobRefusal = "token_invalid"
)

// VerifyRequestAttributed is VerifyRequest that also says whose token a
// refused one was, when that is known for certain. See VerifyAttributed.
func (v *PAJobVerifier) VerifyRequestAttributed(r *http.Request) (PAJob, int64, PAJobRefusal, error) {
	hdr := r.Header.Get("Authorization")
	if !strings.HasPrefix(hdr, "Bearer ") {
		return PAJob{}, 0, PAJobRefusedInvalid, ErrNoPAJobToken
	}
	tok := strings.TrimSpace(strings.TrimPrefix(hdr, "Bearer "))
	if tok == "" {
		return PAJob{}, 0, PAJobRefusedInvalid, ErrNoPAJobToken
	}
	return v.VerifyAttributed(r.Context(), tok)
}

// VerifyAttributed is Verify. On a refusal it also returns the principal
// the token was minted for, so the refusal can be audited in that
// principal's chain (threat model T12, #1315), and a refusal label.
//
// A principal is returned only for a token this server signed (signature
// valid, payload decoded, our issuer) that has the pa-job audience and a
// consistent principal: an expired or revoked pa-job token of ours. For
// anything else (a bad signature, a malformed payload, another audience,
// a token of another issuer) it is 0: the claims of a token whose
// signature did not check out are attacker-controlled and are never used
// to pick a chain to write to.
func (v *PAJobVerifier) VerifyAttributed(ctx context.Context, tok string) (PAJob, int64, PAJobRefusal, error) {
	c, err := VerifyWithClaims(tok, v.secret, v.issuer)
	if err != nil {
		principal := attributablePAPrincipal(c, v.issuer)
		reason := PAJobRefusedInvalid
		if principal != 0 && c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt {
			reason = PAJobRefusedExpired
		}
		return PAJob{}, principal, reason, err
	}
	j, err := checkPAJobShape(c)
	if err != nil {
		return PAJob{}, attributablePAPrincipal(c, v.issuer), PAJobRefusedInvalid, err
	}
	revoked, err := v.revocationCache.IsRevoked(ctx, c.Jti, c.TelegramID, originAnchor(c))
	if err != nil {
		return PAJob{}, j.Principal, PAJobRefusedRevoked, fmt.Errorf("check pa-job token revocation: %w", err)
	}
	if revoked {
		return PAJob{}, j.Principal, PAJobRefusedRevoked, errors.New("pa-job token revoked")
	}
	return j, 0, "", nil
}

// attributablePAPrincipal returns the principal of claims c that
// VerifyWithClaims handed back (signature valid, payload decoded), if c is
// one of our pa-job tokens: our issuer, exactly the pa-job audience, and a
// principal that subject and telegram id agree on. Otherwise 0.
func attributablePAPrincipal(c *Claims, issuer string) int64 {
	if c == nil || c.Issuer != issuer || c.PAPrincipal <= 0 || c.TelegramID != c.PAPrincipal ||
		c.Subject != PAJobSubjectPrefix+strconv.FormatInt(c.PAPrincipal, 10) {
		return 0
	}
	aud := c.Audience
	if aud == nil {
		var err error
		if aud, err = audienceList(c.AudienceRaw); err != nil {
			return 0
		}
	}
	if len(aud) != 1 || aud[0] != PAJobAudience {
		return 0
	}
	return c.PAPrincipal
}

// Verify checks signature, issuer, expiry, exact audience, shape and
// revocation (by the inherited jti and by the principal).
func (v *PAJobVerifier) Verify(ctx context.Context, tok string) (PAJob, error) {
	c, err := Verify(tok, v.secret, v.issuer)
	if err != nil {
		return PAJob{}, err
	}
	j, err := checkPAJobShape(c)
	if err != nil {
		return PAJob{}, err
	}
	revoked, err := v.revocationCache.IsRevoked(ctx, c.Jti, c.TelegramID, originAnchor(c))
	if err != nil {
		return PAJob{}, fmt.Errorf("check pa-job token revocation: %w", err)
	}
	if revoked {
		return PAJob{}, errors.New("pa-job token revoked")
	}
	return j, nil
}
