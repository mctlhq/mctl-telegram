package localjwt

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestVerifyAttributed: a refused pa-job token names its principal only
// when this server minted it as a pa-job token (signature, issuer, exact
// audience, consistent subject). Everything else is attributed to nobody,
// because its claims are attacker-controlled.
func TestVerifyAttributed(t *testing.T) {
	ctx := context.Background()
	v, iss, cache, revokeAll := newPAJobFixture(t)

	ok, _ := iss.MintPAJob(paJob(), "pool-jti", time.Now().Add(-time.Minute).Unix(), time.Minute)
	if j, p, reason, err := v.VerifyAttributed(ctx, ok); err != nil || p != 0 || reason != "" || j.Principal != 555 {
		t.Fatalf("valid token: job %+v principal %d reason %q err %v", j, p, reason, err)
	}

	past := time.Now().Add(-time.Hour)
	expired, err := iss.Mint(Claims{
		Subject: PAJobSubjectPrefix + "555", TelegramID: 555, PAPrincipal: 555, JobID: 7, JobAttempt: 1,
		ContextDigest: paDigest, JobTools: []string{"tg/get_messages"}, Jti: "pool-jti",
		OriginalIssuedAt: past.Add(-time.Minute).Unix(), Audience: []string{PAJobAudience},
		IssuedAt: past.Unix(), ExpiresAt: past.Add(time.Minute).Unix(),
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, p, reason, err := v.VerifyAttributed(ctx, expired); err == nil || p != 555 || reason != PAJobRefusedExpired {
		t.Fatalf("expired: principal %d reason %q err %v", p, reason, err)
	}

	other, _ := NewIssuer(bytes.Repeat([]byte{7}, 32), testIssuer)
	forged, _ := other.MintPAJob(paJob(), "pool-jti", time.Now().Add(-time.Minute).Unix(), time.Minute)
	foreign, _ := NewIssuer(testSecret, "https://other.example")
	foreignTok, _ := foreign.MintPAJob(paJob(), "pool-jti", time.Now().Add(-time.Minute).Unix(), time.Minute)
	agentJob, _ := iss.Mint(Claims{Subject: "agent:555", TelegramID: 555, Audience: []string{"agent-job"}, Jti: "pool-jti",
		JobID: 7, JobAttempt: 1, OriginalIssuedAt: time.Now().Unix()}, time.Minute)
	// Our signature and issuer, pa-job audience, but the subject names
	// another principal than the telegram id: not attributable.
	mixed, _ := iss.Mint(Claims{Subject: PAJobSubjectPrefix + "556", TelegramID: 555, PAPrincipal: 555, JobID: 7, JobAttempt: 1,
		ContextDigest: paDigest, JobTools: []string{"tg/get_messages"}, Jti: "pool-jti",
		OriginalIssuedAt: time.Now().Unix(), Audience: []string{PAJobAudience}}, time.Minute)
	twoAud, _ := iss.Mint(Claims{Subject: PAJobSubjectPrefix + "555", TelegramID: 555, PAPrincipal: 555, JobID: 7, JobAttempt: 1,
		ContextDigest: paDigest, JobTools: []string{"tg/get_messages"}, Jti: "pool-jti",
		OriginalIssuedAt: time.Now().Unix(), Audience: []string{PAJobAudience, "agent-job"}}, time.Minute)
	for name, tok := range map[string]string{
		"other secret": forged, "other issuer": foreignTok, "agent-job": agentJob,
		"subject mismatch": mixed, "two audiences": twoAud, "garbage": "a.b.c", "tampered": ok[:len(ok)-2] + "xx",
	} {
		_, p, reason, err := v.VerifyAttributed(ctx, tok)
		if err == nil || p != 0 || reason != PAJobRefusedInvalid {
			t.Errorf("%s: principal %d reason %q err %v", name, p, reason, err)
		}
		if err != nil && strings.Contains(err.Error(), tok) {
			t.Errorf("%s: token in error", name)
		}
	}

	if err := revokeAll(); err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(ctx); err != nil { // as the cache TTL running out would
		t.Fatal(err)
	}
	fresh, _ := iss.MintPAJob(paJob(), "pool-jti", time.Now().Add(-time.Minute).Unix(), time.Minute)
	if _, p, reason, err := v.VerifyAttributed(ctx, fresh); err == nil || p != 555 || reason != PAJobRefusedRevoked {
		t.Fatalf("revoked: principal %d reason %q err %v", p, reason, err)
	}
}
