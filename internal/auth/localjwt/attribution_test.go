package localjwt

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
)

// TestVerifyWithClaims_NoClaimsAtOrBeforeSignature is the security assertion
// behind item 2: a token that fails at or before the signature check must
// come back with nil claims, because that payload is unauthenticated
// attacker-controlled input.
func TestVerifyWithClaims_NoClaimsAtOrBeforeSignature(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:1"}, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	t.Run("malformed token", func(t *testing.T) {
		c, err := VerifyWithClaims("not-a-jwt", testSecret, testIssuer)
		if err == nil {
			t.Fatal("expected an error for a malformed token")
		}
		if c != nil {
			t.Fatalf("expected nil claims for a malformed token, got %+v", c)
		}
	})

	t.Run("tampered signature", func(t *testing.T) {
		parts := strings.Split(tok, ".")
		tampered := parts[0] + "." + parts[1] + ".not-the-real-signature"
		c, err := VerifyWithClaims(tampered, testSecret, testIssuer)
		if err == nil {
			t.Fatal("expected an error for a tampered signature")
		}
		if c != nil {
			t.Fatalf("expected nil claims for a tampered signature, got %+v", c)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		c, err := VerifyWithClaims(tok, []byte("a-completely-different-secret!!"), testIssuer)
		if err == nil {
			t.Fatal("expected an error for the wrong secret")
		}
		if c != nil {
			t.Fatalf("expected nil claims for the wrong secret, got %+v", c)
		}
	})
}

// TestVerifyWithClaims_ClaimsPresentAfterSignature is the other half: a
// token whose signature verifies but is rejected for issuer, expiry, or
// audience-shape reasons must come back with non-nil claims, since the
// payload was vouched for by our own HMAC key.
func TestVerifyWithClaims_ClaimsPresentAfterSignature(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)

	t.Run("expired", func(t *testing.T) {
		tok, err := iss.Mint(Claims{Subject: "tg:500100101", ClientID: "acme-cli"}, -time.Second)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		c, err := VerifyWithClaims(tok, testSecret, testIssuer)
		if err == nil {
			t.Fatal("expected an error for an expired token")
		}
		if c == nil {
			t.Fatal("expected non-nil claims for an expired-but-signed token")
		}
		if c.Subject != "tg:500100101" || c.ClientID != "acme-cli" {
			t.Errorf("claims = %+v", c)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		tok, err := iss.Mint(Claims{Subject: "tg:1"}, time.Hour)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		c, err := VerifyWithClaims(tok, testSecret, "https://other.example")
		if err == nil {
			t.Fatal("expected an error for the wrong issuer")
		}
		if c == nil {
			t.Fatal("expected non-nil claims for a wrong-issuer-but-signed token")
		}
	})
}

// TestVerify_UnchangedBehavior locks in that Verify (the pre-existing
// exported function) keeps nilling claims on every error path, including
// the new post-signature ones VerifyWithClaims now distinguishes — its
// signature and behavior must stay exactly what every existing caller
// depends on.
func TestVerify_UnchangedBehavior(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	tok, err := iss.Mint(Claims{Subject: "tg:1"}, -time.Second)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c, err := Verify(tok, testSecret, testIssuer)
	if err == nil {
		t.Fatal("expected an error for an expired token")
	}
	if c != nil {
		t.Fatalf("Verify must nil the claims on any error, got %+v", c)
	}
}

// attributionFromProviderFailure drives Provider.Authenticate through an
// HTTP request carrying tok and returns the AttributedError's attribution,
// if any.
func attributionFromProviderFailure(t *testing.T, p *Provider, tok string) (auth.TokenAttribution, bool, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	_, err := p.Authenticate(r)
	if err == nil {
		return auth.TokenAttribution{}, false, nil
	}
	attr, ok := auth.AttributionOf(err)
	return attr, ok, err
}

// TestProvider_AttributesPostSignatureFailuresOnly is T5 from the provider
// side: an expired-but-signed token's failure carries an attribution with
// the four claims, while a tampered-signature token's failure carries none.
func TestProvider_AttributesPostSignatureFailuresOnly(t *testing.T) {
	iss, _ := NewIssuer(testSecret, testIssuer)
	store := newTestLocaljwtStore(t)
	p, _ := NewProvider(store, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer})

	t.Run("expired token is attributed", func(t *testing.T) {
		tok, err := iss.Mint(Claims{
			Subject:  "tg:500100101",
			ClientID: "acme-cli",
			Jti:      "jti-abc123",
		}, -time.Second)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		attr, ok, err := attributionFromProviderFailure(t, p, tok)
		if err == nil {
			t.Fatal("expected an error for an expired token")
		}
		if !ok {
			t.Fatalf("expected an AttributedError, got a plain %v", err)
		}
		if attr.Subject != "tg:500100101" || attr.ClientID != "acme-cli" || attr.Jti != "jti-abc123" || attr.ExpiresAt == 0 {
			t.Errorf("attribution = %+v", attr)
		}
	})

	t.Run("tampered signature is never attributed", func(t *testing.T) {
		tok, err := iss.Mint(Claims{Subject: "tg:evil-controlled-subject", ClientID: "attacker-client"}, time.Hour)
		if err != nil {
			t.Fatalf("Mint: %v", err)
		}
		parts := strings.Split(tok, ".")
		tampered := parts[0] + "." + parts[1] + ".not-the-real-signature"
		_, ok, err := attributionFromProviderFailure(t, p, tampered)
		if err == nil {
			t.Fatal("expected an error for a tampered signature")
		}
		if ok {
			t.Fatal("a tampered-signature token must never carry an attribution — its claims are attacker-controlled")
		}
	})
}
