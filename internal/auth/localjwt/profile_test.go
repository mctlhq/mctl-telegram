package localjwt

import (
	"net/http/httptest"
	"testing"
	"time"
)

// The prf claim reaches the Identity unchanged, and is empty when the token
// has none. internal/mcp restricts the caller by it, so a dropped field would
// silently put a profiled client back on its full scope surface.
func TestProvider_ProfilePropagates(t *testing.T) {
	store := newTestLocaljwtStore(t)
	p, err := NewProvider(store, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	for _, want := range []string{"core-readonly", ""} {
		tok, err := iss.Mint(Claims{Subject: "tg:5", TelegramID: 5, ClientID: "claude.ai", Profile: want}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		id, err := p.Authenticate(r)
		if err != nil || id == nil {
			t.Fatalf("prf %q: %v", want, err)
		}
		if id.Profile != want {
			t.Errorf("Profile = %q, want %q", id.Profile, want)
		}
	}
}
