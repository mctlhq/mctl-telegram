package localjwt

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The client_id claim reaches the Identity whichever way the token arrives,
// and is empty when the token has none. The broadcast approval page
// (issue-439) keys on it, so a dropped field would fail the page closed and a
// defaulted one would open it.
func TestProvider_ClientIDPropagates(t *testing.T) {
	store := newTestLocaljwtStore(t)
	p, err := NewProvider(store, ProviderConfig{Secret: testSecret, ExpectedIssuer: testIssuer})
	if err != nil {
		t.Fatal(err)
	}
	iss, _ := NewIssuer(testSecret, testIssuer)
	withClient, _ := iss.Mint(Claims{Subject: "tg:5", TelegramID: 5, ClientID: "mctl_self_connect"}, time.Hour)
	without, _ := iss.Mint(Claims{Subject: "tg:5", TelegramID: 5}, time.Hour)

	bearer := httptest.NewRequest("GET", "/", nil)
	bearer.Header.Set("Authorization", "Bearer "+withClient)
	cookie := httptest.NewRequest("GET", "/telegram/connect/broadcasts", nil)
	cookie.AddCookie(&http.Cookie{Name: "mctl_connect_token", Value: withClient})
	none := httptest.NewRequest("GET", "/", nil)
	none.Header.Set("Authorization", "Bearer "+without)

	for name, tc := range map[string]struct {
		r    *http.Request
		want string
	}{"bearer": {bearer, "mctl_self_connect"}, "cookie": {cookie, "mctl_self_connect"}, "absent": {none, ""}} {
		id, err := p.Authenticate(tc.r)
		if err != nil || id == nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id.ClientID != tc.want {
			t.Errorf("%s: ClientID = %q, want %q", name, id.ClientID, tc.want)
		}
	}
}
