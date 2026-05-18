package telegramoidc

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestParseIdentity covers the id-claim shapes #48 found and the contingency
// cases. parseIdentity is pure, so this runs fully offline.
func TestParseIdentity(t *testing.T) {
	tests := []struct {
		name     string
		claims   idTokenClaims
		wantTGID int64
		wantSub  string
		wantErr  bool
	}{
		{
			name:     "string id — Telegram's actual shape (spike #48)",
			claims:   idTokenClaims{ID: json.RawMessage(`"210408407"`), Sub: "1234567890123456789"},
			wantTGID: 210408407,
			wantSub:  "1234567890123456789",
		},
		{
			name:     "numeric id — tolerated fallback",
			claims:   idTokenClaims{ID: json.RawMessage(`210408407`), Sub: "s"},
			wantTGID: 210408407,
			wantSub:  "s",
		},
		{
			name:     "string id with surrounding whitespace",
			claims:   idTokenClaims{ID: json.RawMessage(` "210408407" `), Sub: "s"},
			wantTGID: 210408407,
			wantSub:  "s",
		},
		{
			name:    "sub only, no id claim",
			claims:  idTokenClaims{Sub: "1234567890123456789"},
			wantSub: "1234567890123456789",
		},
		{
			name:    "null id, sub present",
			claims:  idTokenClaims{ID: json.RawMessage(`null`), Sub: "s"},
			wantSub: "s",
		},
		{
			name:     "carries username and names",
			claims:   idTokenClaims{ID: json.RawMessage(`"42"`), Username: "u", FirstName: "F", LastName: "L"},
			wantTGID: 42,
		},
		{
			name:    "neither id nor sub — rejected",
			claims:  idTokenClaims{},
			wantErr: true,
		},
		{
			name:    "non-numeric string id — rejected",
			claims:  idTokenClaims{ID: json.RawMessage(`"not-a-number"`), Sub: "s"},
			wantErr: true,
		},
		{
			name:    "zero id — rejected",
			claims:  idTokenClaims{ID: json.RawMessage(`"0"`), Sub: "s"},
			wantErr: true,
		},
		{
			name:    "negative id — rejected",
			claims:  idTokenClaims{ID: json.RawMessage(`"-5"`), Sub: "s"},
			wantErr: true,
		},
		{
			name:    "float id — rejected",
			claims:  idTokenClaims{ID: json.RawMessage(`210408407.5`), Sub: "s"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseIdentity(tt.claims)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got identity %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.TelegramID != tt.wantTGID {
				t.Errorf("TelegramID = %d, want %d", got.TelegramID, tt.wantTGID)
			}
			if got.Sub != tt.wantSub {
				t.Errorf("Sub = %q, want %q", got.Sub, tt.wantSub)
			}
		})
	}
}

// telegramJWKS mirrors the structure of the JWKS Telegram serves (observed
// 2026-05-18): four keys, one per kid/alg. Key material is abbreviated — the
// filter keys off `crv`, not on cryptographic validity. The secp256k1 key
// (kid=oidc-es256k-1) is the one go-jose cannot decode.
const telegramJWKS = `{
  "keys": [
    {"alg":"RS256","e":"AQAB","kty":"RSA","n":"5Rne","kid":"oidc-1"},
    {"alg":"ES256","kty":"EC","x":"a","y":"b","crv":"P-256","kid":"oidc-es256-1","use":"sig"},
    {"alg":"EdDSA","crv":"Ed25519","x":"c","kty":"OKP","kid":"oidc-eddsa-1","use":"sig"},
    {"alg":"ES256K","kty":"EC","x":"d","y":"e","crv":"secp256k1","kid":"oidc-es256k-1","use":"sig"}
  ]
}`

// TestFilterJWKS confirms the secp256k1 key is stripped while the keys go-jose
// can decode — including the RS256 key the verifier relies on — are kept.
func TestFilterJWKS(t *testing.T) {
	out, changed := filterJWKS([]byte(telegramJWKS))
	if !changed {
		t.Fatal("expected the secp256k1 key to be filtered out")
	}
	var doc struct {
		Keys []struct {
			Kid string `json:"kid"`
			Crv string `json:"crv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("filtered JWKS is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 3 {
		t.Fatalf("kept %d keys, want 3", len(doc.Keys))
	}
	var haveRS256 bool
	for _, k := range doc.Keys {
		if k.Crv == "secp256k1" {
			t.Errorf("secp256k1 key %q was not filtered", k.Kid)
		}
		if k.Kid == "oidc-1" {
			haveRS256 = true
		}
	}
	if !haveRS256 {
		t.Error("RS256 key oidc-1 must be kept — the verifier depends on it")
	}
}

// TestFilterJWKS_NonJWKSUntouched confirms a non-JWKS JSON body (the OIDC
// discovery document) passes through unchanged.
func TestFilterJWKS_NonJWKSUntouched(t *testing.T) {
	discovery := []byte(`{"issuer":"https://oauth.telegram.org","jwks_uri":"https://oauth.telegram.org/jwks"}`)
	out, changed := filterJWKS(discovery)
	if changed {
		t.Error("non-JWKS body must not be rewritten")
	}
	if string(out) != string(discovery) {
		t.Errorf("body altered: %s", out)
	}
}

// TestFilterJWKS_PreservesOtherFields confirms re-marshalling keeps top-level
// JWKS fields other than "keys".
func TestFilterJWKS_PreservesOtherFields(t *testing.T) {
	in := `{"keys":[{"kty":"EC","crv":"secp256k1","kid":"x"},{"kty":"RSA","kid":"y"}],"extra":"v"}`
	out, changed := filterJWKS([]byte(in))
	if !changed {
		t.Fatal("expected the secp256k1 key to be filtered out")
	}
	var doc struct {
		Keys  []json.RawMessage `json:"keys"`
		Extra string            `json:"extra"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("filtered body is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 1 {
		t.Errorf("kept %d keys, want 1", len(doc.Keys))
	}
	if doc.Extra != "v" {
		t.Errorf("extra top-level field dropped: %q", doc.Extra)
	}
}

// stubRoundTripper returns a canned response, standing in for the network.
type stubRoundTripper struct {
	contentType string
	body        string
}

func (s stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	h := make(http.Header)
	if s.contentType != "" {
		h.Set("Content-Type", s.contentType)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(s.body)),
	}, nil
}

// TestJWKSFilterTransport covers the RoundTripper end to end: a JWKS response
// has its unsupported key stripped and Content-Length corrected, while a
// non-JSON response passes through untouched.
func TestJWKSFilterTransport(t *testing.T) {
	tr := newJWKSFilterTransport(stubRoundTripper{contentType: "application/json", body: telegramJWKS})
	resp, err := tr.RoundTrip(httptest.NewRequest("GET", "https://oauth.telegram.org/jwks", nil))
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	var doc struct {
		Keys []struct {
			Crv string `json:"crv"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("filtered body is not valid JSON: %v", err)
	}
	if len(doc.Keys) != 3 {
		t.Errorf("kept %d keys, want 3", len(doc.Keys))
	}
	for _, k := range doc.Keys {
		if k.Crv == "secp256k1" {
			t.Error("secp256k1 key was not stripped")
		}
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(got)) {
		t.Errorf("Content-Length = %q, want %d", cl, len(got))
	}

	tr = newJWKSFilterTransport(stubRoundTripper{contentType: "text/html", body: "<html>"})
	resp, err = tr.RoundTrip(httptest.NewRequest("GET", "https://example.com/", nil))
	if err != nil {
		t.Fatalf("RoundTrip (non-JSON): %v", err)
	}
	if got, _ := io.ReadAll(resp.Body); string(got) != "<html>" {
		t.Errorf("non-JSON body altered: %s", got)
	}
}

func TestParseIdentityKeepsProfileFields(t *testing.T) {
	got, err := parseIdentity(idTokenClaims{
		ID:        json.RawMessage(`"42"`),
		Username:  "alice",
		FirstName: "Alice",
		LastName:  "Liddell",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Username != "alice" || got.FirstName != "Alice" || got.LastName != "Liddell" {
		t.Errorf("profile fields not preserved: %+v", got)
	}
}
