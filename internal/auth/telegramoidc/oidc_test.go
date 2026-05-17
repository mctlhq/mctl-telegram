package telegramoidc

import (
	"encoding/json"
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
