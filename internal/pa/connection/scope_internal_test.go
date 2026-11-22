package connection

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// A token set sealed before #1318 slice C2b has no "x" field: it opens
// with an unknown expiry, never a zero one read as "already expired" and
// never as "does not expire".
func TestTokenSet_OldBlobDecodes(t *testing.T) {
	ts, err := unmarshalTokenSet([]byte(`{"a":"fake-at-old","r":"fake-rt-old","e":3600}`))
	if err != nil {
		t.Fatalf("old blob: %v", err)
	}
	if ts.AccessToken.Reveal() != "fake-at-old" || ts.RefreshToken.Reveal() != "fake-rt-old" || ts.ExpiresIn != 3600 {
		t.Fatalf("old blob fields: %+v", ts)
	}
	if !ts.ExpiresAt.IsZero() {
		t.Fatalf("old blob expiry %v, want unknown", ts.ExpiresAt)
	}
}

func TestTokenSet_ExpiryRoundTrip(t *testing.T) {
	at := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	in := TokenSet{AccessToken: NewSecret("fake-at"), RefreshToken: NewSecret("fake-rt"), ExpiresIn: 3600}.receivedAt(at)
	if want := at.Add(time.Hour); !in.ExpiresAt.Equal(want) {
		t.Fatalf("stamped %v, want %v", in.ExpiresAt, want)
	}
	b, err := in.marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := unmarshalTokenSet(b)
	if err != nil || !out.ExpiresAt.Equal(in.ExpiresAt) {
		t.Fatalf("round trip %v (%v), want %v", out.ExpiresAt, err, in.ExpiresAt)
	}
	// expires_in 0 or absent: unknown, and it stays unknown sealed.
	for _, ei := range []int64{0} {
		z := TokenSet{AccessToken: NewSecret("fake-at"), ExpiresIn: ei}.receivedAt(at)
		if !z.ExpiresAt.IsZero() {
			t.Fatalf("expires_in %d stamped %v, want unknown", ei, z.ExpiresAt)
		}
		b, _ := z.marshal()
		// The blob keeps the pre-C2b shape, byte for byte: a build
		// rolled back to before this slice reads it unchanged.
		if bytes.Contains(b, []byte(`"x"`)) {
			t.Fatalf("unknown expiry written as %s", b)
		}
		if got, err := unmarshalTokenSet(b); err != nil || !got.ExpiresAt.IsZero() {
			t.Fatalf("unknown expiry sealed as %v (%v)", got.ExpiresAt, err)
		}
	}
}

// A negative stored expiry is unreadable, not "expired long ago" and not
// unknown.
func TestTokenSet_NegativeExpiryUnreadable(t *testing.T) {
	if _, err := unmarshalTokenSet([]byte(`{"a":"fake-at","x":-1}`)); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("negative expiry: %v, want ErrUnreadable", err)
	}
}

// An absurd expires_in is cut to MaxExpiresIn (#1397 review): without the
// cap, a lifetime past about 9.2e9s overflows time.Duration, the expiry
// lands in the past, and every call refreshes ahead.
func TestTokenSet_ExpiresInCapped(t *testing.T) {
	at := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	want := at.Add(MaxExpiresIn * time.Second)
	for _, raw := range []string{"9223372036854775807", "10000000000", "31536001"} {
		check := VerifyTokenResponse(ServerTG, []byte(`{"access_token":"fake-at","token_type":"Bearer","scope":"`+
			mustCanonical(t)+`","expires_in":`+raw+`}`))
		if check.Err != nil {
			t.Fatalf("expires_in %s: %v", raw, check.Err)
		}
		got := check.Tokens.receivedAt(at)
		if !got.ExpiresAt.Equal(want) {
			t.Fatalf("expires_in %s: expiry %v, want %v (capped)", raw, got.ExpiresAt, want)
		}
	}
}

func mustCanonical(t *testing.T) string {
	t.Helper()
	s, ok := CanonicalScope(ServerTG)
	if !ok {
		t.Fatal("no canonical tg scope")
	}
	return s
}
