package telegramwidget

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testBotToken = "123456:test-bot-token"

// signFields produces a valid hash for the given fields using the same
// algorithm as Telegram's signing infrastructure. Used by tests only.
func signFields(t *testing.T, token string, fields map[string]string) string {
	t.Helper()
	secret := sha256.Sum256([]byte(token))
	keys := make([]string, 0, len(fields))
	for k, v := range fields {
		if k == "hash" || v == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fields[k])
	}
	mac := hmac.New(sha256.New, secret[:])
	mac.Write([]byte(b.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestVerifier(t *testing.T, now time.Time) *Verifier {
	t.Helper()
	v, err := New(testBotToken)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	v.now = func() time.Time { return now }
	return v
}

func TestVerify_HappyPath(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	fields := map[string]string{
		"id":         "210408407",
		"first_name": "Dmitry",
		"username":   "MashkovD",
		"auth_date":  strconv.FormatInt(now.Unix()-30, 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)

	payload, err := v.Verify(fields)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if payload.ID != 210408407 {
		t.Errorf("ID = %d, want 210408407", payload.ID)
	}
	if payload.Username != "MashkovD" {
		t.Errorf("Username = %q, want MashkovD", payload.Username)
	}
	if payload.FirstName != "Dmitry" {
		t.Errorf("FirstName = %q, want Dmitry", payload.FirstName)
	}
}

func TestVerify_TamperedHash(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	fields := map[string]string{
		"id":        "1",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
		"hash":      strings.Repeat("0", 64),
	}
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted a tampered hash")
	}
}

func TestVerify_TamperedField(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	fields := map[string]string{
		"id":        "1",
		"username":  "alice",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)
	// Mutate after signing — verification must catch this.
	fields["username"] = "bob"
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted a payload with a mutated field")
	}
}

func TestVerify_ExpiredAuthDate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	// 25h ago — exceeds DefaultMaxAge.
	old := now.Add(-25 * time.Hour).Unix()
	fields := map[string]string{
		"id":        "1",
		"auth_date": strconv.FormatInt(old, 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted an expired auth_date")
	}
}

func TestVerify_FutureAuthDate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	// 10 min in the future — exceeds the 5-min skew window.
	future := now.Add(10 * time.Minute).Unix()
	fields := map[string]string{
		"id":        "1",
		"auth_date": strconv.FormatInt(future, 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted a future auth_date beyond skew window")
	}
}

func TestVerify_SkewWindowAccepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	// 2 min in the future — within skew window.
	future := now.Add(2 * time.Minute).Unix()
	fields := map[string]string{
		"id":        "1",
		"auth_date": strconv.FormatInt(future, 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)
	if _, err := v.Verify(fields); err != nil {
		t.Fatalf("Verify rejected within skew window: %v", err)
	}
}

func TestVerify_MissingRequired(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	cases := []struct {
		name   string
		fields map[string]string
	}{
		{"no hash", map[string]string{"id": "1", "auth_date": "1"}},
		{"no id", map[string]string{"auth_date": "1", "hash": strings.Repeat("0", 64)}},
		{"no auth_date", map[string]string{"id": "1", "hash": strings.Repeat("0", 64)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := v.Verify(c.fields); err == nil {
				t.Fatal("Verify accepted a payload missing a required field")
			}
		})
	}
}

func TestVerify_InvalidID(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	fields := map[string]string{
		"id":        "not-a-number",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	fields["hash"] = signFields(t, testBotToken, fields)
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted a non-numeric id")
	}
}

func TestVerify_WrongBotToken(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	v := newTestVerifier(t, now)
	fields := map[string]string{
		"id":        "1",
		"auth_date": strconv.FormatInt(now.Unix(), 10),
	}
	// Sign with a DIFFERENT token than the verifier was constructed with.
	fields["hash"] = signFields(t, "different-token", fields)
	if _, err := v.Verify(fields); err == nil {
		t.Fatal("Verify accepted a payload signed by a different bot")
	}
}

func TestNew_EmptyToken(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New accepted an empty bot token")
	}
}
