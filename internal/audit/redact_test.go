package audit

import (
	"log/slog"
	"strings"
	"testing"
)

func TestScrubText(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "redacts @handle inside an error",
			in:   `peer "@alice_telegram" not found`,
			want: `peer "[redacted]" not found`,
		},
		{
			name: "redacts phone-like digit run",
			in:   "resolve +14155550123: invalid",
			want: "resolve [redacted]: invalid",
		},
		{
			name: "redacts bare long digit run (numeric peer id)",
			in:   "peer 1980654735 not found",
			want: "peer [redacted] not found",
		},
		{
			name: "leaves MTProto error codes intact",
			in:   "SESSION_PASSWORD_NEEDED",
			want: "SESSION_PASSWORD_NEEDED",
		},
		{
			name: "leaves FLOOD_WAIT short numbers intact",
			in:   "FLOOD_WAIT_30: rpc error",
			want: "FLOOD_WAIT_30: rpc error",
		},
		{
			name: "leaves plain text untouched",
			in:   "telegram client failed: context deadline exceeded",
			want: "telegram client failed: context deadline exceeded",
		},
		{
			name: "redacts multiple identifiers",
			in:   `@bobby and @carol_x both failed`,
			want: `[redacted] and [redacted] both failed`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ScrubText(tc.in); got != tc.want {
				t.Errorf("ScrubText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactAttr_ApprovalCodeCiphertext(t *testing.T) {
	got := redactAttr(slog.String("approval_code_encrypted", "secret-ciphertext"))
	if got.Value.Kind() != slog.KindString || !strings.HasPrefix(got.Value.String(), "[redacted len=") {
		t.Fatalf("approval ciphertext was not redacted: %v", got)
	}
}
