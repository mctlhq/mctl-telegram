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
			name: "redacts a bare username in resolve %q",
			in:   `peer "@alice_telegram" is not in your dialog list: resolve "alice_telegram": rpc error code 400: USERNAME_NOT_OCCUPIED`,
			want: `peer "[redacted]" is not in your dialog list: resolve "[redacted]": rpc error code 400: USERNAME_NOT_OCCUPIED`,
		},
		{
			name: "redacts a bare username passed without @",
			in:   `peer "bob_handle" not found in dialogs`,
			want: `peer "[redacted]" not found in dialogs`,
		},
		{
			name: "redacts the typed peer in every telegram error shape",
			in:   `could not resolve "carol_x"; cannot build InputPeer for "user:42"; unrecognized peer format: "dana?"`,
			want: `could not resolve "[redacted]"; cannot build InputPeer for "[redacted]"; unrecognized peer format: "[redacted]"`,
		},
		{
			name: "redacts a short numeric channel id in a peer position",
			in:   `peer "channel:12345" could not be accessed (CHANNEL_INVALID)`,
			want: `peer "[redacted]" could not be accessed (CHANNEL_INVALID)`,
		},
		{
			name: "handles escaped quotes inside the value",
			in:   `peer "a\"b_handle" not found`,
			want: `peer "[redacted]" not found`,
		},
		{
			name: "leaves quoted non-peer text alone",
			in:   `call list_dialogs and pass an id (e.g. "channel:<id>")`,
			want: `call list_dialogs and pass an id (e.g. "channel:<id>")`,
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

// TestRedactAttr_LocalBridgeSensitiveKeys is T-redact: activation codes, PoP
// nonces/signatures, device_registration_key, and minted worker/bridge token
// strings must never appear unredacted in slog output, matched
// case-insensitively like every other entry in sensitiveKeys.
func TestRedactAttr_LocalBridgeSensitiveKeys(t *testing.T) {
	keys := []string{
		"user_code",
		"device_code",
		"consent_token",
		"nonce",
		"signature",
		"device_registration_key",
		"worker_token",
		"bridge_token",
		"file_base64",
		"file_path",
		// Case-insensitivity check, matching the package's stated matching
		// rule for every other entry.
		"Nonce",
		"WORKER_TOKEN",
	}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "super-secret-value"))
			if got.Value.Kind() != slog.KindString || !strings.HasPrefix(got.Value.String(), "[redacted len=") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
			if strings.Contains(got.Value.String(), "super-secret-value") {
				t.Fatalf("key %q leaked its value: %v", k, got)
			}
		})
	}
}

// TestRedactAttr_DevicePubkeyExempt asserts the deliberate exemption:
// device_pubkey is public key material, not a secret, and must pass through
// unredacted so device-mismatch reports stay debuggable.
func TestRedactAttr_DevicePubkeyExempt(t *testing.T) {
	got := redactAttr(slog.String("device_pubkey", "not-a-secret-public-key"))
	if got.Value.Kind() != slog.KindString || got.Value.String() != "not-a-secret-public-key" {
		t.Fatalf("device_pubkey should be exempt from redaction, got: %v", got)
	}
}

// TestRedactAttr_ClientIdentityNames is T17: first_name and last_name
// (issue-438's captured Telegram identity attributes) must never appear
// unredacted in slog output, matched case-insensitively like every other
// entry in sensitiveKeys.
func TestRedactAttr_ClientIdentityNames(t *testing.T) {
	keys := []string{"first_name", "last_name", "First_Name", "LAST_NAME"}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "Alice Example"))
			if got.Value.Kind() != slog.KindString || !strings.HasPrefix(got.Value.String(), "[redacted len=") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
			if strings.Contains(got.Value.String(), "Alice Example") {
				t.Fatalf("key %q leaked its value: %v", k, got)
			}
		})
	}
}

// TestRedactAttr_BotReceiverKeys covers the keys added for the login-bot update
// receiver (issue-619). The receiver itself never decodes message text or
// callback data, so it cannot log them; these entries exist so that a LATER
// handler which does decode content cannot leak it by naming the field in the
// obvious way. Case-insensitive, like every other entry in sensitiveKeys.
func TestRedactAttr_BotReceiverKeys(t *testing.T) {
	keys := []string{
		"bot_token",
		"callback_data",
		"callback_payload",
		"update_json",
		"Bot_Token",
		"CALLBACK_DATA",
	}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "123456:AAHsecret-or-payload"))
			if got.Value.Kind() != slog.KindString || !strings.HasPrefix(got.Value.String(), "[redacted len=") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
			if strings.Contains(got.Value.String(), "AAHsecret-or-payload") {
				t.Fatalf("key %q leaked its value: %v", k, got)
			}
		})
	}
}

func TestRedactAttr_BotStartBridgeTokenKeys(t *testing.T) {
	for _, k := range []string{"bot_start_bridge_token", "BOT_START_BRIDGE_TOKEN", "BotStartBridgeToken"} {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "bridge-secret-value-abcdefghijklmnop"))
			if got.Value.Kind() != slog.KindString || !strings.HasPrefix(got.Value.String(), "[redacted len=") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
			if strings.Contains(got.Value.String(), "bridge-secret-value") {
				t.Fatalf("key %q leaked its value: %v", k, got)
			}
		})
	}
}

func TestRedactAttr_BroadcastContentKeys(t *testing.T) {
	for _, k := range []string{"content", "campaign_content", "broadcast_text", "Content"} {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "New tool released today"))
			if !strings.HasPrefix(got.Value.String(), "[redacted len=") || strings.Contains(got.Value.String(), "New tool") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
		})
	}
}

// TestRedactAttr_HumanInputContentKeys: the question an agent asked and the
// answer the owner typed (issue-571) must never reach a log line.
func TestRedactAttr_HumanInputContentKeys(t *testing.T) {
	for _, k := range []string{"question", "options", "answer", "value", "Question"} {
		t.Run(k, func(t *testing.T) {
			got := redactAttr(slog.String(k, "private-content"))
			if !strings.HasPrefix(got.Value.String(), "[redacted len=") || strings.Contains(got.Value.String(), "private-content") {
				t.Fatalf("key %q was not redacted: %v", k, got)
			}
		})
	}
}
