package telegram

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/gotd/td/tgerr"
)

func TestIsCallerRefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"channel_invalid", tgerr.New(400, "CHANNEL_INVALID"), true},
		{"peer_id_invalid", tgerr.New(400, "PEER_ID_INVALID"), true},
		{"chat_id_invalid_wrapped", fmt.Errorf("history: %w", tgerr.New(400, "CHAT_ID_INVALID")), true},
		{"chat_write_forbidden", tgerr.New(403, "CHAT_WRITE_FORBIDDEN"), true},
		{"peer_not_accessible", &peerNotAccessibleError{peer: "@nobody", code: "PEER_ID_INVALID"}, true},
		{"peer_not_accessible_wrapped", fmt.Errorf("get_messages: %w", &peerNotAccessibleError{peer: "-100", code: "CHANNEL_INVALID"}), true},
		// draft_reply's refusals are decided from a successful reply, so they
		// must not count as session-borrow failures.
		{"no_existing_dialog_wrapped", fmt.Errorf("draft: %w", ErrNoExistingDialog), true},
		{"cannot_post", ErrCannotPost, true},
		// A reply that proves nothing about the caller, or that says the
		// session itself is unhealthy, must keep counting against the SLI.
		{"peer_flood", tgerr.New(400, "PEER_FLOOD"), false},
		{"api_id_invalid", tgerr.New(400, "API_ID_INVALID"), false},
		{"connection_not_inited_wrapped", fmt.Errorf("init: %w", tgerr.New(400, "CONNECTION_NOT_INITED")), false},
		{"connection_system_empty", tgerr.New(400, "CONNECTION_SYSTEM_EMPTY"), false},
		{"connection_device_model_empty", tgerr.New(400, "CONNECTION_DEVICE_MODEL_EMPTY"), false},
		{"connection_app_version_empty", tgerr.New(400, "CONNECTION_APP_VERSION_EMPTY"), false},
		{"connection_lang_pack_invalid_wrapped", fmt.Errorf("init: %w", tgerr.New(400, "CONNECTION_LANG_PACK_INVALID")), false},
		{"input_method_invalid", tgerr.New(400, "INPUT_METHOD_INVALID"), false},
		{"flood_wait", tgerr.New(420, "FLOOD_WAIT_17"), false},
		{"session_password_needed", tgerr.New(400, "SESSION_PASSWORD_NEEDED"), false},
		{"session_revoked", tgerr.New(401, "SESSION_REVOKED"), false},
		{"auth_key_unregistered", tgerr.New(401, "AUTH_KEY_UNREGISTERED"), false},
		{"user_deactivated", tgerr.New(401, "USER_DEACTIVATED_BAN"), false},
		{"telegram_internal", tgerr.New(500, "RPC_CALL_FAIL"), false},
		{"telegram_internal_plain", tgerr.New(500, "INTERNAL"), false},
		{"flood_wait_wrapped", fmt.Errorf("history: %w", tgerr.New(420, "FLOOD_WAIT_5")), false},
		{"unexpected_eof", io.ErrUnexpectedEOF, false},
		{"plain", errors.New("x"), false},
		{"transport", errors.New("connection reset by peer"), false},
		{"canceled", context.Canceled, false},
		{"deadline", context.DeadlineExceeded, false},
		{"pool_full", ErrPoolFull, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsCallerRefusal(tc.err); got != tc.want {
				t.Fatalf("IsCallerRefusal(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// The re-phrased refusal keeps the exact guidance text clients rely on, and
// must not unwrap to the raw RPC error a catalog renderer would substitute.
func TestPeerNotAccessibleError(t *testing.T) {
	err := error(&peerNotAccessibleError{peer: "@nobody", code: "PEER_ID_INVALID"})
	want := `peer "@nobody" could not be accessed (PEER_ID_INVALID): it is not in your dialog list; ` +
		"call list_dialogs and use an id exactly as returned there"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err.Error(), want)
	}
	if !errors.Is(err, ErrPeerNotAccessible) {
		t.Fatal("errors.Is(err, ErrPeerNotAccessible) = false")
	}
	var te *tgerr.Error
	if errors.As(err, &te) {
		t.Fatalf("errors.As(err, *tgerr.Error) = true (%v); the guidance text would be replaced", te)
	}
}
