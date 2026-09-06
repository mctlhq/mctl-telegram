package oauth

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gotd/td/tgerr"
)

func TestFriendlyErr_KnownMTProtoCodes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantSubs string
	}{
		{
			name:     "PHONE_NUMBER_INVALID",
			err:      tgerr.New(400, "PHONE_NUMBER_INVALID"),
			wantSubs: "phone number",
		},
		{
			name:     "PHONE_CODE_INVALID",
			err:      tgerr.New(400, "PHONE_CODE_INVALID"),
			wantSubs: "code is incorrect",
		},
		{
			name:     "PHONE_CODE_EXPIRED",
			err:      tgerr.New(400, "PHONE_CODE_EXPIRED"),
			wantSubs: "expired",
		},
		{
			name:     "FLOOD_WAIT",
			err:      tgerr.New(420, "FLOOD_WAIT_30"),
			wantSubs: "rate limit",
		},
		{
			name:     "deadline exceeded",
			err:      context.DeadlineExceeded,
			wantSubs: "expired",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := friendlyErr(tc.err)
			if !strings.Contains(strings.ToLower(got), strings.ToLower(tc.wantSubs)) {
				t.Errorf("friendlyErr(%v) = %q, want substring %q", tc.err, got, tc.wantSubs)
			}
		})
	}
}

func TestShortReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "nil",
			err:  nil,
			want: "unknown",
		},
		{
			name: "PHONE_NUMBER_INVALID",
			err:  tgerr.New(400, "PHONE_NUMBER_INVALID"),
			want: "phone_invalid",
		},
		{
			name: "PHONE_CODE_INVALID",
			err:  tgerr.New(400, "PHONE_CODE_INVALID"),
			want: "code_invalid",
		},
		{
			name: "PHONE_CODE_EXPIRED",
			err:  tgerr.New(400, "PHONE_CODE_EXPIRED"),
			want: "code_expired",
		},
		{
			name: "FLOOD_WAIT",
			err:  tgerr.New(420, "FLOOD_WAIT_60"),
			want: "flood_wait",
		},
		{
			name: "deadline",
			err:  context.DeadlineExceeded,
			want: "timeout",
		},
		{
			name: "identity cleanup timeout",
			err:  wrapIdentityCleanupErr("clear wrong-account session", context.DeadlineExceeded),
			want: "identity_cleanup_timeout",
		},
		{
			name: "canceled",
			err:  context.Canceled,
			want: "timeout",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shortReason(tc.err)
			if got != tc.want {
				t.Errorf("shortReason(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

func TestWrapIdentityCleanupErr_RepairDeadlineIsNotLoginExpiry(t *testing.T) {
	ops := []string{"revoke wrong-account session", "clear wrong-account session"}
	sentinels := []error{context.DeadlineExceeded, context.Canceled}
	for _, op := range ops {
		for _, inner := range sentinels {
			err := wrapIdentityCleanupErr(op, inner)
			if err == nil {
				t.Fatalf("wrapIdentityCleanupErr(%q, %v) = nil", op, inner)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Errorf("wrap(%q, %v) still unwraps to a login-expiry sentinel", op, inner)
			}
			if !errors.Is(err, errIdentityCleanupTimeout) {
				t.Errorf("wrap(%q, %v) = %v; want errors.Is(..., errIdentityCleanupTimeout)", op, inner, err)
			}
			got := friendlyErr(err)
			if strings.Contains(got, "login attempt expired") {
				t.Errorf("friendlyErr(%v) = %q; repair timeout must not look like CodeTTL expiry", err, got)
			}
			if !strings.Contains(got, op) {
				t.Errorf("friendlyErr(%v) = %q; want the cleanup op %q", err, got, op)
			}
			if reason := shortReason(err); reason == "timeout" {
				t.Errorf("shortReason(%v) = %q; repair timeout must not use the login timeout tag", err, reason)
			}
		}
	}

	plain := errors.New("disk full")
	wrapped := wrapIdentityCleanupErr("clear wrong-account session", plain)
	if !errors.Is(wrapped, plain) {
		t.Errorf("non-timeout wrap should still unwrap: %v", wrapped)
	}
	if errors.Is(wrapped, errIdentityCleanupTimeout) {
		t.Errorf("non-timeout wrap must not become a repair timeout: %v", wrapped)
	}
}
