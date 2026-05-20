package oauth

import (
	"context"
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
			want: "code_expired",
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
