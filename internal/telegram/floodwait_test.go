package telegram

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/tgerr"
)

func TestFloodWaitSeconds(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{
			name: "nil error",
			err:  nil,
			want: 0,
		},
		{
			name: "non-tgerr",
			err:  errors.New("connection refused"),
			want: 0,
		},
		{
			name: "FLOOD_WAIT_30",
			err:  tgerr.New(420, "FLOOD_WAIT_30"),
			want: 30,
		},
		{
			name: "FLOOD_WAIT_0",
			err:  tgerr.New(420, "FLOOD_WAIT_0"),
			want: 0,
		},
		{
			name: "FLOOD_WAIT_86400",
			err:  tgerr.New(420, "FLOOD_WAIT_86400"),
			want: 86400,
		},
		{
			name: "PEER_ID_INVALID (non-flood tgerr)",
			err:  tgerr.New(400, "PEER_ID_INVALID"),
			want: 0,
		},
		{
			name: "wrapped FLOOD_WAIT_30",
			err:  fmt.Errorf("borrow: %w", tgerr.New(420, "FLOOD_WAIT_30")),
			want: 30,
		},
		{
			name: "420 without FLOOD_WAIT_ prefix",
			err:  tgerr.New(420, "SLOWMODE_WAIT_15"),
			want: 0,
		},
		{
			name: "auth code 401 not a flood",
			err:  tgerr.New(401, "AUTH_KEY_INVALID"),
			want: 0,
		},
		{
			name: "FLOOD_PREMIUM_WAIT_60",
			err:  tgerr.New(420, "FLOOD_PREMIUM_WAIT_60"),
			want: 60,
		},
		{
			name: "FLOOD_PREMIUM_WAIT_0",
			err:  tgerr.New(420, "FLOOD_PREMIUM_WAIT_0"),
			want: 0,
		},
		{
			name: "wrapped FLOOD_PREMIUM_WAIT_120",
			err:  fmt.Errorf("borrow: %w", tgerr.New(420, "FLOOD_PREMIUM_WAIT_120")),
			want: 120,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := FloodWaitSeconds(tc.err)
			if got != tc.want {
				t.Errorf("FloodWaitSeconds(%v) = %d, want %d", tc.err, got, tc.want)
			}
		})
	}
}
