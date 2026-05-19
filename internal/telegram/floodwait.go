package telegram

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gotd/td/tgerr"
)

// FloodWaitSeconds extracts the wait duration (in seconds) encoded in a
// Telegram FLOOD_WAIT_X or FLOOD_PREMIUM_WAIT_X MTProto error (both code 420).
// Returns 0 when err is nil, is not a tgerr.Error, or is not a flood-wait
// error. The returned value is suitable for use as a sleep duration: callers
// should cap it (e.g. at 60s) before using it as a time.Duration multiplier.
func FloodWaitSeconds(err error) int {
	if err == nil {
		return 0
	}
	var te *tgerr.Error
	if !errors.As(err, &te) {
		return 0
	}
	if te.Code != 420 {
		return 0
	}
	msg := te.Message
	for _, prefix := range []string{"FLOOD_WAIT_", "FLOOD_PREMIUM_WAIT_"} {
		if strings.HasPrefix(msg, prefix) {
			n, parseErr := strconv.Atoi(msg[len(prefix):])
			if parseErr == nil && n >= 0 {
				return n
			}
		}
	}
	return 0
}
