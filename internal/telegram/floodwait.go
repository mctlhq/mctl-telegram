package telegram

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gotd/td/tgerr"
)

// FloodWaitSeconds extracts the wait duration (in seconds) encoded in a
// Telegram FLOOD_WAIT_X MTProto error. Returns 0 when err is nil, is not a
// tgerr.Error, or is not a FloodWait error. The returned value is suitable
// for use as a sleep duration: callers should cap it (e.g. at 60s) before
// using it as a time.Duration multiplier.
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
	const prefix = "FLOOD_WAIT_"
	msg := te.Message
	if !strings.HasPrefix(msg, prefix) {
		return 0
	}
	n, parseErr := strconv.Atoi(msg[len(prefix):])
	if parseErr != nil || n < 0 {
		return 0
	}
	return n
}
