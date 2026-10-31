package telegram

import (
	"errors"
	"strconv"
	"strings"

	"github.com/gotd/td/tgerr"
)

// IsPeerFlood reports whether err is Telegram's PEER_FLOOD refusal. Unlike
// FLOOD_WAIT_X it is not a transient rate limit: it is the anti-spam
// system's verdict on the account, carries no wait, and repeating the
// refused call is the behaviour Telegram bans accounts for. It must never
// be retried.
func IsPeerFlood(err error) bool {
	return err != nil && tgerr.Is(err, "PEER_FLOOD")
}

// IsFrozenAccount reports whether err is one of Telegram's refusals for a
// frozen account (FROZEN_METHOD_INVALID, FROZEN_PARTICIPANT_MISSING; see
// https://core.telegram.org/api/auth#frozen-accounts). Telegram answered,
// so the session and the service work: it is a caller refusal, not an
// outage, even though FROZEN_METHOD_INVALID arrives with code 420.
func IsFrozenAccount(err error) bool {
	var te *tgerr.Error
	return errors.As(err, &te) && strings.HasPrefix(te.Type, "FROZEN_")
}

// FloodWaitSeconds extracts the wait duration (in seconds) encoded in a
// Telegram FLOOD_WAIT_X or FLOOD_PREMIUM_WAIT_X MTProto error (both code 420).
// Returns 0 when err is nil, is not a tgerr.Error, or is not a flood-wait
// error. The returned value is suitable for use as a sleep duration: callers
// should cap it (e.g. at 60s) before using it as a time.Duration multiplier.
func FloodWaitSeconds(err error) int {
	n, _ := floodWait(err)
	return n
}

// floodWait is FloodWaitSeconds that also reports whether err was a flood
// wait at all, so FLOOD_WAIT_0 is not mistaken for no flood wait.
func floodWait(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var te *tgerr.Error
	if !errors.As(err, &te) {
		return 0, false
	}
	if te.Code != 420 {
		return 0, false
	}
	msg := te.Message
	for _, prefix := range []string{"FLOOD_WAIT_", "FLOOD_PREMIUM_WAIT_"} {
		if strings.HasPrefix(msg, prefix) {
			n, parseErr := strconv.Atoi(msg[len(prefix):])
			if parseErr == nil && n >= 0 {
				return n, true
			}
		}
	}
	return 0, false
}
