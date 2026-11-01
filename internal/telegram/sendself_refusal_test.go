package telegram

import (
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/tgerr"
)

func TestRefusalClass_ClosedList(t *testing.T) {
	for _, class := range []string{"USER_IS_BLOCKED", "PEER_ID_INVALID", "INPUT_USER_DEACTIVATED"} {
		got, ok := RefusalClass(fmt.Errorf("send: %w", tgerr.New(400, class)))
		if !ok || got != class {
			t.Errorf("%s: got %q ok=%v", class, got, ok)
		}
	}
	for _, err := range []error{
		tgerr.New(400, "RANDOM_ID_DUPLICATE"),
		tgerr.New(420, "FLOOD_WAIT_5"),
		tgerr.New(500, "INTERNAL"),
		errors.New("i/o timeout"),
	} {
		if class, ok := RefusalClass(err); ok {
			t.Errorf("%v classified as a refusal (%s)", err, class)
		}
	}
}
