package telegram

import (
	"errors"
	"testing"

	"github.com/gotd/td/tgerr"
)

func TestClassifySendError_RandomIDDuplicate(t *testing.T) {
	err := classifySendError(tgerr.New(400, "RANDOM_ID_DUPLICATE"))
	if !errors.Is(err, ErrRandomIDDuplicate) {
		t.Fatalf("RANDOM_ID_DUPLICATE not tagged: %v", err)
	}
	if err := classifySendError(tgerr.New(400, "PEER_ID_INVALID")); errors.Is(err, ErrRandomIDDuplicate) {
		t.Fatalf("other RPC error tagged as duplicate: %v", err)
	}
}
