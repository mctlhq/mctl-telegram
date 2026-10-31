package main

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func TestMapPoolSendError_Duplicate(t *testing.T) {
	err := mapPoolSendError(fmt.Errorf("borrow: %w", telegram.ErrRandomIDDuplicate))
	if !errors.Is(err, executor.ErrAlreadyDelivered) {
		t.Fatalf("duplicate not mapped to ErrAlreadyDelivered: %v", err)
	}
	if err := mapPoolSendError(errors.New("timeout")); errors.Is(err, executor.ErrAlreadyDelivered) {
		t.Fatalf("plain error mapped to ErrAlreadyDelivered: %v", err)
	}
}

func TestMapPoolSelfSendError_Duplicate(t *testing.T) {
	err := mapPoolSelfSendError(fmt.Errorf("borrow: %w", telegram.ErrRandomIDDuplicate))
	if !errors.Is(err, executor.ErrAlreadyDelivered) {
		t.Fatalf("duplicate not mapped to ErrAlreadyDelivered: %v", err)
	}
	if err := mapPoolSelfSendError(errors.New("timeout")); errors.Is(err, executor.ErrAlreadyDelivered) {
		t.Fatalf("plain error mapped to ErrAlreadyDelivered: %v", err)
	}
}

// Without an access hash there is nothing safe to look up with: the lookup
// reports not found without borrowing a client.
func TestPoolSenderLocateDelivered_ZeroAccessHash(t *testing.T) {
	s := &poolSender{}
	id, found, err := s.LocateDelivered(t.Context(), 1, 500100202, 0, "hello Bob", time.Now())
	if id != 0 || found || err != nil {
		t.Fatalf("got id=%d found=%v err=%v, want 0/false/nil", id, found, err)
	}
}
