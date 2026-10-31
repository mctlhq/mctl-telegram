package main

import (
	"errors"
	"fmt"
	"testing"

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
