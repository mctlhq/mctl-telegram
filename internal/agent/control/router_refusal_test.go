package control

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/agent/executor"
)

// A draft Telegram refused is reported to the owner as not sent, with the
// likely cause, not as an internal error (#1055).
func TestApproverErrText_SendRefused(t *testing.T) {
	got := approverErrText(fmt.Errorf("%w: USER_IS_BLOCKED", executor.ErrSendRefused))
	if !strings.Contains(got, "not sent") || strings.Contains(got, "internal error") {
		t.Fatalf("text = %q", got)
	}
}
