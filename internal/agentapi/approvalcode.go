package agentapi

import "github.com/mctlhq/mctl-telegram/internal/answercode"

// newApprovalCode returns a random 6-character approval code. The generator
// (alphabet without ambiguous characters, rejection sampling for a uniform
// distribution) is shared with human-input answer codes via
// internal/answercode; the caller still retries on the rare insert conflict
// (see actions.go).
func newApprovalCode() (string, error) {
	return answercode.New()
}
