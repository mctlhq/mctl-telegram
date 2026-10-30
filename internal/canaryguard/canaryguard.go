// Package canaryguard names the Telegram accounts the monitoring canary runs
// as (CANARY_TELEGRAM_IDS) so that every path which ends such an account's
// session asks for an explicit confirmation first (issue #961).
//
// On 2026-10-28 the canary account was disconnected from the manage page
// during manual testing and the canary stayed red for about 38 hours. A
// disconnect of a listed account is still allowed -- the owner may need it --
// but only with a second, deliberate step: a confirmation page on
// /telegram/connect/manage, confirm_canary=true on the API and MCP tools.
// An override is recorded in the audit log under the tool name with
// OverrideSuffix appended.
package canaryguard

import (
	"fmt"
	"strconv"
	"strings"
)

// OverrideSuffix is appended to the audited tool name when a caller confirmed
// a session-ending action on a canary account.
const OverrideSuffix = ":canary_override"

// Refusal is the error text returned when a session-ending action on a canary
// account arrives without confirmation. param names the confirmation the
// caller has to add.
func Refusal(param string) string {
	return "This Telegram account is the monitoring canary: ending its session makes the canary fail until the account is re-linked. Retry with " + param + " to proceed."
}

// Set is the parsed CANARY_TELEGRAM_IDS. The zero value guards nothing.
type Set map[int64]struct{}

// Parse reads a comma-separated list of positive Telegram ids. Blank entries
// are skipped, so "" and " , " are an empty set; anything else that is not a
// positive integer is an error rather than silently dropped, because a typo
// would leave the canary unguarded without anyone noticing.
func Parse(raw string) (Set, error) {
	s := Set{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseInt(part, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid Telegram id %q: must be a positive integer", part)
		}
		s[n] = struct{}{}
	}
	return s, nil
}

// Contains reports whether tgID is a canary account. Non-positive ids never
// match, so an identity without a Telegram id is never treated as the canary.
func (s Set) Contains(tgID int64) bool {
	if tgID <= 0 {
		return false
	}
	_, ok := s[tgID]
	return ok
}
