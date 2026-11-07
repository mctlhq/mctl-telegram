package web

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/mctlhq/mctl-telegram/internal/broadcast"
)

// categoryLabels name the notification categories for a human approver.
var categoryLabels = map[string]string{
	"product_updates": "Product updates (opt-in)",
	"maintenance":     "Maintenance notices",
	"security":        "Security notices",
}

// skipLabels explain each countable skip reason in plain words.
var skipLabels = map[string]string{
	"no_account":   "no live account",
	"policy":       "tier not targeted",
	"unsubscribed": "no consent for this category",
	"unreachable":  "the bot cannot reach them",
}

// describeAudience renders a stored selector as one plain sentence, so the
// approver does not have to read JSON to learn who will receive the message.
// ok is false when the stored selector cannot be read: the caller must then
// say so, never fall back to an empty or "everyone" sentence.
func describeAudience(selectorJSON string) (text string, ok bool) {
	var sel broadcast.Selector
	if err := json.Unmarshal([]byte(selectorJSON), &sel); err != nil || sel.Category == "" {
		return "", false
	}
	label, known := categoryLabels[sel.Category]
	if !known {
		label = sel.Category
	}
	var b strings.Builder
	b.WriteString(label)
	b.WriteString(" for ")
	b.WriteString(describeTiers(sel.Tiers))
	b.WriteString(".")

	var limits []string
	if len(sel.OnlyTelegramIDs) > 0 {
		ids := make([]string, len(sel.OnlyTelegramIDs))
		for i, id := range sel.OnlyTelegramIDs {
			ids[i] = strconv.FormatInt(id, 10)
		}
		limits = append(limits, fmt.Sprintf("only these %d Telegram ids: %s", len(ids), strings.Join(ids, ", ")))
	}
	if len(sel.ConnectedVia) > 0 {
		limits = append(limits, "connected via "+strings.Join(sel.ConnectedVia, ", "))
	}
	if sel.ActiveWithinDays > 0 {
		limits = append(limits, fmt.Sprintf("seen in the last %d days", sel.ActiveWithinDays))
	}
	if len(limits) == 0 {
		b.WriteString(" No further restriction: every eligible account.")
	} else {
		b.WriteString(" Limited to ")
		b.WriteString(strings.Join(limits, "; "))
		b.WriteString(".")
	}
	return b.String(), true
}

func describeTiers(tiers []string) string {
	switch {
	case len(tiers) == 0:
		return "no tier recorded"
	case len(tiers) == 1 && tiers[0] == broadcast.TierClient:
		return "clients"
	case len(tiers) == 1 && tiers[0] == broadcast.TierAdmin:
		return "admins"
	default:
		return strings.Join(tiers, " and ")
	}
}

// describeOutcome renders the stored preview counts as one sentence. ok is
// false when they cannot be read; an unreadable count is never "0 skipped".
func describeOutcome(previewJSON string) (text string, ok bool) {
	var c broadcast.Counts
	if err := json.Unmarshal([]byte(previewJSON), &c); err != nil {
		return "", false
	}
	var b strings.Builder
	switch c.Eligible {
	case 0:
		b.WriteString("Nobody will receive it.")
	case 1:
		b.WriteString("1 account will receive it.")
	default:
		fmt.Fprintf(&b, "%d accounts will receive it.", c.Eligible)
	}
	reasons := make([]string, 0, len(c.Skipped))
	for reason, n := range c.Skipped {
		if n > 0 {
			reasons = append(reasons, reason)
		}
	}
	sort.Strings(reasons)
	skipped := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		label, known := skipLabels[reason]
		if !known {
			label = reason
		}
		skipped = append(skipped, fmt.Sprintf("%d (%s)", c.Skipped[reason], label))
	}
	if len(skipped) > 0 {
		b.WriteString(" Skipped: ")
		b.WriteString(strings.Join(skipped, ", "))
		b.WriteString(".")
	} else {
		b.WriteString(" None skipped.")
	}
	return b.String(), true
}
