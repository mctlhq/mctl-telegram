// Package humaninput is the Telegram surface adapter for agent human-input
// (clarification) requests, issue-571. It delivers a pending request to the
// linked operator's Saved Messages, accepts the operator's single-choice or
// free-text answer as /mctl input <code> <value>, and submits it to mctl-api
// as the canonical HumanInputResponse. mctl-api owns every authorization and
// state decision; this package only renders and relays.
//
// It never touches the approval path: it has no Executor, never reads
// agent_actions, and its answer codes live in their own table. Logs carry ids
// and outcome classes only, never question text, option labels or answers.
package humaninput

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/mctlhq/mctl-telegram/internal/sanitize"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

// Per-field caps applied to the allowlisted DTO fields before rendering.
const (
	maxQuestionRunes = 600
	maxReasonRunes   = 400
	maxLabelRunes    = 120
	maxOptions       = 10
	maxLinks         = 3
	maxLinkRunes     = 200
	maxRefRunes      = 120
	// maxMessageRunes is Telegram's text-message cap.
	maxMessageRunes = 4096
)

// Header is the first line of every delivered request. It is deliberately
// distinct from approval notifications, which never use this text.
const Header = "INPUT REQUEST (not an approval)"

// NoLongerActive is the reply and follow-up for a request that can no longer
// take an answer.
const NoLongerActive = "This question is no longer active."

// continuationPrefix starts every line of a multi-line question or reason
// after its first. Render's own frame lines (Work:, Question:, Reason:,
// Options:, the numbered options, Expires:, Link:, Answer:, Ref:) all start
// at column 0, and no agent-supplied text ever does: a question cannot forge
// a second "Answer: /mctl input <other code> ..." line or a fake option.
const continuationPrefix = "  | "

// Render builds the delivered message for v and code. It reads only the
// allowlisted RequestView fields (question, reason, options, expires_at,
// work/request refs, https context refs), runs each through sanitize with a
// cap, and caps the whole message at 4096 runes while keeping the answer line
// intact.
func Render(v workctx.RequestView, code string) string {
	var head strings.Builder
	head.WriteString(Header)
	head.WriteString("\n")
	ref := v.WorkRef
	if ref == "" {
		ref = v.WorkItemID
	}
	if ref != "" {
		fmt.Fprintf(&head, "Work: %s\n", oneLine(ref, maxRefRunes))
	}
	fmt.Fprintf(&head, "Question: %s\n", block(v.Question, maxQuestionRunes))
	if strings.TrimSpace(v.Reason) != "" {
		fmt.Fprintf(&head, "Reason: %s\n", block(v.Reason, maxReasonRunes))
	}
	if v.ResponseType == workctx.HumanInputTypeSingleChoice {
		head.WriteString("Options:\n")
		for i, o := range v.Options {
			if i >= maxOptions {
				break
			}
			fmt.Fprintf(&head, "%d. %s\n", i+1, oneLine(o, maxLabelRunes))
		}
	}
	if t, ok := parseExpiry(v.ExpiresAt); ok {
		fmt.Fprintf(&head, "Expires: %s\n", t.UTC().Format("2006-01-02 15:04 UTC"))
	}
	links := 0
	for _, l := range v.ContextRefs {
		if links >= maxLinks {
			break
		}
		// A link is shown only if sanitizing would not change it: one
		// carrying invisible, bidi-control or other format code points
		// (which could make it read as another host) is dropped, not
		// rewritten into a different URL.
		if u, err := url.Parse(l); err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != "" && len([]rune(l)) <= maxLinkRunes && !strings.ContainsFunc(l, isBreakOrSpace) && oneLine(l, maxLinkRunes) == l {
			fmt.Fprintf(&head, "Link: %s\n", l)
			links++
		}
	}

	var tail strings.Builder
	if v.ResponseType == workctx.HumanInputTypeSingleChoice {
		fmt.Fprintf(&tail, "Answer: /mctl input %s <number>\n", code)
	} else {
		fmt.Fprintf(&tail, "Answer: /mctl input %s <your answer>\n", code)
	}
	fmt.Fprintf(&tail, "Ref: request %s v%d", oneLine(v.RequestID, 64), v.RequestVersion)

	// The answer line is the point of the message: if the composed text is
	// somehow over the cap, trim the head, never the tail.
	budget := maxMessageRunes - len([]rune(tail.String()))
	h := []rune(head.String())
	if len(h) > budget {
		h = h[:budget]
		// Never end a truncated head mid-line: the tail must start at
		// column 0 on its own line.
		h = append(h[:len(h)-1], '\n')
	}
	return string(h) + tail.String()
}

// oneLine sanitizes a short field into a single capped line. Unicode line and
// paragraph separators, which sanitize keeps and Telegram renders as breaks,
// become spaces too.
func oneLine(s string, max int) string {
	return strings.Map(func(r rune) rune {
		if r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, sanitize.Name(s, max))
}

// block sanitizes a multi-line field and indents every line after the first
// with continuationPrefix, so no line of agent text starts at column 0.
func block(s string, max int) string {
	clean := strings.Map(func(r rune) rune {
		if r == '\u2028' || r == '\u2029' || r == '\r' {
			return '\n'
		}
		return r
	}, sanitize.UserContent(s, max))
	lines := strings.Split(clean, "\n")
	for i := range lines {
		lines[i] = strings.TrimRightFunc(lines[i], unicode.IsSpace)
	}
	return strings.Join(lines, "\n"+continuationPrefix)
}

func isBreakOrSpace(r rune) bool { return unicode.IsSpace(r) || r == '\u2028' || r == '\u2029' }

// parseExpiry accepts what mctl-api's sealed expires_at uses: RFC 3339 with
// Z or an offset, or a naive timestamp read as UTC.
func parseExpiry(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05.999999999", s, time.UTC); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// WorkRefFromExternalKey turns a binding's normalised issue URL into the
// readable "owner/repo#n" form, or "" when it is not an issue URL.
func WorkRefFromExternalKey(key string) string {
	u, err := url.Parse(key)
	if err != nil || !strings.EqualFold(u.Host, "github.com") {
		return ""
	}
	seg := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(seg) != 4 || seg[2] != "issues" {
		return ""
	}
	if n, err := strconv.ParseUint(seg[3], 10, 64); err != nil || n == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%s#%s", seg[0], seg[1], seg[3])
}
