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

	"github.com/mctlhq/mctl-telegram/internal/sanitize"
	"github.com/mctlhq/mctl-telegram/internal/workctx"
)

// Per-field caps applied to the allowlisted DTO fields before rendering.
const (
	maxQuestionRunes = 600
	maxWhyRunes      = 400
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

// Render builds the delivered message for v and code. It reads only the
// allowlisted RequestView fields (question, why, options, deadline, work/request
// refs, safe links), runs each through sanitize with a cap, and caps the whole
// message at 4096 runes while keeping the answer line intact.
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
	fmt.Fprintf(&head, "Question: %s\n", sanitize.UserContent(v.Question, maxQuestionRunes))
	if strings.TrimSpace(v.Why) != "" {
		fmt.Fprintf(&head, "Why: %s\n", sanitize.UserContent(v.Why, maxWhyRunes))
	}
	if v.Kind == workctx.HumanInputKindSingleChoice {
		head.WriteString("Options:\n")
		for i, o := range v.Options {
			if i >= maxOptions {
				break
			}
			fmt.Fprintf(&head, "  %d. %s\n", i+1, oneLine(o.Label, maxLabelRunes))
		}
	}
	if t, err := time.Parse(time.RFC3339, v.Deadline); err == nil {
		fmt.Fprintf(&head, "Deadline: %s\n", t.UTC().Format("2006-01-02 15:04 UTC"))
	}
	links := 0
	for _, l := range v.Links {
		if links >= maxLinks {
			break
		}
		if u, err := url.Parse(l); err == nil && strings.EqualFold(u.Scheme, "https") && u.Host != "" && len([]rune(l)) <= maxLinkRunes && !strings.ContainsAny(l, " \n\t") {
			fmt.Fprintf(&head, "Link: %s\n", l)
			links++
		}
	}

	var tail strings.Builder
	if v.Kind == workctx.HumanInputKindSingleChoice {
		fmt.Fprintf(&tail, "Answer: /mctl input %s <number>\n", code)
	} else {
		fmt.Fprintf(&tail, "Answer: /mctl input %s <your answer>\n", code)
	}
	fmt.Fprintf(&tail, "Ref: request %s v%d", oneLine(v.RequestID, 64), v.Version)

	// The answer line is the point of the message: if the composed text is
	// somehow over the cap, trim the head, never the tail.
	budget := maxMessageRunes - len([]rune(tail.String()))
	h := []rune(head.String())
	if len(h) > budget {
		h = h[:budget]
	}
	return string(h) + tail.String()
}

// oneLine sanitizes a short field into a single capped line.
func oneLine(s string, max int) string {
	return sanitize.Name(s, max)
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
