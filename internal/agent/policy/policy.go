// Package policy is the server-side authority on what the communication agent
// may do. Model output and system prompts are never treated as a security
// boundary: every proposed action is evaluated here before it can reach
// Telegram.
package policy

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// telegramMaxMessageLen is Telegram's hard per-message character cap — see
// internal/sanitize.UserContent's doc comment ("pass 4096 for Telegram
// message bodies") for the same constant used elsewhere in this codebase.
const telegramMaxMessageLen = 4096

// Decision is the outcome of evaluating a proposed action.
type Decision string

const (
	Allow           Decision = "allow"
	RequireApproval Decision = "require_approval"
	Deny            Decision = "deny"
)

// DisclosureSep is the separator used by the executor when it appends the AI
// disclosure to an outgoing reply. The reply-length policy counts it.
const DisclosureSep = "\n"

// Action is a proposed agent action associated with a DB conversation.
type Action struct {
	Type     string
	Intent   string
	Text     string
	PeerTGID int64
}

// Input contains all state required by Evaluate. Evaluate performs no I/O.
type Input struct {
	Profile          db.AgentProfile
	Conversation     db.Conversation
	Action           Action
	RecentAgentSends []time.Time
	GlobalKill       bool
	Now              time.Time
}

// Result contains the policy decision and user-facing/audit reasons.
type Result struct {
	Decision Decision
	Reasons  []string
}

func deny(reasons ...string) Result { return Result{Decision: Deny, Reasons: reasons} }

const riskyTLD = `com|net|org|io|ru|me|dev|co|ai|app|xyz|zip|link|click|top|info|biz|site|online|live|shop|store|cloud|tech|space|website|fun|icu|cc|tv|ly|sh|to|gg|fm|gl|be|us|uk|de|fr|es|it|nl|pl|cz|eu|in|id|ua|by|kz|tr|cn|jp|br|mx|ca|au|nz|jobs|agency|careers|career|work|works|team|company|group|consulting|solutions|network|community|recruiting|staffing|hr`

var (
	// Explicit schemes and www hosts are always links.
	explicitURLPattern = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+|\bwww\.\S+`)
	// ASCII and internationalized bare domains. The punctuation after an IDN
	// is included in the match and trimmed before tech-name comparison.
	// TLDs are a curated list rather than a generic "any 3+ letter suffix"
	// match: a generic match treats any dotted identifier whose final
	// component is 3-24 letters as a domain, which fires on ordinary Go
	// prose (http.Client, context.Context, resume.pdf) far more often than
	// on real links. The list includes recruiting-site TLDs (.jobs,
	// .agency, .careers, ...) alongside the common ccTLD/generic set.
	bareDomainPattern = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.(` + riskyTLD + `)\b|[\p{L}\p{N}][\p{L}\p{N}-]*(\.[\p{L}\p{N}-]+)*\.(xn--[a-z0-9-]{2,}|рф|укр|бел|срб|мкд|ею|бг|қаз|мон|` + riskyTLD + `)(?:$|[^\p{L}\p{N}])`)
	// Numeric hosts are denied only when they have an unambiguous URL suffix
	// (port or path). This avoids treating four-part versions as links.
	ipv4LinkPattern = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5}|/\S+)`)
)

var techNames = map[string]struct{}{
	"asp.net": {}, "vb.net": {}, "ado.net": {}, "socket.io": {},
	"angular.io": {}, "material.io": {},
}

func containsURL(text string) bool {
	if explicitURLPattern.MatchString(text) {
		return true
	}
	for _, loc := range ipv4LinkPattern.FindAllStringIndex(text, -1) {
		token := text[loc[0]:loc[1]]
		host := token
		if i := strings.IndexAny(host, ":/"); i >= 0 {
			host = host[:i]
		}
		if net.ParseIP(host) != nil {
			return true
		}
	}
	for _, loc := range bareDomainPattern.FindAllStringIndex(text, -1) {
		raw := text[loc[0]:loc[1]]
		host := strings.ToLower(strings.TrimRight(raw, ".,;:!?"))
		if _, ok := techNames[host]; !ok {
			return true
		}
		if loc[1] >= len(text) {
			continue
		}
		suffix := text[loc[1]:]
		switch suffix[0] {
		case '/':
			return true
		case ':':
			if len(suffix) > 1 && suffix[1] >= '0' && suffix[1] <= '9' {
				return true
			}
		case '?', '#':
			if queryOrFragmentHasValue(suffix[1:]) {
				return true
			}
		}
	}
	return false
}

func queryOrFragmentHasValue(s string) bool {
	if s == "" {
		return false
	}
	r, _ := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return true // malformed UTF-8 is not a safe prose exemption
	}
	return !unicode.IsSpace(r) && !unicode.IsPunct(r)
}

const (
	lbound = `(?:^|[^\p{L}\p{N}])`
	rbound = `(?:$|[^\p{L}\p{N}])`
)

var credentialPatterns = []*regexp.Regexp{
	// Card-like digit runs.
	regexp.MustCompile(`\b(\d[ -]?){12,}\d\b`),
	// Digits before a secret label: "483920 is the code".
	regexp.MustCompile(`(?i)\b\d{4,8}\s*(?:-|—|:)?\s*(?:is\s+|are\s+|это\s+)?(?:the\s+|your\s+|my\s+)?(code|otp|pin|password|passcode|пароль|код)` + rbound),
	// Digits after an unambiguous label, including across one line break.
	regexp.MustCompile(`(?i)` + lbound + `(otp|pin|password|passcode|пароль)[^\p{L}\p{N}][^.!?]{0,19}?\d{4,8}\b`),
	// Bare "код" (Russian) keeps its connector optional. Russian software-
	// error phrasing puts the qualifier before the noun ("код ошибки 4040"),
	// so there is no "код 4040" prose collision to guard against the way
	// English "error code 4040" collides with bare "code".
	regexp.MustCompile(`(?i)` + lbound + `код(?:\s+доступа|\s+подтверждения)?\s*(?:is|:|=|—|-)?\s*\d{4,8}\b`),
	// Bare "code" (English) needs a REQUIRED connector so software prose like
	// "error code 4040" (just whitespace between the label and the number)
	// is not treated as a disclosed OTP.
	regexp.MustCompile(`(?i)\bcode\s*(?:is|:|=|—|-)\s*\d{4,8}\b`),
	// A verification/security-qualified "code" is unambiguous real-world OTP
	// delivery copy even without a connector ("Your verification code
	// 483920"), unlike bare "error code 4040" software prose.
	regexp.MustCompile(`(?i)\b(?:verification|security|confirmation|authentication|access|2fa|two-factor)\s+code\s+\d{4,8}\b`),
	// Seed phrases/mnemonics require an explicit value, not just the topic.
	regexp.MustCompile(`(?i)\b(seed\s*phrase|mnemonic)\b\s*(?:is|:|=|—|-)\s*[\p{L}]+(?:\s+[\p{L}]+){1,23}`),
	// Password/private-key labels require an actual value or numeric secret.
	regexp.MustCompile(`(?i)(?:\b(password|passcode|private\s*key)\b|` + lbound + `парол\p{L}*)\s*(?:is|:|=|—|-)\s*\S{4,}`),
	// Unambiguous machine-credential shapes.
	regexp.MustCompile(`\b(sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,})\b|\bBearer\s+[A-Za-z0-9._+/=-]{20,}`),
	// Labelled API keys and access tokens with token-shaped values.
	regexp.MustCompile(`(?i)(?:\b(api[\s_-]?(?:key|token|secret)|access[\s_-]?token|auth[\s_-]?token|bearer[\s_-]?token|refresh[\s_-]?token|secret[\s_-]?key|client[\s_-]?secret)\b|` + lbound + `(?:api[\s-]?токен|токен\s+доступа|секретный\s+ключ|ключ\s+api))\s*(?:is|:|=|—)\s*[A-Za-z0-9._+/=-]{12,}`),
}

var phoneCandidatePattern = regexp.MustCompile(`\+?\(?\d[\d\s().-]{7,}\d`)

func containsCredentialLike(text string) bool {
	for _, re := range credentialPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return containsPhoneLike(text)
}

func containsPhoneLike(text string) bool {
	for _, candidate := range phoneCandidatePattern.FindAllString(text, -1) {
		digits, groups := phoneDigitsAndGroups(candidate)
		if len(digits) < 10 || len(digits) > 15 {
			continue
		}
		trimmed := strings.TrimSpace(candidate)
		if strings.HasPrefix(trimmed, "+") || strings.ContainsAny(trimmed, "()") {
			return true
		}
		// Two long groups separated only by a dash are usually a salary/range,
		// e.g. 80000-90000. Space-grouped values such as 07700 900123 are
		// common phone numbers and must not use this exemption.
		if len(groups) == 2 && len(groups[0]) >= 4 && len(groups[1]) >= 4 &&
			strings.Contains(trimmed, "-") && !strings.ContainsAny(trimmed, " .()") {
			continue
		}
		// A range where each side is itself thousand-grouped with spaces, e.g.
		// "80 000 - 90 000", is a salary range, not a phone number, even though
		// its leading digit may be 0/8.
		if isSpaceGroupedRange(trimmed) {
			continue
		}
		// NANP 3-3-4 grouping.
		if len(groups) == 3 && len(groups[0]) == 3 && len(groups[1]) == 3 && len(groups[2]) == 4 {
			return true
		}
		// Domestic trunk prefixes cover common Russian, UK, French and similar
		// formats, compact or grouped.
		if digits[0] == '0' || digits[0] == '8' {
			return true
		}
		// An unbroken 10-digit run with no separators at all (e.g.
		// "4155551212") is the classic compact NANP shape and has no trunk
		// digit to key off.
		if len(groups) == 1 && len(digits) == 10 {
			return true
		}
	}
	return false
}

// isSpaceGroupedRange reports whether s is two thousand-grouped numbers
// joined by a dash, e.g. "80 000 - 90 000".
func isSpaceGroupedRange(s string) bool {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return false
	}
	return isThousandGrouped(strings.TrimSpace(parts[0])) && isThousandGrouped(strings.TrimSpace(parts[1]))
}

// isThousandGrouped reports whether s is a sequence of space-separated digit
// groups shaped like a thousand-grouped number: a 1-3 digit leading group
// followed by one or more exact 3-digit groups (e.g. "80 000", "1 250 000").
func isThousandGrouped(s string) bool {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return false
	}
	for _, f := range fields {
		for _, r := range f {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	if len(fields[0]) < 1 || len(fields[0]) > 3 {
		return false
	}
	for _, f := range fields[1:] {
		if len(f) != 3 {
			return false
		}
	}
	return true
}

func phoneDigitsAndGroups(s string) (string, []string) {
	var digits strings.Builder
	var groups []string
	var group strings.Builder
	flush := func() {
		if group.Len() > 0 {
			groups = append(groups, group.String())
			group.Reset()
		}
	}
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits.WriteRune(r)
			group.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return digits.String(), groups
}

// Evaluate applies hard denials first, then accumulates approval requirements.
func Evaluate(in Input) Result {
	if in.GlobalKill {
		return deny("global kill switch engaged")
	}
	// A worker that accidentally pairs one user's AgentProfile with another
	// user's Conversation must not authorize a reply under the wrong
	// allowlist/blocklist/mode/rate-limit. Both rows carry UserID; fail
	// closed unless they agree. Scoped to ActionTypeReply: owner-facing
	// actions (summary/approval) are not conversation-scoped authorization
	// decisions the same way, and a caller may legitimately have no
	// Conversation row for them at all.
	if in.Action.Type == db.ActionTypeReply &&
		(in.Profile.UserID == 0 || in.Conversation.UserID == 0 || in.Profile.UserID != in.Conversation.UserID) {
		return deny("profile and conversation belong to different users")
	}
	switch in.Profile.Mode {
	case db.AgentModeObserve, db.AgentModeGuarded:
	case db.AgentModeOff:
		return deny("agent mode is off")
	default:
		return deny("unrecognized agent mode " + strconv.Quote(in.Profile.Mode))
	}
	if in.Profile.AutopilotPaused {
		return deny("autopilot paused for this account")
	}
	switch in.Conversation.State {
	case db.ConversationActive:
	case db.ConversationTakenOver:
		return deny("conversation taken over by owner")
	case db.ConversationClosed:
		return deny("conversation closed")
	case db.ConversationPaused:
		return deny("conversation paused")
	default:
		return deny("unrecognized conversation state " + strconv.Quote(in.Conversation.State))
	}
	if isBlocked(in.Profile.BlockedSenders, in.Conversation.PeerTGID) {
		return deny("sender is blocked")
	}

	switch in.Action.Type {
	case db.ActionTypeReply:
	case db.ActionTypeOwnerSummary, db.ActionTypeOwnerApproval:
		return Result{Decision: Allow, Reasons: []string{"owner-facing action"}}
	default:
		return deny("unrecognized action type " + strconv.Quote(in.Action.Type))
	}

	// Zero means the caller did not echo a peer; the executor uses the DB peer.
	if in.Action.PeerTGID != 0 && in.Action.PeerTGID != in.Conversation.PeerTGID {
		return deny("reply peer does not match conversation")
	}
	if strings.TrimSpace(in.Profile.DisclosureText) == "" {
		return deny("no disclosure text configured")
	}
	text := in.Action.Text
	if strings.TrimSpace(text) == "" {
		return deny("empty reply")
	}
	maxChars := in.Profile.MaxReplyChars
	if maxChars <= 0 {
		maxChars = 1200
	}
	if maxChars > telegramMaxMessageLen {
		// A misconfigured MAX_REPLY_CHARS above Telegram's own limit would
		// let this length check pass a payload the send RPC itself then
		// rejects with the permanent MESSAGE_TOO_LONG — and the executor
		// treats every send error as transient, so recovery would retry
		// the identical oversized payload forever (Codex finding on #307).
		// Clamp so this check is never looser than what can actually be
		// delivered.
		maxChars = telegramMaxMessageLen
	}
	if len([]rune(text))+len([]rune(DisclosureSep))+len([]rune(in.Profile.DisclosureText)) > maxChars {
		return deny("reply exceeds max length once the disclosure is appended")
	}
	if containsURL(text) {
		return deny("reply contains a URL")
	}
	if containsCredentialLike(text) {
		return deny("reply contains credentials-like content")
	}

	var reasons []string
	if in.Profile.Mode == db.AgentModeObserve {
		reasons = append(reasons, "observe mode: never auto-send")
	}
	maxTurns := in.Profile.MaxAutonomousTurns
	if maxTurns <= 0 {
		maxTurns = 6
	}
	if in.Conversation.AutonomousTurns >= maxTurns {
		reasons = append(reasons, "autonomous turn budget exhausted")
	}
	if !intentAllowed(in.Profile.IntentAllowlist, in.Action.Intent) {
		reasons = append(reasons, "intent not in allowlist")
	}
	if overRate(in.RecentAgentSends, in.Profile.MaxMsgsPerMinute, in.Now) {
		reasons = append(reasons, "rate limit exceeded")
	}
	if len(reasons) > 0 {
		return Result{Decision: RequireApproval, Reasons: reasons}
	}
	return Result{Decision: Allow, Reasons: []string{"guarded: allowlisted discovery intent"}}
}

func isBlocked(csv string, peerID int64) bool { return containsID(csv, peerID) }

func intentAllowed(csv, intent string) bool {
	if strings.TrimSpace(intent) == "" {
		return false
	}
	for _, part := range strings.Split(csv, ",") {
		if strings.EqualFold(strings.TrimSpace(part), strings.TrimSpace(intent)) {
			return true
		}
	}
	return false
}

func overRate(sends []time.Time, maxPerMin int, now time.Time) bool {
	if maxPerMin <= 0 {
		maxPerMin = 2
	}
	windowStart := now.Add(-time.Minute)
	n := 0
	for _, t := range sends {
		if t.After(windowStart) {
			n++
		}
	}
	return n >= maxPerMin
}

func containsID(csv string, id int64) bool {
	if id == 0 || strings.TrimSpace(csv) == "" {
		return false
	}
	target := strconv.FormatInt(id, 10)
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == target {
			return true
		}
	}
	return false
}
