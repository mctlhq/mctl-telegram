// Package control implements the owner's Saved Messages command surface:
// parsing /mctl commands, routing them to the right store/executor call, and
// delivering summaries and approval requests back into Saved Messages.
package control

import (
	"errors"
	"fmt"
	"strings"
)

// CommandType identifies a parsed /mctl subcommand.
type CommandType string

const (
	CmdStatus        CommandType = "status"
	CmdLeads         CommandType = "leads"
	CmdShow          CommandType = "show"
	CmdContinue      CommandType = "continue"
	CmdPause         CommandType = "pause"
	CmdTakeover      CommandType = "takeover"
	CmdApprove       CommandType = "approve"
	CmdReject        CommandType = "reject"
	CmdConversations CommandType = "conversations"
	// CmdWork is issue-443's /mctl work <issue-url|status|note|resume>
	// subcommand. Its own sub-action is carried on Command.Sub, since "work"
	// itself is not enough to dispatch on — see the Sub* constants below.
	CmdWork CommandType = "work"
	// CmdLink is /mctl link <code>, the one-time surface-identity redeem
	// flow. Sub is always empty for this command.
	CmdLink CommandType = "link"
)

// Sub values for a parsed CmdWork command — which /mctl work form the owner
// typed. Every other (pre-existing) CommandType keeps an empty Sub, so their
// Command{} zero values stay byte-identical to before this field existed.
const (
	SubWorkOpen   = "open"
	SubWorkStatus = "status"
	SubWorkNote   = "note"
	SubWorkResume = "resume"
)

// Command is a parsed owner instruction typed into Saved Messages. Sub is
// populated only for CmdWork (one of the Sub* constants above); every other
// CommandType leaves it empty.
type Command struct {
	Type CommandType
	Arg  string
	Sub  string
}

// ErrNotACommand means the text does not start with /mctl at all. The
// listener already filters Saved Messages down to /mctl text before ever
// calling the router (see listener.isMCTLCommand), so callers outside a
// test rarely see this — ParseCommand still checks defensively rather than
// assuming the caller's filtering is airtight.
var ErrNotACommand = errors.New("not a /mctl command")

// ErrUnknownCommand means the text starts with /mctl but the subcommand
// after it is not one this package understands.
var ErrUnknownCommand = errors.New("unknown /mctl command")

// ErrMissingArg means a subcommand that requires an argument (show,
// continue, takeover, approve, reject) was given none.
var ErrMissingArg = errors.New("command requires an argument")

// ParseCommand is a pure function: same input, same output, no I/O. Matches
// /mctl case-insensitively (mirrors listener.isMCTLCommand); the subcommand
// itself is also matched case-insensitively so "/mctl Approve ABC123" and
// "/mctl approve ABC123" behave identically — the owner is typing this by
// hand on a phone keyboard that may autocapitalize.
func ParseCommand(text string) (Command, error) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 || !strings.EqualFold(fields[0], "/mctl") {
		return Command{}, ErrNotACommand
	}
	if len(fields) < 2 {
		return Command{}, ErrUnknownCommand
	}
	sub := CommandType(strings.ToLower(fields[1]))
	var arg string
	if len(fields) > 2 {
		arg = strings.Join(fields[2:], " ")
	}
	switch sub {
	case CmdStatus, CmdLeads, CmdPause:
		return Command{Type: sub}, nil
	case CmdConversations:
		// Optional count or @handle/substring filter. Full paging is not
		// required; the router uses this to say when the default 20-row
		// window was truncated (#525).
		return Command{Type: sub, Arg: arg}, nil
	case CmdApprove, CmdReject:
		if arg == "" {
			return Command{}, fmt.Errorf("%w: /mctl %s <arg>", ErrMissingArg, sub)
		}
		// Only the first token is the code. A trailing autocorrected word
		// ("/mctl approve AB12CD oops") must not get folded into the code
		// (GetAgentActionByCode would then just fail to find "AB12CD oops"
		// with a confusing "not found" reply) — codes never legitimately
		// contain spaces, unlike show/continue/takeover's numeric ids, whose
		// strconv.ParseInt already rejects trailing garbage on its own.
		return Command{Type: sub, Arg: fields[2]}, nil
	case CmdShow, CmdContinue, CmdTakeover:
		if arg == "" {
			return Command{}, fmt.Errorf("%w: /mctl %s <arg>", ErrMissingArg, sub)
		}
		return Command{Type: sub, Arg: arg}, nil
	case CmdLink:
		if arg == "" {
			return Command{}, fmt.Errorf("%w: /mctl link <code>", ErrMissingArg)
		}
		// Only the first token is the code, same rationale as
		// approve/reject above: a code never legitimately contains spaces.
		return Command{Type: sub, Arg: fields[2]}, nil
	case CmdWork:
		return parseWorkCommand(fields)
	default:
		return Command{}, fmt.Errorf("%w: %q", ErrUnknownCommand, fields[1])
	}
}

// parseWorkCommand parses everything after "/mctl work". URL validation
// (CanonicalIssueURL) deliberately does NOT happen here — ParseCommand stays
// a pure function with no notion of what a valid GitHub issue URL looks
// like; that belongs to internal/workctx.CanonicalIssueURL, called by the
// work handler.
func parseWorkCommand(fields []string) (Command, error) {
	if len(fields) < 3 {
		return Command{}, fmt.Errorf("%w: /mctl work <issue-url>|status|note <text>|resume", ErrMissingArg)
	}
	switch strings.ToLower(fields[2]) {
	case SubWorkStatus:
		return Command{Type: CmdWork, Sub: SubWorkStatus}, nil
	case SubWorkResume:
		return Command{Type: CmdWork, Sub: SubWorkResume}, nil
	case SubWorkNote:
		if len(fields) < 4 {
			return Command{}, fmt.Errorf("%w: /mctl work note <text>", ErrMissingArg)
		}
		return Command{Type: CmdWork, Sub: SubWorkNote, Arg: strings.Join(fields[3:], " ")}, nil
	default:
		// Anything else is taken as the issue-url argument to "open" — the
		// URL itself is validated later by workctx.CanonicalIssueURL, not
		// here.
		return Command{Type: CmdWork, Sub: SubWorkOpen, Arg: strings.Join(fields[2:], " ")}, nil
	}
}
