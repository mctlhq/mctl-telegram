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
)

// Command is a parsed owner instruction typed into Saved Messages.
type Command struct {
	Type CommandType
	Arg  string
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
	default:
		return Command{}, fmt.Errorf("%w: %q", ErrUnknownCommand, fields[1])
	}
}
