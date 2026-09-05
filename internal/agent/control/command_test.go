package control

import (
	"errors"
	"testing"
)

func TestParseCommand_Table(t *testing.T) {
	cases := []struct {
		name    string
		text    string
		want    Command
		wantErr error
	}{
		{"status", "/mctl status", Command{Type: CmdStatus}, nil},
		{"leads", "/mctl leads", Command{Type: CmdLeads}, nil},
		{"conversations", "/mctl conversations", Command{Type: CmdConversations}, nil},
		{"conversations case insensitive", "/mctl Conversations", Command{Type: CmdConversations}, nil},
		{"pause", "/mctl pause", Command{Type: CmdPause}, nil},
		{"show with id", "/mctl show 42", Command{Type: CmdShow, Arg: "42"}, nil},
		{"continue with id", "/mctl continue 7", Command{Type: CmdContinue, Arg: "7"}, nil},
		{"takeover with id", "/mctl takeover 7", Command{Type: CmdTakeover, Arg: "7"}, nil},
		{"approve with code", "/mctl approve AB12CD", Command{Type: CmdApprove, Arg: "AB12CD"}, nil},
		{"reject with code", "/mctl reject AB12CD", Command{Type: CmdReject, Arg: "AB12CD"}, nil},
		{"case insensitive prefix and subcommand", "/MCTL Approve AB12CD", Command{Type: CmdApprove, Arg: "AB12CD"}, nil},
		{"extra whitespace", "  /mctl   status  ", Command{Type: CmdStatus}, nil},
		{"not a command", "just a saved note", Command{}, ErrNotACommand},
		{"empty text", "", Command{}, ErrNotACommand},
		{"bare /mctl no subcommand", "/mctl", Command{}, ErrUnknownCommand},
		{"unknown subcommand", "/mctl frobnicate", Command{}, ErrUnknownCommand},
		{"show missing arg", "/mctl show", Command{}, ErrMissingArg},
		{"approve missing arg", "/mctl approve", Command{}, ErrMissingArg},
		{"approve arg takes only the first token, ignores trailing words", "/mctl approve AB12CD oops", Command{Type: CmdApprove, Arg: "AB12CD"}, nil},
		{"show arg still joins remaining fields (numeric parse rejects it anyway)", "/mctl show 42 oops", Command{Type: CmdShow, Arg: "42 oops"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseCommand(c.text)
			if c.wantErr != nil {
				if !errors.Is(err, c.wantErr) {
					t.Fatalf("err = %v, want %v", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}
