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
		{"conversations count", "/mctl conversations 50", Command{Type: CmdConversations, Arg: "50"}, nil},
		{"conversations filter", "/mctl conversations @anna_hr", Command{Type: CmdConversations, Arg: "@anna_hr"}, nil},
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

func TestParseCommand_Input(t *testing.T) {
	cmd, err := ParseCommand("/mctl Input k7qm3r  use  the\nsecond reading ")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cmd.Type != CmdInput || cmd.Sub != SubInputAnswer || cmd.Arg != "k7qm3r" || cmd.Value != "use  the\nsecond reading" {
		t.Fatalf("cmd = %+v", cmd)
	}
	cmd, err = ParseCommand("/mctl input status")
	if err != nil || cmd.Sub != SubInputStatus || cmd.Arg != "" {
		t.Fatalf("status = %+v err=%v", cmd, err)
	}
	cmd, err = ParseCommand("/mctl input STATUS K7QM3R")
	if err != nil || cmd.Sub != SubInputStatus || cmd.Arg != "K7QM3R" {
		t.Fatalf("status code = %+v err=%v", cmd, err)
	}
	for _, in := range []string{"/mctl input", "/mctl input K7QM3R"} {
		if _, err := ParseCommand(in); !errors.Is(err, ErrMissingArg) {
			t.Errorf("%q err = %v, want ErrMissingArg", in, err)
		}
	}
}
