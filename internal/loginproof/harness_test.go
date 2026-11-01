package loginproof

import (
	"context"
	"errors"
	"testing"

	"github.com/gotd/td/tgerr"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

type fake struct {
	loginErr     error
	session      []byte
	callErr      error
	logoutErr    error
	fallbackErr  error
	stillListed  bool
	called       bool
	loggedOut    bool
	scanned      bool
	fallbackUsed bool
}

func (f *fake) steps() Steps {
	return Steps{
		Login:       func(context.Context) error { return f.loginErr },
		LoadSession: func(context.Context) ([]byte, error) { return f.session, nil },
		SaveSession: func(context.Context, []byte) error { return nil },
		CallTool:    func(context.Context) error { f.called = true; return f.callErr },
		LogOut: func(context.Context, []byte) error {
			if f.logoutErr == nil {
				f.loggedOut = true
			}
			return f.logoutErr
		},
		Fallback: func(context.Context) error { f.fallbackUsed = true; return f.fallbackErr },
		StillAuthorized: func(context.Context) (bool, error) {
			return f.stillListed, nil
		},
		Scanned: func() bool { return f.scanned },
	}
}

func okFake() *fake { return &fake{session: []byte("s")} }

func TestRun_QR_Pass(t *testing.T) {
	f := okFake()
	out, reached := Run(context.Background(), ModeQR, f.steps())
	if out != OutcomePass || reached != StepCleanup || !f.called || !f.loggedOut {
		t.Fatalf("out=%s reached=%s called=%v loggedOut=%v", out, reached, f.called, f.loggedOut)
	}
}

func TestRun_QR_Mutations(t *testing.T) {
	cases := map[string]func(f *fake) Steps{
		"session not persisted": func(f *fake) Steps { f.session = nil; return f.steps() },
		"mcp call skipped": func(f *fake) Steps {
			s := f.steps()
			s.CallTool = func(context.Context) error { return errors.New("is_error") }
			return s
		},
		"mcp step missing": func(f *fake) Steps {
			f.callErr = errors.New("is_error")
			return f.steps()
		},
		"logout and reset fail": func(f *fake) Steps {
			f.logoutErr = errors.New("x")
			f.fallbackErr = errors.New("y")
			return f.steps()
		},
		"logout fails, hash still listed": func(f *fake) Steps {
			f.logoutErr = errors.New("x")
			f.stillListed = true
			return f.steps()
		},
		"anchor never accepts": func(f *fake) Steps {
			f.loginErr = telegram.ErrQRLoginExpired
			return f.steps()
		},
		"identity mismatch": func(f *fake) Steps {
			f.loginErr = ErrIdentityMismatch
			return f.steps()
		},
		"flood wait": func(f *fake) Steps {
			f.loginErr = &tgerr.Error{Code: 420, Type: "FLOOD_WAIT", Message: "FLOOD_WAIT_9"}
			return f.steps()
		},
	}
	for name, mk := range cases {
		out, _ := Run(context.Background(), ModeQR, mk(okFake()))
		if out == OutcomePass {
			t.Errorf("%s: passed", name)
		}
	}
}

func TestRun_FallbackCleanupPasses(t *testing.T) {
	f := okFake()
	f.logoutErr = errors.New("x")
	out, _ := Run(context.Background(), ModeQR, f.steps())
	if out != OutcomePass || !f.fallbackUsed {
		t.Fatalf("out=%s fallbackUsed=%v", out, f.fallbackUsed)
	}
}

func TestRun_CleanupFailedOutcome(t *testing.T) {
	f := okFake()
	f.logoutErr, f.fallbackErr = errors.New("x"), errors.New("y")
	if out, _ := Run(context.Background(), ModeQR, f.steps()); out != OutcomeCleanupFailed {
		t.Fatalf("out = %s", out)
	}
}

func TestRun_ScannedLoginFailureCleansUp(t *testing.T) {
	f := okFake()
	f.loginErr = telegram.ErrQRLoginExpired
	f.scanned = true
	out, _ := Run(context.Background(), ModeQR, f.steps())
	if out == OutcomePass || !f.fallbackUsed {
		t.Fatalf("out=%s fallbackUsed=%v", out, f.fallbackUsed)
	}
}

func TestRun_Phone_NoMCPCall(t *testing.T) {
	f := okFake()
	s := f.steps()
	s.CallTool = func(context.Context) error { return errors.New("no") }
	if out, _ := Run(context.Background(), ModePhone, s); out == OutcomePass {
		t.Fatal("phone ok without an MCP call passed")
	}
}

func TestRun_Negative(t *testing.T) {
	badPw := &tgerr.Error{Code: 400, Type: "PASSWORD_HASH_INVALID", Message: "PASSWORD_HASH_INVALID"}
	f := &fake{loginErr: badPw}
	if out, _ := Run(context.Background(), ModePhoneWrongPassword, f.steps()); out != OutcomePass {
		t.Fatalf("matching outcome, no session: %s", out)
	}
	f = &fake{loginErr: badPw, session: []byte("s")}
	if out, _ := Run(context.Background(), ModePhoneWrongPassword, f.steps()); out == OutcomePass {
		t.Fatal("wrong-password with a stored session passed")
	}
	invalid := &tgerr.Error{Code: 400, Type: "PHONE_CODE_INVALID", Message: "PHONE_CODE_INVALID"}
	f = &fake{loginErr: invalid}
	out, _ := Run(context.Background(), ModePhoneExpiredCode, f.steps())
	if out == OutcomePass || out != OutcomeCodeInvalid {
		t.Fatalf("expired-code with code_invalid = %s", out)
	}
	f = &fake{session: []byte("s")}
	if out, _ := Run(context.Background(), ModePhoneWrongPassword, f.steps()); out == OutcomePass || !f.loggedOut {
		t.Fatalf("unexpected login success: out=%s loggedOut=%v", out, f.loggedOut)
	}
}
