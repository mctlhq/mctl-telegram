package telegram

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

func TestCodeDelivery(t *testing.T) {
	withNext := &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeApp{Length: 5}}
	withNext.SetNextType(&tg.AuthCodeTypeSMS{})
	withNext.SetTimeout(60)

	for _, tc := range []struct {
		name          string
		sent          *tg.AuthSentCode
		delivery, nxt string
		timeout       int
	}{
		{"app with sms fallback", withNext, "auth.sentCodeTypeApp", "auth.codeTypeSms", 60},
		{"email only", &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeEmailCode{}}, "auth.sentCodeTypeEmailCode", "", 0},
		{"fragment", &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeFragmentSMS{}}, "auth.sentCodeTypeFragmentSms", "", 0},
		{"no type", &tg.AuthSentCode{}, "unknown", "", 0},
		{"nil", nil, "unknown", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, n, to := codeDelivery(tc.sent)
			if d != tc.delivery || n != tc.nxt || to != tc.timeout {
				t.Fatalf("codeDelivery = (%q, %q, %d), want (%q, %q, %d)", d, n, to, tc.delivery, tc.nxt, tc.timeout)
			}
		})
	}
}

func TestLoginCodeDigits(t *testing.T) {
	for in, want := range map[string]string{
		"12345":              "12345",
		" 12 345 ":           "12345",
		"12-345":             "12345",
		"Login code: 12345.": "12345",
		"١٢345":              "345", // non-ASCII digits are not login-code digits
		"code":               "",
		"":                   "",
	} {
		if got := LoginCodeDigits(in); got != want {
			t.Errorf("LoginCodeDigits(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeFlowClient scripts the auth.FlowClient calls runPhoneFlow makes. Each
// SendCode returns the next queued error, or a fresh code with hash
// "hash-<n>" once the queue is empty. SignIn accepts goodCode only, and only
// with the latest hash; signInErrs, when queued, are returned first.
type fakeFlowClient struct {
	sendCodeErrs []error
	signInErrs   []error
	goodCode     string
	needPassword bool
	goodPassword string

	sendCodes   int
	signInCodes []string
	signInHash  []string
	passwords   []string
	hash        string
}

func (f *fakeFlowClient) SendCode(_ context.Context, _ string, _ auth.SendCodeOptions) (tg.AuthSentCodeClass, error) {
	f.sendCodes++
	if len(f.sendCodeErrs) > 0 {
		err := f.sendCodeErrs[0]
		f.sendCodeErrs = f.sendCodeErrs[1:]
		return nil, err
	}
	f.hash = fmt.Sprintf("hash-%d", f.sendCodes)
	return &tg.AuthSentCode{Type: &tg.AuthSentCodeTypeApp{Length: 5}, PhoneCodeHash: f.hash}, nil
}

func (f *fakeFlowClient) SignIn(_ context.Context, _, code, hash string) (*tg.AuthAuthorization, error) {
	f.signInCodes = append(f.signInCodes, code)
	f.signInHash = append(f.signInHash, hash)
	if len(f.signInErrs) > 0 {
		err := f.signInErrs[0]
		f.signInErrs = f.signInErrs[1:]
		return nil, err
	}
	if hash != f.hash || code != f.goodCode {
		return nil, tgerr.New(400, "PHONE_CODE_INVALID")
	}
	if f.needPassword {
		return nil, auth.ErrPasswordAuthNeeded
	}
	return &tg.AuthAuthorization{User: &tg.User{ID: 4242}}, nil
}

func (f *fakeFlowClient) Password(_ context.Context, pw string) (*tg.AuthAuthorization, error) {
	f.passwords = append(f.passwords, pw)
	if pw != f.goodPassword {
		// What gotd's auth.Client.Password returns for PASSWORD_HASH_INVALID.
		return nil, auth.ErrPasswordInvalid
	}
	return &tg.AuthAuthorization{User: &tg.User{ID: 4242}}, nil
}

func (f *fakeFlowClient) SignUp(context.Context, auth.SignUp) (*tg.AuthAuthorization, error) {
	return nil, errors.New("unexpected sign-up")
}

// scriptedPrompt answers a code or password prompt from inputs in order and
// records the Reprompt each call carried (zero Reprompt for a first prompt).
type scriptedPrompt struct {
	inputs []string
	seen   []Reprompt
}

func (p *scriptedPrompt) ask(ctx context.Context) (string, error) {
	rp, _ := RepromptFrom(ctx)
	p.seen = append(p.seen, rp)
	if len(p.seen) > len(p.inputs) {
		return "", errors.New("prompt asked more times than scripted")
	}
	return p.inputs[len(p.seen)-1], nil
}

func runScriptedPhoneFlow(f *fakeFlowClient, codes, passwords *scriptedPrompt) error {
	a := &interactiveAuthenticator{phone: "+14155551234", code: codes.ask}
	if passwords != nil {
		a.password = passwords.ask
	}
	return runPhoneFlow(context.Background(), f, a)
}

func TestRunPhoneFlow_WrongCodeThenRightCodeReusesHash(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345"}
	codes := &scriptedPrompt{inputs: []string{"54321", "12345"}}
	if err := runScriptedPhoneFlow(f, codes, nil); err != nil {
		t.Fatalf("flow: %v", err)
	}
	if f.sendCodes != 1 {
		t.Errorf("SendCode calls = %d, want 1 (a wrong code must not request a new one)", f.sendCodes)
	}
	if len(f.signInHash) != 2 || f.signInHash[0] != "hash-1" || f.signInHash[1] != "hash-1" {
		t.Errorf("SignIn hashes = %v, want the same phone_code_hash twice", f.signInHash)
	}
	want := []Reprompt{{}, {Reason: RepromptCodeInvalid, AttemptsLeft: 2}}
	if fmt.Sprint(codes.seen) != fmt.Sprint(want) {
		t.Errorf("prompts saw %v, want %v", codes.seen, want)
	}
}

func TestRunPhoneFlow_CodeAttemptsAreBounded(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345"}
	codes := &scriptedPrompt{inputs: []string{"11111", "22222", "33333", "12345"}}
	err := runScriptedPhoneFlow(f, codes, nil)
	if !tgerr.Is(err, "PHONE_CODE_INVALID") {
		t.Fatalf("err = %v, want PHONE_CODE_INVALID after the last attempt", err)
	}
	if len(codes.seen) != LoginCodeAttempts || len(f.signInCodes) != LoginCodeAttempts {
		t.Errorf("prompts = %d, SignIn calls = %d, want %d each", len(codes.seen), len(f.signInCodes), LoginCodeAttempts)
	}
}

func TestRunPhoneFlow_CodeExpiredEndsTheFlow(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345", signInErrs: []error{tgerr.New(400, "PHONE_CODE_EXPIRED")}}
	codes := &scriptedPrompt{inputs: []string{"12345", "12345"}}
	err := runScriptedPhoneFlow(f, codes, nil)
	if !tgerr.Is(err, "PHONE_CODE_EXPIRED") {
		t.Fatalf("err = %v, want PHONE_CODE_EXPIRED", err)
	}
	if len(codes.seen) != 1 || f.sendCodes != 1 {
		t.Errorf("prompts = %d, SendCode = %d, want 1 and 1", len(codes.seen), f.sendCodes)
	}
}

func TestRunPhoneFlow_WrongPasswordThenRightPassword(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345", needPassword: true, goodPassword: "hunter2"}
	codes := &scriptedPrompt{inputs: []string{"12345"}}
	pws := &scriptedPrompt{inputs: []string{"hunter1", "hunter2"}}
	if err := runScriptedPhoneFlow(f, codes, pws); err != nil {
		t.Fatalf("flow: %v", err)
	}
	if len(f.signInCodes) != 1 || f.sendCodes != 1 {
		t.Errorf("SignIn = %d, SendCode = %d: a wrong password must not re-run the code step", len(f.signInCodes), f.sendCodes)
	}
	want := []Reprompt{{}, {Reason: RepromptBadPassword, AttemptsLeft: 2}}
	if fmt.Sprint(pws.seen) != fmt.Sprint(want) {
		t.Errorf("password prompts saw %v, want %v", pws.seen, want)
	}
}

func TestRunPhoneFlow_PasswordAttemptsAreBounded(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345", needPassword: true, goodPassword: "hunter2"}
	codes := &scriptedPrompt{inputs: []string{"12345"}}
	pws := &scriptedPrompt{inputs: []string{"a", "b", "c", "hunter2"}}
	err := runScriptedPhoneFlow(f, codes, pws)
	if !errors.Is(err, auth.ErrPasswordInvalid) {
		t.Fatalf("err = %v, want auth.ErrPasswordInvalid after the last attempt", err)
	}
	if len(f.passwords) != LoginPasswordAttempts {
		t.Errorf("password checks = %d, want %d", len(f.passwords), LoginPasswordAttempts)
	}
}

func TestRunPhoneFlow_AuthRestartOnSendCodeRetriedOnce(t *testing.T) {
	restart := func() error { return fmt.Errorf("send: %w", tgerr.New(500, "AUTH_RESTART")) }

	t.Run("one restart is absorbed", func(t *testing.T) {
		f := &fakeFlowClient{goodCode: "12345", sendCodeErrs: []error{restart()}}
		codes := &scriptedPrompt{inputs: []string{"12345"}}
		if err := runScriptedPhoneFlow(f, codes, nil); err != nil {
			t.Fatalf("flow: %v", err)
		}
		if f.sendCodes != 2 {
			t.Errorf("SendCode calls = %d, want 2", f.sendCodes)
		}
	})

	t.Run("a second restart surfaces", func(t *testing.T) {
		f := &fakeFlowClient{goodCode: "12345", sendCodeErrs: []error{restart(), restart()}}
		codes := &scriptedPrompt{inputs: []string{"12345"}}
		err := runScriptedPhoneFlow(f, codes, nil)
		if !tgerr.Is(err, "AUTH_RESTART") {
			t.Fatalf("err = %v, want AUTH_RESTART", err)
		}
		if f.sendCodes != 2 || len(codes.seen) != 0 {
			t.Errorf("SendCode = %d, prompts = %d, want 2 and 0", f.sendCodes, len(codes.seen))
		}
	})
}

func TestRunPhoneFlow_AuthRestartOnSignInSendsANewCode(t *testing.T) {
	f := &fakeFlowClient{goodCode: "12345", signInErrs: []error{tgerr.New(500, "AUTH_RESTART")}}
	codes := &scriptedPrompt{inputs: []string{"12345", "12345"}}
	if err := runScriptedPhoneFlow(f, codes, nil); err != nil {
		t.Fatalf("flow: %v", err)
	}
	if f.sendCodes != 2 || fmt.Sprint(f.signInHash) != "[hash-1 hash-2]" {
		t.Errorf("SendCode = %d, hashes = %v, want a restart onto hash-2", f.sendCodes, f.signInHash)
	}
	want := []Reprompt{{}, {Reason: RepromptAuthRestart, AttemptsLeft: LoginCodeAttempts}}
	if fmt.Sprint(codes.seen) != fmt.Sprint(want) {
		t.Errorf("prompts saw %v, want %v", codes.seen, want)
	}
}

func TestRetryAuthRestartOnce(t *testing.T) {
	ctx := context.Background()
	script := func(errs ...error) (func() (int, error), *int) {
		calls := 0
		return func() (int, error) {
			calls++
			if calls <= len(errs) {
				return 0, errs[calls-1]
			}
			return 42, nil
		}, &calls
	}
	restart := fmt.Errorf("export: %w", tgerr.New(500, "AUTH_RESTART"))

	fn, calls := script(restart)
	if v, err := retryAuthRestartOnce(ctx, fn); err != nil || v != 42 || *calls != 2 {
		t.Errorf("one restart: v=%d err=%v calls=%d, want 42 nil 2", v, err, *calls)
	}
	fn, calls = script(restart, restart)
	if _, err := retryAuthRestartOnce(ctx, fn); !tgerr.Is(err, "AUTH_RESTART") || *calls != 2 {
		t.Errorf("two restarts: err=%v calls=%d, want AUTH_RESTART after 2", err, *calls)
	}
	other := errors.New("qr token expired")
	fn, calls = script(other)
	if _, err := retryAuthRestartOnce(ctx, fn); !errors.Is(err, other) || *calls != 1 {
		t.Errorf("other error: err=%v calls=%d, want it unretried", err, *calls)
	}
}
