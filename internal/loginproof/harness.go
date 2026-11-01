package loginproof

import (
	"context"
	"errors"
	"fmt"
)

// Steps is what a live command supplies to Run. Every function does one thing
// against the real system (or a fake in tests); Run alone decides the verdict.
type Steps struct {
	// Login runs the product login (telegram.LoginQR or telegram.Login) and
	// returns an error for a failed login. A signed-in account that is not the
	// expected one is reported as ErrIdentityMismatch.
	Login func(ctx context.Context) error
	// LoadSession returns the session bytes the login left in the store, nil
	// when there is none.
	LoadSession func(ctx context.Context) ([]byte, error)
	// SaveSession makes the stored session usable by the pool, as cmd/login
	// does after a login. May be nil.
	SaveSession func(ctx context.Context, data []byte) error
	// CallTool makes the one read-only MCP call and returns an error unless it
	// returned a non-error result.
	CallTool func(ctx context.Context) error
	// LogOut ends the new authorization from its session bytes.
	LogOut func(ctx context.Context, data []byte) error
	// Fallback ends the new authorization by other means (the anchor's
	// account.resetAuthorization). Nil when there is none.
	Fallback func(ctx context.Context) error
	// StillAuthorized reports whether the new authorization is still listed.
	// Used to verify Fallback. Nil when there is no way to check.
	StillAuthorized func(ctx context.Context) (bool, error)
	// Scanned reports whether a new authorization may exist even though Login
	// failed (the anchor already accepted the token). Nil means no.
	Scanned func() bool
}

// Run executes the proof in mode and returns the evidence-ready verdict. expect
// is the outcome a negative mode must see from Login.
func Run(ctx context.Context, mode Mode, s Steps) (outcome string, reached Step) {
	var rec Recorder
	err := run(ctx, mode, s, &rec)
	return rec.Verdict(mode, err), rec.Reached()
}

var expectedOutcome = map[Mode]string{
	ModePhoneWrongPassword: OutcomeBadPassword,
	ModePhoneExpiredCode:   OutcomeCodeExpired,
}

func run(ctx context.Context, mode Mode, s Steps, rec *Recorder) error {
	if want, negative := expectedOutcome[mode]; negative {
		return runNegative(ctx, want, s, rec)
	}
	loginErr := s.Login(ctx)
	if loginErr != nil {
		// The product login logs out what it did not settle, but a token the
		// anchor accepted may still have created an authorization.
		if s.Scanned != nil && s.Scanned() {
			if cerr := cleanup(ctx, nil, s); cerr != nil {
				return cerr
			}
		}
		return loginErr
	}
	rec.Observe(StepLogin)

	data, err := s.LoadSession(ctx)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	if len(data) == 0 {
		// Logged in but nothing persisted: still end the authorization.
		if cerr := cleanup(ctx, nil, s); cerr != nil {
			return cerr
		}
		return nil
	}
	rec.Observe(StepPersisted)

	var callErr error
	if s.SaveSession != nil {
		callErr = s.SaveSession(ctx, data)
	}
	if callErr == nil {
		callErr = s.CallTool(ctx)
		if callErr == nil {
			rec.Observe(StepMCPCall)
		}
	}

	if cerr := cleanup(ctx, data, s); cerr != nil {
		return cerr
	}
	rec.Observe(StepCleanup)
	if callErr != nil {
		return fmt.Errorf("mcp: %w", callErr)
	}
	return nil
}

func runNegative(ctx context.Context, want string, s Steps, rec *Recorder) error {
	loginErr := s.Login(ctx)
	if loginErr == nil {
		// The login must not have succeeded. End whatever it created.
		if data, err := s.LoadSession(ctx); err == nil && len(data) > 0 {
			if cerr := cleanup(ctx, data, s); cerr != nil {
				return cerr
			}
		}
		return errors.New("login succeeded where a failure was expected")
	}
	if got := Classify(loginErr); got != want {
		return loginErr
	}
	rec.Observe(StepExpectOutcome)
	data, err := s.LoadSession(ctx)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}
	if len(data) != 0 {
		_ = cleanup(ctx, data, s)
		return errors.New("a session was stored by a failed login")
	}
	rec.Observe(StepNoSession)
	return nil
}

// cleanup ends the new authorization: LogOut first, then the Fallback verified
// with StillAuthorized. It returns an error wrapping nothing classifiable as a
// pass; the caller reports it as cleanup_failed.
func cleanup(ctx context.Context, data []byte, s Steps) error {
	if len(data) > 0 && s.LogOut != nil {
		if err := s.LogOut(ctx, data); err == nil {
			return nil
		}
	}
	if s.Fallback != nil && s.StillAuthorized != nil {
		if err := s.Fallback(ctx); err == nil {
			still, cerr := s.StillAuthorized(ctx)
			if cerr == nil && !still {
				return nil
			}
		}
	}
	return ErrCleanupFailed
}

// ErrCleanupFailed means the authorization the proof created may still exist.
var ErrCleanupFailed = errors.New("cleanup failed")
