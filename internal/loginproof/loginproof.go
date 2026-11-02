// Package loginproof holds the verdict logic of the low-frequency live Telegram
// login proof (issue #1057, cmd/login-proof). It does no Telegram I/O: the
// command supplies the steps as functions, this package decides whether the
// run proved anything.
//
// The rule it enforces is that a proof passes only when every step the mode
// requires was positively observed, and never because an error was absent. An
// outcome that cannot be told (flood wait, refusal, unknown error) is recorded
// as such and is never a pass.
//
// The proof must use the dedicated login-proof service account, never a
// personal, operator or canary account, and must never run on a schedule.
package loginproof

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	tdauth "github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tgerr"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// Mode names what is being proven.
type Mode string

const (
	ModeQR                 Mode = "qr"
	ModePhone              Mode = "phone"
	ModePhoneWrongPassword Mode = "phone-wrong-password"
	ModePhoneExpiredCode   Mode = "phone-expired-code"
)

// Step is a postcondition a harness observed.
type Step string

const (
	StepLogin         Step = "login"
	StepPersisted     Step = "persisted"
	StepMCPCall       Step = "mcp_call"
	StepCleanup       Step = "cleanup"
	StepExpectOutcome Step = "expect_outcome"
	StepNoSession     Step = "no_session"
)

// Outcomes is the closed set of values Evidence.Outcome may take.
const (
	OutcomePass             = "pass"
	OutcomeFail             = "fail"
	OutcomeBadPassword      = "bad_password"
	OutcomeCodeExpired      = "code_expired"
	OutcomeCodeInvalid      = "code_invalid"
	OutcomeFloodWait        = "flood_wait"
	OutcomeAuthRestart      = "auth_restart"
	OutcomeIdentityMismatch = "identity_mismatch"
	OutcomeRefused          = "refused"
	OutcomeCleanupFailed    = "cleanup_failed"
	OutcomeTimeout          = "timeout"
	OutcomeUnknown          = "unknown"
)

// required lists, per mode, the steps that must all be observed for a pass,
// in the order they happen. It is the only place that says what a pass means.
var required = map[Mode][]Step{
	ModeQR:                 {StepLogin, StepPersisted, StepMCPCall, StepCleanup},
	ModePhone:              {StepLogin, StepPersisted, StepMCPCall, StepCleanup},
	ModePhoneWrongPassword: {StepExpectOutcome, StepNoSession},
	ModePhoneExpiredCode:   {StepExpectOutcome, StepNoSession},
}

// Required returns a copy of the steps mode needs for a pass.
func Required(m Mode) []Step { return append([]Step(nil), required[m]...) }

// ErrIdentityMismatch is returned by a harness when the signed-in account is
// not the expected service account.
var ErrIdentityMismatch = errors.New("signed in as a different Telegram account than expected")

// ErrRefused is returned when Telegram or the proof itself refuses to
// continue, for example when an account would have to be created.
var ErrRefused = errors.New("refused")

// Recorder collects the steps a run observed.
type Recorder struct {
	seen map[Step]bool
	last Step
}

// Observe records that step's postcondition was checked and held.
func (r *Recorder) Observe(s Step) {
	if r.seen == nil {
		r.seen = map[Step]bool{}
	}
	r.seen[s] = true
	r.last = s
}

// Reached is the last step observed, "none" when there was none.
func (r *Recorder) Reached() Step {
	if r.last == "" {
		return "none"
	}
	return r.last
}

// Verdict is the outcome of a run in mode with the error runErr that the run
// ended with. It is OutcomePass only when runErr is nil and every required
// step was observed.
func (r *Recorder) Verdict(mode Mode, runErr error) string {
	if runErr != nil {
		return Classify(runErr)
	}
	steps, ok := required[mode]
	if !ok {
		return OutcomeFail
	}
	for _, s := range steps {
		if !r.seen[s] {
			return OutcomeFail
		}
	}
	return OutcomePass
}

// Classify maps an error to an outcome from the closed set. It never returns
// OutcomePass; an unrecognised error is OutcomeUnknown.
func Classify(err error) string {
	switch {
	case err == nil:
		return OutcomeUnknown
	case errors.Is(err, ErrIdentityMismatch):
		return OutcomeIdentityMismatch
	case errors.Is(err, ErrRefused):
		return OutcomeRefused
	case errors.Is(err, ErrCleanupFailed):
		return OutcomeCleanupFailed
	case errors.Is(err, telegram.ErrQRLoginExpired),
		errors.Is(err, context.DeadlineExceeded),
		errors.Is(err, context.Canceled):
		return OutcomeTimeout
	case errors.Is(err, tdauth.ErrPasswordInvalid):
		return OutcomeBadPassword
	}
	var rpcErr *tgerr.Error
	if errors.As(err, &rpcErr) {
		switch {
		case rpcErr.Message == "PHONE_CODE_INVALID":
			return OutcomeCodeInvalid
		case rpcErr.Message == "PHONE_CODE_EXPIRED":
			return OutcomeCodeExpired
		case rpcErr.Message == "PASSWORD_HASH_INVALID":
			return OutcomeBadPassword
		case strings.HasPrefix(rpcErr.Message, "FLOOD_WAIT_"):
			return OutcomeFloodWait
		case rpcErr.Message == "AUTH_RESTART":
			return OutcomeAuthRestart
		case rpcErr.Message == "PHONE_NUMBER_UNOCCUPIED":
			return OutcomeRefused
		}
	}
	m := strings.ToLower(err.Error())
	switch {
	case strings.Contains(m, "different telegram account"):
		return OutcomeIdentityMismatch
	case strings.Contains(m, "invalid password") || strings.Contains(m, "password_hash_invalid"):
		return OutcomeBadPassword
	case strings.Contains(m, "sign up") || strings.Contains(m, "signup"):
		return OutcomeRefused
	}
	return OutcomeUnknown
}

// Evidence is the one line a proof prints. It has no field that can hold an
// identifier: only fixed-vocabulary values and a sanitised commit.
type Evidence struct {
	Mode    string
	Outcome string
	Reached string
	Commit  string
	At      string
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// NewEvidence builds the evidence for a finished run. A commit that is not a
// hex SHA is replaced by "unknown" rather than printed.
func NewEvidence(mode Mode, outcome string, reached Step, commit string, at time.Time) Evidence {
	if !commitRE.MatchString(commit) {
		commit = "unknown"
	}
	return Evidence{
		Mode:    string(mode),
		Outcome: outcome,
		Reached: string(reached),
		Commit:  commit,
		At:      at.UTC().Format(time.RFC3339),
	}
}

// Line renders the single evidence line.
func (e Evidence) Line() string {
	return fmt.Sprintf("login-proof mode=%s outcome=%s reached=%s commit=%s at=%s",
		e.Mode, e.Outcome, e.Reached, e.Commit, e.At)
}
