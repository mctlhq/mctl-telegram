package agenteval

import (
	"errors"
	"fmt"
)

// ErrBindingMismatch means a run's result does not belong to what it is
// being used for.
var ErrBindingMismatch = errors.New("eval run binding mismatch")

// RunBinding is what one eval run is bound to. A result counts for a
// promotion only when all five fields match the fork version being
// promoted, so a result for one digest, base, suite or scoring rule never
// counts for another.
type RunBinding struct {
	UserID         int64
	ForkDigest     string
	BaseDigest     string
	SuiteDigest    string
	HarnessVersion string
}

// BindingFor is the binding of a run of t for userID, with this package's
// HarnessVersion. The definition under test must be a fork.
func BindingFor(userID int64, t *Target) (RunBinding, error) {
	if t == nil || t.Entry.Definition.Metadata.Fork == nil {
		return RunBinding{}, errors.New("only a fork version is promoted")
	}
	b := RunBinding{
		UserID:         userID,
		ForkDigest:     t.Entry.Digest,
		BaseDigest:     t.Base.Digest,
		SuiteDigest:    t.Suite.Digest,
		HarnessVersion: HarnessVersion,
	}
	return b, b.validate()
}

func (b RunBinding) validate() error {
	if b.UserID <= 0 || b.ForkDigest == "" || b.BaseDigest == "" || b.SuiteDigest == "" || b.HarnessVersion == "" {
		return fmt.Errorf("%w: incomplete binding", ErrBindingMismatch)
	}
	return nil
}

// Check reports whether a run bound to b may serve want. An incomplete
// binding on either side never matches: a field that was not recorded is
// not a field that agrees.
func (b RunBinding) Check(want RunBinding) error {
	if err := b.validate(); err != nil {
		return err
	}
	if err := want.validate(); err != nil {
		return err
	}
	switch {
	case b.UserID != want.UserID:
		return fmt.Errorf("%w: another account's run", ErrBindingMismatch)
	case b.ForkDigest != want.ForkDigest:
		return fmt.Errorf("%w: run is for fork %s, not %s", ErrBindingMismatch, b.ForkDigest, want.ForkDigest)
	case b.BaseDigest != want.BaseDigest:
		return fmt.Errorf("%w: run is for base %s, not %s", ErrBindingMismatch, b.BaseDigest, want.BaseDigest)
	case b.SuiteDigest != want.SuiteDigest:
		return fmt.Errorf("%w: run used suite %s, not %s", ErrBindingMismatch, b.SuiteDigest, want.SuiteDigest)
	case b.HarnessVersion != want.HarnessVersion:
		return fmt.Errorf("%w: run used harness %s, not %s", ErrBindingMismatch, b.HarnessVersion, want.HarnessVersion)
	}
	return nil
}
