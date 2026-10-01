package jsonstrict

import (
	"errors"
	"fmt"
	"testing"
)

func TestRejectDuplicateKeys(t *testing.T) {
	for _, tc := range []struct {
		name, in string
		want     error // nil: accepted; otherwise errors.Is target
		syntax   bool  // a decoder syntax error, not one of the sentinels
	}{
		{name: "flat object", in: `{"a":1,"b":"x","c":null}`},
		{name: "nested distinct", in: `{"a":{"a":1},"b":[{"a":1},{"a":2}]}`},
		{name: "scalar", in: `42`},
		{name: "duplicate", in: `{"a":1,"a":2}`, want: ErrDuplicateKey},
		{name: "nested duplicate", in: `{"x":[{"b":1,"b":2}]}`, want: ErrDuplicateKey},
		// Exact comparison: case variants are distinct names here, and
		// callers needing an exact key set check spelling themselves.
		{name: "case variants are distinct", in: `{"a":1,"A":2}`},
		{name: "trailing value", in: `{"a":1} {}`, want: ErrTrailingData},
		{name: "truncated", in: `{"a":`, syntax: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RejectDuplicateKeys([]byte(tc.in))
			switch {
			case tc.syntax:
				if err == nil {
					t.Fatal("accepted malformed JSON")
				}
			case tc.want == nil:
				if err != nil {
					t.Fatalf("rejected valid JSON: %v", err)
				}
			case !errors.Is(err, tc.want):
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// The unexpected-delimiter branch is not reachable through
// RejectDuplicateKeys (the decoder's token state machine reports a stray
// closer as a syntax error first), so its error type is pinned directly.
func TestUnexpectedDelimError(t *testing.T) {
	var err error = &UnexpectedDelimError{Delim: '}'}
	if !errors.Is(err, ErrUnexpectedDelim) {
		t.Error("UnexpectedDelimError does not match ErrUnexpectedDelim")
	}
	if got, want := err.Error(), `unexpected JSON delimiter "}"`; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	var de *UnexpectedDelimError
	if !errors.As(fmt.Errorf("wrapped: %w", err), &de) || de.Delim != '}' {
		t.Errorf("errors.As through a wrap lost the delimiter: %+v", de)
	}
}
