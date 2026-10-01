// Package jsonstrict holds JSON validation that encoding/json does not do on
// its own, shared by the strict request paths (the admin agent-profile
// envelope, the bot-start bridge).
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Sentinel causes returned (wrapped) by RejectDuplicateKeys, so a caller can
// map them to its own wording.
var (
	// ErrDuplicateKey is a member name repeated within one object.
	ErrDuplicateKey = errors.New("duplicate JSON key")
	// ErrTrailingData is anything after the first complete JSON value.
	ErrTrailingData = errors.New("document must contain exactly one JSON value")
	// ErrNonStringKey is an object member name that is not a string.
	ErrNonStringKey = errors.New("object key must be a string")
	// ErrInvalidObject is an object not closed by '}'.
	ErrInvalidObject = errors.New("invalid JSON object")
	// ErrInvalidArray is an array not closed by ']'.
	ErrInvalidArray = errors.New("invalid JSON array")
	// ErrUnexpectedDelim is a delimiter where a value was expected. It is
	// returned as an *UnexpectedDelimError, which carries the delimiter.
	ErrUnexpectedDelim = errors.New("unexpected JSON delimiter")
)

// UnexpectedDelimError reports which delimiter appeared where a value was
// expected. It matches ErrUnexpectedDelim under errors.Is, and carries the
// delimiter as data so a caller can word the message itself.
type UnexpectedDelimError struct {
	Delim json.Delim
}

func (e *UnexpectedDelimError) Error() string {
	return fmt.Sprintf("%v %q", ErrUnexpectedDelim, e.Delim)
}

// Is reports a match against ErrUnexpectedDelim.
func (e *UnexpectedDelimError) Is(target error) bool { return target == ErrUnexpectedDelim }

// RejectDuplicateKeys validates that raw is exactly one JSON value whose
// objects, at every depth, repeat no member name. encoding/json keeps the
// last of a repeated member and DisallowUnknownFields does not notice, so a
// strict decoder must run this on the raw bytes first.
//
// Member names are compared exactly. encoding/json also matches struct
// fields case-insensitively, so a caller that needs an exact key set must
// check spelling separately.
func RejectDuplicateKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrNonStringKey
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("%w %q", ErrDuplicateKey, key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim('}') {
				return ErrInvalidObject
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := dec.Token()
			if err != nil {
				return err
			}
			if end != json.Delim(']') {
				return ErrInvalidArray
			}
		default:
			return &UnexpectedDelimError{Delim: delim}
		}
		return nil
	}

	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return ErrTrailingData
		}
		return err
	}
	return nil
}
