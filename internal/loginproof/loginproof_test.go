package loginproof

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	tdauth "github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tgerr"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"code expired", &tgerr.Error{Code: 400, Type: "PHONE_CODE_EXPIRED", Message: "PHONE_CODE_EXPIRED"}, OutcomeCodeExpired},
		{"code invalid", &tgerr.Error{Code: 400, Type: "PHONE_CODE_INVALID", Message: "PHONE_CODE_INVALID"}, OutcomeCodeInvalid},
		{"password sentinel", tdauth.ErrPasswordInvalid, OutcomeBadPassword},
		{"password wrapped", fmt.Errorf("x: %w", tdauth.ErrPasswordInvalid), OutcomeBadPassword},
		{"password hash", &tgerr.Error{Code: 400, Type: "PASSWORD_HASH_INVALID", Message: "PASSWORD_HASH_INVALID"}, OutcomeBadPassword},
		{"flood", &tgerr.Error{Code: 420, Type: "FLOOD_WAIT", Message: "FLOOD_WAIT_30"}, OutcomeFloodWait},
		{"restart", &tgerr.Error{Code: 500, Type: "AUTH_RESTART", Message: "AUTH_RESTART"}, OutcomeAuthRestart},
		{"qr expired", telegram.ErrQRLoginExpired, OutcomeTimeout},
		{"deadline", context.DeadlineExceeded, OutcomeTimeout},
		{"mismatch", ErrIdentityMismatch, OutcomeIdentityMismatch},
		{"cleanup", ErrCleanupFailed, OutcomeCleanupFailed},
		{"refused", ErrRefused, OutcomeRefused},
		{"arbitrary", errors.New("boom"), OutcomeUnknown},
		{"nil", nil, OutcomeUnknown},
	}
	for _, c := range cases {
		got := Classify(c.err)
		if got != c.want {
			t.Errorf("%s: Classify = %q, want %q", c.name, got, c.want)
		}
		if got == OutcomePass {
			t.Errorf("%s: Classify returned pass", c.name)
		}
	}
}

func TestVerdict_EveryRequiredStepMatters(t *testing.T) {
	for mode, steps := range required {
		var full Recorder
		for _, s := range steps {
			full.Observe(s)
		}
		if got := full.Verdict(mode, nil); got != OutcomePass {
			t.Fatalf("%s: all steps observed = %q, want pass", mode, got)
		}
		if got := full.Verdict(mode, errors.New("x")); got == OutcomePass {
			t.Errorf("%s: a run error must never pass", mode)
		}
		for _, omit := range steps {
			var r Recorder
			for _, s := range steps {
				if s != omit {
					r.Observe(s)
				}
			}
			if got := r.Verdict(mode, nil); got == OutcomePass {
				t.Errorf("%s: omitting %s still passed", mode, omit)
			}
		}
	}
	var none Recorder
	if got := none.Verdict("nonsense", nil); got == OutcomePass {
		t.Error("unknown mode passed")
	}
}

func TestEvidenceLine(t *testing.T) {
	typ := reflect.TypeOf(Evidence{})
	want := []string{"Mode", "Outcome", "Reached", "Commit", "At"}
	if typ.NumField() != len(want) {
		t.Fatalf("Evidence fields changed: have %d, want %v; a new field must not hold an identifier", typ.NumField(), want)
	}
	for i, n := range want {
		if typ.Field(i).Name != n || typ.Field(i).Type.Kind() != reflect.String {
			t.Errorf("field %d = %s, want string %s", i, typ.Field(i).Name, n)
		}
	}
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	line := NewEvidence(ModeQR, OutcomePass, StepCleanup, "abc1234", at).Line()
	if line != "login-proof mode=qr outcome=pass reached=cleanup commit=abc1234 at=2026-11-01T12:00:00Z" {
		t.Errorf("line = %q", line)
	}
	if l := NewEvidence(ModeQR, OutcomePass, StepCleanup, "+15550100000 secret", at).Line(); strings.Contains(l, "5550100000") {
		t.Errorf("a non-SHA commit leaked into the line: %q", l)
	}
	if strings.Count(line, "\n") != 0 {
		t.Error("evidence must be one line")
	}
}
