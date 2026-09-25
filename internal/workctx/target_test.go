package workctx

import (
	"errors"
	"testing"
)

func TestCanonicalIssueURL_Table(t *testing.T) {
	cases := []struct {
		name    string
		arg     string
		want    string
		wantErr bool
	}{
		{"plain", "https://github.com/mctlhq/mctl-telegram/issues/443", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"uppercase host and scheme", "HTTPS://GITHUB.COM/mctlhq/mctl-telegram/issues/443", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"trailing slash", "https://github.com/mctlhq/mctl-telegram/issues/443/", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"query", "https://github.com/mctlhq/mctl-telegram/issues/443?tab=comments", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"mixed-case issues segment", "https://github.com/mctlhq/mctl-telegram/Issues/443", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"mixed-case owner and repo", "https://github.com/MCTLHQ/MCTL-Telegram/issues/443", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"fragment", "https://github.com/mctlhq/mctl-telegram/issues/443#issuecomment-1", "https://github.com/mctlhq/mctl-telegram/issues/443", false},
		{"empty", "", "", true},
		{"missing arg trimmed", "   ", "", true},
		{"a title, not a url", "fix the bug please", "", true},
		{"pull request url", "https://github.com/mctlhq/mctl-telegram/pull/443", "", true},
		{"another owner", "https://github.com/other/mctl-telegram/issues/443", "", true},
		{"another host", "https://gitlab.com/mctlhq/mctl-telegram/issues/443", "", true},
		{"non-numeric issue number", "https://github.com/mctlhq/mctl-telegram/issues/abc", "", true},
		{"missing issue number", "https://github.com/mctlhq/mctl-telegram/issues/", "", true},
		{"missing issue number no slash", "https://github.com/mctlhq/mctl-telegram/issues", "", true},
		{"http not https", "http://github.com/mctlhq/mctl-telegram/issues/443", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := CanonicalIssueURL(c.arg)
			if c.wantErr {
				if !errors.Is(err, ErrNotAnIssueURL) {
					t.Fatalf("err = %v, want ErrNotAnIssueURL", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestIdempotencyKey_StableAndScoped(t *testing.T) {
	k1 := IdempotencyKey(555, 101, "open", 0)
	k2 := IdempotencyKey(555, 101, "open", 0)
	if k1 != k2 {
		t.Fatalf("IdempotencyKey not stable: %q != %q", k1, k2)
	}
	if k1 != "tg:v1:555:101:open" {
		t.Fatalf("IdempotencyKey = %q, want tg:v1:555:101:open", k1)
	}
	resumeKey := IdempotencyKey(555, 101, "resume", 7)
	if resumeKey != "tg:v1:555:101:resume:7" {
		t.Fatalf("IdempotencyKey (resume) = %q, want tg:v1:555:101:resume:7", resumeKey)
	}
	otherThread := IdempotencyKey(555, 102, "open", 0)
	if otherThread == k1 {
		t.Fatalf("two different threads produced the same idempotency key: %q", k1)
	}
}
