package workctx

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ErrNotAnIssueURL means the /mctl work argument is not an acceptable
// runnable target. The owner-facing usage line, not this error's text, is
// what the caller should show — see the work handler.
var ErrNotAnIssueURL = errors.New("workctx: not a mctlhq GitHub issue URL")

// canonicalIssueOwner is the only GitHub org this pilot accepts as a
// runnable target — the dispatcher (mctl-agents#461) only ever runs a
// mctlhq issue's DevLoop.
const canonicalIssueOwner = "mctlhq"

// CanonicalIssueURL validates and normalises a /mctl work argument. It
// accepts only https://github.com/mctlhq/<repo>/issues/<n>, scheme and host
// case-insensitive; a trailing slash, query string or fragment are
// stripped. Anything else — a missing argument, a pull request URL, another
// owner, another host, a non-numeric or missing issue number — is refused
// with ErrNotAnIssueURL and no I/O of any kind: this is a pure function.
func CanonicalIssueURL(arg string) (string, error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", ErrNotAnIssueURL
	}
	u, err := url.Parse(arg)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotAnIssueURL, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", ErrNotAnIssueURL
	}
	if !strings.EqualFold(u.Host, "github.com") {
		return "", ErrNotAnIssueURL
	}
	segments := splitPath(u.Path)
	// Expect exactly [owner, repo, "issues", number].
	if len(segments) != 4 || !strings.EqualFold(segments[0], canonicalIssueOwner) || segments[2] != "issues" {
		return "", ErrNotAnIssueURL
	}
	repo := segments[1]
	if repo == "" {
		return "", ErrNotAnIssueURL
	}
	n, err := strconv.ParseUint(segments[3], 10, 64)
	if err != nil || n == 0 {
		return "", ErrNotAnIssueURL
	}
	return fmt.Sprintf("https://github.com/%s/%s/issues/%d", canonicalIssueOwner, repo, n), nil
}

func splitPath(p string) []string {
	trimmed := strings.Trim(p, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

// IdempotencyKey derives a deterministic, thread-scoped Idempotency-Key so a
// retry after a crash or timeout is a no-op at the platform, while two
// threads on the same issue still submit two distinct requests. stateVersion
// is only meaningful (and only included) for a resume request — pass 0 for
// every other op to omit the ":<version>" suffix.
func IdempotencyKey(chatTGID, rootMsgID int64, op string, stateVersion int64) string {
	base := fmt.Sprintf("tg:v1:%d:%d:%s", chatTGID, rootMsgID, op)
	if stateVersion != 0 {
		base += fmt.Sprintf(":%d", stateVersion)
	}
	return base
}
