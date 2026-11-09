package glovo

import (
	"os/exec"
	"strings"
	"testing"
)

// The facade is an independent binary: it must not link the Telegram server's
// packages, a Temporal client or MTProto, and the Telegram server must not
// link the facade (so tg.mctl.ai, its descriptors and its allowlist cannot
// change through it).
var facadeBanned = []string{
	"github.com/mctlhq/mctl-telegram/internal/telegram",
	"github.com/mctlhq/mctl-telegram/internal/oauth",
	"github.com/mctlhq/mctl-telegram/internal/db",
	"github.com/mctlhq/mctl-telegram/internal/bridge",
	"github.com/mctlhq/mctl-telegram/internal/mcp",
	"github.com/mctlhq/mctl-telegram/cmd/server",
	"go.temporal.io/",
	"github.com/gotd/",
}

// offending returns the deps that equal a banned package or live under it.
func offending(deps, banned []string) []string {
	var bad []string
	for _, d := range deps {
		for _, b := range banned {
			if d == b || strings.HasPrefix(d, strings.TrimSuffix(b, "/")+"/") {
				bad = append(bad, d)
				break
			}
		}
	}
	return bad
}

func deps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", pkg)
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps %s: %v\n%s", pkg, err, out)
	}
	return strings.Fields(string(out))
}

func TestFacadeBinaryImportBoundary(t *testing.T) {
	if bad := offending(deps(t, "./cmd/glovo-mcp"), facadeBanned); len(bad) > 0 {
		t.Fatalf("cmd/glovo-mcp links forbidden packages: %v", bad)
	}
}

func TestTelegramServerDoesNotLinkFacade(t *testing.T) {
	if bad := offending(deps(t, "./cmd/server"), []string{"github.com/mctlhq/mctl-telegram/internal/glovo"}); len(bad) > 0 {
		t.Fatalf("cmd/server links the facade: %v", bad)
	}
}

func TestBoundaryDetectsPlantedImport(t *testing.T) {
	planted := []string{"fmt", "github.com/mctlhq/mctl-telegram/internal/telegram/session", "go.temporal.io/sdk/client", "github.com/mctlhq/mctl-telegram/internal/glovo/authn"}
	if got := offending(planted, facadeBanned); len(got) != 2 {
		t.Fatalf("planted imports not detected: %v", got)
	}
	if got := offending(planted, []string{"github.com/mctlhq/mctl-telegram/internal/glovo"}); len(got) != 1 {
		t.Fatalf("planted facade import not detected: %v", got)
	}
}
