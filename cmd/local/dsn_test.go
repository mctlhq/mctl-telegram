package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/mctlhq/mctl-telegram/internal/db"
)

// TestSQLiteDSN covers the shapes a real config directory can take. The
// Windows cases are the reason this helper exists: string concatenation put a
// drive colon and backslashes into the URI, and the daemon died opening its
// own database on the first run.
func TestSQLiteDSN(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{
			name: "posix",
			path: "/Users/me/.config/mctl-telegram-local/state.db",
			want: "file:///Users/me/.config/mctl-telegram-local/state.db",
		},
		{
			name: "windows drive path",
			path: `C:\Users\me\.config\mctl-telegram-local\state.db`,
			want: "file:///C:/Users/me/.config/mctl-telegram-local/state.db",
		},
		{
			name: "windows unc-style forward slashes",
			path: "D:/data/state.db",
			want: "file:///D:/data/state.db",
		},
		{
			name: "space in home directory",
			path: "/Users/Jane Doe/.config/state.db",
			want: "file:///Users/Jane%20Doe/.config/state.db",
		},
		{
			name: "query and fragment characters are escaped, not parsed",
			path: "/Users/od#d?ball/state.db",
			want: "file:///Users/od%23d%3Fball/state.db",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sqliteDSN(tc.path); got != tc.want {
				t.Errorf("sqliteDSN(%q)\n got %q\nwant %q", tc.path, got, tc.want)
			}
		})
	}
}

// TestSQLiteDSNOpensAwkwardPath proves the escaping is not merely
// well-formed but is what the driver actually accepts. A directory whose name
// contains a space and a '#' reproduces on any platform the class of failure
// that Windows hits on every path.
func TestSQLiteDSNOpensAwkwardPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "od#d ball")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	dsn := sqliteDSN(filepath.Join(dir, "state.db")) +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"

	conn, err := db.Open(context.Background(), dsn, 0, 0)
	if err != nil {
		t.Fatalf("open %q: %v", dsn, err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.PingContext(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}
}
