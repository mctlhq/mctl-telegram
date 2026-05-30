package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowed(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	cases := []struct {
		name    string
		roots   []string
		path    string
		wantErr bool
	}{
		{
			name:    "path inside root",
			roots:   []string{dir},
			path:    filepath.Join(dir, "file.txt"),
			wantErr: false,
		},
		{
			name:    "path is root itself",
			roots:   []string{dir},
			path:    dir,
			wantErr: false,
		},
		{
			name:    "path in subdirectory of root",
			roots:   []string{dir},
			path:    filepath.Join(sub, "nested.txt"),
			wantErr: false,
		},
		{
			name:    "path outside root",
			roots:   []string{dir},
			path:    filepath.Join(outside, "file.txt"),
			wantErr: true,
		},
		{
			name:    "empty roots deny all",
			roots:   []string{},
			path:    filepath.Join(dir, "file.txt"),
			wantErr: true,
		},
		{
			name:    "nil roots deny all",
			roots:   nil,
			path:    filepath.Join(dir, "file.txt"),
			wantErr: true,
		},
		{
			name:    "empty path denied",
			roots:   []string{dir},
			path:    "",
			wantErr: true,
		},
		{
			name:    "traversal via .. rejected",
			roots:   []string{sub},
			path:    filepath.Join(sub, "..", "escape.txt"),
			wantErr: true,
		},
		{
			name:    "null byte rejected",
			roots:   []string{dir},
			path:    filepath.Join(dir, "file\x00.txt"),
			wantErr: true,
		},
		{
			name:    "glob star rejected",
			roots:   []string{dir},
			path:    filepath.Join(dir, "*.txt"),
			wantErr: true,
		},
		{
			name:    "glob question mark rejected",
			roots:   []string{dir},
			path:    filepath.Join(dir, "file?.txt"),
			wantErr: true,
		},
		{
			name:    "glob bracket rejected",
			roots:   []string{dir},
			path:    filepath.Join(dir, "[abc].txt"),
			wantErr: true,
		},
		{
			name:    "second root matches",
			roots:   []string{outside, dir},
			path:    filepath.Join(dir, "file.txt"),
			wantErr: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Allowed(c.roots, c.path)
			if c.wantErr {
				if err == nil {
					t.Errorf("Allowed() = %q, want error", got)
				}
			} else {
				if err != nil {
					t.Errorf("Allowed() error = %v, want nil", err)
				}
				if got == "" {
					t.Error("Allowed() returned empty path on success")
				}
			}
		})
	}
}

func TestAllowed_SymlinkEscape(t *testing.T) {
	root := t.TempDir()
	escape := t.TempDir()

	// Create a symlink inside root that points outside it.
	link := filepath.Join(root, "link")
	if err := os.Symlink(escape, link); err != nil {
		t.Skip("symlink creation failed (unsupported on this OS)")
	}

	_, err := Allowed([]string{root}, filepath.Join(link, "secret.txt"))
	if err == nil {
		t.Error("expected Allowed() to deny a symlink escaping the root, got nil error")
	}
}
