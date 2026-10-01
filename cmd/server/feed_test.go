package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validEntryYAML = `schema: mctl-telegram.product-update/v1
id: send-message
kind: new_tool
title: Send messages
summary: You can now send a message to a chat.
locale: en
delivery: next_digest
tools: [send_message]
evidence:
  from: 0.69.0
  changes:
    - {tool: send_message, change: added}
status: approved
provenance:
  author: alice
  reviewed_by: alice
created_at: "2026-09-24"
reviewed_at: "2026-09-24"
`

// TestLoadProductUpdateFeed_MissingDirectory is T13 (boot): a missing feed
// directory is a load error, not an empty feed -- the server is always
// configured with a feed directory, so its absence is a packaging or
// configuration mistake (the #715 image shipped without it) that must show
// up as "feed not loaded", not as a feed with no entries. It still never
// blocks boot: Err is only logged, and LatestRelease still resolves.
func TestLoadProductUpdateFeed_MissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	src := loadProductUpdateFeed(dir, "1.2.3")
	if src.Err == nil || !strings.Contains(src.Err.Error(), "does not exist") {
		t.Fatalf("Err = %v, want a missing-directory load error", src.Err)
	}
	if len(src.Feed.Entries) != 0 {
		t.Fatalf("entries = %d, want 0", len(src.Feed.Entries))
	}
	if src.LatestRelease != "1.2.3" {
		t.Fatalf("LatestRelease = %q, want 1.2.3", src.LatestRelease)
	}
}

// TestLoadProductUpdateFeed_NotADirectory: a file where the directory should
// be is a load error too, not an empty feed.
func TestLoadProductUpdateFeed_NotADirectory(t *testing.T) {
	file := filepath.Join(t.TempDir(), "product-updates")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if src := loadProductUpdateFeed(file, "1.2.3"); src.Err == nil {
		t.Fatal("a file in place of the feed directory did not produce a load error")
	}
}

// TestLoadProductUpdateFeed_InvalidEntry is the other half of task 3's DoD:
// an invalid entry is logged (Err set) but never aborts boot -- the caller
// (main) only logs it and continues.
func TestLoadProductUpdateFeed_InvalidEntry(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("schema: not-the-right-schema\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := loadProductUpdateFeed(dir, "1.2.3")
	if src.Err == nil {
		t.Fatal("an invalid entry did not produce a load error")
	}
}

// TestLoadProductUpdateFeed_LatestRelease covers the release-resolution half:
// a MAJOR.MINOR.PATCH build version resolves to LatestRelease, a non-release
// version (the "dev" default) resolves to "", independent of whether the
// feed itself loaded cleanly.
func TestLoadProductUpdateFeed_LatestRelease(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "send-message.yaml"), []byte(validEntryYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		want    string
	}{
		{"0.70.0", "0.70.0"},
		{"dev", ""},
		{"", ""},
	} {
		src := loadProductUpdateFeed(dir, tc.version)
		if src.Err != nil {
			t.Fatalf("version %q: unexpected load error: %v", tc.version, src.Err)
		}
		if len(src.Feed.Entries) != 1 {
			t.Fatalf("version %q: entries = %d, want 1", tc.version, len(src.Feed.Entries))
		}
		if src.LatestRelease != tc.want {
			t.Fatalf("version %q: LatestRelease = %q, want %q", tc.version, src.LatestRelease, tc.want)
		}
	}
}
