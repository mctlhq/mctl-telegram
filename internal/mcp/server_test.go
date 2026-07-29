package mcp

import "testing"

func TestServer_WithVersion(t *testing.T) {
	s := &Server{}
	if got := s.WithVersion("1.2.3").Version; got != "1.2.3" {
		t.Fatalf("Version = %q, want %q", got, "1.2.3")
	}
}

func TestServer_WithVersion_EmptyLeavesUnset(t *testing.T) {
	s := &Server{}
	s.WithVersion("")
	if s.Version != "" {
		t.Fatalf("Version = %q, want empty (HTTPHandler applies the \"dev\" fallback)", s.Version)
	}
}
