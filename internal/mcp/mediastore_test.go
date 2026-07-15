package mcp

import (
	"testing"
	"time"
)

func TestMediaStore_SetAndPop(t *testing.T) {
	ms := NewMediaStore()
	ref := &MediaDownloadRef{Peer: "user:1", MessageID: 42, MediaType: "photo"}
	ms.Set("key1", ref)
	got := ms.Pop("key1")
	if got == nil {
		t.Fatal("Pop returned nil for a freshly Set key")
	}
	if got.Peer != "user:1" || got.MessageID != 42 {
		t.Errorf("Pop returned wrong ref: %+v", got)
	}
}

func TestMediaStore_DoublePop(t *testing.T) {
	ms := NewMediaStore()
	ref := &MediaDownloadRef{Peer: "user:1", MessageID: 1, MediaType: "document"}
	ms.Set("key2", ref)
	first := ms.Pop("key2")
	if first == nil {
		t.Fatal("first Pop returned nil")
	}
	second := ms.Pop("key2")
	if second != nil {
		t.Fatal("second Pop must return nil (single-shot)")
	}
}

func TestMediaStore_Expiry(t *testing.T) {
	ms := NewMediaStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ms.now = func() time.Time { return fixed }
	ref := &MediaDownloadRef{Peer: "user:2", MessageID: 5, MediaType: "audio"}
	ms.Set("key3", ref)
	// Advance past TTL.
	ms.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	got := ms.Pop("key3")
	if got != nil {
		t.Fatal("Pop must return nil for an expired ref")
	}
}

func TestMediaStore_Sweep(t *testing.T) {
	ms := NewMediaStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ms.now = func() time.Time { return fixed }
	ms.Set("key4", &MediaDownloadRef{Peer: "user:3", MessageID: 7, MediaType: "video"})
	// Advance past TTL.
	ms.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	n := ms.Sweep()
	if n != 1 {
		t.Errorf("Sweep removed %d entries, want 1", n)
	}
}

func TestMediaStore_Get_NonDestructive(t *testing.T) {
	ms := NewMediaStore()
	ref := &MediaDownloadRef{Peer: "user:1", MessageID: 42, MediaType: "photo"}
	ms.Set("key5", ref)
	first := ms.Get("key5")
	if first == nil {
		t.Fatal("Get returned nil for a freshly Set key")
	}
	second := ms.Get("key5")
	if second == nil {
		t.Fatal("second Get must return the ref (non-destructive)")
	}
	if first.Peer != second.Peer || first.MessageID != second.MessageID {
		t.Fatal("Get must return the same ref on repeated calls")
	}
}

func TestMediaStore_Get_Expired(t *testing.T) {
	ms := NewMediaStore()
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ms.now = func() time.Time { return fixed }
	ms.Set("key6", &MediaDownloadRef{Peer: "user:1", MessageID: 5, MediaType: "audio"})
	ms.now = func() time.Time { return fixed.Add(ConfirmationTTL + time.Second) }
	if got := ms.Get("key6"); got != nil {
		t.Fatal("Get must return nil for an expired ref")
	}
}

func TestMediaStore_Delete(t *testing.T) {
	ms := NewMediaStore()
	ms.Set("key7", &MediaDownloadRef{Peer: "user:1", MessageID: 1, MediaType: "video"})
	ms.Delete("key7")
	if got := ms.Get("key7"); got != nil {
		t.Fatal("Get must return nil after Delete")
	}
}
