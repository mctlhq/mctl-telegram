package mcp

import (
	"sync"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/telegram"
)

// MediaDownloadRef holds the server-side file location context for a pending
// get_media call. The client never sees the Location internals (AccessHash,
// FileReference) — only the confirmation_id handle. Stored in MediaStore,
// keyed by confirmation_id.
type MediaDownloadRef struct {
	Peer      string
	MessageID int
	MediaType string
	MimeType  string
	FileName  string
	Size      int64
	Location  telegram.MediaFileLocation
	ExpiresAt time.Time
}

// MediaStore is a tiny in-memory TTL map keyed by confirmation_id.
type MediaStore struct {
	mu  sync.Mutex
	m   map[string]*MediaDownloadRef
	now func() time.Time
	ttl time.Duration
}

func NewMediaStore() *MediaStore {
	return &MediaStore{
		m:   map[string]*MediaDownloadRef{},
		now: time.Now,
		ttl: ConfirmationTTL,
	}
}

// Set stores ref under key. Any previous entry for key is overwritten.
func (ms *MediaStore) Set(key string, ref *MediaDownloadRef) {
	ref.ExpiresAt = ms.now().Add(ms.ttl)
	ms.mu.Lock()
	ms.m[key] = ref
	ms.mu.Unlock()
}

// Pop atomically retrieves and deletes the entry. Returns nil when key is
// absent or expired.
func (ms *MediaStore) Pop(key string) *MediaDownloadRef {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ref, ok := ms.m[key]
	if !ok {
		return nil
	}
	delete(ms.m, key)
	if ms.now().After(ref.ExpiresAt) {
		return nil
	}
	return ref
}

// Get returns the ref without removing it from the store. Returns nil when key is
// absent or the entry has expired. Used by get_media alongside Claim/Finalize so the
// ref persists until the download completes.
func (ms *MediaStore) Get(key string) *MediaDownloadRef {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ref, ok := ms.m[key]
	if !ok {
		return nil
	}
	if ms.now().After(ref.ExpiresAt) {
		return nil
	}
	return ref
}

// Delete removes the entry for key unconditionally. No-op if the key is absent.
// Called via defer in toolGetMedia alongside Finalize to release the media ref after
// the download terminates.
func (ms *MediaStore) Delete(key string) {
	ms.mu.Lock()
	delete(ms.m, key)
	ms.mu.Unlock()
}

// Sweep removes expired entries.
func (ms *MediaStore) Sweep() int {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	now := ms.now()
	n := 0
	for k, ref := range ms.m {
		if now.After(ref.ExpiresAt) {
			delete(ms.m, k)
			n++
		}
	}
	return n
}
