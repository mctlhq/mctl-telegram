package mcp

import (
	"sync"
	"time"
)

// MediaDownloadRef holds the server-side file location context for a pending
// get_media call. The client never sees AccessHash or FileReference — only the
// confirmation_id handle. Stored in MediaStore, keyed by confirmation_id.
type MediaDownloadRef struct {
	Peer          string
	MessageID     int
	MediaType     string
	MimeType      string
	FileName      string
	Size          int64
	IsDocument    bool
	DocID         int64
	AccessHash    int64
	FileReference []byte
	// Photo-only fields:
	PhotoID   int64
	ThumbSize string // e.g. "m" — largest available *tg.PhotoSize type code
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
