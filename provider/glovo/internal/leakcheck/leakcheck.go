// Package leakcheck scans captured bytes for canary secrets.
package leakcheck

import (
	"bytes"
	"sync"
)

var Canaries = []string{"canary-session-token-7f3a", "canary-address-9 Fake Street", "canary-cart-note"}

// Recorder remembers every blob it is shown and reports canary hits.
type Recorder struct {
	mu   sync.Mutex
	Seen [][]byte
}

func (r *Recorder) Add(b []byte) {
	r.mu.Lock()
	r.Seen = append(r.Seen, append([]byte(nil), b...))
	r.mu.Unlock()
}

func Find(b []byte) []string {
	var hits []string
	for _, c := range Canaries {
		if bytes.Contains(b, []byte(c)) {
			hits = append(hits, c)
		}
	}
	return hits
}

func (r *Recorder) Hits() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, b := range r.Seen {
		out = append(out, Find(b)...)
	}
	return out
}

// Len reports how many payloads were recorded.
func (r *Recorder) Len() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.Seen) }
