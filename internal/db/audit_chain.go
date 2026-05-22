package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"hash"
	"time"
)

// hashAuditEntry computes the canonical SHA-256 over the fixed-order
// fields of one audit row, chained with prev. The encoding is "field
// length || field bytes" for every variable-length field so two adjacent
// (peer || status) strings cannot collide with a single longer (peer)
// string. Integer fields are big-endian to be platform-independent.
//
// Field order (frozen — changing this invalidates every existing chain):
//  1. prev_hash bytes
//  2. user_id BE64
//  3. tool_name (len-prefixed)
//  4. peer_redacted (len-prefixed)
//  5. status (len-prefixed)
//  6. error (len-prefixed)
//  7. created_at unix-nanos BE64
//  8. call_path (len-prefixed) — appended ONLY when callPath.Valid (M4+ rows).
//     Rows written before the M4 call_path column was added have a NULL
//     call_path and were hashed over fields 1–7 only; omitting the field
//     here for NULL keeps those pre-M4 chains valid after the column lands.
func hashAuditEntry(prev []byte, userID int64, tool, peer, status, errCol string, callPath sql.NullString, createdAt time.Time) []byte {
	h := sha256.New()
	h.Write(prev)
	writeBE64(h, uint64(userID))
	writeLenPrefixed(h, []byte(tool))
	writeLenPrefixed(h, []byte(peer))
	writeLenPrefixed(h, []byte(status))
	writeLenPrefixed(h, []byte(errCol))
	writeBE64(h, uint64(createdAt.UTC().UnixNano()))
	if callPath.Valid {
		writeLenPrefixed(h, []byte(callPath.String))
	}
	return h.Sum(nil)
}

func writeBE64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	h.Write(b[:])
}

func writeLenPrefixed(h hash.Hash, p []byte) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(p)))
	h.Write(b[:])
	h.Write(p)
}
