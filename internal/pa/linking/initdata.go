package linking

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// InitData is the verified part of a Mini App initData string. Only
// VerifyInitData builds one, so holding an InitData means its HMAC checked
// out against the bot token it was verified with.
type InitData struct {
	UserID     int64
	FirstName  string
	Username   string
	StartParam string
	AuthDate   time.Time
}

// Errors of VerifyInitData. None carries the input.
var (
	ErrInitDataMissing   = errors.New("pa linking: no raw initData")
	ErrInitDataMalformed = errors.New("pa linking: malformed initData")
	ErrInitDataSignature = errors.New("pa linking: initData signature does not verify")
	ErrInitDataExpired   = errors.New("pa linking: initData too old")
)

const (
	// maxInitData bounds the raw string; real initData is well under 1 KiB.
	maxInitData = 4096
	// initDataMaxAge is T1 step 1's auth_date limit.
	initDataMaxAge = 5 * time.Minute
	// initDataSkew tolerates a client clock slightly ahead of ours.
	initDataSkew = 30 * time.Second
)

// VerifyInitData checks a raw Mini App initData string against botToken
// (the Bot API Mini App rules): the data-check-string is every field but
// hash, sorted by key and joined as key=value with "\n"; the secret key is
// HMAC-SHA256(key "WebAppData", botToken); hash must equal
// HMAC-SHA256(secret key, data-check-string) in hex. auth_date must be no
// older than five minutes at now.
//
// Only the raw string is ever accepted. initDataUnsafe is the client's own
// parse of it and carries no signature, so nothing here takes it (S1-L1).
// A duplicated key is malformed, so a client cannot smuggle a second
// user or start_param past the signature.
func VerifyInitData(raw, botToken string, now time.Time) (InitData, error) {
	if raw == "" {
		return InitData{}, ErrInitDataMissing
	}
	if len(raw) > maxInitData || botToken == "" {
		return InitData{}, ErrInitDataMalformed
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		return InitData{}, ErrInitDataMalformed
	}
	got := ""
	keys := make([]string, 0, len(vals))
	for k, v := range vals {
		if len(v) != 1 {
			return InitData{}, ErrInitDataMalformed
		}
		if k == "hash" {
			got = v[0]
			continue
		}
		keys = append(keys, k)
	}
	gotMAC, err := hex.DecodeString(got)
	if err != nil || len(gotMAC) != sha256.Size {
		return InitData{}, ErrInitDataMalformed
	}
	sort.Strings(keys)
	lines := make([]string, len(keys))
	for i, k := range keys {
		lines[i] = k + "=" + vals[k][0]
	}
	if !hmac.Equal(gotMAC, initDataMAC(botToken, strings.Join(lines, "\n"))) {
		return InitData{}, ErrInitDataSignature
	}

	authSec, err := strconv.ParseInt(vals.Get("auth_date"), 10, 64)
	if err != nil || authSec <= 0 {
		return InitData{}, ErrInitDataMalformed
	}
	auth := time.Unix(authSec, 0).UTC()
	if now.Sub(auth) > initDataMaxAge || auth.Sub(now) > initDataSkew {
		return InitData{}, ErrInitDataExpired
	}
	var user struct {
		ID        int64  `json:"id"`
		IsBot     bool   `json:"is_bot"`
		FirstName string `json:"first_name"`
		Username  string `json:"username"`
	}
	if err := json.Unmarshal([]byte(vals.Get("user")), &user); err != nil || user.ID <= 0 || user.IsBot {
		return InitData{}, fmt.Errorf("%w: no human user", ErrInitDataMalformed)
	}
	return InitData{
		UserID: user.ID, FirstName: user.FirstName, Username: user.Username,
		StartParam: vals.Get("start_param"), AuthDate: auth,
	}, nil
}

func initDataMAC(botToken, dataCheck string) []byte {
	k := hmac.New(sha256.New, []byte("WebAppData"))
	k.Write([]byte(botToken))
	m := hmac.New(sha256.New, k.Sum(nil))
	m.Write([]byte(dataCheck))
	return m.Sum(nil)
}
