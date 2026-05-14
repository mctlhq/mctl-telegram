// Package telegramwidget verifies the signed payload that the Telegram Login
// Widget delivers to a website after a user confirms login in the Telegram
// app. Spec: https://core.telegram.org/widgets/login#checking-authorization
//
// The widget POSTs (or appends to a redirect URL) the fields:
//   - id              numeric Telegram user id
//   - first_name      (optional)
//   - last_name       (optional)
//   - username        (optional)
//   - photo_url       (optional)
//   - auth_date       unix seconds when Telegram signed the payload
//   - hash            hex HMAC-SHA256 over the data-check-string
//
// The verification algorithm:
//  1. Take every field except `hash`, sort by key, join as "key=value\n"
//     (no trailing newline) — that is the "data-check-string".
//  2. secret_key = SHA256(bot_token)
//  3. expected_hash = HMAC-SHA256(data-check-string, secret_key)
//  4. Compare with the supplied `hash` constant-time.
//  5. Reject if auth_date is older than maxAge (default 24h).
//
// The bot must have been registered with @BotFather via /setdomain so Telegram
// is willing to issue widget callbacks back to our domain.
package telegramwidget

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxAge bounds how long a signed widget payload is acceptable. Telegram
// stamps auth_date at sign time; replaying a stale payload is rejected after
// this window. 24h matches Telegram's own recommendation.
const DefaultMaxAge = 24 * time.Hour

// Payload is the parsed Telegram Login Widget callback. All optional fields
// may be empty; only ID and AuthDate are guaranteed non-zero after Verify.
type Payload struct {
	ID        int64
	FirstName string
	LastName  string
	Username  string
	PhotoURL  string
	AuthDate  int64
}

// Verifier holds the static configuration for HMAC verification. Construct
// once and reuse for every widget callback.
type Verifier struct {
	// secretKey is SHA-256(bot_token); precomputed so we don't hash on every
	// request. bot_token never leaves this struct.
	secretKey []byte
	// MaxAge caps how old auth_date can be before the payload is rejected.
	// Zero means DefaultMaxAge.
	MaxAge time.Duration
	// now returns the current time. Test-injectable.
	now func() time.Time
}

// New constructs a Verifier for the given bot token. The token is the value
// @BotFather hands out (digits:letters). It is hashed once and held as a
// fixed-size key — the caller's copy may be zeroed afterward without
// affecting verification.
func New(botToken string) (*Verifier, error) {
	if botToken == "" {
		return nil, errors.New("telegramwidget: bot token required")
	}
	sum := sha256.Sum256([]byte(botToken))
	return &Verifier{
		secretKey: sum[:],
		MaxAge:    DefaultMaxAge,
		now:       time.Now,
	}, nil
}

// Verify takes the raw callback fields as-received (typically url.Values from
// a GET/POST). The supplied map is treated as immutable; Verify does not
// modify it. Returns the parsed Payload on success.
//
// Required fields: "id", "auth_date", "hash". Every other key with a non-empty
// value contributes to the data-check-string, including custom fields Telegram
// may add in the future — verification stays forward-compatible.
func (v *Verifier) Verify(fields map[string]string) (*Payload, error) {
	if v == nil {
		return nil, errors.New("telegramwidget: nil verifier")
	}
	hashHex, ok := fields["hash"]
	if !ok || hashHex == "" {
		return nil, errors.New("telegramwidget: missing hash field")
	}
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return nil, fmt.Errorf("telegramwidget: hash is not valid hex: %w", err)
	}

	// Build data-check-string from every non-empty, non-hash field in
	// alphabetical key order. Empty values are skipped per Telegram spec —
	// the widget never sends a key with an empty value, but operators may
	// pre-strip them when forwarding through their own infrastructure.
	keys := make([]string, 0, len(fields))
	for k, val := range fields {
		if k == "hash" || val == "" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(fields[k])
	}

	mac := hmac.New(sha256.New, v.secretKey)
	mac.Write([]byte(b.String()))
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, hashBytes) {
		return nil, errors.New("telegramwidget: hash mismatch — payload was tampered with or signed by a different bot")
	}

	// Required fields are present and correctly typed.
	idStr := fields["id"]
	if idStr == "" {
		return nil, errors.New("telegramwidget: missing id field")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		return nil, fmt.Errorf("telegramwidget: id is not a positive integer: %q", idStr)
	}
	authDateStr := fields["auth_date"]
	if authDateStr == "" {
		return nil, errors.New("telegramwidget: missing auth_date field")
	}
	authDate, err := strconv.ParseInt(authDateStr, 10, 64)
	if err != nil || authDate <= 0 {
		return nil, fmt.Errorf("telegramwidget: auth_date is not a positive integer: %q", authDateStr)
	}
	maxAge := v.MaxAge
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	now := v.now()
	age := now.Sub(time.Unix(authDate, 0))
	if age > maxAge {
		return nil, fmt.Errorf("telegramwidget: auth_date is %s old, exceeds max age %s", age.Truncate(time.Second), maxAge)
	}
	// Reject obviously-future timestamps (allow a small clock-skew window so
	// minor pod/Telegram drift does not cause spurious 401s).
	if age < -5*time.Minute {
		return nil, fmt.Errorf("telegramwidget: auth_date is in the future by %s", (-age).Truncate(time.Second))
	}

	return &Payload{
		ID:        id,
		FirstName: fields["first_name"],
		LastName:  fields["last_name"],
		Username:  fields["username"],
		PhotoURL:  fields["photo_url"],
		AuthDate:  authDate,
	}, nil
}
