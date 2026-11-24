// Copyright 2025 MCTL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/pa/catalog"
)

// The principals are the synthetic Alice (555) and Bob (556) of the store
// tests.
const (
	alice int64 = 555
	bob   int64 = 556
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func sha(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:])
}

const testArgs = `{"level":3}`

func testBinding() Binding {
	return Binding{
		Principal: alice, ConnectionID: "pac_1", AuthorityRevision: 5,
		Server: "alice", Tool: "alice_set_volume", Class: catalog.ClassWrite,
		SchemaSHA: sha("schema"), DescriptionSHA: sha("description"), AnnotationSHA: sha("annotations"),
		ArgsSHA: sha(testArgs), ConversationID: "pcv_1", JobID: 7,
	}
}

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNew_BindsEverythingAndExpiresInFiveMinutes(t *testing.T) {
	a, err := New(testBinding(), t0.Add(1500*time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	if a.Binding != testBinding() {
		t.Errorf("binding = %+v, want the one given", a.Binding)
	}
	if a.Status != StatusPending || a.Approver != 0 || a.SealedArgs != nil {
		t.Errorf("new approval = %+v, want pending, no approver, no arguments", a)
	}
	if !a.CreatedAt.Equal(t0.Add(time.Millisecond)) || !a.ExpiresAt.Equal(a.CreatedAt.Add(5*time.Minute)) {
		t.Errorf("created %s expires %s, want millisecond precision and +5m", a.CreatedAt, a.ExpiresAt)
	}
	ids := map[string]bool{a.ID: true, a.ApproveCallbackID: true, a.CancelCallbackID: true, a.IdempotencyKey: true}
	if len(ids) != 4 {
		t.Errorf("ids are not distinct: %+v", a)
	}
	for id := range ids {
		if len(id) != 22 {
			t.Errorf("id %q is not 128 random bits in base64url", id)
		}
	}
	b, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if b.ID == a.ID || b.IdempotencyKey == a.IdempotencyKey {
		t.Error("two approvals share an id or an idempotency key")
	}
	if _, err := New(testBinding(), time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no creation time: err = %v, want ErrInvalid", err)
	}
}

// An approval that does not bind every part is refused before it exists.
func TestBinding_ValidateNeedsEveryPart(t *testing.T) {
	if err := testBinding().Validate(); err != nil {
		t.Fatalf("the full binding: %v", err)
	}
	d := testBinding()
	d.Class = catalog.ClassDisclosure
	if err := d.Validate(); err != nil {
		t.Fatalf("a disclosure binding: %v", err)
	}
	for name, edit := range map[string]func(b *Binding){
		"principal":          func(b *Binding) { b.Principal = 0 },
		"connection":         func(b *Binding) { b.ConnectionID = "" },
		"authority revision": func(b *Binding) { b.AuthorityRevision = 0 },
		"server":             func(b *Binding) { b.Server = "" },
		"tool":               func(b *Binding) { b.Tool = "" },
		"class read":         func(b *Binding) { b.Class = catalog.ClassRead },
		"class empty":        func(b *Binding) { b.Class = "" },
		"schema hash":        func(b *Binding) { b.SchemaSHA = "" },
		"description hash":   func(b *Binding) { b.DescriptionSHA = "abc" },
		"annotation hash":    func(b *Binding) { b.AnnotationSHA = sha("x")[:63] },
		"args hash":          func(b *Binding) { b.ArgsSHA = sha("x")[:63] + "G" },
		"conversation":       func(b *Binding) { b.ConversationID = "" },
		"job id":             func(b *Binding) { b.JobID = -1 },
	} {
		b := testBinding()
		edit(&b)
		if err := b.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("without %s: err = %v, want ErrInvalid", name, err)
		}
		if _, err := New(b, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("New without %s: err = %v, want ErrInvalid", name, err)
		}
	}
}

func TestStatuses(t *testing.T) {
	open := map[Status]bool{StatusPending: true, StatusApproved: true}
	for _, s := range []Status{StatusPending, StatusApproved, StatusDispatching, StatusDone,
		StatusCancelled, StatusExpired, StatusRefused} {
		if !s.Valid() {
			t.Errorf("%q is not valid", s)
		}
		if s.Open() != open[s] {
			t.Errorf("%q: Open = %v", s, s.Open())
		}
	}
	for _, s := range []Status{"", "paused", "APPROVED"} {
		if s.Valid() || s.Open() {
			t.Errorf("%q is valid or open", s)
		}
	}
	for _, s := range []DispatchStatus{DispatchOK, DispatchToolError, DispatchRefused, DispatchFenced, DispatchOutcomeUnknown} {
		if !s.Valid() || !s.Final() {
			t.Errorf("%q: valid %v final %v, want both", s, s.Valid(), s.Final())
		}
	}
	if !DispatchDispatching.Valid() || DispatchDispatching.Final() {
		t.Error("dispatching must be valid and not final")
	}
	for _, s := range []DispatchStatus{"", "sent"} {
		if s.Valid() || s.Final() {
			t.Errorf("%q is valid or final", s)
		}
	}
}

func TestSealer_RoundTrip(t *testing.T) {
	s := testSealer(t)
	a, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(a, []byte(testArgs))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.SealedArgs, []byte("level")) {
		t.Fatal("the sealed arguments contain the plaintext")
	}
	got, err := s.Open(sealed)
	if err != nil || string(got) != testArgs {
		t.Fatalf("open = %q, %v; want the exact canonical bytes", got, err)
	}
	again, err := s.Seal(a, []byte(testArgs))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again.SealedArgs, sealed.SealedArgs) {
		t.Error("two seals of the same arguments are identical: the nonce repeats")
	}
}

// What is sealed is exactly what the hash names: bytes that are not
// canonical, or that hash to something else, never enter a row.
func TestSealer_SealRefusesWhatTheHashDoesNotName(t *testing.T) {
	s := testSealer(t)
	a, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	other := a
	other.ArgsSHA = sha(`{"level":4}`)
	noID := a
	noID.ID = ""
	spaced := a
	spaced.ArgsSHA = sha(`{"level": 3}`)
	big := bytes.Repeat([]byte("a"), MaxArgsBytes+1)
	cases := map[string]struct {
		a    Approval
		args []byte
	}{
		"other arguments than the hash":   {other, []byte(testArgs)},
		"not canonical, hash of the form": {spaced, []byte(`{"level": 3}`)},
		"not JSON":                        {a, []byte("level=3")},
		"empty":                           {a, nil},
		"too large":                       {a, big},
		"no approval id":                  {noID, []byte(testArgs)},
	}
	for name, c := range cases {
		got, err := s.Seal(c.a, c.args)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
		if got.SealedArgs != nil {
			t.Errorf("%s: a refused seal returned a blob", name)
		}
	}
}

// A blob opens only as what it was sealed as: for that principal, that
// approval and that argument hash. Anything else is unreadable, never
// arguments and never "no arguments".
func TestSealer_OpenIsBoundToTheApproval(t *testing.T) {
	s := testSealer(t)
	a, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(a, []byte(testArgs))
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := NewSealer(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) Approval {
		c := sealed
		c.SealedArgs = append([]byte(nil), sealed.SealedArgs...)
		c.SealedArgs[i] ^= 1
		return c
	}
	edit := func(fn func(c *Approval)) Approval {
		c := sealed
		fn(&c)
		return c
	}
	cases := map[string]struct {
		s *Sealer
		a Approval
	}{
		"another principal":   {s, edit(func(c *Approval) { c.Principal = bob })},
		"another approval id": {s, edit(func(c *Approval) { c.ID = NewID() })},
		"another args hash":   {s, edit(func(c *Approval) { c.ArgsSHA = sha(`{"level":4}`) })},
		"another master key":  {otherKey, sealed},
		"a flipped body bit":  {s, flip(len(sealed.SealedArgs) - 1)},
		"a flipped nonce bit": {s, flip(1)},
		"another version":     {s, flip(0)},
		"truncated":           {s, edit(func(c *Approval) { c.SealedArgs = c.SealedArgs[:5] })},
		"no blob":             {s, edit(func(c *Approval) { c.SealedArgs = nil })},
		"no approval id":      {s, edit(func(c *Approval) { c.ID = "" })},
	}
	for name, c := range cases {
		got, err := c.s.Open(c.a)
		if !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: err = %v, want ErrUnreadable", name, err)
		}
		if got != nil {
			t.Errorf("%s: a refused open returned bytes", name)
		}
	}
}

func TestSealer_Key(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewSealer(make([]byte, n)); !errors.Is(err, ErrSealerKey) {
			t.Errorf("%d-byte key: err = %v, want ErrSealerKey", n, err)
		}
	}
	var none *Sealer
	a, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := none.Seal(a, []byte(testArgs)); !errors.Is(err, ErrInvalid) {
		t.Errorf("seal without a sealer: err = %v, want ErrInvalid", err)
	}
	if _, err := none.Open(a); !errors.Is(err, ErrInvalid) {
		t.Errorf("open without a sealer: err = %v, want ErrInvalid", err)
	}
	// The key is copied: the caller zeroing its buffer does not change it.
	master := bytes.Repeat([]byte{7}, 32)
	s, err := NewSealer(master)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := s.Seal(a, []byte(testArgs))
	if err != nil {
		t.Fatal(err)
	}
	clear(master)
	if _, err := s.Open(sealed); err != nil {
		t.Errorf("open after the caller cleared its key buffer: %v", err)
	}
}

// TestSealer_Detail: card detail is sealed with the arguments, comes back
// only through OpenWithDetail, and a blob of one version never opens as
// the other.
func TestSealer_Detail(t *testing.T) {
	s := testSealer(t)
	a, err := New(testBinding(), t0)
	if err != nil {
		t.Fatal(err)
	}
	const detail = `{"speaker":{"id":"spk-kitchen-0001","name":"Kitchen speaker"}}`
	sealed, err := s.SealWithDetail(a, []byte(testArgs), []byte(detail))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.SealedArgs, []byte("Kitchen")) || bytes.Contains(sealed.SealedArgs, []byte("level")) {
		t.Fatal("the sealed blob contains plaintext")
	}
	args, got, err := s.OpenWithDetail(sealed)
	if err != nil || string(args) != testArgs || string(got) != detail {
		t.Fatalf("open with detail = %q, %q, %v", args, got, err)
	}
	// Open gives the arguments and nothing of the detail.
	if only, err := s.Open(sealed); err != nil || string(only) != testArgs {
		t.Fatalf("open = %q, %v", only, err)
	}
	// An approval sealed without detail has none.
	plain, err := s.Seal(a, []byte(testArgs))
	if err != nil {
		t.Fatal(err)
	}
	if args, got, err := s.OpenWithDetail(plain); err != nil || string(args) != testArgs || got != nil {
		t.Fatalf("open of a blob without detail = %q, %q, %v", args, got, err)
	}
	// The version byte is authenticated: neither blob opens as the other.
	for name, blob := range map[string][]byte{"detail as plain": sealed.SealedArgs, "plain as detail": plain.SealedArgs} {
		flipped := sealed
		flipped.SealedArgs = bytes.Clone(blob)
		flipped.SealedArgs[0] ^= 0x03
		if _, _, err := s.OpenWithDetail(flipped); !errors.Is(err, ErrUnreadable) {
			t.Errorf("%s: err = %v, want ErrUnreadable", name, err)
		}
	}
	// The detail is bound like the arguments.
	other := sealed
	other.ID = "pap_other"
	if _, _, err := s.OpenWithDetail(other); !errors.Is(err, ErrUnreadable) {
		t.Errorf("another approval's blob: err = %v, want ErrUnreadable", err)
	}
	for name, d := range map[string][]byte{"empty": nil, "too large": bytes.Repeat([]byte("a"), MaxDetailBytes+1)} {
		if got, err := s.SealWithDetail(a, []byte(testArgs), d); !errors.Is(err, ErrInvalid) || got.SealedArgs != nil {
			t.Errorf("%s detail: err = %v, blob %v", name, err, got.SealedArgs != nil)
		}
	}
}
