package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeDevicePoPServer builds an httptest server implementing /nonce,
// /credential and /refresh well enough to exercise bootstrapDeviceCredential
// and refreshDeviceCredential without depending on internal/oauth. It
// verifies the PoP signature exactly the way the real server does, so a test
// using the wrong private key fails realistically rather than by accident.
type fakeDevicePoPServer struct {
	pub ed25519.PublicKey

	// credentialStatus/credentialBody, if set, override the default
	// first-issuance behavior (always 200 on first call, 409 thereafter).
	credentialCalls  atomic.Int32
	credentialStatus func(call int32) int
	credentialBody   func(call int32) []byte

	refreshCalls  atomic.Int32
	refreshStatus func(call int32) int
	refreshBody   func(call int32) []byte

	lastNonce atomic.Value // string
}

func newFakeDevicePoPServer(pub ed25519.PublicKey) *fakeDevicePoPServer {
	s := &fakeDevicePoPServer{pub: pub}
	s.lastNonce.Store("")
	return s
}

func (s *fakeDevicePoPServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/devices/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/local-bridge/devices/")
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			http.Error(w, "bad path", http.StatusNotFound)
			return
		}
		action := parts[1]
		switch action {
		case "nonce":
			nonce := "nonce-" + strconv.FormatInt(time.Now().UnixNano(), 10)
			s.lastNonce.Store(nonce)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"nonce": nonce, "expires_in": 60})
		case "credential":
			call := s.credentialCalls.Add(1)
			if !s.verifyPoP(w, r, parts[0]) {
				return
			}
			status := http.StatusOK
			if s.credentialStatus != nil {
				status = s.credentialStatus(call)
			} else if call > 1 {
				status = http.StatusConflict
			}
			s.writeCredentialResponse(w, call, status, s.credentialBody)
		case "refresh":
			call := s.refreshCalls.Add(1)
			if !s.verifyPoP(w, r, parts[0]) {
				return
			}
			status := http.StatusOK
			if s.refreshStatus != nil {
				status = s.refreshStatus(call)
			}
			s.writeCredentialResponse(w, call, status, s.refreshBody)
		default:
			http.Error(w, "unknown action", http.StatusNotFound)
		}
	})
	return mux
}

func (s *fakeDevicePoPServer) verifyPoP(w http.ResponseWriter, r *http.Request, deviceID string) bool {
	var req devicePoPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		http.Error(w, "bad signature encoding", http.StatusForbidden)
		return false
	}
	msg := []byte(deviceID + "." + req.Nonce)
	if !ed25519.Verify(s.pub, msg, sig) {
		http.Error(w, "invalid or revoked device", http.StatusForbidden)
		return false
	}
	return true
}

func (s *fakeDevicePoPServer) writeCredentialResponse(w http.ResponseWriter, call int32, status int, bodyFn func(int32) []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if bodyFn != nil {
		_, _ = w.Write(bodyFn(call))
		return
	}
	if status != http.StatusOK {
		_, _ = w.Write([]byte(`{"error":"conflict"}`))
		return
	}
	_ = json.NewEncoder(w).Encode(deviceCredentialResponse{
		WorkerToken: "hdr." + strconv.Itoa(int(call)) + ".sig",
		ExpiresAt:   time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339),
		Jti:         "jti-" + strconv.Itoa(int(call)),
	})
}

// TestBootstrapDeviceCredential_HappyPath covers task 3's DoD: a 200 from
// /credential is persisted to the device record with device_id/worker_token/
// expires_at/jti all populated.
func TestBootstrapDeviceCredential_HappyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	srv := newFakeDevicePoPServer(pub)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	if err := bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub); err != nil {
		t.Fatalf("bootstrapDeviceCredential: %v", err)
	}

	rec, err := readDeviceRecord()
	if err != nil {
		t.Fatalf("readDeviceRecord: %v", err)
	}
	if rec.DeviceID != "dev1" {
		t.Errorf("device_id = %q, want dev1", rec.DeviceID)
	}
	if !deviceCredentialUsable(rec) {
		t.Errorf("record not usable after bootstrap: %+v", rec)
	}
}

// TestBootstrapDeviceCredential_SecondRunIsNoOp covers T10: a second
// activate run against a device that already has a usable credential for
// the SAME device_id exits 0 (no error) without re-minting -- the server's
// 409 is handled as success.
func TestBootstrapDeviceCredential_SecondRunIsNoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	srv := newFakeDevicePoPServer(pub)
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	if err := bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub); err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	recAfterFirst, _ := readDeviceRecord()

	// Second call: credentialCalls will be 2, defaulting to 409 -- the
	// record already carries a usable credential for dev1, so this must be
	// a no-op success with no /refresh call at all.
	if err := bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub); err != nil {
		t.Fatalf("second bootstrap (expected no-op success): %v", err)
	}
	if srv.refreshCalls.Load() != 0 {
		t.Errorf("refresh was called %d times, want 0 -- already-usable credential must short-circuit", srv.refreshCalls.Load())
	}
	recAfterSecond, _ := readDeviceRecord()
	if recAfterFirst.WorkerToken != recAfterSecond.WorkerToken {
		t.Error("credential was re-minted on a no-op second run")
	}
}

// TestBootstrapDeviceCredential_409RepairsHalfClaimedLineage is table-driven
// over T15's stored-credential shapes: absent, empty, truncated, invalid
// JSON, missing device_id, unusable-but-later-expiring, and usable-but-
// naming-a-different-device-with-a-later-expiry. Every case must recover via
// /refresh and end with daemon-startable state.
func TestBootstrapDeviceCredential_409RepairsHalfClaimedLineage(t *testing.T) {
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)

	cases := []struct {
		name string
		seed *deviceRecord // nil means "don't write a credential at all"
	}{
		{name: "absent credential", seed: nil},
		{name: "empty credential fields", seed: &deviceRecord{}},
		{
			name: "truncated worker_token (not a 3-segment JWT)",
			seed: &deviceRecord{DeviceID: "dev1", WorkerToken: "nota.jwt", ExpiresAt: future, Jti: "j"},
		},
		{
			name: "missing device_id",
			seed: &deviceRecord{WorkerToken: "a.b.c", ExpiresAt: future, Jti: "j"},
		},
		{
			name: "unusable but later expires_at",
			seed: &deviceRecord{DeviceID: "dev1", WorkerToken: "not-a-jwt", ExpiresAt: future, Jti: "j"},
		},
		{
			name: "usable but names a DIFFERENT device with a later expiry",
			seed: &deviceRecord{DeviceID: "some-earlier-device", WorkerToken: "a.b.c", ExpiresAt: future, Jti: "j"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("HOME", dir)

			_, priv, pub, err := loadOrCreateDeviceIdentity()
			if err != nil {
				t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
			}
			if tc.seed != nil {
				rec, rerr := readDeviceRecord()
				if rerr != nil {
					t.Fatalf("readDeviceRecord: %v", rerr)
				}
				rec.DeviceID = tc.seed.DeviceID
				rec.WorkerToken = tc.seed.WorkerToken
				rec.ExpiresAt = tc.seed.ExpiresAt
				rec.Jti = tc.seed.Jti
				if err := writeDeviceRecord(rec); err != nil {
					t.Fatalf("seed record: %v", err)
				}
			}

			srv := newFakeDevicePoPServer(pub)
			// Force /credential to always answer 409, simulating a lineage
			// the server considers already claimed for "dev1".
			srv.credentialStatus = func(int32) int { return http.StatusConflict }
			ts := httptest.NewServer(srv.handler())
			defer ts.Close()

			if err := bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub); err != nil {
				t.Fatalf("bootstrapDeviceCredential: %v", err)
			}
			if srv.refreshCalls.Load() != 1 {
				t.Errorf("refresh called %d times, want exactly 1", srv.refreshCalls.Load())
			}

			rec, err := readDeviceRecord()
			if err != nil {
				t.Fatalf("readDeviceRecord: %v", err)
			}
			if rec.DeviceID != "dev1" {
				t.Errorf("device_id = %q, want dev1 after repair", rec.DeviceID)
			}
			if !deviceCredentialUsable(rec) {
				t.Errorf("record not usable after repair: %+v", rec)
			}
		})
	}
}

// TestBootstrapDeviceCredential_409WithUsableSameDeviceCredentialIsNoOp
// covers the other half of T10/T15's split: a 409 where a usable credential
// for the SAME device already exists is a no-op success with no /refresh
// call.
func TestBootstrapDeviceCredential_409WithUsableSameDeviceCredentialIsNoOp(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	future := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := mergeDeviceCredential(pub, "dev1", "a.b.c", future, "jti-existing"); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	srv := newFakeDevicePoPServer(pub)
	srv.credentialStatus = func(int32) int { return http.StatusConflict }
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	if err := bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub); err != nil {
		t.Fatalf("bootstrapDeviceCredential: %v", err)
	}
	if srv.refreshCalls.Load() != 0 {
		t.Errorf("refresh called %d times, want 0", srv.refreshCalls.Load())
	}
	rec, _ := readDeviceRecord()
	if rec.Jti != "jti-existing" {
		t.Errorf("existing usable credential was disturbed: jti = %q", rec.Jti)
	}
}

// TestBootstrapDeviceCredential_RefreshFailureDuring409RepairFailsLoudly
// covers T19: if the repair path's /refresh answers 500, activate must exit
// non-zero (return an error) and write NO credential file.
func TestBootstrapDeviceCredential_RefreshFailureDuring409RepairFailsLoudly(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	srv := newFakeDevicePoPServer(pub)
	srv.credentialStatus = func(int32) int { return http.StatusConflict }
	srv.refreshStatus = func(int32) int { return http.StatusInternalServerError }
	srv.refreshBody = func(int32) []byte { return []byte(`{"error":"internal error"}`) }
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	err = bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub)
	if err == nil {
		t.Fatal("expected an error when the repair refresh fails, got nil")
	}

	rec, rerr := readDeviceRecord()
	if rerr != nil {
		t.Fatalf("readDeviceRecord: %v", rerr)
	}
	if rec.DeviceID != "" || rec.WorkerToken != "" {
		t.Errorf("a credential file was written despite the failing repair: %+v", rec)
	}
}

// TestBootstrapDeviceCredential_OtherFailureReportsActivatedButRetryable
// covers the "any other failure" branch: a non-200, non-409 status from
// /credential must not write a credential file and must return an error
// naming the device as activated and the step as retryable.
func TestBootstrapDeviceCredential_OtherFailureReportsActivatedButRetryable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	_, priv, pub, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}

	srv := newFakeDevicePoPServer(pub)
	srv.credentialStatus = func(int32) int { return http.StatusInternalServerError }
	ts := httptest.NewServer(srv.handler())
	defer ts.Close()

	err = bootstrapDeviceCredential(context.Background(), ts.URL, "dev1", priv, pub)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "dev1") || !strings.Contains(err.Error(), "retried") {
		t.Errorf("error does not name the device as activated and retryable: %v", err)
	}

	rec, _ := readDeviceRecord()
	if rec.DeviceID != "" {
		t.Errorf("a credential file was written despite the failure: %+v", rec)
	}
}
