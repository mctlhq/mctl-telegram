package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// withFastPolling replaces activateSleep/activateNow with no-op/deterministic
// stand-ins for the duration of a test, so the poll loop does not wait on
// real wall-clock time.
func withFastPolling(t *testing.T) {
	t.Helper()
	origSleep, origNow := activateSleep, activateNow
	var fakeNow atomic.Int64
	fakeNow.Store(time.Now().UnixNano())
	activateSleep = func(d time.Duration) {
		fakeNow.Add(int64(d))
	}
	activateNow = func() time.Time {
		return time.Unix(0, fakeNow.Load())
	}
	t.Cleanup(func() {
		activateSleep = origSleep
		activateNow = origNow
	})
}

func TestRunActivateFlow_HappyPath(t *testing.T) {
	withFastPolling(t)

	var polls int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode start request: %v", err)
		}
		if req["telegram_id"] != float64(210408407) {
			t.Errorf("telegram_id = %v, want 210408407", req["telegram_id"])
		}
		if req["device_registration_key"] == "" || req["device_registration_key"] == nil {
			t.Error("device_registration_key missing from start request")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code":      "dc-happy",
			"user_code":        "AAAA-BBBB",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600,
			"interval":         5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		polls++
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["device_code"] != "dc-happy" {
			t.Errorf("poll device_code = %q, want dc-happy", req["device_code"])
		}
		if polls < 3 {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "done", "device_id": "dev_abc123"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	deviceID, err := runActivateFlow(context.Background(), &out, ts.URL, 210408407, "test-device-key", "test-laptop")
	if err != nil {
		t.Fatalf("runActivateFlow: %v", err)
	}
	if deviceID != "dev_abc123" {
		t.Errorf("device_id = %q, want dev_abc123", deviceID)
	}
	if polls < 3 {
		t.Errorf("polls = %d, want at least 3 (pending, pending, done)", polls)
	}

	printed := out.String()
	if !strings.Contains(printed, "AAAA-BBBB") {
		t.Errorf("output did not print the user_code: %q", printed)
	}
	if !strings.Contains(printed, "https://tg.test/local-bridge/activate") {
		t.Errorf("output did not print the verification_uri: %q", printed)
	}
	// The whole point of the user_code is that it never appears embedded in
	// a URL — assert no printed line concatenates the two.
	for _, line := range strings.Split(printed, "\n") {
		if strings.Contains(line, "AAAA-BBBB") && strings.Contains(line, "http") {
			t.Errorf("a printed line combines the user_code with a URL: %q", line)
		}
	}
}

func TestRunActivateFlow_Denied(t *testing.T) {
	withFastPolling(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-denied", "user_code": "CCCC-DDDD",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600, "interval": 5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "denied", "reason": "telegram account mismatch"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label")
	if !errors.Is(err, errActivationDenied) {
		t.Fatalf("err = %v, want errActivationDenied", err)
	}
	if !strings.Contains(err.Error(), "telegram account mismatch") {
		t.Errorf("error does not carry the server's reason: %v", err)
	}
}

func TestRunActivateFlow_TimesOut(t *testing.T) {
	withFastPolling(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-timeout", "user_code": "EEEE-FFFF",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       1, // 1 second -- the fake clock advances past this on the first sleep
			"interval":         5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label")
	if !errors.Is(err, errActivationTimedOut) {
		t.Fatalf("err = %v, want errActivationTimedOut", err)
	}
}

func TestRunActivateFlow_UnknownDeviceCodeReportsExpired(t *testing.T) {
	withFastPolling(t)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-expired", "user_code": "GGGG-HHHH",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600, "interval": 5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"unknown or expired device_code"}`, http.StatusBadRequest)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label")
	if !errors.Is(err, errActivationTimedOut) {
		t.Fatalf("err = %v, want errActivationTimedOut", err)
	}
}

func TestLoadOrCreateDeviceKey_PersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	key1, err := loadOrCreateDeviceKey()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceKey: %v", err)
	}
	if key1 == "" {
		t.Fatal("empty device key generated")
	}
	key2, err := loadOrCreateDeviceKey()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceKey (second call): %v", err)
	}
	if key1 != key2 {
		t.Errorf("device key not reused across calls: %q != %q", key1, key2)
	}

	p, err := deviceKeyFilePath()
	if err != nil {
		t.Fatalf("deviceKeyFilePath: %v", err)
	}
	if _, statErr := os.Stat(p); statErr != nil {
		t.Errorf("device key file not created at %s: %v", p, statErr)
	}
}
