package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

// testKeypair generates a fresh Ed25519 keypair for tests that need a
// device_pubkey but don't care about its actual value.
func testKeypair(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return priv, pub
}

// testSharedPub is a fixed Ed25519 public key for tests that need to pass
// something to runActivateFlow but don't care about its value.
var testSharedPub = func() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return pub
}()

// withFastPolling replaces activateSleep/activateNow with no-op/deterministic
// stand-ins for the duration of a test, so the poll loop does not wait on
// real wall-clock time.
func withFastPolling(t *testing.T) {
	t.Helper()
	origSleep, origNow := activateSleep, activateNow
	var fakeNow atomic.Int64
	fakeNow.Store(time.Now().UnixNano())
	activateSleep = func(ctx context.Context, d time.Duration) error {
		// Mirrors the real activateSleep's contract -- cancellation wins over
		// the wait -- while advancing a fake clock instead of waiting on a
		// real one. A seam that ignored ctx would let a test claim to cover
		// cancellation while covering nothing.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		fakeNow.Add(int64(d))
		return nil
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
		// Task 2's DoD: device_pubkey must be present and correctly base64
		// (standard) encoded in the outgoing request body.
		pkB64, _ := req["device_pubkey"].(string)
		if pkB64 == "" {
			t.Error("device_pubkey missing from start request")
		}
		decoded, decErr := base64.StdEncoding.DecodeString(pkB64)
		if decErr != nil {
			t.Errorf("device_pubkey is not valid standard base64: %v", decErr)
		} else if !bytes.Equal(decoded, testSharedPub) {
			t.Errorf("device_pubkey decodes to %x, want %x", decoded, []byte(testSharedPub))
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
	deviceID, err := runActivateFlow(context.Background(), &out, ts.URL, 210408407, "test-device-key", "test-laptop", testSharedPub)
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
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label", testSharedPub)
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
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label", testSharedPub)
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
	_, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label", testSharedPub)
	if !errors.Is(err, errActivationTimedOut) {
		t.Fatalf("err = %v, want errActivationTimedOut", err)
	}
}

// TestLoadOrCreateDeviceIdentity_PersistsAndReuses covers task 1's DoD and
// T25: a fresh config directory produces a keypair on first invocation, and
// a second invocation reuses the SAME keypair and device_registration_key
// (no regeneration, no rotation) rather than generating a new one.
func TestLoadOrCreateDeviceIdentity_PersistsAndReuses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	rec1, priv1, pub1, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity: %v", err)
	}
	if rec1.DeviceRegistrationKey == "" {
		t.Fatal("empty device_registration_key generated")
	}
	if len(priv1) != ed25519.PrivateKeySize {
		t.Fatalf("priv1 has length %d, want %d", len(priv1), ed25519.PrivateKeySize)
	}
	if len(pub1) != ed25519.PublicKeySize {
		t.Fatalf("pub1 has length %d, want %d", len(pub1), ed25519.PublicKeySize)
	}

	rec2, priv2, pub2, err := loadOrCreateDeviceIdentity()
	if err != nil {
		t.Fatalf("loadOrCreateDeviceIdentity (second call): %v", err)
	}
	if rec1.DeviceRegistrationKey != rec2.DeviceRegistrationKey {
		t.Errorf("device_registration_key not reused across calls: %q != %q", rec1.DeviceRegistrationKey, rec2.DeviceRegistrationKey)
	}
	if !bytes.Equal(pub1, pub2) {
		t.Errorf("public key bytes not reused across calls: %x != %x", []byte(pub1), []byte(pub2))
	}
	if !bytes.Equal(priv1, priv2) {
		t.Errorf("private key bytes not reused across calls: %x != %x", []byte(priv1), []byte(priv2))
	}

	p, err := deviceKeyFilePath()
	if err != nil {
		t.Fatalf("deviceKeyFilePath: %v", err)
	}
	info, statErr := os.Stat(p)
	if statErr != nil {
		t.Fatalf("device identity file not created at %s: %v", p, statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("device identity file has mode %04o, want 0600", got)
	}
}

// A 5xx from the server is transient: an ingress returning 502 during a
// rollout, or any temporary 500, says nothing about the activation, which
// lives on the server and is still waiting for the browser leg. The flow must
// wait it out. Before this, every non-200 was read as "expired" and the CLI
// abandoned a sign-in the user had already half-completed.
func TestRunActivateFlow_TransientServerErrorRecovers(t *testing.T) {
	withFastPolling(t)

	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-5xx", "user_code": "IIII-JJJJ",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600, "interval": 5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		switch polls.Add(1) {
		case 1:
			http.Error(w, "bad gateway", http.StatusBadGateway)
		case 2:
			http.Error(w, "internal", http.StatusInternalServerError)
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "done", "device_id": "dev_after_5xx"})
		}
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	deviceID, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label", testSharedPub)
	if err != nil {
		t.Fatalf("runActivateFlow: %v", err)
	}
	if deviceID != "dev_after_5xx" {
		t.Fatalf("device_id = %q, want dev_after_5xx", deviceID)
	}
	if got := polls.Load(); got < 3 {
		t.Fatalf("polled %d times, expected the two failures to be retried", got)
	}
}

// The same for a transport-level failure: a dropped connection, a DNS blip or
// the client timeout. The activation is untouched on the server, so the flow
// keeps polling rather than exiting.
func TestRunActivateFlow_TransientNetworkErrorRecovers(t *testing.T) {
	withFastPolling(t)

	var polls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-net", "user_code": "KKKK-LLLL",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600, "interval": 5,
		})
	})
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		if polls.Add(1) == 1 {
			// Hijack and close without a response: the client sees a
			// transport error, not an HTTP status.
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_ = conn.Close()
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "done", "device_id": "dev_after_reset"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	deviceID, err := runActivateFlow(context.Background(), &out, ts.URL, 1, "key", "label", testSharedPub)
	if err != nil {
		t.Fatalf("runActivateFlow: %v", err)
	}
	if deviceID != "dev_after_reset" {
		t.Fatalf("device_id = %q, want dev_after_reset", deviceID)
	}
}

// A cancelled context must stop the flow immediately, and must be the reason
// it stops. The cancellation is triggered from inside the poll handler rather
// than by a wall-clock sleep in a goroutine: with the fake clock advancing
// five seconds per iteration, a timer-based cancel loses the race to the
// activation's own 600-second deadline every time, and the test would pass on
// errActivationTimedOut while never exercising cancellation at all.
func TestRunActivateFlow_CancelledContextStopsRetrying(t *testing.T) {
	withFastPolling(t)

	ctx, cancel := context.WithCancel(context.Background())
	mux := http.NewServeMux()
	mux.HandleFunc("/api/local-bridge/activate/start", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"device_code": "dc-cancel", "user_code": "MMMM-NNNN",
			"verification_uri": "https://tg.test/local-bridge/activate",
			"expires_in":       600, "interval": 5,
		})
	})
	var polls atomic.Int32
	mux.HandleFunc("/api/local-bridge/activate/poll", func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		cancel() // the user hits Ctrl-C while the first poll is in flight
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	var out bytes.Buffer
	_, err := runActivateFlow(ctx, &out, ts.URL, 1, "key", "label", testSharedPub)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if got := polls.Load(); got != 1 {
		t.Fatalf("polled %d times after cancellation, want exactly 1", got)
	}
}

// The poll interval is the longest the CLI is ever idle, so a cancellation
// arriving during it must be observed then rather than one interval later.
// Exercises the real activateSleep, not the test seam.
func TestActivateSleep_ReturnsOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	started := time.Now()
	err := activateSleep(ctx, 10*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("waited %v for a cancellation that arrived after 10ms", elapsed)
	}
}
