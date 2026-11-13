package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CANARY_BASE_URL", "https://tg.example.test")
	t.Setenv("CANARY_TG_USER_ID", "11")
	t.Setenv("CANARY_BEARER_TOKEN", "")
	t.Setenv("CANARY_BEARER_TOKEN_FILE", "")
	t.Setenv("CANARY_TOKEN_SECRET_NAME", "")
}

func TestLoadConfig_TokenFile(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("CANARY_BEARER_TOKEN_FILE", writeTokenFile(t, "projected-token\n"))
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.bearerToken != "projected-token" || cfg.tokenFile == "" {
		t.Fatalf("token not read from file: %+v", cfg)
	}
}

func TestLoadConfig_TokenSourceErrors(t *testing.T) {
	cases := map[string]func(t *testing.T){
		"neither": func(t *testing.T) {},
		"both": func(t *testing.T) {
			t.Setenv("CANARY_BEARER_TOKEN", "minted")
			t.Setenv("CANARY_BEARER_TOKEN_FILE", writeTokenFile(t, "projected"))
		},
		"missing file": func(t *testing.T) {
			t.Setenv("CANARY_BEARER_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
		},
		"empty file": func(t *testing.T) {
			t.Setenv("CANARY_BEARER_TOKEN_FILE", writeTokenFile(t, " \n"))
		},
		"removed renewal switch": func(t *testing.T) {
			t.Setenv("CANARY_BEARER_TOKEN_FILE", writeTokenFile(t, "projected"))
			t.Setenv("CANARY_TOKEN_SECRET_NAME", "mctl-telegram-canary")
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			setBaseEnv(t)
			setup(t)
			if cfg, err := loadConfig(); err == nil {
				t.Fatalf("want error, got %+v", cfg)
			}
		})
	}
}

// jwtWithExp builds an unsigned-but-well-formed JWT carrying only exp. The
// canary never inspects its own token, so the content only has to differ.
func jwtWithExp(exp time.Time) string {
	payload, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	return "aGRy." + base64.RawURLEncoding.EncodeToString(payload) + ".c2ln"
}

// The projected token is rotated by kubelet in place: every run must present
// what the file holds now.
func TestRun_TokenFileIsReRead(t *testing.T) {
	var lastAuth atomic.Value
	srv := newFakeServer(t, validOAuthHandler, func(w http.ResponseWriter, r *http.Request) {
		lastAuth.Store(r.Header.Get("Authorization"))
		writeJSON(w, http.StatusOK, validMCPResponse())
	})
	defer srv.Close()

	path := writeTokenFile(t, jwtWithExp(time.Now().Add(10*time.Minute)))
	rotated := jwtWithExp(time.Now().Add(20 * time.Minute))
	cfg := &config{baseURL: srv.URL, bearerToken: "stale", tokenFile: path, tgUserID: "11", timeout: 5 * time.Second, mcpPath: "/mcp"}
	met := newCanaryMetrics()
	if err := os.WriteFile(path, []byte(rotated+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !run(context.Background(), cfg, met) {
		t.Fatal("run failed")
	}
	if got, _ := lastAuth.Load().(string); got != "Bearer "+rotated {
		t.Fatalf("run must present the rotated file token, got %q", got)
	}
}

func TestRun_UnreadableTokenFileFailsTheRun(t *testing.T) {
	cfg := &config{baseURL: "http://127.0.0.1:1", tokenFile: filepath.Join(t.TempDir(), "gone"), tgUserID: "11", timeout: 10 * time.Millisecond, mcpPath: "/mcp"}
	met := newCanaryMetrics()
	if run(context.Background(), cfg, met) {
		t.Fatal("a missing token file must fail the run")
	}
}
