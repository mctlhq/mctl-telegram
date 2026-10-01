package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mctlhq/mctl-telegram/internal/bot"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/metrics"
)

func TestMountBotStartBridge(t *testing.T) {
	ctx := context.Background()
	conn, err := db.Open(ctx, "file:"+t.Name()+"?mode=memory&cache=shared", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := db.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	store := db.NewStore(conn, nil)
	m := metrics.New()

	post := func(mux http.Handler) int {
		req := httptest.NewRequest(http.MethodPost, bot.BotStartObservationPath, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	// Unset: not configured, not an error, route absent.
	auth, err := botStartBridgeAuth("")
	if auth != nil || err != nil {
		t.Errorf("unset token: auth=%v err=%v, want nil, nil", auth, err)
	}
	mux := chi.NewRouter()
	if mountBotStartBridge(mux, store, m, auth) {
		t.Error("unset token: bridge reported mounted")
	}
	if code := post(mux); code != http.StatusNotFound {
		t.Errorf("unset token: status = %d, want 404 (route absent)", code)
	}

	// Set but too short: a startup error (main exits) that wraps the
	// constructor's cause and does not echo the token.
	short := strings.Repeat("s", bot.MinBridgeTokenLen-1)
	auth, err = botStartBridgeAuth(short)
	if err == nil || auth != nil {
		t.Fatalf("short token: auth=%v err=%v, want nil and an error", auth, err)
	}
	if _, cause := bot.NewBearerTokenAuth(short); errors.Unwrap(err) == nil || errors.Unwrap(err).Error() != cause.Error() {
		t.Errorf("startup error %q does not wrap the constructor's error %q", err, cause)
	}
	if strings.Contains(err.Error(), short) {
		t.Errorf("startup error echoes the token: %v", err)
	}

	auth, err = botStartBridgeAuth(strings.Repeat("a", bot.MinBridgeTokenLen))
	if auth == nil || err != nil {
		t.Fatalf("valid token: auth=%v err=%v", auth, err)
	}
	mux = chi.NewRouter()
	if !mountBotStartBridge(mux, store, m, auth) {
		t.Fatal("valid token: bridge not mounted")
	}
	// Mounted, and guarded by its own auth rather than open.
	if code := post(mux); code != http.StatusUnauthorized {
		t.Errorf("valid token, unauthenticated call: status = %d, want 401", code)
	}
}

// TestServerBootWithBridgeToken is the process-level half: a set but too short
// BOT_START_BRIDGE_TOKEN makes the real binary exit non-zero before serving,
// without echoing the token, while an unset one boots normally.
func TestServerBootWithBridgeToken(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the server binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build server: %v\n%s", err, out)
	}
	start := func(t *testing.T, token string) (*exec.Cmd, *syncBuffer, chan error, string) {
		addr := freeLoopbackAddr(t)
		cmd := exec.Command(bin)
		// Drop any inherited value rather than relying on override order.
		// os/exec documents that the last duplicate in Cmd.Env wins, so an
		// appended value already takes effect today; filtering keeps the
		// child's environment unambiguous regardless.
		var env []string
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "BOT_START_BRIDGE_TOKEN=") {
				env = append(env, kv)
			}
		}
		cmd.Env = append(env,
			"AUTH_MODE=local-dev",
			"ADDR="+addr,
			"PUBLIC_BASE_URL=http://"+addr,
			"DATABASE_URL=file:"+filepath.Join(t.TempDir(), "boot.db"),
			"BOT_START_BRIDGE_TOKEN="+token,
		)
		logs := &syncBuffer{}
		cmd.Stdout, cmd.Stderr = logs, logs
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		return cmd, logs, exited, addr
	}

	t.Run("set but short is fatal", func(t *testing.T) {
		short := "short-bridge-token-value"
		cmd, logs, exited, _ := start(t, short)
		select {
		case err := <-exited:
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() == 0 {
				t.Fatalf("exit = %v, want a non-zero exit\n%s", err, logs.String())
			}
		case <-time.After(60 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
			t.Fatalf("server kept running with a short bridge token\n%s", logs.String())
		}
		out := logs.String()
		if !strings.Contains(out, "BOT_START_BRIDGE_TOKEN is set but unusable") || !strings.Contains(out, "shorter than") {
			t.Errorf("exit did not name the bridge token problem:\n%s", out)
		}
		// Validated before any wiring: the process exits before it even logs
		// "starting", so no store, route or background worker exists yet.
		if strings.Contains(out, `"msg":"starting"`) {
			t.Errorf("bridge token validated only after startup began:\n%s", out)
		}
		if strings.Contains(out, short) {
			t.Errorf("startup log echoes the token:\n%s", out)
		}
	})

	t.Run("unset boots", func(t *testing.T) {
		cmd, logs, exited, addr := start(t, "")
		t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
		deadline := time.Now().Add(60 * time.Second)
		for {
			resp, err := http.Get("http://" + addr + "/healthz")
			if err == nil {
				_ = resp.Body.Close()
				break
			}
			select {
			case werr := <-exited:
				exited <- werr
				t.Fatalf("server exited without a bridge token: %v\n%s", werr, logs.String())
			default:
			}
			if time.Now().After(deadline) {
				t.Fatalf("server never answered /healthz\n%s", logs.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !strings.Contains(logs.String(), `"msg":"starting"`) {
			t.Fatalf("no \"starting\" line, so its absence above proves nothing:\n%s", logs.String())
		}
		if !strings.Contains(logs.String(), "bot-start bridge disabled") {
			t.Errorf("unset token did not log the bridge as disabled:\n%s", logs.String())
		}
	})
}
