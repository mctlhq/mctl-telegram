package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/internal/auth"
	"github.com/mctlhq/mctl-telegram/internal/broadcast"
	"github.com/mctlhq/mctl-telegram/internal/db"
	"github.com/mctlhq/mctl-telegram/internal/oauth"
	"github.com/mctlhq/mctl-telegram/internal/web"
)

// TestServerBootsWithMissingFeedDir is T13 / task 3's DoD at process level:
// the real server binary, pointed at a feed directory that does not exist,
// logs the load failure once, starts, answers /healthz with 200 and still
// serves /docs/product-updates (a notice, not a 500).
func TestServerBootsWithMissingFeedDir(t *testing.T) {
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
	addr := freeLoopbackAddr(t)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		"AUTH_MODE=local-dev",
		"ADDR="+addr,
		"PUBLIC_BASE_URL=http://"+addr,
		"DATABASE_URL=file:"+filepath.Join(dir, "boot.db"),
		"PRODUCT_UPDATE_FEED_DIR="+filepath.Join(dir, "no-such-feed"),
	)
	var logs syncBuffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })

	base := "http://" + addr
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("/healthz = %d, want 200\n%s", resp.StatusCode, logs.String())
			}
			break
		}
		select {
		case werr := <-exited:
			exited <- werr // for the cleanup
			t.Fatalf("server exited before answering /healthz: %v\n%s", werr, logs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never answered /healthz: %v\n%s", err, logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	resp, err := http.Get(base + "/docs/product-updates")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/docs/product-updates = %d, want 200 (a notice, not a failure)", resp.StatusCode)
	}
	out := logs.String()
	if n := strings.Count(out, "product update feed load failed"); n != 1 || !strings.Contains(out, "does not exist") {
		t.Fatalf("want exactly one load-failure log naming the missing directory, got %d:\n%s", n, out)
	}
}

// TestMissingFeedDirReachesBroadcastsPage is the other half: the feed source
// the server builds from a missing directory, handed to the broadcasts page
// exactly as main does (ProductUpdateFeedSource.DigestSource), makes
// prepare-from-digest refuse with "feed is not loaded" and write nothing.
func TestMissingFeedDirReachesBroadcastsPage(t *testing.T) {
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
	const operator = int64(777000333)
	uid, err := store.EnsureUserByTelegramCapture(ctx, db.TelegramIdentityCapture{
		TelegramID: operator, Username: "op", FirstName: "Op", Source: "telegram_oidc", CapturedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	svc := broadcast.NewService(store, broadcast.Config{
		Operators: map[int64]bool{operator: true},
		Policy:    broadcast.Policy{AdminTelegramIDs: map[int64]bool{operator: true}},
	}, nil)
	const issuer = "https://tg.example"
	src := loadProductUpdateFeed(filepath.Join(t.TempDir(), "no-such-feed"), "1.2.3")
	page := web.NewBroadcastServer(store, svc, issuer, oauth.ConnectClientID, src.DigestSource())

	form := url.Values{"category": {"maintenance"}, "digest_id": {"maintenance-2026-w39"}, "version": {"1"}}
	req := httptest.NewRequest(http.MethodPost, "/telegram/connect/broadcasts/prepare-digest", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", issuer)
	req = req.WithContext(auth.With(req.Context(), &auth.Identity{
		UserID: uid, TelegramID: operator, ClientID: oauth.ConnectClientID, Scopes: []string{"admin:broadcast"},
	}))
	w := httptest.NewRecorder()
	page.HandlePrepareDigest(w, req)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "feed is not loaded") {
		t.Fatalf("prepare-digest with a missing feed directory = %d %s, want 409 \"feed is not loaded\"", w.Code, w.Body.String())
	}
	if list, err := store.ListBroadcastCampaigns(ctx, 10); err != nil || len(list) != 0 {
		t.Fatalf("campaigns after the refusal = %d (%v), want 0", len(list), err)
	}
	if _, err := store.GetProductUpdateDigest(ctx, "maintenance-2026-w39", 1); err == nil {
		t.Fatal("a digest was stored although the feed is not loaded")
	}
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
}

// syncBuffer is a bytes.Buffer safe for the child's stdout and stderr to
// write while the test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
