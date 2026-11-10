//go:build unix

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/mctlhq/mctl-telegram/provider/glovo/internal/bridgeclient/bridgefake"
)

// A real SIGTERM delivered through signal.NotifyContext ends run with nil.
func TestSIGTERMExitsCleanly(t *testing.T) {
	f := bridgefake.New()
	defer f.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- run(ctx, baseEnv(t, f.URL())) }()
	time.Sleep(300 * time.Millisecond)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no clean exit after SIGTERM")
	}
}
